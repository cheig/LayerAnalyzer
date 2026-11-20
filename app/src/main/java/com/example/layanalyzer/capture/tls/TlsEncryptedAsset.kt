// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import org.json.JSONTokener

enum class TlsAssetPurpose(val wireName: String) {
    CAPTURE_SECRETS("capture-secrets"),
    CA_PRIVATE_KEY("ca-private-key")
}

/** Local identifiers only; these values are metadata, never paths or secret material. */
data class TlsAssetIdentity(
    val purpose: TlsAssetPurpose,
    val assetId: String,
    val captureId: String? = null,
    val caId: String? = null
) {
    init {
        if (!validId(assetId) ||
            (purpose == TlsAssetPurpose.CAPTURE_SECRETS && (!validId(captureId) || caId != null)) ||
            (purpose == TlsAssetPurpose.CA_PRIVATE_KEY && (!validId(caId) || captureId != null))
        ) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
    }

    companion object {
        fun validId(value: String?): Boolean = value != null &&
            value.length in 1..128 && value.first().isLetterOrDigit() &&
            value.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '_' }
    }
}

enum class TlsAssetErrorCode {
    INVALID_ARGUMENT, INVALID_FORMAT, UNSUPPORTED_VERSION, BINDING_MISMATCH,
    AUTHENTICATION_FAILED, KEY_UNAVAILABLE, TRUNCATED_TAIL, INVALID_SEQUENCE,
    NONCE_REUSED, CAPACITY_EXCEEDED, ALREADY_EXISTS, IN_USE, CLOSED, IO_ERROR, DISK_FULL,
    NOT_FOUND, NATIVE_CLEANUP_FAILED
}

/** The cause and filesystem/provider message deliberately do not cross this boundary. */
class TlsAssetException(val code: TlsAssetErrorCode) : IOException(code.name)

enum class TlsTailRecovery { REJECT, TRUNCATE_INCOMPLETE }

data class TlsAssetWatermark(
    val sequence: Long,
    val plaintextBytes: Long,
    val fileBytes: Long
)

/** Bounds include the nonce index, not just the per-record buffer. Callers may lower them. */
data class TlsAssetLimits(
    val maxPlaintextBytes: Long = 16L * 1024 * 1024,
    val maxRecords: Int = 131_072,
    val maxFileBytes: Long = 32L * 1024 * 1024
) {
    init {
        if (maxPlaintextBytes !in 1..16L * 1024 * 1024 || maxRecords !in 1..131_072 ||
            maxFileBytes !in 10..32L * 1024 * 1024
        ) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
    }
}

/**
 * C06 LAKS v1 primitive. Paths must come from the private local asset store, never
 * imported JSON. Owns an exclusive file lock until close; it does not own a manifest.
 * A returned append watermark means the record has been synced, not that a manifest
 * or a capture has been finalized. No JNI/Wireshark state is changed here.
 */
class TlsEncryptedAsset private constructor(
    private val file: RandomAccessFile,
    private val lock: FileLock,
    val identity: TlsAssetIdentity,
    private val header: ByteArray,
    private val keyBytes: ByteArray,
    private val limits: TlsAssetLimits,
    private val random: SecureRandom
) : AutoCloseable {
    private val nonces = HashSet<Nonce>()
    private var current = TlsAssetWatermark(0, 0, header.size.toLong())
    private var closed = false
    private var failed = false
    private var reading = false
    var recoveredTailBytes: Long = 0
        private set

    val watermark: TlsAssetWatermark
        @Synchronized get() {
            checkOpen()
            return current
        }

    /** One NSS line (without LF), or one CA PKCS#8 block. Caller retains its buffer. */
    @Synchronized
    fun append(plaintext: ByteArray): TlsAssetWatermark {
        checkOpen()
        if (plaintext.isEmpty() || plaintext.size > MAX_PLAINTEXT_RECORD_BYTES) {
            throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        }
        checkBudget(current.sequence + 1, current.plaintextBytes + plaintext.size,
            current.fileBytes + 4 + 36 + plaintext.size)
        // Reject a collision instead of retrying a faulty entropy source indefinitely.
        val nonce = ByteArray(12).also(random::nextBytes)
        if (!nonces.add(Nonce.of(nonce))) throw TlsAssetException(TlsAssetErrorCode.NONCE_REUSED)
        val sequence = current.sequence + 1
        try {
            val ciphertext = crypt(Cipher.ENCRYPT_MODE, keyBytes, header, sequence, nonce, plaintext)
            file.seek(current.fileBytes)
            file.writeInt(20 + ciphertext.size)
            file.writeLong(sequence)
            file.write(nonce)
            file.write(ciphertext)
            file.fd.sync()
            current = TlsAssetWatermark(sequence, current.plaintextBytes + plaintext.size, file.filePointer)
            return current
        } catch (error: Exception) {
            // An uncertain write must be reopened and authenticated before another append.
            failed = true
            throw sanitized(error)
        }
    }

    /**
     * Streams authenticated records, at most 16 KiB each. The callback must consume/copy
     * the borrowed buffer before returning; it is cleared even if the callback throws.
     * The entire file was verified at open. A caller producing output still must discard
     * that output on any failure (e.g. external modification or a cancelled consumer).
     */
    @Synchronized
    fun readRecords(consume: (sequence: Long, plaintext: ByteArray) -> Unit) {
        checkOpen()
        reading = true
        try {
            val scan = scan(TlsTailRecovery.REJECT, consume)
            if (scan.watermark != current) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        } catch (error: Exception) {
            failed = true
            if (error is IOException || error is GeneralSecurityException) throw sanitized(error)
            throw error // A consumer cancellation is not a storage error.
        } finally {
            reading = false
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        if (reading) throw TlsAssetException(TlsAssetErrorCode.IN_USE)
        closed = true
        keyBytes.fill(0)
        nonces.clear()
        try {
            lock.release()
        } catch (error: IOException) {
            throw sanitized(error)
        } finally {
            try { file.close() } catch (error: IOException) { throw sanitized(error) }
        }
    }

    private fun checkOpen() {
        if (closed || failed) throw TlsAssetException(TlsAssetErrorCode.CLOSED)
        if (reading) throw TlsAssetException(TlsAssetErrorCode.IN_USE)
    }

    private fun checkBudget(sequence: Long, plaintext: Long, bytes: Long) {
        if (sequence > limits.maxRecords || plaintext > limits.maxPlaintextBytes || bytes > limits.maxFileBytes) {
            throw TlsAssetException(TlsAssetErrorCode.CAPACITY_EXCEEDED)
        }
    }

    private data class Scan(val watermark: TlsAssetWatermark, val tail: Long, val nonces: Set<Nonce>)

    private fun scan(recovery: TlsTailRecovery, consume: ((Long, ByteArray) -> Unit)? = null): Scan {
        val fileLength = file.length()
        if (fileLength > limits.maxFileBytes) throw TlsAssetException(TlsAssetErrorCode.CAPACITY_EXCEEDED)
        file.seek(0)
        val liveHeader = ByteArray(header.size)
        file.readFully(liveHeader)
        if (!liveHeader.contentEquals(header)) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        var mark = TlsAssetWatermark(0, 0, header.size.toLong())
        val seen = HashSet<Nonce>()
        while (file.filePointer < fileLength) {
            val start = file.filePointer
            val remaining = fileLength - start
            if (remaining < 4) return incomplete(recovery, mark, fileLength - start, seen)
            val length = file.readInt()
            // Validate signed/overflowing lengths before allocation or trusting EOF.
            if (length !in MIN_RECORD_BYTES..MAX_RECORD_BYTES) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            if (remaining < 4L + length) return incomplete(recovery, mark, fileLength - start, seen)
            val sequence = file.readLong()
            if (sequence != mark.sequence + 1) throw TlsAssetException(TlsAssetErrorCode.INVALID_SEQUENCE)
            val nonce = ByteArray(12).also(file::readFully)
            if (!seen.add(Nonce.of(nonce))) throw TlsAssetException(TlsAssetErrorCode.NONCE_REUSED)
            val plainSize = length - MIN_RECORD_BYTES
            checkBudget(sequence, mark.plaintextBytes + plainSize, start + 4L + length)
            val ciphertext = ByteArray(length - 20).also(file::readFully)
            val plaintext = crypt(Cipher.DECRYPT_MODE, keyBytes, header, sequence, nonce, ciphertext)
            try {
                consume?.invoke(sequence, plaintext)
            } finally {
                plaintext.fill(0)
            }
            mark = TlsAssetWatermark(sequence, mark.plaintextBytes + plainSize, file.filePointer)
        }
        return Scan(mark, 0, seen)
    }

    private fun incomplete(recovery: TlsTailRecovery, mark: TlsAssetWatermark, tail: Long, seen: Set<Nonce>): Scan {
        if (recovery == TlsTailRecovery.REJECT) throw TlsAssetException(TlsAssetErrorCode.TRUNCATED_TAIL)
        // Only reached after every preceding COMPLETE record passed authentication.
        file.setLength(mark.fileBytes)
        file.fd.sync()
        return Scan(mark, tail, seen)
    }

    private data class Nonce(val first: Long, val last: Int) {
        companion object {
            fun of(bytes: ByteArray): Nonce = ByteBuffer.wrap(bytes).let { Nonce(it.long, it.int) }
        }
    }

    companion object {
        const val MAX_HEADER_JSON_BYTES = 4096
        const val MIN_RECORD_BYTES = 36
        const val MAX_RECORD_BYTES = 16384
        const val MAX_PLAINTEXT_RECORD_BYTES = MAX_RECORD_BYTES - MIN_RECORD_BYTES
        private const val MAGIC = 0x4c414b53
        private val creationLock = Any()

        /**
         * Creates only absent targets in an existing private directory. Neither a damaged
         * pair nor a missing wrapping key is repaired by overwriting existing ciphertext.
         * Store-level replacement must use a new asset ID and then commit its manifest.
         */
        fun create(
            assetFile: File,
            wrappedKeyFile: File,
            identity: TlsAssetIdentity,
            wrappingKeys: TlsWrappingKeyProvider,
            limits: TlsAssetLimits = TlsAssetLimits(),
            random: SecureRandom = SecureRandom()
        ): TlsEncryptedAsset = synchronized(creationLock) {
            storageOperation {
                validateFiles(assetFile, wrappedKeyFile)
                if (assetFile.exists() || wrappedKeyFile.exists()) throw TlsAssetException(TlsAssetErrorCode.ALREADY_EXISTS)
                val header = encodeHeader(identity)
                if (header.size > limits.maxFileBytes) throw TlsAssetException(TlsAssetErrorCode.CAPACITY_EXCEEDED)
                val dataKey = ByteArray(32).also(random::nextBytes)
                var reserved = false
                var keyCommitted = false
                var output: RandomAccessFile? = null
                var fileLock: FileLock? = null
                try {
                    val wrapped = wrappingKeys.wrap(identity, dataKey)
                    if (wrapped.size != AesGcmTlsWrappingKeyProvider.WRAPPED_SIZE) {
                        throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
                    }
                    Files.createFile(assetFile.toPath()) // exclusive reservation, also across processes
                    reserved = true
                    output = RandomAccessFile(assetFile, "rw")
                    fileLock = output.channel.tryLock() ?: throw TlsAssetException(TlsAssetErrorCode.IN_USE)
                    writeAtomic(wrappedKeyFile, wrapped)
                    keyCommitted = true
                    output.write(header)
                    output.fd.sync()
                    TlsEncryptedAsset(output, fileLock, identity, header, dataKey.copyOf(), limits, random)
                } catch (error: Exception) {
                    // Best-effort cleanup only of files reserved by this create operation.
                    // A failed cleanup leaves an unusable pair; create still refuses overwrite.
                    runCatching { fileLock?.release() }
                    runCatching { output?.close() }
                    if (reserved) runCatching { Files.deleteIfExists(assetFile.toPath()) }
                    if (keyCommitted) runCatching { Files.deleteIfExists(wrappedKeyFile.toPath()) }
                    throw error
                } finally {
                    dataKey.fill(0)
                }
            }
        }

        fun open(
            assetFile: File,
            wrappedKeyFile: File,
            expectedIdentity: TlsAssetIdentity,
            wrappingKeys: TlsWrappingKeyProvider,
            recovery: TlsTailRecovery = TlsTailRecovery.REJECT,
            limits: TlsAssetLimits = TlsAssetLimits(),
            random: SecureRandom = SecureRandom()
        ): TlsEncryptedAsset = storageOperation {
            validateFiles(assetFile, wrappedKeyFile)
            if (!assetFile.isFile || !wrappedKeyFile.isFile) throw TlsAssetException(TlsAssetErrorCode.IO_ERROR)
            val file = RandomAccessFile(assetFile, "rw")
            var lock: FileLock? = null
            var key: ByteArray? = null
            try {
                lock = try { file.channel.tryLock() } catch (_: OverlappingFileLockException) { null }
                if (lock == null) throw TlsAssetException(TlsAssetErrorCode.IN_USE)
                if (file.length() > limits.maxFileBytes) throw TlsAssetException(TlsAssetErrorCode.CAPACITY_EXCEEDED)
                val header = readHeader(file, expectedIdentity)
                val wrapped = RandomAccessFile(wrappedKeyFile, "r").use {
                    if (it.length() != AesGcmTlsWrappingKeyProvider.WRAPPED_SIZE.toLong()) {
                        throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
                    }
                    ByteArray(AesGcmTlsWrappingKeyProvider.WRAPPED_SIZE).also(it::readFully)
                }
                key = wrappingKeys.unwrap(expectedIdentity, wrapped)
                if (key.size != 32) throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
                val asset = TlsEncryptedAsset(file, lock, expectedIdentity, header, key, limits, random)
                val scan = asset.scan(recovery)
                asset.current = scan.watermark
                asset.recoveredTailBytes = scan.tail
                asset.nonces.addAll(scan.nonces)
                asset
            } catch (error: Exception) {
                key?.fill(0)
                try { lock?.release() } finally { file.close() }
                throw error
            }
        }

        private fun validateFiles(asset: File, wrapped: File) {
            val parent = asset.absoluteFile.parentFile
            if (parent == null || parent != wrapped.absoluteFile.parentFile || asset.absoluteFile == wrapped.absoluteFile ||
                !parent.isDirectory
            ) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
            // Android's own data directory is not lexically canonical (the framework hands out
            // /data/user/0/<pkg> while its resolved path is /data/data/<pkg>), so compare resolved
            // paths rather than demanding the trusted caller's path already be canonical. A symlink or
            // `..` in the part the caller controls still fails: a redirected final component lands in
            // another directory or under another name.
            val canonicalParent = parent.canonicalFile
            val canonicalAsset = asset.canonicalFile
            val canonicalWrapped = wrapped.canonicalFile
            if (canonicalAsset.parentFile != canonicalParent || canonicalWrapped.parentFile != canonicalParent ||
                canonicalAsset == canonicalWrapped || canonicalAsset.name != asset.name ||
                canonicalWrapped.name != wrapped.name
            ) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        }

        private fun encodeHeader(identity: TlsAssetIdentity): ByteArray {
            val json = JSONObject().put("purpose", identity.purpose.wireName).put("assetId", identity.assetId)
                .put("cipher", "AES-256-GCM")
            identity.captureId?.let { json.put("captureId", it) }
            identity.caId?.let { json.put("caId", it) }
            val bytes = json.toString().toByteArray(Charsets.UTF_8)
            if (bytes.size > MAX_HEADER_JSON_BYTES) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
            return ByteBuffer.allocate(10 + bytes.size).putInt(MAGIC).putShort(1).putInt(bytes.size).put(bytes).array()
        }

        private fun readHeader(file: RandomAccessFile, expected: TlsAssetIdentity): ByteArray {
            if (file.length() < 10) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            if (file.readInt() != MAGIC) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            if (file.readUnsignedShort() != 1) throw TlsAssetException(TlsAssetErrorCode.UNSUPPORTED_VERSION)
            val length = file.readInt()
            if (length !in 1..MAX_HEADER_JSON_BYTES || file.length() < 10L + length) {
                throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            }
            val bytes = ByteArray(length).also(file::readFully)
            val json = try {
                val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
                val tokener = JSONTokener(text)
                val parsed = tokener.nextValue() as? JSONObject ?: throw IllegalArgumentException()
                if (tokener.nextClean() != '\u0000') throw IllegalArgumentException()
                parsed
            } catch (_: Exception) { throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT) }
            val fields = if (expected.purpose == TlsAssetPurpose.CAPTURE_SECRETS) {
                setOf("purpose", "assetId", "captureId", "cipher")
            } else setOf("purpose", "assetId", "caId", "cipher")
            if (json.keys().asSequence().toSet() != fields || json.opt("cipher") != "AES-256-GCM") {
                throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            }
            if (json.opt("purpose") != expected.purpose.wireName || json.opt("assetId") != expected.assetId ||
                (expected.captureId != null && json.opt("captureId") != expected.captureId) ||
                (expected.caId != null && json.opt("caId") != expected.caId)
            ) throw TlsAssetException(TlsAssetErrorCode.BINDING_MISMATCH)
            return ByteBuffer.allocate(10 + length).putInt(MAGIC).putShort(1).putInt(length).put(bytes).array()
        }

        private fun crypt(mode: Int, key: ByteArray, header: ByteArray, sequence: Long,
                          nonce: ByteArray, input: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(header)
            cipher.updateAAD(ByteBuffer.allocate(8).putLong(sequence).array())
            return cipher.doFinal(input)
        }

        /** Encrypted bytes only. Never deletes an old target before attempting atomic rename. */
        private fun writeAtomic(target: File, bytes: ByteArray) {
            val temporary = File.createTempFile(".tls-wrapped-", ".tmp", target.absoluteFile.parentFile)
            try {
                FileOutputStream(temporary).use { out -> out.write(bytes); out.fd.sync() }
                Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
            } finally {
                Files.deleteIfExists(temporary.toPath())
            }
        }

        private inline fun <T> storageOperation(operation: () -> T): T = try {
            operation()
        } catch (error: Exception) { throw sanitized(error) }

        internal fun sanitized(error: Exception): TlsAssetException = when (error) {
            is TlsAssetException -> error
            is AEADBadTagException -> TlsAssetException(TlsAssetErrorCode.AUTHENTICATION_FAILED)
            is GeneralSecurityException -> TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
            is java.nio.file.FileAlreadyExistsException -> TlsAssetException(TlsAssetErrorCode.ALREADY_EXISTS)
            is IOException -> {
                // Android libcore exposes ENOSPC in IOException text; do not return that text.
                val message = error.message.orEmpty().lowercase(java.util.Locale.ROOT)
                TlsAssetException(if ("enospc" in message || "no space left" in message || "disk full" in message ||
                    "not enough space on the disk" in message) TlsAssetErrorCode.DISK_FULL else TlsAssetErrorCode.IO_ERROR)
            }
            else -> TlsAssetException(TlsAssetErrorCode.IO_ERROR)
        }
    }
}
