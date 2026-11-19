// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import android.content.Context
import com.example.layanalyzer.data.TlsAnalysisSecretLease
import com.example.layanalyzer.data.CaptureFileAccess
import com.example.layanalyzer.data.CaptureFiles
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import org.json.JSONObject
import org.json.JSONTokener

/** Local metadata only. Persisted sequence is NOT an analysis generation or completeness claim. */
data class TlsSecretAssetRef(
    val captureId: String,
    val assetId: String,
    val watermark: TlsAssetWatermark,
    val keyLogBytes: Long
)

/** Defaults support a replacement lease while the old analysis is still being cleared. */
internal data class TlsSecretStoreLimits(
    val maxKeyLogBytes: Long = KeyLogParser.MAX_TOTAL_BYTES + 1,
    val maxActiveLeases: Int = 2
) {
    init {
        if (maxKeyLogBytes !in 1..KeyLogParser.MAX_TOTAL_BYTES + 1 || maxActiveLeases !in 1..2) {
            throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        }
    }
}

/**
 * All public operations accept local IDs, never imported paths. New imports are immutable
 * LAKS assets with fresh data keys; current.json is the atomic publication point. It is a
 * private storage index, not the future capture.json manifest (TLS-301), and contains no
 * secrets, arbitrary paths, analysis generation or assertion of complete TLS decryption.
 * Blocking I/O: call off the UI thread. checkCancelled may call coroutine ensureActive().
 */
class TlsSecretStore internal constructor(
    noBackupDirectory: File,
    private val wrappingKeys: TlsWrappingKeyProvider,
    private val limits: TlsSecretStoreLimits = TlsSecretStoreLimits()
) {
    constructor(context: Context) : this(context.applicationContext.noBackupFilesDir, AndroidTlsWrappingKeyProvider())

    private val root = storeIo { noBackupDirectory.canonicalFile }
    private val assetsRoot = File(root, "capture-secrets")
    private val leasesRoot = File(root, "tls-analysis-leases")

    /** Only a complete parser Success can be imported; failure has no partial record API. */
    fun importRecords(
        captureId: String,
        parsed: KeyLogParseResult.Success,
        checkCancelled: () -> Unit = {}
    ): TlsSecretAssetRef = usingCapture(captureId) {
        validateId(captureId)
        checkCancelled()
        if (parsed.records.isEmpty() || parsed.records.size > TlsAssetLimits().maxRecords) {
            fail(TlsAssetErrorCode.INVALID_ARGUMENT)
        }
        var keyLogBytes = 0L
        for (record in parsed.records) {
            checkCancelled()
            validateRecord(record)
            keyLogBytes += record.encodedSizeBytes + 1L
            if (keyLogBytes > limits.maxKeyLogBytes) fail(TlsAssetErrorCode.CAPACITY_EXCEEDED)
        }
        val capture = childDirectory(assetsRoot, captureId)
        val old = readIndex(capture, captureId)
        cleanupCapture(capture, old)
        val assetId = UUID.randomUUID().toString()
        val directory = childDirectory(capture, assetId)
        val identity = identity(captureId, assetId)
        var published = false
        try {
            val watermark = TlsEncryptedAsset.create(
                File(directory, ENCRYPTED), File(directory, WRAPPED), identity, wrappingKeys
            ).use { asset ->
                for (record in parsed.records) {
                    checkCancelled()
                    val bytes = record.toNssLine().toByteArray(Charsets.US_ASCII)
                    try { asset.append(bytes) } finally { bytes.fill(0) }
                }
                asset.watermark
            }
            val reference = TlsSecretAssetRef(captureId, assetId, watermark, keyLogBytes)
            checkCancelled()
            writeIndex(capture, reference)
            published = true
            // A cleanup failure must not turn an already published import into failure.
            // The next access/startup retries deletion of unpublished/previous assets.
            try { storeIo { cleanupCapture(capture, reference) } } catch (_: TlsAssetException) { }
            reference
        } finally {
            if (!published) removeAssetDirectory(directory)
        }
    }

    /**
     * Opens a live, append-only secrets asset for one capture (TLS-210). The
     * returned sink is the real-time path: it accepts records while the capture
     * runs and publishes the watermark it actually reached when it is finished.
     * Encryption and sync happen on the sink's own consumer thread, so this call
     * and [TlsLiveSecretSink.offer] never perform blocking disk I/O;
     * [TlsLiveSecretSink.finish] blocks for at most its drain budget.
     *
     * The asset stays unpublished, and therefore invisible to [currentAsset] and
     * [acquireLease], until it is finished. One capture has at most one live sink
     * in this process.
     */
    internal fun openLiveSecrets(
        captureId: String,
        limits: TlsLiveSecretLimits = TlsLiveSecretLimits(),
        threadFactory: (Runnable) -> Thread = TlsLiveSecretSink.DEFAULT_THREAD_FACTORY
    ): TlsLiveSecretSink = locked {
        validateId(captureId)
        val capture = childDirectory(assetsRoot, captureId)
        val assetId = UUID.randomUUID().toString()
        val directory = childDirectory(capture, assetId)
        val use = CaptureFileAccess.retain(capture)
        activeLiveUses[directory.absolutePath] = use
        activeLiveDirectories.add(directory.absolutePath)
        var asset: TlsEncryptedAsset? = null
        try {
            val encrypted = checkedChild(directory, ENCRYPTED)
            asset = TlsEncryptedAsset.create(
                encrypted, checkedChild(directory, WRAPPED), identity(captureId, assetId),
                wrappingKeys, limits.asset
            )
            TlsLiveSecretSink(
                TlsLiveSecretTarget(
                    captureId = captureId,
                    assetId = assetId,
                    encrypted = encrypted,
                    asset = asset,
                    publish = { watermark -> publishLive(capture, captureId, assetId, watermark) },
                    discard = { discardLive(directory) },
                    detach = { detachLive(directory) }
                ),
                limits,
                threadFactory
            )
        } catch (error: Exception) {
            // Nothing was published, so the unpublished pair is removed rather
            // than left for a later sweep to find.
            activeLiveDirectories.remove(directory.absolutePath)
            activeLiveUses.remove(directory.absolutePath)?.close()
            runCatching { asset?.close() }
            runCatching { removeAssetDirectory(directory) }
            throw sanitizedStoreError(error)
        }
    }

    /** No manifest means no secrets; never search for adjacent user keylogs. */
    fun currentAsset(captureId: String): TlsSecretAssetRef? = locked {
        validateId(captureId)
        val capture = checkedChild(assetsRoot, captureId)
        if (!capture.exists()) return@locked null
        requireDirectory(capture)
        readIndex(capture, captureId).also { cleanupCapture(capture, it) }
    }

    /** Rollback only for a new bundle import whose fresh capture id has not been exposed. */
    internal fun discardUnattachedImport(reference: TlsSecretAssetRef) = locked {
        validateId(reference.captureId)
        val capture = checkedChild(assetsRoot, reference.captureId)
        val current = readIndex(capture, reference.captureId)
        if (current?.assetId != reference.assetId) fail(TlsAssetErrorCode.BINDING_MISMATCH)
        Files.delete(checkedChild(capture, INDEX).toPath())
        cleanupCapture(capture, null)
        Files.delete(capture.toPath())
    }

    /**
     * Imports keys for the current analysis only. It deliberately never publishes
     * current.json or replaces the capture's retained encrypted asset: a valid but
     * unrelated keylog must not destroy the keys named by a saved VPN manifest.
     * The same private-file, liveness-lock and capacity rules as retained leases
     * apply, and close/startup cleanup removes the temporary plaintext.
     */
    fun acquireImportedLease(
        captureId: String,
        parsed: KeyLogParseResult.Success,
        checkCancelled: () -> Unit = {}
    ): TlsAnalysisSecretLease = usingCapture(captureId) {
        checkCancelled()
        if (parsed.records.isEmpty() || parsed.records.size > TlsAssetLimits().maxRecords) {
            fail(TlsAssetErrorCode.INVALID_ARGUMENT)
        }
        var bytes = 0L
        for (record in parsed.records) {
            checkCancelled()
            validateRecord(record)
            bytes += record.encodedSizeBytes + 1L
            if (bytes > limits.maxKeyLogBytes) fail(TlsAssetErrorCode.CAPACITY_EXCEEDED)
        }
        // No encrypted asset is published for this analysis-only reference.
        val sequence = parsed.records.size.toLong()
        val reference = TlsSecretAssetRef(captureId, UUID.randomUUID().toString(),
            TlsAssetWatermark(sequence, bytes - sequence, 0), bytes)
        createLease(reference, checkCancelled) { output ->
            for (record in parsed.records) {
                checkCancelled()
                val line = record.toNssLine().toByteArray(Charsets.US_ASCII)
                try { output.write(line); output.write('\n'.code) } finally { line.fill(0) }
            }
        }
    }

    /** expectedAssetId prevents a delayed import transaction from using a newer replacement. */
    fun acquireLease(
        captureId: String,
        expectedAssetId: String? = null,
        checkCancelled: () -> Unit = {}
    ): TlsAnalysisSecretLease = locked {
        validateId(captureId)
        if (expectedAssetId != null) validateId(expectedAssetId)
        checkCancelled()
        cleanupLeasesLocked()
        val capture = checkedChild(assetsRoot, captureId)
        val reference = readIndex(capture, captureId) ?: fail(TlsAssetErrorCode.NOT_FOUND)
        if (expectedAssetId != null && expectedAssetId != reference.assetId) fail(TlsAssetErrorCode.BINDING_MISMATCH)
        cleanupCapture(capture, reference)
        val assetDirectory = checkedChild(capture, reference.assetId).also(::requireDirectory)
        val encrypted = checkedChild(assetDirectory, ENCRYPTED)
        val wrapped = checkedChild(assetDirectory, WRAPPED)
        checkCancelled()
        TlsEncryptedAsset.open(encrypted, wrapped, identity(captureId, reference.assetId), wrappingKeys).use { asset ->
            // Whole-record deletion can authenticate; compare the separately committed watermark.
            if (asset.watermark != reference.watermark) fail(TlsAssetErrorCode.INVALID_FORMAT)
            createLease(reference, checkCancelled, beforeDelivery = { asset.close() }) { output ->
                var written = 0L
                asset.readRecords { _, bytes ->
                    checkCancelled()
                    if (bytes.isEmpty() || bytes.size > KeyLogParser.MAX_LINE_BYTES ||
                        bytes.any { it.toInt() !in 0x20..0x7e }) fail(TlsAssetErrorCode.INVALID_FORMAT)
                    written += bytes.size + 1L
                    if (written > limits.maxKeyLogBytes || written > reference.keyLogBytes) {
                        fail(TlsAssetErrorCode.CAPACITY_EXCEEDED)
                    }
                    output.write(bytes)
                    output.write('\n'.code)
                }
                if (written != reference.keyLogBytes) fail(TlsAssetErrorCode.INVALID_FORMAT)
            }
        }
    }

    /** Called under the store lock; every exit before delivery releases the file and liveness lock. */
    private fun createLease(
        reference: TlsSecretAssetRef,
        checkCancelled: () -> Unit,
        beforeDelivery: () -> Unit = {},
        write: (FileOutputStream) -> Unit
    ): TlsAnalysisSecretLease {
        cleanupLeasesLocked()
        var active = 0
        forEachChild(leasesRoot) { active++ }
        if (active >= limits.maxActiveLeases || reference.keyLogBytes > limits.maxKeyLogBytes) {
            fail(TlsAssetErrorCode.CAPACITY_EXCEEDED)
        }
        val directory = childDirectory(leasesRoot, UUID.randomUUID().toString())
        val live = acquireFileLock(checkedChild(directory, LIVE_LOCK)) ?: fail(TlsAssetErrorCode.IN_USE)
        activeLeaseDirectories.add(directory.absolutePath)
        val plaintext = checkedChild(directory, PLAINTEXT)
        val captureUse = CaptureFileAccess.retain(checkedChild(assetsRoot, reference.captureId))
        var delivered = false
        try {
            createPrivateFile(plaintext)
            FileOutputStream(plaintext).use { output ->
                write(output)
                output.fd.sync()
            }
            checkCancelled()
            beforeDelivery() // Close authenticated input before exposing any plaintext.
            val lease = TlsAnalysisSecretLease(reference, plaintext) {
                locked { releaseLease(directory, live) }
                captureUse.close()
            }
            delivered = true
            return lease
        } finally {
            if (!delivered) {
                try { releaseLease(directory, live) } finally {
                    live.close()
                    activeLeaseDirectories.remove(directory.absolutePath)
                    captureUse.close()
                }
            }
        }
    }

    /**
     * Called at application startup and safe to repeat while leases are active. A kernel
     * file lock (not a PID/age heuristic) distinguishes another live lease/process from an
     * orphan after process death. Failed cleanup is reported; no new plaintext is created.
     */
    fun cleanupOrphans(): Int = locked {
        val removed = cleanupLeasesLocked()
        forEachChild(assetsRoot) { capture ->
            if (TlsAssetIdentity.validId(capture.name)) {
                requireDirectory(capture)
                cleanupCapture(capture, readIndex(capture, capture.name))
            }
        }
        removed
    }

    /** No unwrap is needed to delete, so losing Keystore never blocks capture deletion. */
    fun purgeCapture(captureId: String, beforePurge: () -> Unit = {}, afterPurge: () -> Unit = {}) = locked {
        validateId(captureId)
        val capture = checkedChild(assetsRoot, captureId)
        CaptureFileAccess.idle(listOf(capture)) {
            cleanupLeasesLocked()
            CaptureFiles.checkTree(capture)
            beforePurge()
            // Destroy wrapped per-asset data keys first. The shared Keystore alias also
            // wraps other captures/CA material and must never be deleted here.
            if (capture.exists()) forEachChild(capture) { asset ->
                if (asset.isDirectory) Files.deleteIfExists(checkedChild(asset, WRAPPED).toPath())
            }
            CaptureFiles.deleteTree(capture)
            afterPurge()
        }
    }

    fun cleanupPlaintextOrphans(): Int = locked { cleanupLeasesLocked() }

    /** Recover only this local capture. A sole unpublished live asset can be authenticated
     * after process death; multiple candidates are ambiguous and never guessed. */
    fun recoverCapture(captureId: String): TlsSecretAssetRef? = locked {
        validateId(captureId)
        val capture = checkedChild(assetsRoot, captureId)
        CaptureFileAccess.idle(listOf(capture)) {
            if (!capture.exists()) return@idle null
            requireDirectory(capture)
            val current = readIndex(capture, captureId)
            val candidates = CaptureFiles.children(capture).filter { it.isDirectory }
            val assetId = current?.assetId ?: when (candidates.size) {
                0 -> return@idle null
                1 -> candidates.single().name.also(::requireUuid)
                else -> fail(TlsAssetErrorCode.INVALID_FORMAT)
            }
            val directory = checkedChild(capture, assetId).also(::requireDirectory)
            TlsEncryptedAsset.open(checkedChild(directory, ENCRYPTED), checkedChild(directory, WRAPPED),
                identity(captureId, assetId), wrappingKeys, TlsTailRecovery.TRUNCATE_INCOMPLETE).use { asset ->
                // A committed watermark may not be silently lowered after whole-record loss.
                if (current != null && asset.watermark != current.watermark) fail(TlsAssetErrorCode.INVALID_FORMAT)
                if (asset.watermark.sequence == 0L) return@idle null
                val recovered = TlsSecretAssetRef(captureId, assetId, asset.watermark,
                    asset.watermark.plaintextBytes + asset.watermark.sequence)
                if (recovered.keyLogBytes > limits.maxKeyLogBytes) fail(TlsAssetErrorCode.CAPACITY_EXCEEDED)
                writeIndex(capture, recovered)
                recovered
            }
        }
    }

    private fun <T> usingCapture(captureId: String, operation: () -> T): T {
        validateId(captureId)
        return CaptureFileAccess.retain(checkedChild(assetsRoot, captureId)).use { locked(operation) }
    }

    private fun cleanupLeasesLocked(): Int {
        var removed = 0
        forEachChild(leasesRoot) { directory ->
            requireUuid(directory.name)
            requireDirectory(directory)
            // POSIX fcntl locks may be released by closing ANY fd for that inode in
            // the owning process. Never even open a second fd for our own live lease.
            if (directory.absolutePath !in activeLeaseDirectories) {
                val live = acquireFileLock(checkedChild(directory, LIVE_LOCK))
                if (live != null) {
                    try { releaseLease(directory, live) } finally { live.close() }
                    removed++
                }
            }
        }
        return removed
    }

    private fun releaseLease(directory: File, live: HeldLock) {
        requireDirectory(directory)
        try {
            Files.deleteIfExists(checkedChild(directory, PLAINTEXT).toPath())
        } catch (error: Exception) {
            // Keep the liveness lock if plaintext deletion failed; caller can retry close.
            throw sanitizedStoreError(error)
        }
        live.close()
        activeLeaseDirectories.remove(directory.absolutePath)
        Files.deleteIfExists(checkedChild(directory, LIVE_LOCK).toPath())
        Files.deleteIfExists(directory.toPath())
    }

    private fun cleanupCapture(capture: File, keep: TlsSecretAssetRef?) {
        forEachChild(capture) { child ->
            when {
                child.name == INDEX -> Unit
                child.name.startsWith(".index-") && child.name.endsWith(".tmp") -> {
                    if (!child.isFile) fail(TlsAssetErrorCode.INVALID_FORMAT)
                    Files.delete(child.toPath())
                }
                // A live asset is unpublished until its sink publishes it, so
                // "not the current asset" must not be read as garbage while a
                // capture is still appending to it.
                child.absolutePath in activeLiveDirectories -> Unit
                child.name != keep?.assetId -> {
                    requireUuid(child.name)
                    removeAssetDirectory(child)
                }
            }
        }
    }

    /**
     * Publishes a finished live asset: the index is written first, so the asset
     * becomes reachable only once its watermark is on disk, and only then is the
     * previous asset of this capture removed.
     */
    private fun publishLive(
        capture: File,
        captureId: String,
        assetId: String,
        watermark: TlsAssetWatermark
    ): TlsSecretAssetRef = locked {
        if (watermark.sequence < 1 || watermark.plaintextBytes < 1) fail(TlsAssetErrorCode.INVALID_ARGUMENT)
        val keyLogBytes = watermark.plaintextBytes + watermark.sequence
        if (keyLogBytes > limits.maxKeyLogBytes) fail(TlsAssetErrorCode.CAPACITY_EXCEEDED)
        val reference = TlsSecretAssetRef(captureId, assetId, watermark, keyLogBytes)
        writeIndex(capture, reference)
        activeLiveDirectories.remove(checkedChild(capture, assetId).absolutePath)
        activeLiveUses.remove(checkedChild(capture, assetId).absolutePath)?.close()
        // A cleanup failure must not turn an already published capture into failure.
        try { cleanupCapture(capture, reference) } catch (_: TlsAssetException) { }
        reference
    }

    /** Removes an unpublished live asset. Only called once its consumer has returned. */
    private fun discardLive(directory: File) {
        locked {
            activeLiveDirectories.remove(directory.absolutePath)
            activeLiveUses.remove(directory.absolutePath)?.close()
            if (directory.exists()) removeAssetDirectory(directory)
        }
    }

    /**
     * Drops the active registration without deleting. Called by a consumer that
     * returned after its sink had already given up on the stop budget: from then
     * on the unpublished directory is a leftover, and the next orphan sweep
     * deletes it rather than this call deleting a file a live writer held open.
     */
    private fun detachLive(directory: File) {
        synchronized(processLock) {
            activeLiveDirectories.remove(directory.absolutePath)
            activeLiveUses.remove(directory.absolutePath)?.close()
        }
    }

    private fun removeAssetDirectory(directory: File) {
        if (!directory.exists()) return
        requireDirectory(directory)
        // Flat local asset directory; never recursively follow links or imported names.
        forEachChild(directory) { file ->
            if (!Files.isRegularFile(file.toPath(), NOFOLLOW_LINKS)) fail(TlsAssetErrorCode.INVALID_FORMAT)
            Files.delete(file.toPath())
        }
        Files.delete(directory.toPath())
    }

    private fun writeIndex(capture: File, reference: TlsSecretAssetRef) {
        val json = JSONObject().put("schemaVersion", 1).put("captureId", reference.captureId)
            .put("assetId", reference.assetId).put("secretsPersistedSequence", reference.watermark.sequence)
            .put("plaintextBytes", reference.watermark.plaintextBytes).put("fileBytes", reference.watermark.fileBytes)
            .put("keyLogBytes", reference.keyLogBytes)
        val temporary = checkedChild(capture, ".index-${UUID.randomUUID()}.tmp")
        createPrivateFile(temporary)
        var committed = false
        try {
            FileOutputStream(temporary).use { output ->
                output.write(json.toString().toByteArray(Charsets.UTF_8))
                output.fd.sync()
            }
            // Same-directory atomic replace; never delete the old valid mapping first.
            Files.move(temporary.toPath(), checkedChild(capture, INDEX).toPath(), ATOMIC_MOVE, REPLACE_EXISTING)
            committed = true
        } finally {
            if (!committed) Files.deleteIfExists(temporary.toPath())
        }
    }

    private fun readIndex(capture: File, captureId: String): TlsSecretAssetRef? {
        if (!capture.exists()) return null
        requireDirectory(capture)
        val index = checkedChild(capture, INDEX)
        if (!index.exists()) return null
        if (!index.isFile || index.length() !in 1..MAX_INDEX_BYTES) fail(TlsAssetErrorCode.INVALID_FORMAT)
        val bytes = ByteArray(MAX_INDEX_BYTES.toInt() + 1)
        val text = index.inputStream().use { input ->
            var used = 0
            while (used < bytes.size) {
                val count = input.read(bytes, used, bytes.size - used)
                if (count == -1) break
                if (count == 0) fail(TlsAssetErrorCode.IO_ERROR)
                used += count
            }
            if (used !in 1..MAX_INDEX_BYTES.toInt() || bytes.take(used).any { it.toInt() !in 0x20..0x7e }) {
                fail(TlsAssetErrorCode.INVALID_FORMAT)
            }
            String(bytes, 0, used, Charsets.US_ASCII)
        }
        try {
            val tokener = JSONTokener(text)
            val json = tokener.nextValue() as? JSONObject ?: fail(TlsAssetErrorCode.INVALID_FORMAT)
            if (tokener.nextClean() != '\u0000' || json.keys().asSequence().toSet() != INDEX_FIELDS ||
                indexLong(json, "schemaVersion") != 1L) fail(TlsAssetErrorCode.INVALID_FORMAT)
            if (json.get("captureId") != captureId) fail(TlsAssetErrorCode.BINDING_MISMATCH)
            val assetId = json.get("assetId") as? String ?: fail(TlsAssetErrorCode.INVALID_FORMAT)
            requireUuid(assetId)
            val sequence = indexLong(json, "secretsPersistedSequence")
            val plain = indexLong(json, "plaintextBytes")
            val file = indexLong(json, "fileBytes")
            val keyLog = indexLong(json, "keyLogBytes")
            val bounds = TlsAssetLimits()
            if (sequence !in 1..bounds.maxRecords || plain !in 1..bounds.maxPlaintextBytes ||
                file !in 10..bounds.maxFileBytes || keyLog != plain + sequence ||
                keyLog > KeyLogParser.MAX_TOTAL_BYTES + 1) fail(TlsAssetErrorCode.INVALID_FORMAT)
            return TlsSecretAssetRef(captureId, assetId, TlsAssetWatermark(sequence, plain, file), keyLog)
        } catch (error: TlsAssetException) {
            throw error
        } catch (_: Exception) {
            fail(TlsAssetErrorCode.INVALID_FORMAT)
        }
    }

    private fun indexLong(json: JSONObject, name: String): Long = when (val value = json.get(name)) {
        is Int -> value.toLong()
        is Long -> value
        else -> fail(TlsAssetErrorCode.INVALID_FORMAT)
    }

    private fun <T> locked(operation: () -> T): T = synchronized(processLock) {
        storeIo {
            requireDirectory(root)
            childDirectory(root, assetsRoot.name)
            childDirectory(root, leasesRoot.name)
            val lock = acquireFileLock(checkedChild(root, ".tls-secret-store.lock")) ?: fail(TlsAssetErrorCode.IN_USE)
            lock.use { operation() }
        }
    }

    private fun acquireFileLock(file: File): HeldLock? {
        if (!file.exists()) createPrivateFile(file)
        if (!file.isFile) fail(TlsAssetErrorCode.INVALID_FORMAT)
        val handle = RandomAccessFile(file, "rw")
        try {
            val lock = try { handle.channel.tryLock() } catch (_: OverlappingFileLockException) { null }
            if (lock != null) return HeldLock(handle, lock)
            handle.close()
            return null
        } catch (error: Exception) {
            handle.close()
            throw error
        }
    }

    private class HeldLock(private val handle: RandomAccessFile, private val lock: FileLock) : AutoCloseable {
        override fun close() {
            try { if (lock.isValid) lock.release() } finally { handle.close() }
        }
    }

    private fun childDirectory(parent: File, name: String): File = checkedChild(parent, name).also {
        if (!it.exists()) {
            if (posix) Files.createDirectory(it.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            else Files.createDirectory(it.toPath())
        }
        requireDirectory(it)
    }

    private fun checkedChild(parent: File, name: String): File {
        val child = File(parent, name)
        if (Files.isSymbolicLink(child.toPath()) || child.parentFile != parent || name == "." || name == "..") {
            fail(TlsAssetErrorCode.INVALID_ARGUMENT)
        }
        return child
    }

    private fun requireDirectory(file: File) {
        if (!Files.isDirectory(file.toPath(), NOFOLLOW_LINKS)) fail(TlsAssetErrorCode.INVALID_FORMAT)
    }

    private fun forEachChild(directory: File, consume: (File) -> Unit) {
        Files.newDirectoryStream(directory.toPath()).use { entries ->
            entries.forEach { consume(checkedChild(directory, it.fileName.toString())) }
        }
    }

    private fun createPrivateFile(file: File) {
        if (posix) Files.createFile(file.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        else Files.createFile(file.toPath())
    }

    private fun validateRecord(record: KeyLogRecord) {
        fun lowercaseHex(value: String) = value.all { it in '0'..'9' || it in 'a'..'f' }
        if (record.clientRandomHex.length != 64 || !lowercaseHex(record.clientRandomHex) ||
            record.secretHex.length % 2 != 0 || !record.label.acceptsSecretBytes(record.secretHex.length / 2) ||
            !lowercaseHex(record.secretHex)) fail(TlsAssetErrorCode.INVALID_ARGUMENT)
    }

    private fun validateId(id: String) {
        if (!TlsAssetIdentity.validId(id)) fail(TlsAssetErrorCode.INVALID_ARGUMENT)
    }

    private fun requireUuid(id: String) {
        if (!UUID_PATTERN.matches(id)) fail(TlsAssetErrorCode.INVALID_FORMAT)
    }

    private fun identity(captureId: String, assetId: String) =
        TlsAssetIdentity(TlsAssetPurpose.CAPTURE_SECRETS, assetId, captureId = captureId)

    companion object {
        private const val ENCRYPTED = "downstream.keys.enc"
        private const val WRAPPED = "wrapped-data-key"
        private const val INDEX = "current.json"
        private const val PLAINTEXT = "keylog.tmp"
        private const val LIVE_LOCK = "lease.lock"
        private const val MAX_INDEX_BYTES = 2048L
        private val INDEX_FIELDS = setOf("schemaVersion", "captureId", "assetId", "secretsPersistedSequence", "plaintextBytes", "fileBytes", "keyLogBytes")
        private val UUID_PATTERN = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        private val processLock = Any()
        // Accessed only under processLock, including operations on other store instances.
        private val activeLeaseDirectories = HashSet<String>()
        // Live assets of this process, same rule as the lease registry above. They
        // are unpublished by construction, so the sweep needs to know about them
        // rather than treating them as leftovers.
        private val activeLiveDirectories = HashSet<String>()
        private val activeLiveUses = HashMap<String, AutoCloseable>()
        private val posix = java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")
        private fun fail(code: TlsAssetErrorCode): Nothing = throw TlsAssetException(code)

        private fun sanitizedStoreError(error: Exception): Exception {
            if (error is TlsAssetException) return error
            if (error is IOException || error is SecurityException) {
                val full = error.message.orEmpty().lowercase().let {
                    "enospc" in it || "no space left" in it || "disk full" in it || "not enough space" in it
                }
                return TlsAssetException(if (full) TlsAssetErrorCode.DISK_FULL else TlsAssetErrorCode.IO_ERROR)
            }
            return error // Cancellation/runtime control flow must not become success.
        }

        private fun <T> storeIo(operation: () -> T): T = try {
            operation()
        } catch (error: Exception) {
            throw sanitizedStoreError(error)
        }
    }
}
