// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import android.content.Context
import com.example.layanalyzer.NativeEngine
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.attribute.PosixFilePermissions
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Locale
import java.util.UUID
import org.json.JSONObject
import org.json.JSONTokener

/** Fixed codes only; a CA operation never reports a provider or path message. */
enum class TlsCertificateErrorCode {
    INVALID_ARGUMENT, NOT_READY, UNSUPPORTED, CAPACITY_EXCEEDED,
    IO_ERROR, DISK_FULL, KEY_UNAVAILABLE, INVALID_FORMAT,
    EXPIRED, NOT_YET_VALID, CAPTURE_ACTIVE, IN_USE, ALREADY_EXISTS
}

/**
 * The message is the code name and nothing else. The JNI boundary constructs
 * this with the `(String)` overload through `ThrowNew`, so a native failure and
 * a Kotlin failure are indistinguishable to a caller and neither carries key
 * material, a path, a provider message or a cause.
 */
class TlsCertificateException(val code: TlsCertificateErrorCode) : Exception(code.name) {
    constructor(codeName: String) : this(parse(codeName))

    companion object {
        /** Unknown names become IO_ERROR: a new native code must not be read as success. */
        private fun parse(codeName: String): TlsCertificateErrorCode =
            TlsCertificateErrorCode.entries.firstOrNull { it.name == codeName }
                ?: TlsCertificateErrorCode.IO_ERROR
    }
}

/**
 * The observable root state. `MISSING`, `EXPIRED`, a lost Keystore key and a
 * damaged asset are four different situations with four different user actions,
 * so they are never collapsed into one "not ready".
 */
enum class TlsCaState { MISSING, READY, EXPIRED, NOT_YET_VALID, KEY_UNAVAILABLE, INVALID_FORMAT, IO_ERROR }

/** Public metadata of the published CA plus the manual-removal guidance flag. */
data class TlsCaStatus(
    val state: TlsCaState,
    val caId: String? = null,
    val caGeneration: Long = 0,
    val certificateSha256: String? = null,
    val subjectName: String? = null,
    val notBeforeMillis: Long? = null,
    val notAfterMillis: Long? = null,
    /** A previous CA may still be trusted by the system store after a reset. */
    val systemStoreRemovalRequired: Boolean = false,
    val previousCertificateSha256: String? = null
) {
    /** True for `READY` only; every other state still needs a user decision. */
    val usable: Boolean get() = state == TlsCaState.READY
}

/** Public certificate of the published CA. No private key is reachable from here. */
class TlsCaPublicExport internal constructor(
    val caId: String,
    val caGeneration: Long,
    val certificateDer: ByteArray,
    val certificateSha256: String,
    val subjectName: String,
    val notAfterMillis: Long,
    val systemStoreRemovalRequired: Boolean,
    val previousCertificateSha256: String?
) {
    override fun toString(): String =
        "TlsCaPublicExport(caId=$caId, caGeneration=$caGeneration, certificateSha256=$certificateSha256, " +
            "notAfterMillis=$notAfterMillis, systemStoreRemovalRequired=$systemStoreRemovalRequired)"
}

/**
 * Root material unsealed for exactly one engine run. The private key is wiped on
 * close and is never reachable as a retained reference; the certificate is public
 * and may be kept. `reset` is refused while a lease is open, so an engine that
 * still holds a lease can never be signing with a superseded root.
 */
class TlsCaLease internal constructor(
    val caId: String,
    val caGeneration: Long,
    val certificateDer: ByteArray,
    private val privateKey: ByteArray,
    private val release: () -> Unit
) : AutoCloseable {
    private var closed = false

    /** Borrowed for the duration of [consume]; copy is prohibited, retain is not allowed. */
    @Synchronized
    fun <T> withPrivateKeyPkcs8(consume: (ByteArray) -> T): T {
        if (closed) throw TlsCertificateException(TlsCertificateErrorCode.IN_USE)
        return consume(privateKey)
    }

    /** Idempotent. The key buffer is zeroed before the manager is told about it. */
    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        privateKey.fill(0)
        release()
    }

    override fun toString(): String = "TlsCaLease(caId=$caId, caGeneration=$caGeneration, redacted=true)"
}

/** Source of one CA: exactly `[certificateDER, privateKeyPKCS8]`. */
interface TlsCaMaterialSource {
    fun generate(): Array<ByteArray>
}

/** Production source: the lazily loaded Go bridge behind TLS-201's C ABI. */
object NativeTlsCaMaterialSource : TlsCaMaterialSource {
    override fun generate(): Array<ByteArray> = NativeEngine.generateTlsCaMaterial()
}

/**
 * CA lifecycle for the TLS proxy (design §7.2/§7.3, C06 and C08).
 *
 * The root private key reaches the disk only as a C06 `LAKS` container with
 * purpose `ca-private-key`, and it lives in memory only for the duration of one
 * [TlsCaLease]. The public certificate is stored beside it as DER because it is
 * not secret - it is exactly what the install wizard exports.
 *
 * Layout under the caller's private directory (design §8.3):
 * ```
 * tls-ca/current.json                 atomic publication point
 * tls-ca/<caId>/ca.cer                public DER
 * tls-ca/<caId>/private-key.enc       C06 container, one PKCS#8 record
 * tls-ca/<caId>/wrapped-data-key      C06 wrapped data key
 * ```
 *
 * All public operations do filesystem, Keystore and (for [ensureGenerated] and
 * [reset]) native RSA work: never call them on the main thread. `caGeneration`
 * is persisted per published CA and continues across a [reset] while the index
 * stays readable; it restarts at 1 when the index or the whole `tls-ca`
 * directory is gone. It is therefore an ordering hint **within one `caId`**,
 * never a security boundary or a cross-reset identity: `caId` is the identity,
 * and a superseded CA can never be resurrected under a new `caId`.
 */
class TlsCertificateManager internal constructor(
    noBackupDirectory: File,
    private val wrappingKeys: TlsWrappingKeyProvider,
    private val material: TlsCaMaterialSource = NativeTlsCaMaterialSource,
    private val clock: () -> Long = System::currentTimeMillis
) {
    constructor(context: Context) : this(
        context.applicationContext.noBackupFilesDir,
        AndroidTlsWrappingKeyProvider()
    )

    private val root = File(noBackupDirectory.canonicalFile, DIRECTORY)
    private var activeLeases = 0

    /**
     * Never generates, unseals into the caller or repairs anything; a damaged or
     * unusable CA is reported, never silently replaced (design §7.2 last bullet).
     * Total by design: every readable failure becomes a state, and only control
     * flow (cancellation) still throws.
     */
    @Synchronized
    fun status(): TlsCaStatus = try {
        loadLive()?.let { usableState(it) } ?: TlsCaStatus(TlsCaState.MISSING)
    } catch (error: TlsCertificateException) {
        TlsCaStatus(stateOf(error.code))
    } catch (error: Exception) {
        when (val converted = sanitized(error)) {
            is TlsCertificateException -> TlsCaStatus(stateOf(converted.code))
            else -> throw converted
        }
    }

    /**
     * Creates the first CA when none is published, and is idempotent afterwards.
     * An existing but unusable CA is returned as-is: only an explicit [reset] may
     * replace a CA ID, so a lost Keystore key cannot quietly mint a new identity.
     */
    @Synchronized
    fun ensureGenerated(checkCancelled: () -> Unit = {}): TlsCaStatus = storeIo {
        val current = status()
        if (current.state != TlsCaState.MISSING) return@storeIo current
        publish(generation = FIRST_GENERATION, previous = null, checkCancelled)
    }

    /**
     * Unseals the root for one engine run. An expired, not-yet-valid or unreadable
     * root throws instead of handing Go material it would refuse to sign with.
     * The caller must close the lease when the engine has stopped; [reset] fails
     * with `CAPTURE_ACTIVE` until then.
     */
    @Synchronized
    fun openEngineLease(): TlsCaLease = storeIo {
        val live = loadLive() ?: fail(TlsCertificateErrorCode.NOT_READY)
        val now = clock()
        if (now < live.notBeforeMillis) fail(TlsCertificateErrorCode.NOT_YET_VALID)
        if (now >= live.notAfterMillis) fail(TlsCertificateErrorCode.EXPIRED)
        // One engine at a time: a second lease is a leaked lease, not a second
        // capture, and it would also hide the leak from `reset`'s CAPTURE_ACTIVE.
        if (activeLeases >= MAX_ACTIVE_LEASES) fail(TlsCertificateErrorCode.IN_USE)
        val privateKey = unseal(live)
        activeLeases++
        TlsCaLease(live.caId, live.caGeneration, live.certificateDer.copyOf(), privateKey) {
            synchronized(this) { if (activeLeases > 0) activeLeases-- }
        }
    }

    /**
     * Public certificate only, for `.cer` export and for the install wizard. It
     * stays available for an expired or unreadable root, because knowing which
     * certificate to remove from the system store is exactly the recovery step.
     * The old root's user trust does not disappear with a reset: the caller must
     * offer the manual removal path when `systemStoreRemovalRequired` is set.
     */
    @Synchronized
    fun exportPublicCertificate(): TlsCaPublicExport = storeIo {
        val live = loadLive() ?: fail(TlsCertificateErrorCode.NOT_READY)
        TlsCaPublicExport(
            live.caId, live.caGeneration, live.certificateDer.copyOf(), live.certificateSha256,
            live.subjectName, live.notAfterMillis,
            live.previousCertificateSha256 != null, live.previousCertificateSha256
        )
    }

    /**
     * Replaces the root with a freshly generated one under a new `caId`, which
     * makes every previously issued leaf unreachable (the Go store keys its cache
     * on the CA it was given, TLS-205). It is refused while an engine lease is
     * open: the capture must have stopped and released its material first.
     * A CA that is missing or damaged is treated as absent, so reset doubles as
     * the recovery path for a lost Keystore key or a corrupt asset.
     */
    @Synchronized
    fun reset(checkCancelled: () -> Unit = {}): TlsCaStatus = storeIo {
        checkCancelled()
        if (activeLeases > 0) fail(TlsCertificateErrorCode.CAPTURE_ACTIVE)
        val previous = readIndexQuietly()
        publish((previous?.caGeneration ?: 0L) + 1, previous?.certificateSha256, checkCancelled)
    }

    // ------------------------------------------------------------------ state

    private fun usableState(live: LiveCa): TlsCaStatus {
        val now = clock()
        if (now < live.notBeforeMillis) return live.status(TlsCaState.NOT_YET_VALID)
        if (now >= live.notAfterMillis) return live.status(TlsCaState.EXPIRED)
        return try {
            // Proves the wrapped data key still unwraps rather than assuming it:
            // a deleted or invalidated Keystore alias must not read as READY.
            unseal(live).fill(0)
            live.status(TlsCaState.READY)
        } catch (error: TlsCertificateException) {
            live.status(stateOf(error.code))
        }
    }

    private fun unseal(live: LiveCa): ByteArray = try {
        val directory = checkedChild(root, live.caId).also(::requireDirectory)
        val encrypted = checkedChild(directory, ENCRYPTED)
        val wrapped = checkedChild(directory, WRAPPED)
        var privateKey: ByteArray? = null
        TlsEncryptedAsset.open(
            encrypted, wrapped, identity(live.caId), wrappingKeys, TlsTailRecovery.REJECT, limits()
        ).use { asset ->
            // The CA container holds exactly one record and never a repaired tail.
            if (asset.watermark.sequence != 1L || asset.recoveredTailBytes != 0L) {
                fail(TlsCertificateErrorCode.INVALID_FORMAT)
            }
            asset.readRecords { sequence, bytes ->
                if (sequence != 1L || privateKey != null) fail(TlsCertificateErrorCode.INVALID_FORMAT)
                privateKey = bytes.copyOf()
            }
        }
        privateKey ?: fail(TlsCertificateErrorCode.INVALID_FORMAT)
    } catch (error: Exception) {
        // Container and Keystore failures become the same typed boundary as the rest.
        throw sanitized(error)
    }

    // -------------------------------------------------------------- generation

    /**
     * One publication: write a new `<caId>` directory, then move `current.json`
     * onto it. Until that rename the new CA does not exist, and afterwards the
     * previous one is unreachable. A crash in between leaves an unpublished
     * directory that the next publication deletes.
     */
    private fun publish(generation: Long, previous: String?, checkCancelled: () -> Unit): TlsCaStatus {
        checkCancelled()
        val generated = material.generate()
        if (generated.size != 2) fail(TlsCertificateErrorCode.INVALID_ARGUMENT)
        val certificateDer = generated[0]
        val privateKey = generated[1]
        try {
            checkCancelled()
            val certificate = validateMaterial(certificateDer, privateKey)
            val caId = UUID.randomUUID().toString()
            val index = CaIndex(caId, generation, sha256(certificateDer), certificate.notAfter.time, previous)
            val directory = childDirectory(ensureRoot(), caId)
            var published = false
            try {
                writePrivateFile(checkedChild(directory, CERTIFICATE), certificateDer)
                TlsEncryptedAsset.create(
                    checkedChild(directory, ENCRYPTED), checkedChild(directory, WRAPPED),
                    identity(caId), wrappingKeys, limits()
                ).use { asset ->
                    asset.append(privateKey)
                    if (asset.watermark.sequence != 1L) fail(TlsCertificateErrorCode.INVALID_FORMAT)
                }
                checkCancelled()
                writeIndex(index)
                published = true
            } finally {
                // A cleanup failure must not replace the real error; the leftover
                // directory is removed by the next publication.
                if (!published) runCatching { removeTree(directory) }
            }
            // Best effort: an undeleted superseded directory is not a secret leak,
            // because it is encrypted exactly like the published one.
            runCatching { removeUnpublished(caId) }
            // Just written and already checked, so this is not a probe of a live
            // Keystore: the wrapping key demonstrably worked during create/append.
            return LiveCa(index, certificateDer, certificate).status(TlsCaState.READY)
        } finally {
            privateKey.fill(0)
        }
    }

    /** The generator is trusted no further than any other input. */
    private fun validateMaterial(certificateDer: ByteArray, privateKeyPkcs8: ByteArray): X509Certificate {
        if (certificateDer.isEmpty() || certificateDer.size > MAX_CERTIFICATE_BYTES ||
            privateKeyPkcs8.isEmpty() || privateKeyPkcs8.size > MAX_PRIVATE_KEY_BYTES
        ) fail(TlsCertificateErrorCode.INVALID_ARGUMENT)
        val certificate = parseCertificate(certificateDer)
        if (certificate.basicConstraints < 0) fail(TlsCertificateErrorCode.INVALID_FORMAT)
        // TLS-205 mints RSA 3072 roots; comparing the modulus catches a truncated
        // or mismatched key before it is persisted, instead of at the next start.
        // Another root algorithm would need its own comparison added here.
        if (certificate.publicKey is RSAPublicKey) {
            val publicKey = certificate.publicKey as RSAPublicKey
            val privateKey = try {
                KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKeyPkcs8))
            } catch (_: GeneralSecurityException) {
                fail(TlsCertificateErrorCode.INVALID_FORMAT)
            }
            if (privateKey !is RSAPrivateKey || privateKey.modulus != publicKey.modulus) {
                fail(TlsCertificateErrorCode.INVALID_FORMAT)
            }
            // e is only reachable on the CRT form, which is what a PKCS#8 RSA key
            // decodes to on Android and on the JVM; RSAPrivateKey alone exposes d.
            if (privateKey is RSAPrivateCrtKey && privateKey.publicExponent != publicKey.publicExponent) {
                fail(TlsCertificateErrorCode.INVALID_FORMAT)
            }
        }
        val now = clock()
        if (now < certificate.notBefore.time) fail(TlsCertificateErrorCode.NOT_YET_VALID)
        if (now >= certificate.notAfter.time) fail(TlsCertificateErrorCode.EXPIRED)
        return certificate
    }

    // ------------------------------------------------------------------- index

    private data class CaIndex(
        val caId: String,
        val caGeneration: Long,
        val certificateSha256: String,
        val notAfterMillis: Long,
        val previousCertificateSha256: String?
    )

    private fun writeIndex(index: CaIndex) {
        val json = JSONObject().put("schemaVersion", 1).put("caId", index.caId)
            .put("caGeneration", index.caGeneration).put("certificateSha256", index.certificateSha256)
            .put("notAfterMillis", index.notAfterMillis)
            .put("previousCertificateSha256", index.previousCertificateSha256 ?: JSONObject.NULL)
        val temporary = checkedChild(ensureRoot(), "$TEMPORARY_PREFIX${UUID.randomUUID()}$TEMPORARY_SUFFIX")
        createPrivateFile(temporary)
        var committed = false
        try {
            FileOutputStream(temporary).use { output ->
                output.write(json.toString().toByteArray(Charsets.UTF_8))
                output.fd.sync()
            }
            // Same-directory atomic replace; the old valid CA is never deleted first.
            Files.move(temporary.toPath(), checkedChild(root, INDEX).toPath(), ATOMIC_MOVE, REPLACE_EXISTING)
            committed = true
        } finally {
            if (!committed) Files.deleteIfExists(temporary.toPath())
        }
    }

    private fun readIndex(): CaIndex? {
        val index = checkedChild(root, INDEX)
        if (!index.exists()) return null
        if (!index.isFile || index.length() !in 1..MAX_INDEX_BYTES) fail(TlsCertificateErrorCode.INVALID_FORMAT)
        val bytes = ByteArray(MAX_INDEX_BYTES.toInt() + 1)
        val text = index.inputStream().use { input ->
            var used = 0
            while (used < bytes.size) {
                val count = input.read(bytes, used, bytes.size - used)
                if (count == -1) break
                if (count == 0) fail(TlsCertificateErrorCode.IO_ERROR)
                used += count
            }
            if (used !in 1..MAX_INDEX_BYTES.toInt() || bytes.take(used).any { it.toInt() !in 0x20..0x7e }) {
                fail(TlsCertificateErrorCode.INVALID_FORMAT)
            }
            String(bytes, 0, used, Charsets.US_ASCII)
        }
        try {
            val tokener = JSONTokener(text)
            val json = tokener.nextValue() as? JSONObject ?: fail(TlsCertificateErrorCode.INVALID_FORMAT)
            if (tokener.nextClean() != '\u0000' || json.keys().asSequence().toSet() != INDEX_FIELDS ||
                indexLong(json, "schemaVersion") != 1L
            ) fail(TlsCertificateErrorCode.INVALID_FORMAT)
            val caId = json.get("caId") as? String ?: fail(TlsCertificateErrorCode.INVALID_FORMAT)
            if (!UUID_PATTERN.matches(caId)) fail(TlsCertificateErrorCode.INVALID_FORMAT)
            val generation = indexLong(json, "caGeneration")
            if (generation < FIRST_GENERATION) fail(TlsCertificateErrorCode.INVALID_FORMAT)
            val fingerprint = json.get("certificateSha256") as? String ?: fail(TlsCertificateErrorCode.INVALID_FORMAT)
            if (!isSha256(fingerprint)) fail(TlsCertificateErrorCode.INVALID_FORMAT)
            val notAfter = indexLong(json, "notAfterMillis")
            if (notAfter <= 0L) fail(TlsCertificateErrorCode.INVALID_FORMAT)
            val previous = if (json.isNull("previousCertificateSha256")) null
            else (json.get("previousCertificateSha256") as? String)?.takeIf(::isSha256)
                ?: fail(TlsCertificateErrorCode.INVALID_FORMAT)
            return CaIndex(caId, generation, fingerprint, notAfter, previous)
        } catch (error: TlsCertificateException) {
            throw error
        } catch (_: Exception) {
            fail(TlsCertificateErrorCode.INVALID_FORMAT)
        }
    }

    /** Reset is also the recovery path, so a damaged index must not block it. */
    private fun readIndexQuietly(): CaIndex? = try {
        readIndex()
    } catch (_: Exception) {
        null
    }

    private fun indexLong(json: JSONObject, name: String): Long = when (val value = json.get(name)) {
        is Int -> value.toLong()
        is Long -> value
        else -> fail(TlsCertificateErrorCode.INVALID_FORMAT)
    }

    private fun loadLive(): LiveCa? {
        val index = readIndex() ?: return null
        val directory = checkedChild(root, index.caId).also(::requireDirectory)
        val certificateDer = readBounded(checkedChild(directory, CERTIFICATE), MAX_CERTIFICATE_BYTES)
        if (sha256(certificateDer) != index.certificateSha256) fail(TlsCertificateErrorCode.INVALID_FORMAT)
        val certificate = parseCertificate(certificateDer)
        // Binds the index entry to the certificate actually on disk.
        if (certificate.notAfter.time != index.notAfterMillis) fail(TlsCertificateErrorCode.INVALID_FORMAT)
        return LiveCa(index, certificateDer, certificate)
    }

    private class LiveCa(
        val index: CaIndex,
        val certificateDer: ByteArray,
        private val certificate: X509Certificate
    ) {
        val caId get() = index.caId
        val caGeneration get() = index.caGeneration
        val certificateSha256 get() = index.certificateSha256
        val previousCertificateSha256 get() = index.previousCertificateSha256
        val notBeforeMillis get() = certificate.notBefore.time
        val notAfterMillis get() = certificate.notAfter.time
        val subjectName get() = certificate.subjectX500Principal.name

        fun status(state: TlsCaState) = TlsCaStatus(
            state, caId, caGeneration, certificateSha256, subjectName, notBeforeMillis, notAfterMillis,
            previousCertificateSha256 != null, previousCertificateSha256
        )
    }

    // -------------------------------------------------------------- filesystem

    private fun ensureRoot(): File {
        if (!root.exists()) {
            if (posix) {
                Files.createDirectories(
                    root.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
                )
            } else Files.createDirectories(root.toPath())
        }
        requireDirectory(root)
        return root
    }

    private fun childDirectory(parent: File, name: String): File = checkedChild(parent, name).also {
        if (!it.exists()) {
            if (posix) {
                Files.createDirectory(
                    it.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
                )
            } else Files.createDirectory(it.toPath())
        }
        requireDirectory(it)
    }

    private fun checkedChild(parent: File, name: String): File {
        val child = File(parent, name)
        if (Files.isSymbolicLink(child.toPath()) || child.parentFile != parent || name == "." || name == "..") {
            fail(TlsCertificateErrorCode.INVALID_ARGUMENT)
        }
        return child
    }

    private fun requireDirectory(file: File) {
        if (!Files.isDirectory(file.toPath(), NOFOLLOW_LINKS)) fail(TlsCertificateErrorCode.INVALID_FORMAT)
    }

    private fun forEachChild(directory: File, consume: (File) -> Unit) {
        Files.newDirectoryStream(directory.toPath()).use { entries ->
            entries.forEach { consume(checkedChild(directory, it.fileName.toString())) }
        }
    }

    private fun createPrivateFile(file: File) {
        if (posix) {
            Files.createFile(
                file.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
            )
        } else Files.createFile(file.toPath())
    }

    private fun writePrivateFile(file: File, bytes: ByteArray) {
        createPrivateFile(file)
        FileOutputStream(file).use { output ->
            output.write(bytes)
            output.fd.sync()
        }
    }

    private fun readBounded(file: File, limit: Int): ByteArray {
        if (!file.isFile || file.length() !in 1..limit.toLong()) fail(TlsCertificateErrorCode.INVALID_FORMAT)
        val bytes = ByteArray(limit + 1)
        val used = file.inputStream().use { input ->
            var used = 0
            while (used < bytes.size) {
                val count = input.read(bytes, used, bytes.size - used)
                if (count == -1) break
                if (count == 0) fail(TlsCertificateErrorCode.IO_ERROR)
                used += count
            }
            used
        }
        if (used !in 1..limit) fail(TlsCertificateErrorCode.INVALID_FORMAT)
        return bytes.copyOf(used)
    }

    /** Deletes only what this manager wrote: UUID asset directories and its own temporaries. */
    private fun removeUnpublished(keep: String) {
        forEachChild(root) { child ->
            val name = child.name
            when {
                name == INDEX || name == keep -> Unit
                name.startsWith(TEMPORARY_PREFIX) && name.endsWith(TEMPORARY_SUFFIX) -> {
                    if (!child.isFile) fail(TlsCertificateErrorCode.INVALID_FORMAT)
                    Files.delete(child.toPath())
                }
                UUID_PATTERN.matches(name) -> {
                    requireDirectory(child)
                    removeTree(child)
                }
            }
        }
    }

    private fun removeTree(directory: File) {
        if (!directory.exists()) return
        requireDirectory(directory)
        // Flat local asset directory; never recursively follow links or imported names.
        forEachChild(directory) { file ->
            if (!Files.isRegularFile(file.toPath(), NOFOLLOW_LINKS)) {
                fail(TlsCertificateErrorCode.INVALID_FORMAT)
            }
            Files.delete(file.toPath())
        }
        Files.delete(directory.toPath())
    }

    // ------------------------------------------------------------------ crypto

    private fun identity(caId: String) = TlsAssetIdentity(TlsAssetPurpose.CA_PRIVATE_KEY, caId, caId = caId)

    private fun limits() = TlsAssetLimits(
        maxPlaintextBytes = MAX_PRIVATE_KEY_BYTES.toLong(), maxRecords = 1, maxFileBytes = MAX_CONTAINER_BYTES.toLong()
    )

    private fun parseCertificate(der: ByteArray): X509Certificate = try {
        val factory = CertificateFactory.getInstance("X.509")
        factory.generateCertificate(ByteArrayInputStream(der)) as? X509Certificate
            ?: fail(TlsCertificateErrorCode.INVALID_FORMAT)
    } catch (error: TlsCertificateException) {
        throw error
    } catch (_: Exception) {
        fail(TlsCertificateErrorCode.INVALID_FORMAT)
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(Locale.ROOT, it) }

    private fun isSha256(value: String) =
        value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

    private fun stateOf(code: TlsCertificateErrorCode): TlsCaState = when (code) {
        TlsCertificateErrorCode.KEY_UNAVAILABLE -> TlsCaState.KEY_UNAVAILABLE
        TlsCertificateErrorCode.EXPIRED -> TlsCaState.EXPIRED
        TlsCertificateErrorCode.NOT_YET_VALID -> TlsCaState.NOT_YET_VALID
        TlsCertificateErrorCode.IO_ERROR, TlsCertificateErrorCode.DISK_FULL -> TlsCaState.IO_ERROR
        else -> TlsCaState.INVALID_FORMAT
    }

    // ------------------------------------------------------------------ errors

    private fun <T> storeIo(operation: () -> T): T = try {
        operation()
    } catch (error: Exception) {
        throw sanitized(error)
    }

    private fun sanitized(error: Exception): Exception = when (error) {
        is TlsCertificateException -> error
        is TlsAssetException -> TlsCertificateException(
            when (error.code) {
                TlsAssetErrorCode.KEY_UNAVAILABLE -> TlsCertificateErrorCode.KEY_UNAVAILABLE
                TlsAssetErrorCode.AUTHENTICATION_FAILED, TlsAssetErrorCode.INVALID_FORMAT,
                TlsAssetErrorCode.BINDING_MISMATCH, TlsAssetErrorCode.UNSUPPORTED_VERSION,
                TlsAssetErrorCode.TRUNCATED_TAIL, TlsAssetErrorCode.INVALID_SEQUENCE,
                TlsAssetErrorCode.NONCE_REUSED -> TlsCertificateErrorCode.INVALID_FORMAT
                TlsAssetErrorCode.CAPACITY_EXCEEDED -> TlsCertificateErrorCode.CAPACITY_EXCEEDED
                TlsAssetErrorCode.DISK_FULL -> TlsCertificateErrorCode.DISK_FULL
                TlsAssetErrorCode.ALREADY_EXISTS -> TlsCertificateErrorCode.ALREADY_EXISTS
                TlsAssetErrorCode.IN_USE -> TlsCertificateErrorCode.IN_USE
                TlsAssetErrorCode.NOT_FOUND -> TlsCertificateErrorCode.NOT_READY
                else -> TlsCertificateErrorCode.IO_ERROR
            }
        )
        // A provider message or a filesystem path may name the Keystore alias or a
        // directory, so neither is allowed to reach the caller.
        is SecurityException -> TlsCertificateException(TlsCertificateErrorCode.KEY_UNAVAILABLE)
        is GeneralSecurityException -> TlsCertificateException(TlsCertificateErrorCode.KEY_UNAVAILABLE)
        is IOException -> TlsCertificateException(
            if (diskFull(error.message)) TlsCertificateErrorCode.DISK_FULL else TlsCertificateErrorCode.IO_ERROR
        )
        // Cancellation and other control flow must not be converted into a success.
        else -> error
    }

    private fun diskFull(message: String?): Boolean = message.orEmpty().lowercase(Locale.ROOT).let {
        "enospc" in it || "no space left" in it || "disk full" in it || "not enough space on the disk" in it
    }

    companion object {
        private const val DIRECTORY = "tls-ca"
        private const val INDEX = "current.json"
        private const val CERTIFICATE = "ca.cer"
        private const val ENCRYPTED = "private-key.enc"
        private const val WRAPPED = "wrapped-data-key"
        private const val TEMPORARY_PREFIX = ".index-"
        private const val TEMPORARY_SUFFIX = ".tmp"
        private const val FIRST_GENERATION = 1L
        private const val MAX_INDEX_BYTES = 2048L
        private const val MAX_ACTIVE_LEASES = 1
        private const val MAX_CERTIFICATE_BYTES = 16384

        /** The container stores one PKCS#8 block, so its record bound is the key bound. */
        private const val MAX_PRIVATE_KEY_BYTES = TlsEncryptedAsset.MAX_PLAINTEXT_RECORD_BYTES
        private const val MAX_CONTAINER_BYTES = 32768
        private val INDEX_FIELDS = setOf(
            "schemaVersion", "caId", "caGeneration", "certificateSha256", "notAfterMillis",
            "previousCertificateSha256"
        )
        private val UUID_PATTERN = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        private val posix = java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")

        private fun fail(code: TlsCertificateErrorCode): Nothing = throw TlsCertificateException(code)
    }
}
