// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Locale
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.Executors
import javax.crypto.KeyGenerator
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Synthetic CA material only (see
 * `native_build/verification/tls/generate_certificate_manager_fixture.py`): the
 * committed root is never installed, never shipped and never signs real traffic.
 * No native call happens here - [TlsCaMaterialSource] is a test double, which is
 * also the one difference from the device test.
 */
class TlsCertificateStateTest {
    @get:Rule val temporary = TemporaryFolder()
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private var keyAvailable = true
    private val provider = AesGcmTlsWrappingKeyProvider {
        if (!keyAvailable) throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
        key
    }
    private val fixture = listOf(
        File("app/src/test/resources/tls/certificate-manager"),
        File("src/test/resources/tls/certificate-manager")
    ).firstOrNull { it.isDirectory } ?: error("certificate-manager fixture directory not found")

    private val certificateDer get() = File(fixture, "ca-certificate.der").readBytes()
    private val privateKeyPkcs8 get() = File(fixture, "ca-private-key.pkcs8").readBytes()
    private val otherPrivateKey get() = File(fixture, "other-private-key.pkcs8").readBytes()
    private val root get() = File(temporary.root, "tls-ca")
    private var now = FIXTURE_MIDPOINT
    private var generated = 0

    /** Records every generation so a test can assert "nothing new was minted". */
    private val source = object : TlsCaMaterialSource {
        override fun generate(): Array<ByteArray> {
            generated++
            return arrayOf(certificateDer, privateKeyPkcs8)
        }
    }

    private fun manager(source: TlsCaMaterialSource = this.source) =
        TlsCertificateManager(temporary.root, provider, source) { now }

    private fun assetDirectories() = root.listFiles().orEmpty().filter { it.isDirectory }

    private fun publishedDirectory(): File =
        File(root, JSONObject(File(root, "current.json").readText()).getString("caId"))

    @Test fun committedFixtureIsAMatchingCaAndTheManifestCoversEveryFile() {
        val manifest = JSONObject(File(fixture, "manifest.json").readText())
        assertTrue(manifest.getBoolean("privateKeysCommitted"))
        for (index in 0 until manifest.getJSONArray("files").length()) {
            val entry = manifest.getJSONArray("files").getJSONObject(index)
            val file = File(fixture, entry.getString("file"))
            assertEquals(entry.getInt("bytes").toLong(), file.length())
            assertEquals(entry.getString("sha256"), sha256(file.readBytes()))
        }
        val certificate = parse(certificateDer)
        assertTrue(certificate.basicConstraints >= 0)
        val publicModulus = (certificate.publicKey as RSAPublicKey).modulus
        assertEquals(publicModulus, rsaModulus(privateKeyPkcs8))
        assertNotEquals(publicModulus, rsaModulus(otherPrivateKey))
        assertTrue(FIXTURE_MIDPOINT > certificate.notBefore.time)
        assertTrue(FIXTURE_MIDPOINT < certificate.notAfter.time)
    }

    @Test fun firstGenerationSealsTheKeyAndARestartKeepsTheSameIdentity() {
        val manager = manager()
        assertEquals(TlsCaState.MISSING, manager.status().state)
        expect(TlsCertificateErrorCode.NOT_READY) { manager.openEngineLease() }
        expect(TlsCertificateErrorCode.NOT_READY) { manager.exportPublicCertificate() }

        val created = manager.ensureGenerated()
        assertEquals(TlsCaState.READY, created.state)
        assertTrue(created.usable)
        assertEquals(1L, created.caGeneration)
        UUID.fromString(created.caId)
        assertEquals(sha256(certificateDer), created.certificateSha256)
        assertEquals(parse(certificateDer).notAfter.time, created.notAfterMillis)
        assertEquals(parse(certificateDer).notBefore.time, created.notBeforeMillis)
        assertTrue(created.subjectName!!.contains("LayerAnalyzer capture CA fixture"))
        assertFalse(created.systemStoreRemovalRequired)
        assertNull(created.previousCertificateSha256)
        assertEquals(1, generated)

        val directory = publishedDirectory()
        assertEquals(created.caId, directory.name)
        assertArrayEquals(certificateDer, File(directory, "ca.cer").readBytes())
        assertTrue(File(directory, "private-key.enc").length() > privateKeyPkcs8.size)
        assertEquals(66L, File(directory, "wrapped-data-key").length())
        assertNoPlaintextPrivateKey()
        assertTrue(File(root, "current.json").readText().contains(created.caId!!))

        // A second manager (a fresh process) re-reads the published CA instead of
        // generating another one, so an installed fingerprint survives a restart.
        val reopened = manager()
        val after = reopened.status()
        assertEquals(created.caId, after.caId)
        assertEquals(created.certificateSha256, after.certificateSha256)
        assertEquals(1L, after.caGeneration)
        assertEquals(after, reopened.ensureGenerated())
        assertEquals(1, generated)

        val lease = reopened.openEngineLease()
        try {
            assertEquals(created.caId, lease.caId)
            assertEquals(1L, lease.caGeneration)
            assertArrayEquals(certificateDer, lease.certificateDer)
            assertArrayEquals(privateKeyPkcs8, lease.withPrivateKeyPkcs8 { it })
        } finally { lease.close() }
        lease.close() // idempotent
        var afterClose: TlsCertificateException? = null
        try {
            lease.withPrivateKeyPkcs8 { it.copyOf() }
        } catch (error: TlsCertificateException) {
            afterClose = error
        }
        val closed = afterClose ?: throw AssertionError("Expected IN_USE after close")
        assertEquals(TlsCertificateErrorCode.IN_USE, closed.code)
        assertEquals(TlsCertificateErrorCode.IN_USE.name, closed.message)
        assertEquals(1, generated)

        val exported = manager.exportPublicCertificate()
        assertEquals(created.caId, exported.caId)
        assertArrayEquals(certificateDer, exported.certificateDer)
        assertFalse(exported.systemStoreRemovalRequired)
    }

    @Test fun aSecondLeaseIsRefusedUntilTheFirstIsReleased() {
        val manager = manager()
        manager.ensureGenerated()
        val first = manager.openEngineLease()
        try {
            expect(TlsCertificateErrorCode.IN_USE) { manager.openEngineLease() }
        } finally { first.close() }
        manager.openEngineLease().close()
    }

    @Test fun aLostKeystoreReportsUnavailableAndNeverReplacesTheIdentity() {
        val manager = manager()
        val created = manager.ensureGenerated()
        val certificate = File(publishedDirectory(), "ca.cer").readBytes()
        keyAvailable = false

        val status = manager.status()
        assertEquals(TlsCaState.KEY_UNAVAILABLE, status.state)
        assertFalse(status.usable)
        expect(TlsCertificateErrorCode.KEY_UNAVAILABLE) { manager.openEngineLease() }
        // An unwrap failure must not be answered by minting a new CA.
        assertEquals(TlsCaState.KEY_UNAVAILABLE, manager.ensureGenerated().state)
        assertEquals(1, generated)
        assertEquals(created.caId, manager.exportPublicCertificate().caId)
        assertArrayEquals(certificate, File(publishedDirectory(), "ca.cer").readBytes())

        // Nothing on disk was touched, so restoring the key restores the CA.
        keyAvailable = true
        assertEquals(TlsCaState.READY, manager.status().state)
        val lease = manager.openEngineLease()
        try { assertEquals(created.caId, lease.caId) } finally { lease.close() }
    }

    @Test fun expiredAndNotYetValidRootsAreDistinctReportedStates() {
        val manager = manager()
        val created = manager.ensureGenerated()

        now = created.notAfterMillis!!
        assertEquals(TlsCaState.EXPIRED, manager.status().state)
        expect(TlsCertificateErrorCode.EXPIRED) { manager.openEngineLease() }
        // Exporting what must be removed from the system store still works.
        assertEquals(created.caId, manager.exportPublicCertificate().caId)

        now = created.notBeforeMillis!! - 1
        assertEquals(TlsCaState.NOT_YET_VALID, manager.status().state)
        expect(TlsCertificateErrorCode.NOT_YET_VALID) { manager.openEngineLease() }

        now = FIXTURE_MIDPOINT
        assertEquals(TlsCaState.READY, manager.status().state)
    }

    @Test fun resetRequiresAReleasedLeaseAndPublishesANewIdentity() {
        val manager = manager()
        val first = manager.ensureGenerated()
        val firstDirectory = publishedDirectory()
        val lease = manager.openEngineLease()
        expect(TlsCertificateErrorCode.CAPTURE_ACTIVE) { manager.reset() }
        assertEquals(first.caId, manager.status().caId)
        lease.close()

        val second = manager.reset()
        assertEquals(TlsCaState.READY, second.state)
        assertNotEquals(first.caId, second.caId)
        assertEquals(2L, second.caGeneration)
        assertEquals(first.certificateSha256, second.previousCertificateSha256)
        assertTrue(second.systemStoreRemovalRequired)
        assertEquals(2, generated)
        assertFalse(firstDirectory.exists())
        assertEquals(listOf(second.caId), assetDirectories().map { it.name })

        val exported = manager.exportPublicCertificate()
        assertTrue(exported.systemStoreRemovalRequired)
        assertEquals(first.certificateSha256, exported.previousCertificateSha256)
        assertArrayEquals(certificateDer, exported.certificateDer)

        // The generation only moves when a reset is asked for, never per read.
        assertEquals(2L, manager().status().caGeneration)
        assertEquals(3L, manager().reset().caGeneration)
    }

    @Test fun damagedAssetsAreReportedAndNeverReplaceTheIdentityOnTheirOwn() {
        val manager = manager()
        val created = manager.ensureGenerated()

        // A damaged index is INVALID_FORMAT, never MISSING, so nothing regenerates.
        File(root, "current.json").writeBytes(ByteArray(16) { 0x61 })
        assertEquals(TlsCaState.INVALID_FORMAT, manager.status().state)
        assertEquals(TlsCaState.INVALID_FORMAT, manager.ensureGenerated().state)
        assertEquals(1, generated)
        expect(TlsCertificateErrorCode.INVALID_FORMAT) { manager.openEngineLease() }
        expect(TlsCertificateErrorCode.INVALID_FORMAT) { manager.exportPublicCertificate() }

        // Reset is the recovery path and still mints a usable new CA; the damaged
        // index had no fingerprint left to report, and an unreadable index also
        // restarts the generation counter, which is why caId - not the counter -
        // is what callers must treat as the identity.
        val recovered = manager.reset()
        assertEquals(TlsCaState.READY, recovered.state)
        assertNull(recovered.previousCertificateSha256)
        assertFalse(recovered.systemStoreRemovalRequired)
        assertEquals(1L, recovered.caGeneration)
        assertEquals(listOf(recovered.caId), assetDirectories().map { it.name })

        // A certificate that no longer matches the committed fingerprint is
        // rejected, and the readable index still names what may be installed.
        File(publishedDirectory(), "ca.cer").writeBytes(ByteArray(64) { 0x30 })
        assertEquals(TlsCaState.INVALID_FORMAT, manager.status().state)
        assertEquals(TlsCaState.INVALID_FORMAT, manager.ensureGenerated().state)
        val afterDamagedCertificate = manager.reset()
        assertEquals(recovered.certificateSha256, afterDamagedCertificate.previousCertificateSha256)
        assertTrue(afterDamagedCertificate.systemStoreRemovalRequired)

        // A wrapped key that cannot be authenticated is the same class of damage.
        val encrypted = File(publishedDirectory(), "private-key.enc")
        val tampered = encrypted.readBytes().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        encrypted.writeBytes(tampered)
        assertEquals(TlsCaState.INVALID_FORMAT, manager.status().state)
        expect(TlsCertificateErrorCode.INVALID_FORMAT) { manager.openEngineLease() }
        assertEquals(
            afterDamagedCertificate.certificateSha256, manager.reset().previousCertificateSha256
        )
        assertNotEquals(created.caId, manager.status().caId)
    }

    @Test fun unwelcomeMaterialFromTheGeneratorIsRejectedBeforePersistence() {
        val cases = listOf(
            "one array" to (TlsCertificateErrorCode.INVALID_ARGUMENT to arrayOf(certificateDer)),
            "three arrays" to (TlsCertificateErrorCode.INVALID_ARGUMENT to
                arrayOf(certificateDer, privateKeyPkcs8, certificateDer)),
            "empty certificate" to (TlsCertificateErrorCode.INVALID_ARGUMENT to
                arrayOf(ByteArray(0), privateKeyPkcs8)),
            "oversized certificate" to (TlsCertificateErrorCode.INVALID_ARGUMENT to
                arrayOf(ByteArray(20000) { 1 }, privateKeyPkcs8)),
            "empty private key" to (TlsCertificateErrorCode.INVALID_ARGUMENT to
                arrayOf(certificateDer, ByteArray(0))),
            "not a certificate" to (TlsCertificateErrorCode.INVALID_FORMAT to
                arrayOf(ByteArray(1200) { 0x30 }, privateKeyPkcs8)),
            "key of another certificate" to (TlsCertificateErrorCode.INVALID_FORMAT to
                arrayOf(certificateDer, otherPrivateKey))
        )
        for ((name, value) in cases) {
            val (code, material) = value
            val manager = manager(object : TlsCaMaterialSource {
                override fun generate() = material
            })
            expect(code) { manager.ensureGenerated() }
            assertEquals(name, TlsCaState.MISSING, manager.status().state)
            assertTrue(name, assetDirectories().isEmpty())
            assertFalse(name, File(root, "current.json").exists())
        }
        assertNoPlaintextPrivateKey()
    }

    @Test fun cancellationAfterTheContainerIsWrittenRemovesTheUnpublishedDirectory() {
        val manager = manager()
        var checks = 0
        val cancel = { checks++; if (checks >= 3) throw CancellationException("stop") }
        try {
            manager.ensureGenerated(cancel)
            fail("Expected cancellation")
        } catch (_: CancellationException) { }
        // Cancellation is neither a storage failure nor a publication.
        assertEquals(TlsCaState.MISSING, manager.status().state)
        assertTrue(assetDirectories().isEmpty())
        assertFalse(File(root, "current.json").exists())
        assertNoPlaintextPrivateKey()

        // The same directory is usable on the next attempt.
        assertEquals(TlsCaState.READY, manager.ensureGenerated().state)
    }

    @Test fun concurrentStatusAndLeasesNeverExposeAnotherIdentity() {
        val manager = manager()
        val created = manager.ensureGenerated()
        val executor = Executors.newFixedThreadPool(6)
        try {
            val statuses = (1..6).map { executor.submit<TlsCaState> { manager.status().state } }
            for (status in statuses) assertEquals(TlsCaState.READY, status.get())
            val held = manager.openEngineLease()
            val blocked = executor.submit<TlsCertificateErrorCode> {
                try {
                    manager.openEngineLease().close()
                } catch (error: TlsCertificateException) {
                    return@submit error.code
                }
                throw AssertionError("Expected the second lease to be refused")
            }
            val during = executor.submit<TlsCaStatus> { manager.status() }
            assertEquals(TlsCertificateErrorCode.IN_USE, blocked.get())
            assertEquals(created.caId, during.get().caId)
            held.close()
        } finally { executor.shutdownNow() }
    }

    /** No file this manager writes may contain the private key, in any encoding. */
    private fun assertNoPlaintextPrivateKey() {
        val plaintext = privateKeyPkcs8.toString(Charsets.ISO_8859_1)
        for (file in root.walkTopDown().filter { it.isFile }) {
            val content = file.readBytes().toString(Charsets.ISO_8859_1)
            assertFalse(file.name, content.contains(plaintext))
            assertFalse(file.name, content.contains("PRIVATE KEY"))
        }
    }

    private fun parse(der: ByteArray) =
        CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate

    private fun rsaModulus(pkcs8: ByteArray) = java.security.KeyFactory.getInstance("RSA")
        .generatePrivate(java.security.spec.PKCS8EncodedKeySpec(pkcs8))
        .let { (it as RSAPrivateKey).modulus }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(Locale.ROOT, it) }

    private fun expect(code: TlsCertificateErrorCode, block: () -> Unit): TlsCertificateException {
        try {
            block()
            fail("Expected $code")
        } catch (error: TlsCertificateException) {
            assertEquals(code, error.code)
            assertEquals(code.name, error.message)
            assertNull(error.cause)
            return error
        }
        error("unreachable")
    }

    private companion object {
        /** Safely inside the fixture's 2020-01-01 .. 2045-01-01 window. */
        const val FIXTURE_MIDPOINT = 1_600_000_000_000L
    }
}
