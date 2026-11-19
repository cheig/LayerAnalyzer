// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.capture.tls.AndroidTlsWrappingKeyProvider
import com.example.layanalyzer.capture.tls.TlsCaLease
import com.example.layanalyzer.capture.tls.TlsCaState
import com.example.layanalyzer.capture.tls.TlsCertificateErrorCode
import com.example.layanalyzer.capture.tls.TlsCertificateException
import com.example.layanalyzer.capture.tls.TlsCertificateManager
import java.io.File
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Locale
import java.util.UUID
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The real Android Keystore, the real Go CA generator and the real private
 * `noBackupFilesDir`, inside a UUID directory belonging to this test only: no
 * user CA or capture asset is read, reset or deleted.
 *
 * CA generation needs a `layanalyzerEnableTls=true` build. Without it the
 * capability envelope reports `caGenerationReady=false` and the test is skipped
 * by assumption instead of being counted as passing.
 */
@RunWith(AndroidJUnit4::class)
class TlsCertificateStorageTest {
    private val id = UUID.randomUUID().toString()
    private val alias = "layeranalyzer.tls.catest.$id"
    private lateinit var directory: File

    private val manager get() = TlsCertificateManager(directory, AndroidTlsWrappingKeyProvider(alias))
    private val root get() = File(directory, "tls-ca")

    @Before fun setUp() {
        assumeTrue("TLS CA generation is not built into this variant", caGenerationAvailable())
        directory = File(
            ApplicationProvider.getApplicationContext<Context>().noBackupFilesDir, "tls-certificate-test-$id"
        )
        check(directory.mkdir())
    }

    @After fun tearDown() {
        runCatching { store().deleteEntry(alias) }
        if (::directory.isInitialized && directory.name.startsWith("tls-certificate-test-")) {
            check(directory.deleteRecursively())
        }
    }

    @Test fun generatedRootSurvivesAReopenAndItsKeyStaysWrapped() {
        val created = manager.ensureGenerated()
        assertEquals(TlsCaState.READY, created.state)
        assertTrue(created.usable)
        UUID.fromString(created.caId)

        // A second manager is what a restarted process does: it must re-read the
        // published CA instead of minting another one.
        val reopened = manager
        val after = reopened.status()
        assertEquals(created.caId, after.caId)
        assertEquals(created.certificateSha256, after.certificateSha256)
        assertEquals(1L, after.caGeneration)
        assertArrayEquals(certificate(created.caId), File(assetDirectory(created.caId), "ca.cer").readBytes())
        assertEquals(66L, File(assetDirectory(created.caId), "wrapped-data-key").length())
        assertFalse(JSONObject(File(root, "current.json").readText()).has("privateKey"))

        // A real, non-exportable Keystore key, created only by the first wrap.
        assertTrue(store().containsAlias(alias))
        assertNull(store().getKey(alias, null).encoded)

        reopened.openEngineLease().use { lease -> assertLeaseMatches(lease, created.caId) }
        assertNoPlaintextPrivateKey()
    }

    @Test fun aDeletedKeystoreAliasReportsUnavailableAndKeepsTheCaId() {
        val created = manager.ensureGenerated()
        val assets = assetDirectory(created.caId).listFiles()!!.associate { it.name to it.readBytes() }
        store().deleteEntry(alias)

        val status = manager.status()
        assertEquals(TlsCaState.KEY_UNAVAILABLE, status.state)
        assertFalse(status.usable)
        expect(TlsCertificateErrorCode.KEY_UNAVAILABLE) { manager.openEngineLease() }
        // The failure must not be answered with a new identity, and nothing on
        // disk may be rewritten or replaced.
        assertEquals(TlsCaState.KEY_UNAVAILABLE, manager.ensureGenerated().state)
        assertEquals(created.caId, manager.exportPublicCertificate().caId)
        assertEquals(assets.keys, assetDirectory(created.caId).listFiles()!!.map { it.name }.toSet())
        for ((name, bytes) in assets) {
            assertArrayEquals(name, bytes, File(assetDirectory(created.caId), name).readBytes())
        }
        assertFalse(store().containsAlias(alias))
        assertNoPlaintextPrivateKey()
    }

    @Test fun resetRequiresAReleasedLeaseAndPublishesANewIdentity() {
        // One instance must hold both the lease and the reset that has to observe
        // it: `activeLeases` is per-manager state, so the fresh instance the
        // `manager` getter returns would not see the lease and the reset would
        // proceed. The JVM half of this card (TlsCertificateStateTest) binds it
        // the same way.
        val ca = manager
        val first = ca.ensureGenerated()
        val lease = ca.openEngineLease()
        expect(TlsCertificateErrorCode.CAPTURE_ACTIVE) { ca.reset() }
        assertEquals(first.caId, ca.status().caId)
        lease.close()

        val second = ca.reset()
        assertEquals(TlsCaState.READY, second.state)
        assertNotEquals(first.caId, second.caId)
        assertEquals(2L, second.caGeneration)
        assertEquals(first.certificateSha256, second.previousCertificateSha256)
        assertTrue(second.systemStoreRemovalRequired)
        assertFalse(assetDirectory(first.caId).exists())
        assertEquals(listOf(second.caId), root.listFiles()!!.filter { it.isDirectory }.map { it.name })

        // The new root is a different certificate the user must trust instead.
        assertFalse(second.certificateSha256 == first.certificateSha256)
        ca.openEngineLease().use { assertLeaseMatches(it, second.caId) }

        val exported = ca.exportPublicCertificate()
        assertTrue(exported.systemStoreRemovalRequired)
        assertEquals(first.certificateSha256, exported.previousCertificateSha256)
        assertTrue(parse(exported.certificateDer).basicConstraints >= 0)
        assertNoPlaintextPrivateKey()
    }

    @Test fun aDamagedContainerIsReportedAndOnlyAnExplicitResetReplacesIt() {
        val created = manager.ensureGenerated()
        val encrypted = File(assetDirectory(created.caId), "private-key.enc")
        val bytes = encrypted.readBytes().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        encrypted.writeBytes(bytes)

        assertEquals(TlsCaState.INVALID_FORMAT, manager.status().state)
        assertEquals(TlsCaState.INVALID_FORMAT, manager.ensureGenerated().state)
        expect(TlsCertificateErrorCode.INVALID_FORMAT) { manager.openEngineLease() }
        assertEquals(created.caId, manager.status().caId)

        val recovered = manager.reset()
        assertEquals(TlsCaState.READY, recovered.state)
        assertEquals(created.certificateSha256, recovered.previousCertificateSha256)
        assertEquals(listOf(recovered.caId), root.listFiles()!!.filter { it.isDirectory }.map { it.name })
        assertNoPlaintextPrivateKey()
    }

    private fun assertLeaseMatches(lease: TlsCaLease, caId: String?) {
        assertEquals(caId, lease.caId)
        assertTrue(lease.certificateDer.isNotEmpty())
        val certificate = parse(lease.certificateDer)
        val publicKey = certificate.publicKey as RSAPublicKey
        assertTrue(publicKey.modulus.bitLength() >= 3072)
        lease.withPrivateKeyPkcs8 { key ->
            val privateKey = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(key))
            assertEquals(publicKey.modulus, (privateKey as RSAPrivateKey).modulus)
        }
    }

    /** No file this manager writes may contain the private key, in any encoding. */
    private fun assertNoPlaintextPrivateKey() {
        val status = manager.status()
        if (status.state != TlsCaState.READY) return // no unsealed copy is available to compare against
        val privateKey = manager.openEngineLease().use { lease -> lease.withPrivateKeyPkcs8 { it.copyOf() } }
        try {
            val plaintext = privateKey.toString(Charsets.ISO_8859_1)
            for (file in root.walkTopDown().filter { it.isFile }) {
                val content = file.readBytes().toString(Charsets.ISO_8859_1)
                assertFalse(file.name, content.contains(plaintext))
                assertFalse(file.name, content.contains("PRIVATE KEY"))
            }
        } finally {
            privateKey.fill(0)
        }
    }

    private fun assetDirectory(caId: String?) = File(root, caId!!)

    private fun certificate(caId: String?) = File(assetDirectory(caId), "ca.cer").readBytes()

    private fun parse(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate

    private fun sha256(bytes: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(Locale.ROOT, it) }

    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

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

    private fun caGenerationAvailable(): Boolean = try {
        // The build's own CA-capability surface. `libraryLoaded` is deliberately
        // not part of the probe: a capability query must not load Go (TLS-201),
        // so it is false before the first startTlsProxy on any build; requiring
        // it made this guard fire unconditionally and the card's device gate
        // unreachable. Generation itself fails loudly if the library is absent.
        val capabilities = JSONObject(NativeEngine.getTlsProxyCapabilities())
        capabilities.optBoolean("buildEnabled") && capabilities.optBoolean("caGenerationReady")
    } catch (_: Throwable) {
        false
    }
}
