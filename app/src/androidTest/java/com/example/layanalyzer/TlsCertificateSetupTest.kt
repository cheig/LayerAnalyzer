// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import android.os.Build
import android.security.KeyChain
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.capture.tls.AndroidTlsWrappingKeyProvider
import com.example.layanalyzer.capture.tls.TlsCaExportPlan
import com.example.layanalyzer.capture.tls.TlsCaInstallPlan
import com.example.layanalyzer.capture.tls.TlsCaInstallRoute
import com.example.layanalyzer.capture.tls.TlsCaManagerHolder
import com.example.layanalyzer.capture.tls.TlsCaState
import com.example.layanalyzer.capture.tls.TlsCaUiOperations
import com.example.layanalyzer.capture.tls.TlsCertificateErrorCode
import com.example.layanalyzer.capture.tls.TlsCertificateException
import com.example.layanalyzer.capture.tls.TlsCertificateManager
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The CA install wizard's device-true behaviour (TLS-305): the real
 * `KeyChain.createInstallIntent()` route by the device's own API level, the real
 * exported `.cer` bytes and their "no private key" guarantee, and the real
 * `reset` refusal while a lease is held.
 *
 * Everything happens inside a UUID directory and a per-run Keystore alias that
 * belong to this test only; no user CA, capture asset or installed credential is
 * read, reset or deleted. CA generation needs a `layanalyzerEnableTls=true` build,
 * so without it the class is skipped by assumption - a skip is not a pass.
 */
@RunWith(AndroidJUnit4::class)
class TlsCertificateSetupTest {
    private val id = UUID.randomUUID().toString()
    private val alias = "layeranalyzer.tls.setup.$id"
    private lateinit var directory: File
    private var now = System.currentTimeMillis()

    private val manager get() = TlsCertificateManager(directory, AndroidTlsWrappingKeyProvider(alias)) { now }

    @Before fun setUp() {
        assumeTrue("TLS CA generation is not built into this variant", caGenerationAvailable())
        directory = File(
            ApplicationProvider.getApplicationContext<Context>().noBackupFilesDir, "tls-setup-test-$id"
        )
        check(directory.mkdir())
    }

    @After fun tearDown() {
        runCatching { store().deleteEntry(alias) }
        if (::directory.isInitialized && directory.name.startsWith("tls-setup-test-")) {
            check(directory.deleteRecursively())
        }
    }

    @Test fun exportedCerContainsNoPrivateKeyAndIsAUsableCaCertificate() = runBlocking {
        val operations = TlsCaUiOperations(manager)
        val created = operations.generate()
        assertEquals(TlsCaState.READY, created.state)

        val export = operations.export()
        // The acceptance check: the exported bytes carry no private key.
        assertFalse(TlsCaExportPlan.containsPrivateKeyMarker(export.certificateDer))
        val certificate = parse(export.certificateDer)
        assertTrue(certificate.basicConstraints >= 0)
        assertEquals(created.certificateSha256, export.certificateSha256)
        // The suggested name is a public `.cer`, never a key file.
        assertTrue(TlsCaExportPlan.suggestedFileName(export.caId).endsWith(".cer"))

        // The same bytes handed to a PEM envelope are caught, proving the scan has
        // discriminating power on this device too.
        val pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        assertTrue(TlsCaExportPlan.containsPrivateKeyMarker(pem.toByteArray(Charsets.US_ASCII)))
    }

    @Test fun theInstallRouteMatchesThePlatformApiLevel() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val route = TlsCaInstallPlan.routeFor(Build.VERSION.SDK_INT)
        if (Build.VERSION.SDK_INT <= TlsCaInstallPlan.MAX_SYSTEM_INSTALL_API) {
            assertEquals(TlsCaInstallRoute.SystemInstallIntent, route)
            // API 26-29: the system certificate installer must actually resolve.
            assertNotNull(KeyChain.createInstallIntent().resolveActivity(context.packageManager))
        } else {
            // API 30+: the wizard must not pretend to install a CA in-app; it only
            // guides the user to settings, so the route is guidance.
            assertEquals(TlsCaInstallRoute.SettingsGuidance, route)
        }
    }

    @Test fun resetIsRefusedWhileALeaseIsHeldAndPublishesANewIdentity() = runBlocking {
        val ca = manager
        val operations = TlsCaUiOperations(ca)
        val first = operations.generate()
        val lease = ca.openEngineLease()
        try {
            val error = try {
                operations.reset()
                fail("Expected CAPTURE_ACTIVE while a lease is held")
                error("unreachable")
            } catch (error: TlsCertificateException) {
                error
            }
            assertEquals(TlsCertificateErrorCode.CAPTURE_ACTIVE, error.code)
            assertEquals(first.caId, ca.status().caId)
        } finally {
            lease.close()
        }

        val second = operations.reset()
        assertNotEquals(first.caId, second.caId)
        assertEquals(2L, second.caGeneration)
        assertEquals(first.certificateSha256, second.previousCertificateSha256)
        assertTrue(second.systemStoreRemovalRequired)
        // Export names the old fingerprint so the manual removal step is actionable.
        assertEquals(first.certificateSha256, operations.export().previousCertificateSha256)
    }

    @Test fun expiredRootIsReportedAndTheOperationsSurfaceIt() = runBlocking {
        val operations = TlsCaUiOperations(manager)
        val created = operations.generate()
        now = created.notAfterMillis!!
        assertEquals(TlsCaState.EXPIRED, operations.refresh().state)
        // Export still works for an expired root (the recovery step needs it).
        assertFalse(TlsCaExportPlan.containsPrivateKeyMarker(operations.export().certificateDer))
    }

    @Test fun theProcessSingletonIsOneManager() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val first = TlsCaManagerHolder.get(context)
        val second = TlsCaManagerHolder.get(context)
        // The wizard and the capture service must share one manager, or a second
        // instance would let reset bypass "engine holds a lease" (TLS-206/TLS-216).
        assertSame(first, second)
    }

    private fun parse(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate

    private fun store(): java.security.KeyStore =
        java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun caGenerationAvailable(): Boolean = try {
        val capabilities = JSONObject(NativeEngine.getTlsProxyCapabilities())
        capabilities.optBoolean("buildEnabled") && capabilities.optBoolean("caGenerationReady")
    } catch (_: Throwable) {
        false
    }
}
