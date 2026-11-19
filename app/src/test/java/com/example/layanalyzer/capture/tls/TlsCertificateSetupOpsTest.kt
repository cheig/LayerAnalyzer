// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import javax.crypto.KeyGenerator
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * TLS-305's testable core: the install-intent decision by API level, the meaning
 * of an install result, the `.cer` export plan and the UI-operation wrapper over
 * [TlsCertificateManager].
 *
 * Synthetic CA material only (see
 * `native_build/verification/tls/generate_certificate_manager_fixture.py`); no
 * native call happens here because [TlsCaMaterialSource] is a test double, which
 * is the same difference as TLS-206's host test. The install intent itself only
 * exists on a device and is covered by `TlsCertificateSetupTest` (NOT RUN here).
 */
class TlsCertificateSetupOpsTest {
    @get:Rule val temporary = TemporaryFolder()
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val provider = AesGcmTlsWrappingKeyProvider { key }
    private val fixture = listOf(
        File("app/src/test/resources/tls/certificate-manager"),
        File("src/test/resources/tls/certificate-manager")
    ).firstOrNull { it.isDirectory } ?: error("certificate-manager fixture directory not found")

    private val certificateDer get() = File(fixture, "ca-certificate.der").readBytes()
    private val privateKeyPkcs8 get() = File(fixture, "ca-private-key.pkcs8").readBytes()
    private var now = FIXTURE_MIDPOINT

    private val source = object : TlsCaMaterialSource {
        override fun generate(): Array<ByteArray> = arrayOf(certificateDer, privateKeyPkcs8)
    }

    private fun manager() = TlsCertificateManager(temporary.root, provider, source) { now }

    @Test fun installRouteFollowsTheApiLevel() {
        // API 26-29: the system certificate installer can still install a user CA.
        for (sdk in 26..29) assertEquals(TlsCaInstallRoute.SystemInstallIntent, TlsCaInstallPlan.routeFor(sdk))
        // API 30+: createInstallIntent() cannot install a CA, so the wizard guides
        // to settings instead of pretending.
        for (sdk in listOf(30, 31, 33, 34, 35)) {
            assertEquals(TlsCaInstallRoute.SettingsGuidance, TlsCaInstallPlan.routeFor(sdk))
        }
        assertEquals(29, TlsCaInstallPlan.MAX_SYSTEM_INSTALL_API)
    }

    @Test fun anInstallResultNeverBecomesTrustOrInstalled() {
        // There is no INSTALLED or TRUSTED value to reach: the enum is the whole
        // vocabulary, and a completed dialog is only that.
        assertEquals(
            TlsCaInstallObservation.SYSTEM_DIALOG_COMPLETED,
            TlsCaInstallPlan.observationForResult(resultOk = true)
        )
        assertEquals(
            TlsCaInstallObservation.SYSTEM_DIALOG_CANCELLED,
            TlsCaInstallPlan.observationForResult(resultOk = false)
        )
        assertEquals(TlsCaInstallObservation.NO_OBSERVABLE_RESULT, TlsCaInstallPlan.observationForGuidance())
        assertEquals(
            setOf(
                TlsCaInstallObservation.NOT_ATTEMPTED,
                TlsCaInstallObservation.SYSTEM_DIALOG_COMPLETED,
                TlsCaInstallObservation.SYSTEM_DIALOG_CANCELLED,
                TlsCaInstallObservation.NO_OBSERVABLE_RESULT
            ),
            TlsCaInstallObservation.entries.toSet()
        )
    }

    @Test fun suggestedFileNameIsAlwaysACerAndNeverLeaksTheWholeId() {
        val caId = "0123456789ab-cdef-0123-4567-89abcdef0123"
        val name = TlsCaExportPlan.suggestedFileName(caId)
        assertTrue(name.endsWith(".cer"))
        assertEquals("layeranalyzer-ca-01234567.cer", name)
        assertFalse(name.contains(caId))
        // A missing id still yields a public `.cer`, never a `.key`/`.pem`.
        assertEquals("layeranalyzer-ca.cer", TlsCaExportPlan.suggestedFileName(null))
        assertTrue(TlsCaExportPlan.suggestedFileName("nonsense").endsWith(".cer"))
    }

    @Test fun thePrivateKeyMarkerScanRejectsPemAndPassesDer() {
        // Discriminating power: the same key bytes are caught as PEM and the real
        // exported certificate is clean.
        val pem = "-----BEGIN PRIVATE KEY-----\n" +
            Base64.getEncoder().encodeToString(privateKeyPkcs8) +
            "\n-----END PRIVATE KEY-----\n"
        assertTrue(TlsCaExportPlan.containsPrivateKeyMarker(pem.toByteArray(Charsets.US_ASCII)))
        assertFalse(TlsCaExportPlan.containsPrivateKeyMarker(certificateDer))
        assertFalse(TlsCaExportPlan.containsPrivateKeyMarker(ByteArray(0)))
        // The marker scan works on exact ASCII, so a certificate DER with a
        // coincidental binary run is not mistaken for a marker.
        assertTrue(TlsCaExportPlan.containsPrivateKeyMarker("PRIVATE KEY".toByteArray(Charsets.US_ASCII)))
    }

    @Test fun uiOperationsExportOnlyThePublicCertificate() = runBlocking {
        val operations = TlsCaUiOperations(manager())
        assertEquals(TlsCaState.MISSING, operations.refresh().state)
        assertEquals(TlsCaState.READY, operations.generate().state)

        val export = operations.export()
        assertArrayEquals(certificateDer, export.certificateDer)
        assertFalse(TlsCaExportPlan.containsPrivateKeyMarker(export.certificateDer))
        // The export parses as a CA certificate, i.e. it is a certificate and not
        // a key in disguise.
        val certificate = parse(export.certificateDer)
        assertTrue(certificate.basicConstraints >= 0)
        assertTrue(export.subjectName.isNotEmpty())
    }

    @Test fun resetThroughTheOperationsIsRefusedWhileALeaseIsHeld() = runBlocking {
        val manager = manager()
        val operations = TlsCaUiOperations(manager)
        val first = operations.generate()
        val lease = manager.openEngineLease()
        try {
            val error = try {
                operations.reset()
                fail("Expected CAPTURE_ACTIVE while a lease is held")
                error("unreachable")
            } catch (error: TlsCertificateException) {
                error
            }
            assertEquals(TlsCertificateErrorCode.CAPTURE_ACTIVE, error.code)
        } finally {
            lease.close()
        }

        val second = operations.reset()
        assertNotEquals(first.caId, second.caId)
        assertEquals(2L, second.caGeneration)
        assertEquals(first.certificateSha256, second.previousCertificateSha256)
        assertTrue(second.systemStoreRemovalRequired)
    }

    @Test fun theOperationsSurfaceTheExpiredState() = runBlocking {
        val operations = TlsCaUiOperations(manager())
        val created = operations.generate()
        now = created.notAfterMillis!!
        assertEquals(TlsCaState.EXPIRED, operations.refresh().state)
        // Export stays available for an expired root: knowing which certificate to
        // remove is the recovery step.
        assertArrayEquals(certificateDer, operations.export().certificateDer)
    }

    private fun parse(der: ByteArray) =
        CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate

    private companion object {
        /** Safely inside the fixture's 2020-01-01 .. 2045-01-01 window. */
        const val FIXTURE_MIDPOINT = 1_600_000_000_000L
    }
}
