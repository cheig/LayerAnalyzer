// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.model.CaptureArtifactManifest
import com.example.layanalyzer.model.CaptureMode
import com.example.layanalyzer.model.CaptureRetentionPolicy
import com.example.layanalyzer.model.CaptureTlsAssets
import com.example.layanalyzer.model.PacketVantage
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host tests for the saved-capture open plan (TLS-310). They exercise the pure decision
 * — which input is opened, whether a secret lease is required, every degradation branch,
 * the reverse-of-acquisition teardown order — with synthetic [CaptureAnalysisSource] and
 * manifest values. They make no claim about a device, the native engine or real plaintext;
 * that is `D=TlsSavedCaptureOpenTest`'s job.
 */
class CaptureOpenPlanTest {
    private val captureId = "live-2000"

    private fun header(): PcapGlobalHeader {
        val bytes = ByteArray(24)
        bytes[0] = 0xd4.toByte(); bytes[1] = 0xc3.toByte(); bytes[2] = 0xb2.toByte(); bytes[3] = 0xa1.toByte()
        bytes[4] = 2; bytes[5] = 0; bytes[6] = 4; bytes[7] = 0
        putU32(bytes, 16, 65535L)
        putU32(bytes, 20, 101L)
        return PcapGlobalHeader.parse(bytes)
    }

    private fun putU32(bytes: ByteArray, offset: Int, value: Long) {
        for (index in 0 until 4) bytes[offset + index] = (value ushr (8 * index)).toByte()
    }

    private fun merged(
        singleSegment: Boolean = false,
        issues: List<CaptureMergeIssue> = emptyList(),
        manifestIssues: List<CaptureSegmentIssue> = emptyList()
    ) = CaptureAnalysisSource.Merged(
        captureId = captureId,
        analysisFile = File("merged-analysis.pcap"),
        globalHeader = header(),
        segments = emptyList(),
        issues = issues,
        manifestIssues = manifestIssues,
        totalFrames = 42L,
        byteLength = 4096L,
        singleSegment = singleSegment
    )

    private fun manifest(
        tlsEnabled: Boolean = true,
        secretsAssetId: String? = "asset-1",
        tlsComplete: Boolean = true,
        packetDrops: Long = 0L,
        interrupted: Boolean = false,
        captureMode: CaptureMode = CaptureMode.VpnCapture,
        vantage: PacketVantage = PacketVantage.TunInterface,
        retention: CaptureRetentionPolicy = CaptureRetentionPolicy.KeepCaptureAndSecrets
    ) = CaptureArtifactManifest(
        captureId = captureId,
        captureMode = captureMode,
        packetVantage = vantage,
        packetDrops = packetDrops,
        interrupted = interrupted,
        retentionPolicy = retention,
        tls = CaptureTlsAssets(
            enabled = tlsEnabled,
            secretsAssetId = secretsAssetId,
            complete = tlsComplete
        ),
        finalized = true,
        complete = true
    )

    private fun open(plan: CaptureOpenPlan): CaptureOpenPlan.Open {
        assertTrue("expected an Open plan but was $plan", plan is CaptureOpenPlan.Open)
        return plan as CaptureOpenPlan.Open
    }

    // ---- happy path ------------------------------------------------------------

    @Test
    fun aCompleteCaptureWithRetainedSecretsOpensItsMergedFileWithALeaseAndNoDegradation() {
        val plan = open(
            CaptureOpenPlanner.plan(
                captureId,
                merged(),
                CaptureOpenSecrets.Available("asset-1"),
                manifest()
            )
        )
        assertEquals(CaptureOpenScope.WholeCapture, plan.scope)
        assertFalse(plan.singleSegmentOnly)
        assertTrue(plan.requiresSecretLease)
        assertEquals("asset-1", plan.secretAssetId)
        assertFalse(plan.contextIncomplete)
        assertTrue(plan.captureComplete)
        assertTrue(plan.decryptionComplete)
        assertTrue(plan.notices.isEmpty())
        assertEquals(42L, plan.totalFrames)
        assertEquals(File("merged-analysis.pcap"), plan.analysisFile)
        assertEquals(File("merged-analysis.pcap"), plan.derivedAnalysisFile)
    }

    // ---- degradation branches --------------------------------------------------

    @Test
    fun missingTruncatedAndUnfinishedSegmentsAreSurfacedNotHidden() {
        val plan = open(
            CaptureOpenPlanner.plan(
                captureId,
                merged(
                    issues = listOf(
                        CaptureMergeIssue("packets-0002.pcap", CaptureMergeIssueKind.SEGMENT_FILE_MISSING),
                        CaptureMergeIssue("packets-0003.pcap", CaptureMergeIssueKind.SEGMENT_TRUNCATED_TAIL, 4L)
                    ),
                    manifestIssues = listOf(
                        CaptureSegmentIssue.SEGMENT_NOT_FINALIZED,
                        CaptureSegmentIssue.SEGMENT_HASH_MISMATCH
                    )
                ),
                CaptureOpenSecrets.Available("asset-1"),
                manifest()
            )
        )
        assertTrue(plan.contextIncomplete)
        assertFalse(plan.captureComplete)
        assertTrue(CaptureOpenNotice.MISSING_SEGMENT in plan.notices)
        assertTrue(CaptureOpenNotice.TRUNCATED_SEGMENT in plan.notices)
        assertTrue(CaptureOpenNotice.UNFINISHED_SEGMENT in plan.notices)
        assertTrue(CaptureOpenNotice.SEGMENT_HASH_MISMATCH in plan.notices)
    }

    @Test
    fun dropsAndInterruptionAreReportedFromTheManifest() {
        val plan = open(
            CaptureOpenPlanner.plan(
                captureId,
                merged(),
                CaptureOpenSecrets.Available("asset-1"),
                manifest(packetDrops = 3L, interrupted = true)
            )
        )
        assertEquals(3L, plan.packetDrops)
        assertTrue(CaptureOpenNotice.PACKETS_DROPPED in plan.notices)
        assertTrue(CaptureOpenNotice.CAPTURE_INTERRUPTED in plan.notices)
        assertFalse(plan.captureComplete)
    }

    @Test
    fun aSingleSegmentIsAlwaysPresentedAsIncomplete() {
        val plan = open(
            CaptureOpenPlanner.plan(
                captureId,
                merged(singleSegment = true),
                CaptureOpenSecrets.Available("asset-1"),
                manifest()
            )
        )
        assertEquals(CaptureOpenScope.SingleSegment, plan.scope)
        assertTrue(plan.singleSegmentOnly)
        assertTrue(plan.contextIncomplete)
        assertFalse(plan.captureComplete)
        assertTrue(CaptureOpenNotice.SINGLE_SEGMENT_FALLBACK in plan.notices)
    }

    @Test
    fun theDiskFullFallbackMarksBothTheFallbackAndTheSingleSegment() {
        val plan = open(
            CaptureOpenPlanner.singleSegmentFallback(
                captureId,
                merged(singleSegment = true),
                CaptureOpenSecrets.Available("asset-1"),
                manifest()
            )
        )
        assertEquals(CaptureOpenScope.SingleSegment, plan.scope)
        assertTrue(CaptureOpenNotice.DISK_FULL_FALLBACK in plan.notices)
        assertTrue(CaptureOpenNotice.SINGLE_SEGMENT_FALLBACK in plan.notices)
    }

    // ---- secrets ---------------------------------------------------------------

    @Test
    fun absentSecretsDegradeToUndecryptedWithoutATLease() {
        val plan = open(
            CaptureOpenPlanner.plan(captureId, merged(), CaptureOpenSecrets.Absent, manifest())
        )
        assertFalse(plan.requiresSecretLease)
        assertNull(plan.secretAssetId)
        assertFalse(plan.decryptionComplete)
        assertTrue(CaptureOpenNotice.SECRETS_ABSENT in plan.notices)
    }

    @Test
    fun anUnavailableStoreIsReportedDistinctlyFromAbsentSecrets() {
        val plan = open(
            CaptureOpenPlanner.plan(
                captureId,
                merged(),
                CaptureOpenSecrets.Unavailable(TlsAssetErrorCode.CAPACITY_EXCEEDED),
                manifest()
            )
        )
        assertFalse(plan.requiresSecretLease)
        assertTrue(CaptureOpenNotice.SECRETS_UNAVAILABLE in plan.notices)
        assertFalse(CaptureOpenNotice.SECRETS_ABSENT in plan.notices)
    }

    @Test
    fun incompleteKeyRetentionLoadsTheKeysButSaysTheRecordsMayStayEncrypted() {
        val plan = open(
            CaptureOpenPlanner.plan(
                captureId,
                merged(),
                CaptureOpenSecrets.Available("asset-1"),
                manifest(tlsComplete = false)
            )
        )
        assertTrue(plan.requiresSecretLease)
        assertFalse(plan.decryptionComplete)
        assertTrue(CaptureOpenNotice.SECRETS_INCOMPLETE in plan.notices)
    }

    @Test
    fun aTlsDisabledManifestNeverRequestsALease() {
        val plan = open(
            CaptureOpenPlanner.plan(
                captureId,
                merged(),
                CaptureOpenSecrets.Available("asset-1"),
                manifest(tlsEnabled = false)
            )
        )
        assertFalse(plan.requiresSecretLease)
        assertFalse(CaptureOpenNotice.SECRETS_ABSENT in plan.notices)
        assertFalse(CaptureOpenNotice.SECRETS_UNAVAILABLE in plan.notices)
        assertFalse(CaptureOpenNotice.SECRETS_INCOMPLETE in plan.notices)
    }

    @Test
    fun secretsAreNeverResolvedWithoutAManifestEvenIfAnAssetIsOffered() {
        // A legacy capture has no manifest; an adjacent keylog must not be guessed (C08).
        val legacy = CaptureAnalysisSource.Legacy(captureId, File("$captureId.pcap"))
        assertEquals(
            CaptureOpenSecrets.Absent,
            CaptureOpenPlanner.resolveSecrets(null, legacy, "asset-1", "asset-1")
        )
        // Even a stray manifest does not apply to a Legacy source path.
        assertEquals(
            CaptureOpenSecrets.Absent,
            CaptureOpenPlanner.resolveSecrets(manifest(), legacy, "asset-1", "asset-1")
        )
    }

    @Test
    fun aSupersededAssetIsNotSubstitutedForTheOneTheManifestNames() {
        assertEquals(
            CaptureOpenSecrets.Absent,
            CaptureOpenPlanner.resolveSecrets(manifest(), merged(), "asset-1", "asset-2")
        )
        assertEquals(
            CaptureOpenSecrets.Available("asset-1"),
            CaptureOpenPlanner.resolveSecrets(manifest(), merged(), "asset-1", "asset-1")
        )
        assertEquals(
            CaptureOpenSecrets.Absent,
            CaptureOpenPlanner.resolveSecrets(manifest(secretsAssetId = null), merged(), null, "asset-1")
        )
    }

    @Test
    fun aStoreErrorBecomesUnavailableRatherThanAbsent() {
        assertEquals(
            CaptureOpenSecrets.Unavailable(TlsAssetErrorCode.IO_ERROR),
            CaptureOpenPlanner.resolveSecrets(manifest(), merged(), "asset-1", null, TlsAssetErrorCode.IO_ERROR)
        )
    }

    // ---- legacy / missing / refused / cancelled --------------------------------

    @Test
    fun aLegacyCaptureKeepsItsOriginalFileAndOwnsNothingToDelete() {
        val file = File("$captureId.pcap")
        val plan = open(
            CaptureOpenPlanner.plan(
                captureId,
                CaptureAnalysisSource.Legacy(captureId, file),
                CaptureOpenSecrets.Absent,
                manifest = null
            )
        )
        assertEquals(CaptureOpenScope.LegacySingleFile, plan.scope)
        assertEquals(file, plan.analysisFile)
        assertNull(plan.derivedAnalysisFile)
        assertFalse(plan.requiresSecretLease)
        assertFalse(plan.contextIncomplete)
    }

    @Test
    fun missingAndRefusedCapturesBecomeFixedFailures() {
        assertEquals(
            CaptureOpenFailure.NOT_FOUND,
            (CaptureOpenPlanner.plan(captureId, CaptureAnalysisSource.Missing(captureId), CaptureOpenSecrets.Absent) as CaptureOpenPlan.Unavailable).failure
        )
        assertEquals(
            CaptureOpenFailure.CORRUPT,
            (CaptureOpenPlanner.plan(
                captureId,
                CaptureAnalysisSource.Refused(captureId, TlsAssetErrorCode.INVALID_FORMAT),
                CaptureOpenSecrets.Absent
            ) as CaptureOpenPlan.Unavailable).failure
        )
        assertEquals(
            CaptureOpenFailure.NO_SPACE,
            (CaptureOpenPlanner.plan(
                captureId,
                CaptureAnalysisSource.Refused(captureId, TlsAssetErrorCode.DISK_FULL),
                CaptureOpenSecrets.Absent
            ) as CaptureOpenPlan.Unavailable).failure
        )
        assertEquals(
            CaptureOpenFailure.IO_ERROR,
            (CaptureOpenPlanner.plan(
                captureId,
                CaptureAnalysisSource.Refused(captureId, TlsAssetErrorCode.IO_ERROR),
                CaptureOpenSecrets.Absent
            ) as CaptureOpenPlan.Unavailable).failure
        )
    }

    @Test
    fun aCancelledMergeBecomesACancelledPlan() {
        val plan = CaptureOpenPlanner.plan(captureId, CaptureAnalysisSource.Cancelled(captureId), CaptureOpenSecrets.Absent)
        assertTrue(plan is CaptureOpenPlan.Cancelled)
    }

    // ---- identity and teardown order -------------------------------------------

    @Test
    fun theCaptureIdIsTheSavedFileNameWithoutItsExtension() {
        assertEquals("live-2000", CaptureOpenPlanner.captureIdFor(File("live-2000.pcap")))
        assertEquals("live-2000", CaptureOpenPlanner.captureIdFor(File("live-2000")))
        assertEquals("live-2000", CaptureOpenPlanner.captureIdFor(File("/tmp/captures/live-2000.PCAP")))
        assertNull("a space is not a valid local id", CaptureOpenPlanner.captureIdFor(File("my capture.pcap")))
        assertNull("the id must start with a letter or digit", CaptureOpenPlanner.captureIdFor(File("-bad.pcap")))
        assertNull(CaptureOpenPlanner.captureIdFor(File(".pcap")))
    }

    @Test
    fun teardownIsTheReverseOfAcquisition() {
        assertEquals(
            listOf(
                CaptureOpenTeardown.NativeSecrets,
                CaptureOpenTeardown.SecretLease,
                CaptureOpenTeardown.DerivedAnalysisFile
            ),
            CaptureOpenPlanner.TEARDOWN_ORDER
        )
    }
}
