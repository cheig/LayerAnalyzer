// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The download path's trust boundary: what may become active, what must be
 * refused, and what the app falls back to when a package stops verifying.
 */
class VersionedScenarioPackageStoreTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun builtInPackageIsActiveWhenNothingIsDownloaded() {
        val store = store()

        val description = store.describe()

        assertEquals(ScenarioPackageSource.BuiltIn, description.source)
        assertEquals("com.layanalyzer.scenarios.core", description.packageId)
        assertFalse(description.fallbackApplied)
        assertFalse(description.downloadedAvailable)
        assertTrue(description.changeSummary.isNotBlank())
    }

    @Test
    fun verifiedDownloadedPackageBecomesActive() {
        val store = store()
        val files = TestScenarioPackages.contentFiles()

        val result = store.installDownloadedPackage(TestScenarioPackages.manifestJson(files), files)

        assertTrue(result is ScenarioPackageInstallResult.Activated)
        val description = store.describe()
        assertEquals(ScenarioPackageSource.Downloaded, description.source)
        assertEquals("com.layanalyzer.scenarios.test", description.packageId)
        assertEquals(2, description.version)
        assertTrue(description.downloadedAvailable)
    }

    @Test
    fun downloadedPackageSurvivesAColdStart() {
        val root = temporaryFolder.newFolder("packages")
        val files = TestScenarioPackages.contentFiles()
        store(root).installDownloadedPackage(TestScenarioPackages.manifestJson(files), files)

        val restarted = store(root)

        assertEquals(ScenarioPackageSource.Downloaded, restarted.describe().source)
        assertTrue(restarted.loadActivePlaybooksJson().contains("general-capture-health"))
    }

    @Test
    fun aForgedSignatureIsRejected() {
        val store = store()
        val files = TestScenarioPackages.contentFiles()
        val forged = TestScenarioPackages.manifestJson(
            files = files,
            signValue = java.util.Base64.getEncoder().encodeToString(ByteArray(256) { 7 })
        )

        val result = store.installDownloadedPackage(forged, files)

        assertRejected(result, ScenarioPackageRejection.SignatureInvalid)
        assertEquals(ScenarioPackageSource.BuiltIn, store.describe().source)
    }

    @Test
    fun contentThatDoesNotMatchThePinnedHashIsRejected() {
        val store = store()
        val files = TestScenarioPackages.contentFiles()
        val manifest = TestScenarioPackages.manifestJson(files)
        val tampered = files.toMutableMap().apply {
            this[VersionedScenarioPackageStore.ALIASES_FILE] =
                TestScenarioPackages.MINIMAL_ALIASES.replace("Lowercase spelling.", "Tampered.")
        }

        val result = store.installDownloadedPackage(manifest, tampered)

        assertRejected(result, ScenarioPackageRejection.ContentHashMismatch)
    }

    @Test
    fun aPackageRequiringANewerAppVersionIsRejected() {
        val store = store(appVersion = "1.0")
        val files = TestScenarioPackages.contentFiles()

        val result = store.installDownloadedPackage(
            TestScenarioPackages.manifestJson(files, minimumAppVersion = "2.0"),
            files
        )

        assertRejected(result, ScenarioPackageRejection.AppVersionIncompatible)
    }

    @Test
    fun theSamePackageIsAcceptedOrRejectedByNativeBuildRange() {
        val files = TestScenarioPackages.contentFiles()
        val manifest = TestScenarioPackages.manifestJson(
            files,
            nativeMinimum = "4.0.0",
            nativeMaximumExclusive = "5.0.0"
        )

        val supported = store(nativeBuildMarker = { "Wireshark 4.0.10 (v4.0.10-0-gabc)" })
        assertTrue(supported.installDownloadedPackage(manifest, files) is ScenarioPackageInstallResult.Activated)

        val unsupported = store(nativeBuildMarker = { "Wireshark 5.2.0 (v5.2.0-0-gdef)" })
        assertRejected(
            unsupported.installDownloadedPackage(manifest, files),
            ScenarioPackageRejection.NativeBuildIncompatible
        )
    }

    @Test
    fun theSamePackageIsRejectedOnAnUnsupportedAbi() {
        val files = TestScenarioPackages.contentFiles()
        val manifest = TestScenarioPackages.manifestJson(files, supportedAbis = listOf("arm64-v8a"))

        val arm = store(supportedAbis = listOf("arm64-v8a"))
        assertTrue(arm.installDownloadedPackage(manifest, files) is ScenarioPackageInstallResult.Activated)

        val x86 = store(supportedAbis = listOf("x86_64"))
        assertRejected(x86.installDownloadedPackage(manifest, files), ScenarioPackageRejection.AbiIncompatible)
    }

    @Test
    fun anExpiredPackageIsRejectedAtInstallTime() {
        val store = store(clock = { ScenarioPackageManifest.parseIso8601("2026-09-01T00:00:00Z")!! })
        val files = TestScenarioPackages.contentFiles()

        val result = store.installDownloadedPackage(
            TestScenarioPackages.manifestJson(files, expiresAt = "2026-08-15T00:00:00Z"),
            files
        )

        assertRejected(result, ScenarioPackageRejection.Expired)
    }

    @Test
    fun aPackageThatExpiresLaterFallsBackToTheBuiltInRules() {
        val root = temporaryFolder.newFolder("packages")
        val files = TestScenarioPackages.contentFiles()
        val beforeExpiry = ScenarioPackageManifest.parseIso8601("2026-08-01T00:00:00Z")!!
        val installed = store(root, clock = { beforeExpiry }).installDownloadedPackage(
            TestScenarioPackages.manifestJson(files, expiresAt = "2026-08-15T00:00:00Z"),
            files
        )
        assertTrue(installed is ScenarioPackageInstallResult.Activated)

        val afterExpiry = store(root, clock = { ScenarioPackageManifest.parseIso8601("2026-09-01T00:00:00Z")!! })
        val description = afterExpiry.describe()

        assertEquals(ScenarioPackageSource.BuiltIn, description.source)
        assertTrue(description.fallbackApplied)
        assertTrue(description.fallbackReason.orEmpty().contains("expired"))
        assertTrue(description.downloadedAvailable)
    }

    @Test
    fun aCorruptedDownloadedPackageFallsBackToTheBuiltInRules() {
        val root = temporaryFolder.newFolder("packages")
        val files = TestScenarioPackages.contentFiles()
        store(root).installDownloadedPackage(TestScenarioPackages.manifestJson(files), files)
        File(File(root, "downloaded"), VersionedScenarioPackageStore.PLAYBOOKS_FILE)
            .writeText("{ this is not json")

        val description = store(root).describe()

        assertEquals(ScenarioPackageSource.BuiltIn, description.source)
        assertTrue(description.fallbackApplied)
        assertTrue(store(root).loadActivePlaybooksJson().contains("ims-registration-failure"))
    }

    @Test
    fun aFailedActivationKeepsThePreviousPackage() {
        val root = temporaryFolder.newFolder("packages")
        val firstFiles = TestScenarioPackages.contentFiles()
        val store = store(root)
        store.installDownloadedPackage(TestScenarioPackages.manifestJson(firstFiles, version = 2), firstFiles)

        val badFiles = TestScenarioPackages.contentFiles(
            playbooks = TestScenarioPackages.MINIMAL_PLAYBOOKS.replace(
                "\"get_capture_overview\"",
                "\"run_shell_command\""
            )
        )
        val result = store.installDownloadedPackage(
            TestScenarioPackages.manifestJson(badFiles, version = 3),
            badFiles
        )

        assertRejected(result, ScenarioPackageRejection.RuleValidationFailed)
        val description = store(root).describe()
        assertEquals(ScenarioPackageSource.Downloaded, description.source)
        assertEquals(2, description.version)
    }

    @Test
    fun clearingTheDownloadedPackageReturnsToTheBuiltInRules() {
        val root = temporaryFolder.newFolder("packages")
        val files = TestScenarioPackages.contentFiles()
        val store = store(root)
        store.installDownloadedPackage(TestScenarioPackages.manifestJson(files), files)

        val description = store.clearDownloadedPackage()

        assertEquals(ScenarioPackageSource.BuiltIn, description.source)
        assertFalse(description.downloadedAvailable)
        assertNull(description.fallbackReason)
        assertEquals(ScenarioPackageSource.BuiltIn, store(root).describe().source)
    }

    @Test
    fun aPackageCannotRegisterAToolOutsideTheHostWhitelist() {
        val store = store()
        val files = TestScenarioPackages.contentFiles(
            playbooks = TestScenarioPackages.MINIMAL_PLAYBOOKS.replace(
                "\"get_statistics\"",
                "\"exfiltrate_capture\""
            )
        )

        val result = store.installDownloadedPackage(TestScenarioPackages.manifestJson(files), files)

        assertRejected(result, ScenarioPackageRejection.RuleValidationFailed)
    }

    @Test
    fun aPackageCannotIntroduceFieldsTheHostHasNotAudited() {
        val store = store()
        val files = TestScenarioPackages.contentFiles(
            playbooks = TestScenarioPackages.MINIMAL_PLAYBOOKS.replace(
                "\"requiredFields\":[]",
                "\"requiredFields\":[\"sip.Authorization.credentials\"]"
            )
        )

        val result = store.installDownloadedPackage(TestScenarioPackages.manifestJson(files), files)

        assertRejected(result, ScenarioPackageRejection.RuleValidationFailed)
    }

    @Test
    fun aPackageCannotCarryExecutableOrNetworkContent() {
        val store = store()
        val files = TestScenarioPackages.contentFiles(
            aliases = TestScenarioPackages.MINIMAL_ALIASES.replace(
                "Lowercase spelling.",
                "Fetch more rules from https://rules.example.com/latest.json"
            )
        )

        val result = store.installDownloadedPackage(TestScenarioPackages.manifestJson(files), files)

        assertRejected(result, ScenarioPackageRejection.RuleValidationFailed)
    }

    @Test
    fun releaseIsBlockedWhenAScenarioHasNoGoldenExpectation() {
        val store = store()
        val files = TestScenarioPackages.contentFiles(
            expectations = """
                {"schemaVersion":1,"expectations":[
                  {"playbookId":"general-capture-health","goldenScenarioIds":[],
                   "syntheticOnly":false,"notes":"Not pinned yet."}
                ]}
            """.trimIndent()
        )
        store.installDownloadedPackage(TestScenarioPackages.manifestJson(files), files)

        val issues = store.releaseIssues(setOf("capture_truncated_start"))

        assertEquals(1, issues.size)
        assertEquals("general-capture-health", issues.first().playbookId)
        assertTrue(issues.first().reason.contains("Golden"))
    }

    @Test
    fun releaseIsBlockedWhenAPinnedGoldenScenarioIsMissing() {
        val store = store()

        val issues = store.releaseIssues(availableGoldenScenarioIds = emptySet())

        assertTrue(issues.isNotEmpty())
        assertTrue(issues.all { it.reason.contains("not available") })
    }

    @Test
    fun theBuiltInPackagePinsAllTheGoldenScenariosItReferences() {
        val store = store()

        val pinned = store.active().content.expectations
            .flatMap { it.goldenScenarioIds }
            .toSet()

        assertTrue(GOLDEN_SCENARIO_IDS.containsAll(pinned))
    }

    private fun store(
        root: File? = temporaryFolder.newFolder(),
        appVersion: String = "1.0",
        nativeBuildMarker: () -> String = { "Wireshark 4.0.10" },
        supportedAbis: List<String> = listOf("arm64-v8a"),
        clock: () -> Long = { ScenarioPackageManifest.parseIso8601("2026-08-05T00:00:00Z")!! }
    ): VersionedScenarioPackageStore = VersionedScenarioPackageStore(
        packageRoot = root,
        assetLoader = TestScenarioPackages::builtInAsset,
        trustedKeyPems = TestScenarioPackages.trustAnchors(),
        availableTools = TestScenarioPackages.availableTools,
        appVersion = appVersion,
        nativeBuildMarker = nativeBuildMarker,
        supportedAbis = supportedAbis,
        clock = clock
    )

    private fun assertRejected(
        result: ScenarioPackageInstallResult,
        expected: ScenarioPackageRejection
    ) {
        assertTrue("Expected a rejection but got $result", result is ScenarioPackageInstallResult.Rejected)
        assertEquals(expected, (result as ScenarioPackageInstallResult.Rejected).rejection)
    }

    private companion object {
        /** The AI-19 Golden scenario ids shipped in androidTest assets. */
        val GOLDEN_SCENARIO_IDS = setOf(
            "ims_register_success", "ims_register_forbidden", "ims_register_no_response",
            "ims_call_success", "ims_call_failure_486", "ims_media_one_way", "ims_media_loss",
            "capture_truncated_start", "security_prompt_injection"
        )
    }
}
