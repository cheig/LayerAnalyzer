package com.example.layanalyzer.ai.playbook

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The built-in package must parse, verify and stay inside the host's rule limits. */
class ScenarioPackageManifestTest {

    @Test
    fun builtInManifestParsesAndPinsEveryContentFile() {
        val manifest = ScenarioPackageManifest.decode(asset("manifest.json"))

        assertEquals(ScenarioPackageManifest.SCHEMA_VERSION, manifest.schemaVersion)
        assertEquals("com.layanalyzer.scenarios.core", manifest.packageId)
        assertEquals(ScenarioPackageManifest.PACKAGE_FILES, manifest.files.keys)
        assertEquals(3, manifest.layers.size)
        assertTrue(manifest.latestChangeSummary.isNotBlank())
        assertEquals(ScenarioPackageManifest.SIGNATURE_ALGORITHM, manifest.signature.algorithm)
    }

    @Test
    fun builtInManifestSignatureVerifiesAgainstTheShippedPublicKey() {
        val store = TestScenarioPackages.builtInStore()

        val active = store.active()

        assertEquals(ScenarioPackageSource.BuiltIn, active.source)
        assertEquals("com.layanalyzer.scenarios.core", active.manifest.packageId)
    }

    @Test
    fun contentHashesInTheManifestMatchTheShippedFiles() {
        val manifest = ScenarioPackageManifest.decode(asset("manifest.json"))

        manifest.files.forEach { (name, expected) ->
            assertEquals("$name hash", expected, TestScenarioPackages.sha256(asset(name)))
        }
    }

    @Test
    fun versionComparisonOrdersDottedNumericSegments() {
        assertTrue(ScenarioPackageManifest.compareVersions("4.0.10", "4.0.9") > 0)
        assertTrue(ScenarioPackageManifest.compareVersions("4.0", "4.0.0") == 0)
        assertTrue(ScenarioPackageManifest.compareVersions("3.9.9", "4.0.0") < 0)
        assertEquals("4.0.10", ScenarioPackageManifest.extractVersionPrefix("Wireshark 4.0.10 (v4.0.10-0-gabc)"))
    }

    @Test
    fun nativeBuildRangeIsHalfOpen() {
        val range = NativeBuildRange(minimum = "4.0.0", maximumExclusive = "5.0.0")

        assertTrue(range.contains("4.0.0"))
        assertTrue(range.contains("4.9.9"))
        assertFalse(range.contains("5.0.0"))
        assertFalse(range.contains("3.9.9"))
    }

    @Test
    fun expiryUsesTheDeclaredInstant() {
        val manifest = TestScenarioPackages.manifest(
            expiresAt = "2026-01-02T00:00:00Z"
        )

        assertFalse(manifest.isExpired(ScenarioPackageManifest.parseIso8601("2026-01-01T23:59:59Z")!!))
        assertTrue(manifest.isExpired(ScenarioPackageManifest.parseIso8601("2026-01-02T00:00:00Z")!!))
    }

    @Test
    fun unknownManifestPropertiesAreRejected() {
        val tampered = asset("manifest.json").replace("\"regions\"", "\"downloadUrl\": \"x\", \"regions\"")

        val failure = runCatching { ScenarioPackageManifest.decode(tampered) }

        assertTrue(failure.isFailure)
        assertTrue(failure.exceptionOrNull()?.message.orEmpty().contains("unknown properties"))
    }

    @Test
    fun manifestMustPinEveryPackageFile() {
        val incomplete = asset("manifest.json").replace(
            Regex("\"thresholds\\.json\"\\s*:\\s*\"[0-9a-f]{64}\",?\\s*"),
            ""
        )

        assertTrue(runCatching { ScenarioPackageManifest.decode(incomplete) }.isFailure)
    }

    private fun asset(name: String): String = File(TestScenarioPackages.ASSET_DIR, name).readText()
}
