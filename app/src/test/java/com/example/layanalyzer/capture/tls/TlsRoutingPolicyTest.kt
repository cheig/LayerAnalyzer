// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureSettingsJson
import com.example.layanalyzer.model.TlsHostRule
import com.example.layanalyzer.model.TlsHostScope
import com.example.layanalyzer.model.TlsSettingsIssueCode
import com.example.layanalyzer.model.TlsSettingsValidation
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The Kotlin half of the TLS-208 cross-language contract. The same fixture file
 * drives the Go test in `native_go/tlsbridge/internal/policy/fixture_test.go`:
 * this side asserts that its normalizer and frozen encoding reproduce the
 * fixture, and the Go side asserts that the decision maker reads that exact
 * frozen form and decides what the fixture records. Neither side re-implements
 * the other, and no case here claims a device result.
 */
class TlsRoutingPolicyTest {
    private val fixture = readFixture()

    private val rules get() = fixture.getJSONArray("rules")
    private val policies get() = fixture.getJSONArray("policies")

    @Test
    fun fixtureRulesNormalizeToTheFrozenCanonicalText() {
        assertTrue(rules.length() >= 20)
        for (index in 0 until rules.length()) {
            val entry = rules.getJSONObject(index)
            val input = entry.getString("input")
            val parsed = TlsHostRule.parse(input)
            if (entry.isNull("kind")) {
                assertNull("$input must not be accepted as any rule", parsed)
                assertTrue(entry.isNull("value"))
                assertFalse(entry.getBoolean("canonical"))
                continue
            }
            assertNotNull("$input must normalize", parsed)
            val kind = entry.getString("kind")
            val value = entry.getString("value")
            assertEquals("$kind:$value", parsed!!.wireKind + ":" + parsed.frozenValue)
            val canonical = if (kind == "subdomains") "*.$value" else value
            if (entry.getBoolean("canonical")) {
                assertEquals("a canonical entry must be the frozen text", canonical, input)
            } else {
                assertNotEquals("a non-canonical entry is a different text", canonical, input)
            }
            // The frozen text parses back to the same rule, in both spellings
            // Go is asked to accept.
            assertEquals(parsed, TlsHostRule.parse(parsed.canonicalText))
        }
    }

    @Test
    fun frozenEncodingMatchesTheFixtureForEveryPolicy() {
        assertTrue(policies.length() >= 6)
        for (index in 0 until policies.length()) {
            val entry = policies.getJSONObject(index)
            val (policy, validation) = freeze(entry)
            val expected = entry.getJSONObject("frozen")
            assertTrue(
                "frozen policy for ${entry.getString("id")}: ${policy.encode()}",
                JSONObject(policy.encode()).similar(expected)
            )
            if (entry.has("expectIssues")) {
                val issues = entry.getJSONArray("expectIssues")
                assertEquals("rejected settings report one issue per fixture entry", issues.length(), validation.issues.size)
                for (position in 0 until issues.length()) {
                    val issue = issues.getJSONObject(position)
                    assertEquals(issue.getString("code"), validation.issues[position].code.wireName)
                    assertEquals(issue.getString("field"), validation.issues[position].field)
                    assertEquals(issue.getInt("index"), validation.issues[position].index)
                }
                assertFalse(validation.isValid)
            } else {
                assertTrue("${entry.getString("id")} settings must validate", validation.isValid)
            }
        }
    }

    @Test
    fun prefilterMatchesTheFixtureForEveryPolicy() {
        for (index in 0 until policies.length()) {
            val entry = policies.getJSONObject(index)
            val (policy, _) = freeze(entry)
            val screens = entry.getJSONArray("prefilter")
            for (position in 0 until screens.length()) {
                val screen = screens.getJSONObject(position)
                val application = if (screen.isNull("application")) null else screen.getString("application")
                val got = policy.prefilter(screen.getInt("port"), application)
                assertEquals(
                    "${entry.getString("id")} prefilter(${screen.getInt("port")}, $application)",
                    screen.getString("expect"),
                    got.wireName
                )
            }
        }
    }

    @Test
    fun unusableSettingsFreezeToADisabledPolicy() {
        val settings = TlsCaptureSettings(
            enabled = true,
            includeHosts = listOf("*.example.test"),
            bypassHosts = listOf("private-host:443")
        )
        val policy = TlsRoutingPolicy.freeze(settings, listOf("com.example.fixture.app"))
        assertFalse(policy.enabled)
        assertTrue(policy.include.isEmpty())
        assertTrue(policy.bypass.isEmpty())
        assertEquals(TlsRoutingPrefilter.Disabled, policy.prefilter(443, "com.example.fixture.app"))
        // Dropping only the rejected bypass rule would have left interception on.
        val kept = TlsRoutingPolicy.freeze(
            TlsCaptureSettings(enabled = true, includeHosts = listOf("*.example.test")),
            emptyList()
        )
        assertTrue(kept.enabled)
        assertEquals(1, kept.include.size)

        val unknownScope = TlsRoutingPolicy.freeze(
            TlsCaptureSettings(enabled = true, candidatePorts = emptySet()),
            emptyList()
        )
        assertTrue(unknownScope.enabled)
        assertTrue("an empty candidate port set stays empty", unknownScope.candidatePorts.isEmpty())
        assertEquals(TlsRoutingPrefilter.PortNotCandidate, unknownScope.prefilter(443, null))
    }

    @Test
    fun anApplicationScopeWithoutAnAllowlistNeverBecomesAllApplications() {
        val settings = TlsCaptureSettings(
            enabled = true,
            hostScope = TlsHostScope.SelectedApplicationsCandidates
        )
        listOf(emptyList(), listOf("", "  ")).forEach { allowlist ->
            val policy = TlsRoutingPolicy.freeze(settings, allowlist)
            assertFalse("an empty allowlist must not freeze an enabled policy", policy.enabled)
            assertTrue(policy.applications.isEmpty())
            assertEquals(TlsRoutingPrefilter.Disabled, policy.prefilter(443, "com.example.fixture.app"))
        }
    }

    @Test
    fun freezeKeepsTheCanonicalRulesAndDropsNothingElse() {
        val policy = TlsRoutingPolicy.freeze(
            TlsCaptureSettings(
                enabled = true,
                candidatePorts = setOf(8443, 443),
                includeHosts = listOf("Example.TEST.", "example.test", "*.EXAMPLE.test", "192.0.2.1"),
                bypassHosts = listOf("BÜCHER.example")
            ),
            listOf("com.example.fixture.app", " ", "com.example.fixture.app")
        )
        val frozen = JSONObject(policy.encode())
        assertEquals(listOf(443, 8443), frozen.getJSONArray("candidatePorts").toIntList())
        assertEquals(
            listOf("example.test", "*.example.test", "192.0.2.1"),
            frozen.getJSONArray("include").toRuleTexts()
        )
        assertEquals(listOf("xn--bcher-kva.example"), frozen.getJSONArray("bypass").toRuleTexts())
        assertEquals(listOf("com.example.fixture.app"), frozen.getJSONArray("applications").toStringList())
        assertEquals(listOf(TlsHostRule.Subdomains("example.test")), policy.include.filterIsInstance<TlsHostRule.Subdomains>())
    }

    @Test
    fun prefilterScreensPortBeforeApplicationAndNeverWidens() {
        val policy = TlsRoutingPolicy.freeze(
            TlsCaptureSettings(
                enabled = true,
                candidatePorts = setOf(443, 8443),
                hostScope = TlsHostScope.SelectedApplicationsCandidates
            ),
            listOf("com.example.fixture.app", "com.example.fixture.other")
        )
        assertEquals(TlsRoutingPrefilter.Candidate, policy.prefilter(443, "com.example.fixture.app"))
        assertEquals(TlsRoutingPrefilter.Candidate, policy.prefilter(8443, "com.example.fixture.other"))
        listOf(null, "", " ", "10142", "com.example.fixture", "com.example.fixture.app.extra").forEach { application ->
            assertEquals(
                "application $application",
                TlsRoutingPrefilter.ApplicationNotSelected,
                policy.prefilter(443, application)
            )
        }
        assertEquals(TlsRoutingPrefilter.PortNotCandidate, policy.prefilter(80, "com.example.fixture.app"))

        val explicit = TlsRoutingPolicy.freeze(
            TlsCaptureSettings(enabled = true, includeHosts = listOf("example.test")),
            listOf("com.example.fixture.app")
        )
        // The explicit scope has no application requirement, so an unattributed
        // connection is still a candidate and the name decides later.
        assertEquals(TlsRoutingPrefilter.Candidate, explicit.prefilter(443, null))
        assertEquals(TlsRoutingPrefilter.Candidate, explicit.prefilter(443, ""))
        assertEquals(TlsRoutingPrefilter.Disabled, TlsRoutingPolicy.freeze(TlsCaptureSettings(), emptyList()).prefilter(443, null))
    }

    @Test
    fun aFrozenPolicyIsImmutableAndEqualByValue() {
        val settings = TlsCaptureSettings(enabled = true, includeHosts = listOf("example.test"))
        val first = TlsRoutingPolicy.freeze(settings)
        val second = TlsRoutingPolicy.freeze(settings)
        assertEquals(first, second)
        assertEquals(first.encode(), second.encode())
        assertNotEquals(first, TlsRoutingPolicy.freeze(TlsCaptureSettings(enabled = true, includeHosts = listOf("other.test"))))
        val rules = first.include.toMutableList()
        rules.clear()
        assertEquals("the policy's own rule list is untouched", 1, first.include.size)
    }

    @Test
    fun wireNamesAreFixedStringsNotOrdinals() {
        assertEquals(
            listOf("candidate", "disabled", "port_not_candidate", "application_not_selected"),
            TlsRoutingPrefilter.entries.map { it.wireName }
        )
        assertEquals("exactDomain", TlsHostRule.ExactDomain("example.test").wireKind)
        assertEquals("subdomains", TlsHostRule.Subdomains("example.test").wireKind)
        assertEquals("exactIp", TlsHostRule.ExactIp("192.0.2.1").wireKind)
        assertEquals("example.test", TlsHostRule.Subdomains("example.test").frozenValue)
        assertEquals("*.example.test", TlsHostRule.Subdomains("example.test").canonicalText)
        assertEquals(1, TlsRoutingPolicy.FROZEN_SCHEMA_VERSION)
        // The rejected rule is reported by code and position only: no part of the
        // user's text is echoed back.
        val rejected = TlsCaptureSettingsJson.decode("""{"enabled":true,"bypassHosts":["host:443"]}""")
        assertEquals(TlsSettingsIssueCode.INVALID_HOST_RULE, rejected.issues.single().code)
        assertFalse(rejected.toString().contains("host:443"))
    }

    private fun freeze(entry: JSONObject): Pair<TlsRoutingPolicy, TlsSettingsValidation> {
        val allowed = entry.getJSONArray("allowedApplications").toStringList()
        val validation = TlsCaptureSettingsJson.decode(entry.getJSONObject("settings").toString(), allowed)
        return TlsRoutingPolicy.freeze(validation.settings, allowed) to validation
    }

    private fun JSONArray.toStringList(): List<String> = (0 until length()).map { getString(it) }

    private fun JSONArray.toIntList(): List<Int> = (0 until length()).map { getInt(it) }

    private fun JSONArray.toRuleTexts(): List<String> = (0 until length()).map { position ->
        val rule = getJSONObject(position)
        val value = rule.getString("value")
        if (rule.getString("kind") == "subdomains") "*.$value" else value
    }

    private fun readFixture(): JSONObject {
        // The unit test's working directory is the app module, but a fixture
        // shared with the Go module lives above it, so search upwards rather
        // than guessing one relative path. A missing fixture is a failure: it is
        // the only thing that checks the two languages still agree.
        val relative = "native_build/verification/tls/routing-policy/policy-cases.json"
        var directory: File? = File(".").absoluteFile
        while (directory != null) {
            val candidate = File(directory, relative)
            if (candidate.isFile) return JSONObject(candidate.readText())
            directory = directory.parentFile
        }
        error("shared routing policy fixture not found: $relative")
    }
}
