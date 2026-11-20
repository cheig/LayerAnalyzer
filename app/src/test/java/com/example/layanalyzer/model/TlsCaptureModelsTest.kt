// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsCaptureModelsTest {
    @Test
    fun legacyCaptureAndAbsentTlsSettingsDefaultToDisabled() {
        val legacy = TlsCaptureSettingsJson.decodeCaptureSettings("""{"captureIpv6":true}""")
        assertTrue(legacy.isValid)
        assertEquals(TlsCaptureSettings(), legacy.settings)
        assertEquals(TlsCaptureSettings(), TlsCaptureSettingsJson.decode(null).settings)
        assertEquals(TlsCaptureSettings(), TlsCaptureSettingsJson.decode("{}").settings)
        assertFalse(TlsCaptureSettingsJson.decodeCaptureSettings("""{"tls":null}""").isValid)
    }

    @Test
    fun emptyExplicitIncludeAndEmptyCandidatePortsNeverBecomeAllCandidates() {
        val result = TlsCaptureSettingsJson.decode("""{"enabled":true,"includeHosts":[],"candidatePorts":[]}""")
        assertTrue(result.isValid)
        assertTrue(result.settings.enabled)
        assertTrue(result.settings.includeHosts.isEmpty())
        assertTrue(result.settings.candidatePorts.isEmpty())
        assertEquals(TlsHostScope.ExplicitHosts, result.settings.hostScope)
        assertEquals(QuicPolicy.Preserve, result.settings.quicPolicy)
    }

    @Test
    fun selectedApplicationScopeRequiresNonblankVpnPackageAllowlistEvenWhenDisabled() {
        val settings = TlsCaptureSettings(hostScope = TlsHostScope.SelectedApplicationsCandidates)
        listOf(emptyList(), listOf("", "  ")).forEach { packages ->
            val result = TlsCaptureSettingsValidator.validate(settings, packages)
            assertEquals(TlsSettingsIssueCode.APPLICATION_SCOPE_REQUIRED, result.issues.single().code)
            assertEquals(TlsCaptureSettings(), result.settings)
        }
        assertTrue(TlsCaptureSettingsValidator.validate(settings, listOf("com.example.fixture")).isValid)
        val json = """{"tls":{"enabled":true,"hostScope":"SelectedApplicationsCandidates"}}"""
        assertFalse(TlsCaptureSettingsJson.decodeCaptureSettings(json).isValid)
        assertTrue(TlsCaptureSettingsJson.decodeCaptureSettings(json, listOf("com.example.fixture")).settings.enabled)
    }

    @Test
    fun unknownEnumsDisableTheEntireConfigurationWithDisplayableReasons() {
        listOf("hostScope", "quicPolicy").forEach { field ->
            val input = JSONObject().put("enabled", true).put(field, "future-sensitive-value").toString()
            val result = TlsCaptureSettingsJson.decode(input, listOf("com.example.fixture"))
            assertEquals(TlsCaptureSettings(), result.settings)
            assertEquals(TlsSettingsIssueCode.UNKNOWN_ENUM, result.issues.single().code)
            assertTrue(result.issues.single().displayReason.isNotBlank())
            assertFalse(result.toString().contains("future-sensitive-value"))
        }
        assertNull(TlsHostScope.fromWire("1"))
        assertNull(QuicPolicy.fromWire("preserve"))
    }

    @Test
    fun corruptJsonAndWrongTypesDoNotCoerceToAnEnabledSetting() {
        val invalid = listOf(
            "", "not json", "[]", "{", """{"enabled":true}trailing""", """{"enabled":true}{}""",
            """{"enabled":"true"}""", """{"enabled":1}""",
            """{"enabled":true,"retainSecrets":null}""", """{"enabled":true,"hostScope":0}""",
            """{"enabled":true,"candidatePorts":["443"]}""", """{"enabled":true,"candidatePorts":[443.5]}""",
            """{"enabled":true,"candidatePorts":[4294967297]}""", """{"enabled":true,"candidatePorts":null}""",
            """{"enabled":true,"includeHosts":"example.test"}""", """{"enabled":true,"bypassHosts":[null]}""",
            """{"enabled":true,"schemaVersion":2}""", """{"enabled":true,"schemaVersion":"1"}"""
        )
        invalid.forEach { input ->
            val result = TlsCaptureSettingsJson.decode(input)
            assertFalse(input, result.isValid)
            assertEquals(input, TlsCaptureSettings(), result.settings)
        }
    }

    @Test
    fun portBoundariesAreValidatedWithoutDiscardingInvalidEntries() {
        assertTrue(TlsCaptureSettingsValidator.validate(TlsCaptureSettings(candidatePorts = setOf(1, 443, 65535))).isValid)
        listOf(-1, 0, 65536, Int.MAX_VALUE).forEach { invalid ->
            val result = TlsCaptureSettingsValidator.validate(TlsCaptureSettings(enabled = true, candidatePorts = setOf(443, invalid)))
            assertFalse(result.settings.enabled)
            assertEquals(TlsSettingsIssueCode.INVALID_PORT, result.issues.single().code)
        }
    }

    @Test
    fun settingsRoundTripUsesExplicitWireStringsAndKeepsAllOptions() {
        val settings = TlsCaptureSettings(
            enabled = true,
            candidatePorts = setOf(8443, 443),
            hostScope = TlsHostScope.SelectedApplicationsCandidates,
            includeHosts = listOf("example.test", "*.example.test", "192.0.2.1"),
            bypassHosts = listOf("bypass.example.test"),
            quicPolicy = QuicPolicy.Preserve,
            retainSecrets = false
        )
        val encoded = TlsCaptureSettingsJson.encode(settings)
        val json = JSONObject(encoded)
        assertEquals("SelectedApplicationsCandidates", json.getString("hostScope"))
        assertEquals("Preserve", json.getString("quicPolicy"))
        assertEquals(1, json.getInt("schemaVersion"))
        val decoded = TlsCaptureSettingsJson.decode(encoded, listOf("com.example.fixture"))
        assertTrue(decoded.isValid)
        assertEquals(settings, decoded.settings)

        // The blocking policy has its own wire string, and its own scope: TLS-314
        // refuses it for a partial scope (a bypass rule here), so the round trip
        // that keeps it is the selected-applications scope with no bypass.
        val blocking = settings.copy(bypassHosts = emptyList(), quicPolicy = QuicPolicy.BlockSelectedUdp443)
        val blockingEncoded = TlsCaptureSettingsJson.encode(blocking)
        assertEquals("BlockSelectedUdp443", JSONObject(blockingEncoded).getString("quicPolicy"))
        val decodedBlocking = TlsCaptureSettingsJson.decode(blockingEncoded, listOf("com.example.fixture"))
        assertTrue(decodedBlocking.isValid)
        assertEquals(blocking, decodedBlocking.settings)
    }

    @Test
    fun domainsNormalizeIdnaCaseAndOneTrailingDotAndKeepRuleKindsDistinct() {
        assertEquals(TlsHostRule.ExactDomain("xn--bcher-kva.example"), TlsHostRule.parse("BÜCHER.Example."))
        assertEquals(TlsHostRule.Subdomains("example.test"), TlsHostRule.parse("*.Example.TEST."))
        assertEquals(TlsHostRule.ExactDomain("example.test"), TlsHostRule.parse("example.test"))
        assertEquals(TlsHostRule.ExactDomain("badexample.test"), TlsHostRule.parse("badexample.test"))
        val result = TlsCaptureSettingsValidator.validate(
            TlsCaptureSettings(includeHosts = listOf("Example.TEST.", "example.test", "*.EXAMPLE.test"))
        )
        assertTrue(result.isValid)
        assertEquals(listOf("example.test", "*.example.test"), result.settings.includeHosts)
    }

    @Test
    fun exactIpsAreSeparateFromDomainRulesWithoutResolution() {
        assertEquals(TlsHostRule.ExactIp("192.0.2.1"), TlsHostRule.parse("192.0.2.1"))
        assertEquals(TlsHostRule.ExactIp("2001:db8:0:0:0:0:0:1"), TlsHostRule.parse("2001:0DB8::1"))
        assertEquals(TlsHostRule.parse("2001:db8::1"), TlsHostRule.parse("2001:db8:0:0:0:0:0:1"))
        assertEquals(TlsHostRule.ExactIp("0:0:0:0:0:0:0:1"), TlsHostRule.parse("::1"))
        assertEquals(TlsHostRule.ExactIp("0:0:0:0:0:ffff:c000:201"), TlsHostRule.parse("::ffff:192.0.2.1"))
        assertEquals(TlsHostRule.ExactIp("0:0:0:0:0:0:0:0"), TlsHostRule.parse("::"))
    }

    @Test
    fun malformedDomainsIpWildcardsPortsAndRegexInputsAreRejected() {
        listOf(
            "", ".", "example..test", "example.test..", " example.test", "example.test ", "example\n.test",
            "example\u0000.test", "example.test:443", "https://example.test", "example/test", "example\\test",
            "x@example.test", "example.test?x", "example.test#x", "[2001:db8::1]:443", "[::1]", "fe80::1%wlan0",
            "*", "example.*", "*example.test", "*.*.example.test", "^example.test$", "(example).test",
            "*.192.0.2.1", "*.2001:db8::1", "256.0.2.1", "192.00.2.1", "192.0.2", "192.0.2.1.",
            "1:2:3", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8::", "1::2::3", ":::1", ":1:2:3:4:5:6:7",
            "::gggg", "::12345", "::ffff:192.0.2.999", "_invalid.test", "-invalid.test", "invalid-.test",
            "a".repeat(64) + ".test", List(5) { "a".repeat(63) }.joinToString(".")
        ).forEach { assertNull(it, TlsHostRule.parse(it)) }
    }

    @Test
    fun invalidBypassDisablesEverythingAndOnlyReportsFieldAndIndex() {
        val result = TlsCaptureSettingsValidator.validate(
            TlsCaptureSettings(enabled = true, includeHosts = listOf("*.example.test"), bypassHosts = listOf("private-host:443"))
        )
        assertEquals(TlsCaptureSettings(), result.settings)
        assertEquals(TlsSettingsIssue(TlsSettingsIssueCode.INVALID_HOST_RULE, "bypassHosts", 0), result.issues.single())
        assertFalse(result.toString().contains("private-host"))
    }

    @Test
    fun unknownErrorsPhasesAndStatusesRemainUnknownInsteadOfSuccess() {
        assertEquals(TlsErrorCode.UNKNOWN, TlsErrorCode.fromWire("FUTURE_ERROR"))
        assertEquals(TlsErrorCode.UNKNOWN, TlsErrorCode.fromWire(null))
        assertEquals(TlsConnectionPhase.UNKNOWN, TlsConnectionPhase.fromWire("FUTURE_PHASE"))
        assertEquals(TlsCaptureStatus.UNKNOWN, TlsCaptureStatus.fromWire("FUTURE_STATUS"))
        TlsErrorCode.entries.forEach { assertEquals(it, TlsErrorCode.fromWire(it.wireName)) }
        assertTrue(TlsConnectionPhase.CLOSED.isTerminal)
        assertTrue(TlsConnectionPhase.FAILED.isTerminal)
        assertFalse(TlsConnectionPhase.PASSTHROUGH.isTerminal)
        assertFalse(TlsConnectionPhase.UNKNOWN.isTerminal)
        assertNotNull(TlsError(TlsErrorCode.DOWNSTREAM_TLS_REJECTED))
    }

    @Test
    fun initialCountsAndEventHaveNoImpliedProxyPersistenceOrDecryptionSuccess() {
        val stats = TlsCaptureStats()
        assertEquals(TlsCaptureStatus.DISABLED, stats.status)
        assertEquals(List(9) { 0L }, listOf(
            stats.acceptedConnections, stats.proxiedConnections, stats.secretsSavedConnections,
            stats.decryptedConnections, stats.passthroughConnections, stats.failedConnections,
            stats.quicUndecryptedConnections, stats.secretRecordsAccepted, stats.secretRecordsPersisted
        ))
        val acceptedOnly = stats.copy(acceptedConnections = 1, secretRecordsAccepted = 2)
        assertEquals(0L, acceptedOnly.proxiedConnections)
        assertEquals(0L, acceptedOnly.secretsSavedConnections)
        assertEquals(0L, acceptedOnly.decryptedConnections)
        assertEquals(0L, acceptedOnly.secretRecordsPersisted)
        val event = TlsConnectionEvent("capture-a", "connection-b", 7, 100, 200, "192.0.2.1", 443, 3)
        assertEquals("capture-a", event.captureId)
        assertEquals("connection-b", event.connectionId)
        assertEquals(3L, event.networkGeneration)
        assertEquals(TlsConnectionPhase.ACCEPTED, event.phase)
        assertFalse(event.secretsComplete)
        assertEquals(0L, event.secretRecordsAccepted)
        assertEquals(0L, event.secretRecordsPersisted)
        assertNull(event.downstreamTls)
        assertNull(event.upstreamTls)
        val analysis = TlsAnalysisGeneration("capture-a", secretsGeneration = 4, dissectionGeneration = 9)
        assertEquals(4L, analysis.secretsGeneration)
        assertEquals(9L, analysis.dissectionGeneration)
    }
}
