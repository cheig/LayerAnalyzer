// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import com.example.layanalyzer.model.LiveCaptureSettings
import com.example.layanalyzer.model.QuicPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsHostScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * TLS-304: the capture settings document, its migration contract and the freeze
 * at capture start. No `Context`, no Keystore and no filesystem: persistence is
 * behind [CaptureSettingsPersistence] precisely so this runs on the JVM.
 */
class TlsSettingsPersistenceTest {

    private class InMemoryPersistence(private var value: String? = null) : CaptureSettingsPersistence {
        var writes = 0
        override fun read(): String? = value
        override fun write(json: String) {
            value = json
            writes += 1
        }
    }

    @Test
    fun aLegacyDocumentWithoutATlsBlockLoadsWithTlsOff() {
        val legacy = """{"schemaVersion":1,"excludeSelf":false,"captureIpv6":true,"maxDurationMinutes":30,""" +
            """"maxSizeMegabytes":512,"segmentSizeMegabytes":128,"allowedApplications":["com.example.fixture"]}"""
        val loaded = LiveCaptureSettingsStore(InMemoryPersistence(legacy)).load()

        // Old keys survive; the absent TLS block is off, never "intercept everything" (C04).
        assertFalse(loaded.excludeSelf)
        assertTrue(loaded.captureIpv6)
        assertEquals(30, loaded.maxDurationMinutes)
        assertEquals(listOf("com.example.fixture"), loaded.allowedApplications)
        assertEquals(TlsCaptureSettings(), loaded.tls)
        assertFalse(loaded.tls.enabled)
    }

    @Test
    fun anUnknownEnumOrAnOutOfRangePortInTheTlsBlockMigratesToTlsOff() {
        val unknownEnum = """{"allowedApplications":[],"tls":{"enabled":true,"hostScope":"Future"}}"""
        assertEquals(TlsCaptureSettings(), LiveCaptureSettingsStore(InMemoryPersistence(unknownEnum)).load().tls)

        val badPort = """{"allowedApplications":[],"tls":{"enabled":true,"candidatePorts":[70000]}}"""
        assertEquals(TlsCaptureSettings(), LiveCaptureSettingsStore(InMemoryPersistence(badPort)).load().tls)

        val badRule = """{"allowedApplications":[],"tls":{"enabled":true,"includeHosts":["http://example.test"]}}"""
        assertEquals(TlsCaptureSettings(), LiveCaptureSettingsStore(InMemoryPersistence(badRule)).load().tls)
    }

    @Test
    fun anUnreadableDocumentFallsBackToTheCompileTimeDefaults() {
        val store = LiveCaptureSettingsStore(InMemoryPersistence("{not json"))
        assertEquals(LiveCaptureSettings(), store.load())
        assertEquals(LiveCaptureSettings(), LiveCaptureSettingsStore(InMemoryPersistence(null)).load())
    }

    @Test
    fun saveThenLoadRoundTripsEveryFieldIncludingTheNestedTlsBlock() {
        val persistence = InMemoryPersistence()
        val store = LiveCaptureSettingsStore(persistence)
        val settings = LiveCaptureSettings(
            excludeSelf = false,
            captureIpv6 = true,
            maxDurationMinutes = 30,
            maxSizeMegabytes = 512,
            segmentSizeMegabytes = 128,
            allowedApplications = listOf("com.example.fixture"),
            tls = TlsCaptureSettings(
                enabled = true,
                candidatePorts = setOf(443, 8443),
                hostScope = TlsHostScope.ExplicitHosts,
                includeHosts = listOf("example.test"),
                bypassHosts = listOf("*.bypass.test"),
                quicPolicy = QuicPolicy.Preserve,
                retainSecrets = false
            )
        )
        store.save(settings)

        assertEquals(settings, store.load())
        // The document carries the TLS block, and never key material.
        val document = persistence.read().orEmpty()
        assertTrue(document.contains("\"tls\""))
        assertFalse(document.contains("PRIVATE KEY"))
        assertFalse(document.contains("CLIENT_RANDOM"))
    }

    @Test
    fun anEnabledInterceptionWithABadPortOrAnEmptyApplicationScopeCannotStart() {
        val badPort = LiveCaptureSettings(
            tls = TlsCaptureSettings(enabled = true, candidatePorts = setOf(0))
        )
        assertFalse(TlsInterceptionPolicy.canStart(badPort))
        assertNull(TlsInterceptionPolicy.frozenForCapture(badPort))

        val emptyAppScope = LiveCaptureSettings(
            allowedApplications = emptyList(),
            tls = TlsCaptureSettings(enabled = true, hostScope = TlsHostScope.SelectedApplicationsCandidates)
        )
        assertFalse(TlsInterceptionPolicy.canStart(emptyAppScope))
        assertNull(TlsInterceptionPolicy.frozenForCapture(emptyAppScope))
        assertEquals(listOf("INVALID_PORT"), TlsInterceptionPolicy.blockedReasonCodes(badPort))
    }

    @Test
    fun tlsOffAlwaysStartsAndAnEmptyExplicitIncludeStaysEmpty() {
        // No interception: nothing to validate, the capture runs as before.
        val off = LiveCaptureSettings(tls = TlsCaptureSettings(enabled = false))
        assertTrue(TlsInterceptionPolicy.canStart(off))
        assertEquals(off, TlsInterceptionPolicy.frozenForCapture(off))

        // An explicit scope with an empty include is valid but decrypts no domain; it
        // is never widened to "all candidates" (C04).
        val emptyInclude = LiveCaptureSettings(
            tls = TlsCaptureSettings(enabled = true, includeHosts = emptyList())
        )
        assertTrue(TlsInterceptionPolicy.canStart(emptyInclude))
        val frozen = TlsInterceptionPolicy.frozenForCapture(emptyInclude)
        assertTrue(frozen!!.tls.includeHosts.isEmpty())
        assertEquals(setOf(443), frozen.tls.candidatePorts)
    }

    @Test
    fun theFrozenConfigurationIsNormalized() {
        val settings = LiveCaptureSettings(
            tls = TlsCaptureSettings(
                enabled = true,
                candidatePorts = setOf(443, 443),
                includeHosts = listOf("Example.Test", "example.test.", "*.Foo.test")
            )
        )
        val frozen = TlsInterceptionPolicy.frozenForCapture(settings)!!

        // Rules are canonicalized and de-duplicated by the single C04 validator.
        assertEquals(listOf("example.test", "*.foo.test"), frozen.tls.includeHosts)
        assertEquals(setOf(443), frozen.tls.candidatePorts)
    }

    @Test
    fun aCancelledEditNeverChangesThePersistedSettings() {
        val persistence = InMemoryPersistence()
        val store = LiveCaptureSettingsStore(persistence)
        val saved = LiveCaptureSettings(
            allowedApplications = listOf("com.example.fixture"),
            tls = TlsCaptureSettings(enabled = false)
        )
        store.save(saved)
        val writesAfterSave = persistence.writes

        // The screen edits a draft; backing out saves nothing (design §10.1).
        val draft = store.load().copy(
            tls = TlsCaptureSettings(enabled = true, includeHosts = listOf("example.test"))
        )
        assertTrue(draft.tls.enabled)
        assertEquals(saved, store.load())
        assertEquals(writesAfterSave, persistence.writes)
    }

    @Test
    fun committingTheFrozenDraftPersistsExactlyWhatTheRunUses() {
        val store = LiveCaptureSettingsStore(InMemoryPersistence())
        val draft = LiveCaptureSettings(
            allowedApplications = listOf("com.example.fixture"),
            tls = TlsCaptureSettings(enabled = true, includeHosts = listOf("Example.Test"))
        )
        val frozen = TlsInterceptionPolicy.frozenForCapture(draft)!!
        store.save(frozen)

        // Freezing is the commit: what is stored is exactly what the capture runs.
        assertEquals(frozen, store.load())
        assertEquals(listOf("example.test"), store.load().tls.includeHosts)
    }
}
