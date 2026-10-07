// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * OPT-QNT-01 pins for the quarantine visibility channel: the event payload is
 * the stable reason code and nothing else, an event published during app
 * assembly — before any ViewModel subscribes — survives in the buffer instead
 * of being lost, the buffer never blocks or throws on the store's IO path, and
 * the consumer-side dedupe keeps one quarantine to one notice.
 *
 * The channel is pure Kotlin, so these run as plain JVM tests.  The Android
 * log line the assembly sink writes next to the publish stays the store's
 * default behavior; tests keep injecting the channel sink directly, exactly
 * like the quarantine tests in [UserScenarioPlaybookStoreTest] do, because
 * JVM tests cannot touch `android.util.Log`.
 */
class ScenarioQuarantineEventChannelTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun quarantineEventDeclaresNoPayloadBeyondTheReasonCode() {
        // Structural pin on "无文件名、无剧本内容": the type that crosses the
        // data-layer → UI boundary has exactly one field, the code.  The
        // Compose compiler tags classes in this module with a synthetic
        // `$stable` int; anything compiler-generated is ignored.
        val fields = ScenarioQuarantineEvent::class.java.declaredFields
            .filterNot { it.isSynthetic || it.name.startsWith("\$") }
            .map { it.name to it.type.name }
        assertEquals(listOf("reasonCode" to "java.lang.String"), fields)
    }

    @Test
    fun aQuarantinedFilePublishesOnlyTheStableReasonCodeThroughTheChannel() = runBlocking {
        // End-to-end through the real store sink wiring: a corrupt file whose
        // bytes carry a sentinel must not leak into the event the UI consumes.
        val directory = scenarioDirectory()
        directory.mkdirs()
        storedFile().writeText("{ not json SENTINEL-USER-SCENARIO-CONTENT")
        val events = ScenarioQuarantineEventChannel()
        val store = UserScenarioPlaybookStore(
            directory = directory,
            availableTools = TestScenarioPackages.availableTools,
            onQuarantine = { reason -> events.publish(ScenarioQuarantineEvent(reason)) }
        )

        assertTrue(store.load().isEmpty())

        val event = events.events.first()
        assertEquals(
            ScenarioQuarantineEvent(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED),
            event
        )
        val surfaced = event.toString() + event.reasonCode
        assertFalse(surfaced.contains("SENTINEL"))
        assertFalse(surfaced.contains(UserScenarioStore.FILE_NAME))
    }

    @Test
    fun eventsPublishedBeforeAnyCollectorAreBuffered() = runBlocking {
        // The load() during app assembly quarantines before the ViewModel
        // exists; a replay-less hot flow would drop exactly this first event.
        val events = ScenarioQuarantineEventChannel()
        assertTrue(events.publish(ScenarioQuarantineEvent(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED)))

        assertEquals(
            listOf(ScenarioQuarantineEvent(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED)),
            events.events.take(1).toList()
        )
    }

    @Test
    fun aConsumedEventIsNotReplayedToALaterCollector() = runBlocking {
        val events = ScenarioQuarantineEventChannel()
        events.publish(ScenarioQuarantineEvent(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED))
        events.events.first()

        // Once announced, the notice is spent: a recreated consumer must not
        // prompt for the same quarantine again.
        assertNull(withTimeoutOrNull(BUFFER_POLL_MILLIS) { events.events.first() })
    }

    @Test
    fun publishingBeyondCapacityDropsTheOldestWithoutThrowing() = runBlocking {
        val events = ScenarioQuarantineEventChannel(capacity = 2)
        repeat(5) { index ->
            assertTrue(events.publish(ScenarioQuarantineEvent("code-$index")))
        }

        assertEquals(
            listOf("code-3", "code-4"),
            events.events.take(2).toList().map { it.reasonCode }
        )
    }

    @Test
    fun quarantineCodesAreDeduplicatedByReasonCode() {
        val first = nextQuarantineCodes(
            emptyList(),
            ScenarioQuarantineEvent(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED)
        )
        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), first)

        // One quarantine, one notice: a repeat of the same code changes
        // nothing — not even the list instance the UI observes.
        val repeated = nextQuarantineCodes(
            first,
            ScenarioQuarantineEvent(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED)
        )
        assertSame(first, repeated)

        val distinct = nextQuarantineCodes(repeated, ScenarioQuarantineEvent("user_scenario_other"))
        assertEquals(
            listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED, "user_scenario_other"),
            distinct
        )
    }

    private fun scenarioDirectory(): File = File(temporaryFolder.root, UserScenarioStore.DIRECTORY_NAME)

    private fun storedFile(): File = File(scenarioDirectory(), UserScenarioStore.FILE_NAME)

    private companion object {
        const val BUFFER_POLL_MILLIS = 50L
    }
}
