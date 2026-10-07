// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data.radio

import com.example.layanalyzer.model.RadioEvent
import com.example.layanalyzer.model.RadioEventType
import com.example.layanalyzer.model.RadioSeverity
import com.example.layanalyzer.model.RadioSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RadioRepositoryTest {
    @Test
    fun importsEpochEventsAndAliasesCellIdentifiers() {
        val repository = RadioRepository()
        val result = repository.importEvents(
            """
            {
              "schemaVersion": 1,
              "timeBase": "epoch_seconds",
              "timezone": "UTC",
              "source": "user-radio-log",
              "events": [{
                "type": "RAT_CHANGE",
                "startTime": 100.0,
                "endTime": 100.5,
                "severity": "WARNING",
                "rat": "LTE",
                "cellId": "operator-cell-1",
                "sourceFrames": [12],
                "timeUncertaintyMillis": 120
              }]
            }
            """.trimIndent()
        )

        assertTrue(result.isSuccess)
        val query = repository.queryEvents(
            startTime = 99.0,
            endTime = 101.0,
            types = setOf(RadioEventType.RatChange),
            minimumSeverity = RadioSeverity.Info,
            limit = 100
        )
        assertEquals(1, query.returned)
        assertTrue(query.events.single().cellIdAlias?.startsWith("cell-") == true)
        assertFalse(query.events.single().observations.values.any { it.contains("operator-cell-1") })
    }

    @Test
    fun snapshotImportDerivesTransitionsAndPublishesSnapshots() {
        val repository = RadioRepository()
        assertTrue(
            repository.importEvents(
                """
                {
                  "schemaVersion": 1,
                  "timeBase": "epoch_seconds",
                  "timezone": "UTC",
                  "source": "telephony-test",
                  "snapshots": [
                    {"timestamp": 1.0, "rat": "NR", "registrationState": "in_service", "dataState": "connected", "signalMetrics": {"rsrpDbm": -80}},
                    {"timestamp": 2.0, "rat": "LTE", "registrationState": "out_of_service", "dataState": "disconnected", "signalMetrics": {"rsrpDbm": -95}}
                  ]
                }
                """.trimIndent()
            ).isSuccess
        )

        val snapshot = repository.observeSnapshots().value
        assertEquals(2, snapshot.size)
        val events = repository.queryEvents().events
        assertTrue(events.any { it.type == RadioEventType.RatChange })
        assertTrue(events.any { it.type == RadioEventType.OutOfService })
        assertTrue(events.any { it.type == RadioEventType.SignalDrop })
        assertTrue(events.any { it.type == RadioEventType.DataDisconnected })
    }

    @Test
    fun malformedOversizedAndGeographicImportsFailWithoutData() {
        val repository = RadioRepository()
        assertTrue(repository.importEvents("not-json").isFailure)
        assertTrue(
            repository.importEvents(
                """
                {"schemaVersion":1,"timeBase":"epoch_seconds","timezone":"UTC","source":"bad","events":[],"metadata":{"latitude":35.0}}
                """.trimIndent()
            ).isFailure
        )
        assertTrue(repository.importEvents(ByteArray(2 * 1024 * 1024 + 1)).isFailure)
        assertEquals(0, repository.queryEvents().total)
        assertNotNull(repository.queryEvents().unavailableReason)
    }

    @Test
    fun unsupportedSourcesReturnExplicitUnavailableReason() {
        val result = RadioRepository().queryEvents()
        assertFalse(result.dataAvailable)
        assertTrue(result.unavailableReason?.contains("wireless", ignoreCase = true) == true)
    }

    @Test
    fun manualOffsetIsUsedWhenFilteringByEpochTime() {
        val repository = RadioRepository()
        assertTrue(
            repository.importEvents(
                events = listOf(
                    RadioEvent(
                        type = RadioEventType.RatChange,
                        startTime = 100.0,
                        source = "offset-log",
                        manualOffsetMillis = 1_000L
                    )
                )
            ).isSuccess
        )

        assertEquals(1, repository.queryEvents(startTime = 101.0, endTime = 101.0).returned)
    }

    @Test
    fun snapshotsFromDifferentSourcesAreNotComparedAsOneStateStream() {
        val repository = RadioRepository()
        assertTrue(
            repository.importEvents(
                events = emptyList(),
                snapshots = listOf(
                    RadioSnapshot(timestamp = 1.0, rat = "NR", source = "telephony"),
                    RadioSnapshot(timestamp = 2.0, rat = "LTE", source = "wireshark")
                )
            ).isSuccess
        )

        assertTrue(repository.queryEvents().events.isEmpty())
    }
}
