// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.RadioEvent
import com.example.layanalyzer.model.RadioEventType
import com.example.layanalyzer.model.RadioQueryResult
import com.example.layanalyzer.model.RadioSourceCapability
import com.example.layanalyzer.model.RadioSeverity
import com.example.layanalyzer.model.SipMessage
import com.example.layanalyzer.model.TemporalCorrelationConfidence
import com.example.layanalyzer.model.UnifiedTimelineClock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UnifiedNetworkTimelineBuilderTest {
    @Test
    fun manualClockOffsetAlignsRadioWithSipInEpochSeconds() {
        val timeline = UnifiedNetworkTimelineBuilder.build(
            radio = radioResult(
                RadioEvent(
                    type = RadioEventType.RatChange,
                    startTime = 100.0,
                    source = "radio-log",
                    manualOffsetMillis = 1_000L
                )
            ),
            communication = CommunicationAnalysis(
                sipMessages = listOf(
                    SipMessage(frameNumber = 20, time = 101.0, source = "10.0.0.1", destination = "10.0.0.2", method = "INVITE")
                )
            )
        )

        val radio = timeline.events.first { it.track.wireName == "radio" }
        assertEquals(101.0, radio.startTime, 0.0001)
        assertEquals(1_000L, timeline.clocks.first { it.source == "radio-log" }.manualOffsetMillis)
        assertTrue(timeline.temporalCorrelations.any { it.confidence == TemporalCorrelationConfidence.Candidate })
        assertTrue(timeline.temporalCorrelations.none { it.causal })
    }

    @Test
    fun bothSourceUncertaintiesExpandCandidateAssociationWindow() {
        val timeline = UnifiedNetworkTimelineBuilder.build(
            radio = radioResult(
                RadioEvent(
                    type = RadioEventType.SignalDrop,
                    startTime = 1.0,
                    timeUncertaintyMillis = 1_000L,
                    source = "radio"
                )
            ),
            communication = CommunicationAnalysis(
                sipMessages = listOf(
                    SipMessage(frameNumber = 2, time = 2.1, source = "10.0.0.1", destination = "10.0.0.2", method = "BYE")
                )
            ),
            clocks = listOf(UnifiedTimelineClock(source = "capture.sip", uncertaintyMillis = 1_000L))
        )

        val correlation = timeline.temporalCorrelations.first()
        assertEquals(2_250L, correlation.windowMillis)
        assertFalse(correlation.causal)
        assertEquals("timestamp_plus_both_source_uncertainties", correlation.basis)
    }

    @Test
    fun missingRadioDataIsVisibleAndDoesNotBecomeWirelessHealthClaim() {
        val result = RadioQueryResult(
            sourceCapabilities = listOf(
                RadioSourceCapability(
                    source = "radio",
                    available = false,
                    supportsSnapshots = false,
                    supportsEvents = false,
                    unavailableReason = "No supported Radio data is available."
                )
            ),
            unavailableReason = "No supported Radio data is available."
        )
        val timeline = UnifiedNetworkTimelineBuilder.build(result)
        assertFalse(timeline.radioAvailable)
        assertTrue(timeline.unavailableReason?.contains("Radio") == true)
        assertTrue(timeline.limitations.any { it.contains("wireless", ignoreCase = true) })
    }

    private fun radioResult(event: RadioEvent) = RadioQueryResult(
        events = listOf(event),
        returned = 1,
        total = 1,
        sourceCapabilities = listOf(
            RadioSourceCapability(
                source = event.source,
                available = true,
                supportsSnapshots = false,
                supportsEvents = true
            )
        ),
        dataAvailable = true
    )
}
