// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentCommunicationNarrowingTest {

    /**
     * The observed 29 KB / four-session shape: weight comes from nested depth,
     * not from list length, so collapsing the depth is what has to pay off.
     */
    @Test
    fun narrowingCollapsesNestedDepthAndShrinksThePayload() {
        val full = mapOf(
            "coreSessions" to List(4) { session ->
                mapOf(
                    "protocol" to "diameter",
                    "correlationValue" to "session-$session",
                    "messageCount" to 40,
                    "firstFrame" to (session * 10 + 1).toLong(),
                    "stages" to List(9) { stage ->
                        mapOf(
                            "stage" to "stage-$stage",
                            "startFrame" to stage.toLong(),
                            "completeness" to "complete",
                            "evidenceFrames" to listOf(stage.toLong())
                        )
                    },
                    "edges" to List(12) { mapOf("kind" to "correlation", "detail" to "x".repeat(60)) },
                    "limitations" to List(5) { "limitation $it" }
                )
            }
        )

        val narrowed = AgentCommunicationNarrowing.narrow(full)

        assertTrue(
            "narrowing must actually reduce the payload",
            AgentCommunicationNarrowing.encodedSize(narrowed) <
                AgentCommunicationNarrowing.encodedSize(full)
        )

        @Suppress("UNCHECKED_CAST")
        val sessions = narrowed["coreSessions"] as List<Map<String, Any?>>
        // The list of sessions is the answer, so it must survive whole.
        assertEquals(4, sessions.size)
        val session = sessions.first()
        // Identity and outcome stay; heavy interiors become counts.
        assertEquals("diameter", session["protocol"])
        assertEquals(40, session["messageCount"])
        assertEquals(1L, session["firstFrame"])
        assertNull(session["stages"])
        assertEquals(9, session["stagesCount"])
        assertEquals(12, session["edgesCount"])
        assertEquals(5, session["limitationsCount"])
    }

    /**
     * A count is kept rather than the key simply dropped: "9 stages I have not
     * shown you" is actionable, while an absent key reads as "no stages".
     */
    @Test
    fun collapsedCollectionsLeaveTheirSizeBehind() {
        val narrowed = AgentCommunicationNarrowing.narrow(
            mapOf("calls" to listOf(mapOf("messages" to List(7) { mapOf("method" to "INVITE") })))
        )

        @Suppress("UNCHECKED_CAST")
        val call = (narrowed["calls"] as List<Map<String, Any?>>).single()
        assertEquals(7, call["messagesCount"])
        assertNull(call["messages"])
    }

    /** An empty heavy list is simply absent rather than reported as zero. */
    @Test
    fun emptyHeavyCollectionsAddNoCounter() {
        val narrowed = AgentCommunicationNarrowing.narrow(
            mapOf("calls" to listOf(mapOf("stages" to emptyList<Any>())))
        )

        @Suppress("UNCHECKED_CAST")
        val call = (narrowed["calls"] as List<Map<String, Any?>>).single()
        assertNull(call["stages"])
        assertNull(call["stagesCount"])
    }

    /**
     * Frame lists are the citable evidence a finding hangs off, and they are
     * cheap. Dropping them would save little and cost the model the values it is
     * expected to cite.
     */
    @Test
    fun frameEvidenceIsNeverCollapsed() {
        val narrowed = AgentCommunicationNarrowing.narrow(
            mapOf(
                "callSetupAnalysis" to mapOf(
                    "selectedAttempt" to mapOf(
                        "inviteFrame" to 10L,
                        "mediaNegotiationFrames" to listOf(11L, 12L),
                        "coreEventFrames" to listOf(13L),
                        "delayContributions" to List(4) { mapOf("stage" to "s$it") }
                    )
                )
            )
        )

        @Suppress("UNCHECKED_CAST")
        val attempt = (narrowed["callSetupAnalysis"] as Map<String, Any?>)["selectedAttempt"]
            as Map<String, Any?>
        assertEquals(10L, attempt["inviteFrame"])
        assertEquals(listOf(11L, 12L), attempt["mediaNegotiationFrames"])
        assertEquals(listOf(13L), attempt["coreEventFrames"])
        // ...while the heavy sibling is collapsed.
        assertEquals(4, attempt["delayContributionsCount"])
    }

    /** Scalars and the per-domain truncation blocks pass through untouched. */
    @Test
    fun countersAndSourceBlocksArePreserved() {
        val narrowed = AgentCommunicationNarrowing.narrow(
            mapOf(
                "returned" to 4,
                "total" to 4,
                "truncated" to true,
                "sipSource" to mapOf("total" to 5000, "truncated" to true)
            )
        )

        assertEquals(4, narrowed["returned"])
        assertEquals(true, narrowed["truncated"])
        @Suppress("UNCHECKED_CAST")
        val sipSource = narrowed["sipSource"] as Map<String, Any?>
        assertEquals(5000, sipSource["total"])
        assertEquals(true, sipSource["truncated"])
    }

    @Test
    fun aSmallPayloadIsNotConsideredOversized() {
        val small = mapOf("calls" to listOf(mapOf("callId" to "a")))

        assertFalse(AgentCommunicationNarrowing.exceedsAllowance(small, 32 * 1024))
    }
}
