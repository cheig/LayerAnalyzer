package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.model.ExpertInfoItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentExpertGrouperTest {

    /**
     * The whole point of grouping: 96 retransmission entries are one problem, not
     * 96. If they scattered, the summary would be no denser than the list.
     */
    @Test
    fun sameCategoryEntriesCollapseIntoOneGroupDespiteVaryingLabels() {
        val items = (1..96).map { index ->
            item(
                frame = index.toLong(),
                severity = "warn",
                // Real labels carry per-frame values; the category does not.
                label = "This frame is a (suspected) retransmission of frame $index",
                filter = "tcp.analysis.retransmission"
            )
        }

        val grouping = AgentExpertGrouper.group(items)

        assertEquals(1, grouping.groups.size)
        assertEquals(1, grouping.groupsTotal)
        val group = grouping.groups.single()
        assertEquals(96, group.count)
        assertEquals("warning/tcp.analysis.retransmission", group.groupKey)
        assertEquals("tcp.analysis.retransmission", group.displayFilter)
        assertEquals(1L, group.firstFrame)
        assertEquals(96L, group.lastFrame)
        assertEquals(AgentExpertGrouper.MAX_SAMPLE_FRAMES, group.sampleFrames.size)
    }

    /** With no abbrev to key on, the varying part of the label must not split it. */
    @Test
    fun labelFallbackNormalizesFrameSpecificValues() {
        val items = listOf(
            item(1L, "error", "Bad checksum [0x1234]", filter = null),
            item(2L, "error", "Bad checksum [0xbeef]", filter = null),
            item(3L, "error", "Bad checksum [0x0001]", filter = null)
        )

        val grouping = AgentExpertGrouper.group(items)

        assertEquals(1, grouping.groups.size)
        assertEquals(3, grouping.groups.single().count)
    }

    /** Distinct problems must stay distinct even after normalization. */
    @Test
    fun differentLabelsRemainSeparateGroups() {
        val items = listOf(
            item(1L, "error", "Bad checksum [0x1234]", filter = null),
            item(2L, "error", "Bad sequence number [17]", filter = null)
        )

        assertEquals(2, AgentExpertGrouper.group(items).groupsTotal)
    }

    /** Blank abbrevs must not become one catch-all category. */
    @Test
    fun blankFilterFallsBackToTheLabelRatherThanGroupingEverythingTogether() {
        val items = listOf(
            item(1L, "note", "Connection reset", filter = ""),
            item(2L, "note", "Keep-alive segment", filter = "   ")
        )

        assertEquals(2, AgentExpertGrouper.group(items).groupsTotal)
    }

    /**
     * A lone error is usually the answer; a 96-count warning is usually
     * background. Ranking by count alone would hide the former behind the latter.
     */
    @Test
    fun rareErrorSurvivesAlongsideDominantWarningGroups() {
        val items = buildList {
            repeat(96) { index ->
                add(item(index + 10L, "warn", "retransmission", "tcp.analysis.retransmission"))
            }
            repeat(40) { index ->
                add(item(index + 200L, "note", "keep alive", "tcp.analysis.keep_alive"))
            }
            add(item(7L, "error", "Malformed packet", "malformed"))
        }

        val grouping = AgentExpertGrouper.group(items)

        val error = grouping.groups.firstOrNull { it.severity == "error" }
        assertTrue("the single error group must reach the summary", error != null)
        assertEquals(1, error?.count)
        // Severity outranks frequency, so it leads.
        assertEquals("error", grouping.groups.first().severity)
    }

    /** Beyond the cap the summary reports how many categories it did not list. */
    @Test
    fun groupCountIsCappedButTheTotalRemainsVisible() {
        val items = (1..20).map { index ->
            item(index.toLong(), "note", "problem $index", "proto.issue$index")
        }

        val grouping = AgentExpertGrouper.group(items)

        assertEquals(AgentExpertGrouper.MAX_GROUPS, grouping.groups.size)
        assertEquals(20, grouping.groupsTotal)
    }

    /**
     * Native spells a warning "warn" while the tool vocabulary uses "warning".
     * The group key must carry the normalized spelling, or a model filtering for
     * warnings would never match the group it was just shown.
     */
    @Test
    fun nativeWarnSeverityIsNormalizedInTheGroupKey() {
        val grouping = AgentExpertGrouper.group(
            listOf(item(1L, "warn", "retransmission", "tcp.analysis.retransmission"))
        )

        assertEquals("warning", grouping.groups.single().severity)
        assertTrue(grouping.groups.single().groupKey.startsWith("warning/"))
    }

    /** The drill-down key must be derivable from an entry, not just from a group. */
    @Test
    fun groupKeyOfMatchesTheKeyTheSummaryAdvertises() {
        val entry = item(4L, "warn", "retransmission", "tcp.analysis.retransmission")

        val advertised = AgentExpertGrouper.group(listOf(entry)).groups.single().groupKey

        assertEquals(advertised, AgentExpertGrouper.groupKeyOf(entry))
    }

    @Test
    fun emptyInputProducesNoGroups() {
        val grouping = AgentExpertGrouper.group(emptyList())

        assertTrue(grouping.groups.isEmpty())
        assertEquals(0, grouping.groupsTotal)
    }

    private fun item(
        frame: Long,
        severity: String,
        label: String,
        filter: String?
    ) = ExpertInfoItem(
        frameNumber = frame,
        label = label,
        filter = filter,
        severity = severity,
        start = 0,
        length = 0
    )
}
