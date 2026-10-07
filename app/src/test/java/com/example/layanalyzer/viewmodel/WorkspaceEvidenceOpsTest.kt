// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class WorkspaceEvidenceOpsTest {
    private fun manual(frame: Long, addedAtMillis: Long = 0L) = EvidenceItem(
        frameNumber = frame,
        source = EvidenceSource.Manual,
        sourceFindingId = null,
        addedAtMillis = addedAtMillis
    )

    private fun agent(frame: Long, findingId: String, addedAtMillis: Long = 0L) = EvidenceItem(
        frameNumber = frame,
        source = EvidenceSource.AgentFinding,
        sourceFindingId = findingId,
        addedAtMillis = addedAtMillis
    )

    @Test
    fun `toggle adds a Manual item to an empty list and removes it again`() {
        val added = WorkspaceEvidenceOps.toggle(emptyList(), frameNumber = 5L, nowMillis = 1_000L)

        assertEquals(listOf(manual(5L, addedAtMillis = 1_000L)), added)
        assertEquals(EvidenceSource.Manual, added.single().source)

        val removed = WorkspaceEvidenceOps.toggle(added, frameNumber = 5L, nowMillis = 2_000L)

        assertEquals(emptyList<EvidenceItem>(), removed)
    }

    @Test
    fun `toggle removes only the matching frame and preserves the rest`() {
        val first = manual(1L, addedAtMillis = 10L)
        val middle = manual(3L, addedAtMillis = 20L)
        val last = manual(7L, addedAtMillis = 30L)
        val items = listOf(first, middle, last)

        val result = WorkspaceEvidenceOps.toggle(items, frameNumber = 3L, nowMillis = 999L)

        assertEquals(listOf(first, last), result)
    }

    @Test
    fun `add returns the list unchanged when the frame already exists`() {
        val existing = agent(5L, findingId = "finding-1", addedAtMillis = 100L)
        val items = listOf(existing)

        val result = WorkspaceEvidenceOps.add(
            items = items,
            frameNumber = 5L,
            source = EvidenceSource.Manual,
            sourceFindingId = null,
            nowMillis = 9_999L
        )

        assertSame(items, result)
        assertEquals(listOf(agent(5L, findingId = "finding-1", addedAtMillis = 100L)), result)
    }

    @Test
    fun `addAll appends only missing frames ascending with AgentFinding provenance`() {
        val items = listOf(manual(2L, addedAtMillis = 10L))

        val result = WorkspaceEvidenceOps.addAll(
            items = items,
            frameNumbers = listOf(5L, 3L, 1L, 3L),
            source = EvidenceSource.AgentFinding,
            sourceFindingId = "finding-9",
            nowMillis = 500L
        )

        assertEquals(
            listOf(
                manual(2L, addedAtMillis = 10L),
                agent(1L, findingId = "finding-9", addedAtMillis = 500L),
                agent(3L, findingId = "finding-9", addedAtMillis = 500L),
                agent(5L, findingId = "finding-9", addedAtMillis = 500L)
            ),
            result
        )
    }

    @Test
    fun `addAll leaves pre-existing Manual entries untouched`() {
        val preexisting = manual(1L, addedAtMillis = 10L)
        val items = listOf(preexisting)

        val result = WorkspaceEvidenceOps.addAll(
            items = items,
            frameNumbers = listOf(1L, 2L),
            source = EvidenceSource.AgentFinding,
            sourceFindingId = "finding-7",
            nowMillis = 500L
        )

        assertEquals(preexisting, result.first())
        assertEquals(EvidenceSource.Manual, result.first().source)
        assertNull(result.first().sourceFindingId)
        assertEquals(10L, result.first().addedAtMillis)
        assertEquals(2, result.size)
    }

    @Test
    fun `add stamps nowMillis on the appended item and never mutates the input list`() {
        val items = listOf(manual(1L, addedAtMillis = 10L))

        val result = WorkspaceEvidenceOps.add(
            items = items,
            frameNumber = 4L,
            source = EvidenceSource.AgentFinding,
            sourceFindingId = "finding-3",
            nowMillis = 777L
        )

        assertEquals(listOf(manual(1L, addedAtMillis = 10L)), items)
        assertEquals(agent(4L, findingId = "finding-3", addedAtMillis = 777L), result.last())
    }

    @Test
    fun `addAll stamps nowMillis on appended items and never mutates the input list`() {
        val items = listOf(manual(1L, addedAtMillis = 10L))

        val result = WorkspaceEvidenceOps.addAll(
            items = items,
            frameNumbers = listOf(2L, 3L),
            source = EvidenceSource.AgentFinding,
            sourceFindingId = "finding-3",
            nowMillis = 888L
        )

        assertEquals(listOf(manual(1L, addedAtMillis = 10L)), items)
        assertEquals(listOf(2L, 3L), result.drop(1).map { it.frameNumber })
        assertTrue(result.drop(1).all { it.addedAtMillis == 888L })
    }

    @Test
    fun `remove drops the matching frame and keeps the others in original order`() {
        val first = manual(1L, addedAtMillis = 10L)
        val middle = manual(3L, addedAtMillis = 20L)
        val last = manual(7L, addedAtMillis = 30L)
        val items = listOf(first, middle, last)

        val result = WorkspaceEvidenceOps.remove(items, frameNumber = 3L)

        assertEquals(listOf(first, last), result)
    }

    @Test
    fun `remove returns the input list unchanged when nothing matches`() {
        val items = listOf(manual(2L, addedAtMillis = 10L), agent(5L, findingId = "f-1", addedAtMillis = 20L))

        val result = WorkspaceEvidenceOps.remove(items, frameNumber = 9L)

        assertEquals(items, result)
    }

    @Test
    fun `remove drops every duplicate entry for the same frame`() {
        val first = manual(4L, addedAtMillis = 10L)
        val duplicate = manual(4L, addedAtMillis = 20L)
        val other = manual(8L, addedAtMillis = 30L)
        val items = listOf(first, duplicate, other)

        val result = WorkspaceEvidenceOps.remove(items, frameNumber = 4L)

        assertEquals(listOf(other), result)
    }

    @Test
    fun `remove on an empty list returns an empty list`() {
        val result = WorkspaceEvidenceOps.remove(emptyList(), frameNumber = 1L)

        assertEquals(emptyList<EvidenceItem>(), result)
    }

    @Test
    fun `remove never mutates the input list`() {
        val items = listOf(manual(1L, addedAtMillis = 10L), manual(4L, addedAtMillis = 20L))
        val before = items.toList()

        WorkspaceEvidenceOps.remove(items, frameNumber = 4L)

        assertEquals(before.size, items.size)
        assertEquals(before, items)
    }

    @Test
    fun `removeAll returns the input unchanged when frameNumbers is empty`() {
        val items = listOf(manual(2L, addedAtMillis = 10L), agent(5L, findingId = "f-1", addedAtMillis = 20L))

        val result = WorkspaceEvidenceOps.removeAll(items, frameNumbers = emptyList())

        assertSame(items, result)
    }

    @Test
    fun `removeAll drops the matching frames and keeps the rest in original order`() {
        val first = manual(1L, addedAtMillis = 10L)
        val middle = manual(3L, addedAtMillis = 20L)
        val last = manual(7L, addedAtMillis = 30L)
        val items = listOf(first, middle, last)

        val result = WorkspaceEvidenceOps.removeAll(items, frameNumbers = listOf(3L, 1L))

        assertEquals(listOf(last), result)
    }

    @Test
    fun `removeAll returns an empty list when every frame matches`() {
        val items = listOf(manual(1L, addedAtMillis = 10L), manual(3L, addedAtMillis = 20L))

        val result = WorkspaceEvidenceOps.removeAll(items, frameNumbers = listOf(1L, 3L, 7L))

        assertEquals(emptyList<EvidenceItem>(), result)
    }

    @Test
    fun `removeAll ignores frame numbers not present and never throws`() {
        val items = listOf(manual(2L, addedAtMillis = 10L), agent(5L, findingId = "f-1", addedAtMillis = 20L))

        val result = WorkspaceEvidenceOps.removeAll(items, frameNumbers = listOf(9L, 11L))

        assertEquals(items, result)
    }

    @Test
    fun `removeAll drops every duplicate entry for the same frame`() {
        val first = manual(4L, addedAtMillis = 10L)
        val duplicate = manual(4L, addedAtMillis = 20L)
        val other = manual(8L, addedAtMillis = 30L)
        val items = listOf(first, duplicate, other)

        val result = WorkspaceEvidenceOps.removeAll(items, frameNumbers = listOf(4L))

        assertEquals(listOf(other), result)
    }

    @Test
    fun `removeAll never mutates the input list`() {
        val items = listOf(manual(1L, addedAtMillis = 10L), manual(4L, addedAtMillis = 20L), agent(6L, "f-1", 30L))
        val before = items.toList()

        WorkspaceEvidenceOps.removeAll(items, frameNumbers = listOf(4L, 99L))

        assertEquals(before.size, items.size)
        assertEquals(before, items)
    }
}
