// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.PacketReassembly
import com.example.layanalyzer.model.ProtocolNode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketReassemblyResolverTest {
    @Test
    fun linksUseTypedFrameValuesAndNeverParseLabelsCountsOrOffsets() {
        assertEquals(42L, reference("tcp.segment", 42).referencedFrame)
        assertNull(ProtocolNode("Frame: 42", filterValue = "42").referencedFrame)
        assertNull(ProtocolNode("Count", fieldType = "FT_UINT32", filterValue = "42").referencedFrame)
        listOf("0", "-1", "2147483648", "42 bytes", "").forEach {
            assertNull(ProtocolNode("Frame: 42", fieldType = "FT_FRAMENUM", filterValue = it).referencedFrame)
        }
    }

    @Test
    fun groupMenusStayWithinTheirOwnSubtree() {
        val first = group("tcp", 1, 4)
        val second = group("tcp", 3, 4)
        val root = root(first, second, reference("tcp.analysis.acks_frame", 2))
        val actions = PacketReassembly.actions(root)
        assertNull(actions["0"])
        assertEquals(setOf(1L, 4L), actions.getValue("0.0.0").frames)
        assertEquals(setOf(3L, 4L), actions.getValue("0.1.0").frames)
        assertNull(actions["0.2"])
    }

    @Test
    fun earlierIpv4AndIpv6FragmentsResolveThroughBothForwardFieldSpellings() {
        listOf("ip.reassembled_in", "ipv6.reassembled.in").forEach { field ->
            val protocol = field.substringBefore('.')
            val forward = reference(field, 5)
            val first = root(forward)
            val trees = mapOf(1L to first, 3L to root(), 5L to root(group(protocol, 1, 3, 5)))
            val actual = PacketReassemblyResolver(5, trees::get)
                .resolve(1, first, PacketReassembly.fromNode(forward)!!)
            assertEquals(setOf(1L, 3L, 5L), actual)
        }
    }

    @Test
    fun forwardTcpLinkExcludesOtherPdusInTheSameFinalFrame() {
        val first = root(reference("tcp.reassembled_in", 6))
        val final = root(group("tcp", 1, 4, 6), group("tcp", 5, 6))
        val trees = mapOf(1L to first, 4L to root(), 6L to final)
        val actual = PacketReassemblyResolver(6, trees::get).resolve(
            1, first, PacketReassembly("tcp", reassembledIn = 6)
        )
        assertEquals(setOf(1L, 4L, 6L), actual)
    }

    @Test
    fun tcpGroupIncludesUnderlyingIpFragmentsWithoutFollowingTheNextPdu() {
        val selected = group("tcp", 3, 6)
        val final = root(selected, reference("tcp.reassembled_in", 9))
        val trees = mapOf(
            2L to root(reference("ip.reassembled_in", 3)),
            3L to root(group("ip", 2, 3), reference("tcp.reassembled_in", 6)),
            6L to final
        )
        val visited = mutableSetOf<Long>()
        val actual = PacketReassemblyResolver(9) { visited.add(it); trees[it] }
            .resolve(6, final, PacketReassembly.fromNode(selected)!!)
        assertEquals(setOf(2L, 3L, 6L), actual)
        assertEquals(setOf(2L, 3L), visited)
    }

    @Test
    fun duplicateMembersAndErrorFrameReferencesDoNotAddUnrelatedFrames() {
        val selected = group("sctp", 1, 3, 3).let {
            it.copy(children = it.children + reference("sctp.fragment.error", 2))
        }
        val final = root(selected)
        val actual = PacketReassemblyResolver(3) { root() }
            .resolve(3, final, PacketReassembly.fromNode(selected)!!)
        assertEquals(setOf(1L, 3L), actual)
    }

    @Test
    fun incompleteOrInvalidGroupsFailInsteadOfReturningPartialHighlights() {
        val forward = PacketReassembly("tcp", reassembledIn = 4)
        assertTrue(runCatching {
            PacketReassemblyResolver(4) { root(group("tcp", 2, 4)) }.resolve(1, root(), forward)
        }.isFailure)
        assertTrue(runCatching {
            PacketReassemblyResolver(4) { null }.resolve(1, root(), forward)
        }.isFailure)
        assertTrue(runCatching {
            PacketReassemblyResolver(3) { root() }.resolve(1, root(), forward)
        }.isFailure)
    }

    private fun reference(field: String, frame: Long) = ProtocolNode(
        label = "Frame: $frame (offset 0)", filter = field, filterValue = frame.toString(), fieldType = "FT_FRAMENUM"
    )

    private fun group(protocol: String, vararg frames: Long): ProtocolNode {
        val member = if (protocol == "tcp") "segment" else "fragment"
        return ProtocolNode(
            label = "Reassembled", filter = "$protocol.${member}s",
            children = frames.map { reference("$protocol.$member", it) }
        )
    }

    private fun root(vararg children: ProtocolNode) = ProtocolNode("Packet", children = children.toList())
}
