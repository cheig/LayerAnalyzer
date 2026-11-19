// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.PacketReassembly
import com.example.layanalyzer.model.ProtocolNode

/** Resolves one PDU without a display filter or a scan of the entire TCP conversation. */
internal class PacketReassemblyResolver(
    private val frameCount: Int,
    private val loadDetails: (Long) -> ProtocolNode?
) {
    fun resolve(sourceFrame: Long, sourceRoot: ProtocolNode, selection: PacketReassembly): Set<Long> {
        val trees = mutableMapOf(sourceFrame to sourceRoot)
        fun tree(frame: Long): ProtocolNode {
            require(frame in 1..frameCount.toLong()) { "Invalid reassembly frame" }
            return trees[frame] ?: checkNotNull(loadDetails(frame)) { "Frame unavailable" }
        }

        val frames = linkedSetOf<Long>()
        val target = selection.reassembledIn
        if (target != null) {
            // A frame can finish several PDUs. Only groups containing this fragment match.
            val targetRoot = tree(target)
            trees[target] = targetRoot
            val matching = PacketReassembly.groups(targetRoot).filter {
                it.protocol == selection.protocol && sourceFrame in it.frames
            }
            check(matching.isNotEmpty()) { "Reassembly group unavailable" }
            matching.forEach { frames.addAll(it.frames) }
            frames.add(target)
        } else {
            check(selection.frames.isNotEmpty()) { "Reassembly group unavailable" }
            frames.addAll(selection.frames)
            frames.add(sourceFrame)
        }

        // A TCP/SCTP segment may itself be assembled from IP fragments. Follow only
        // backward IP dependencies, never forward links to another application PDU.
        val pending = ArrayDeque(frames)
        val visited = mutableSetOf<Long>()
        while (pending.isNotEmpty()) {
            val frame = pending.removeFirst()
            if (!visited.add(frame)) continue
            val root = tree(frame)
            PacketReassembly.groups(root).filter {
                it.protocol in setOf("ip", "ipv6") && frame in it.frames
            }.forEach { group ->
                group.frames.forEach { if (frames.add(it)) pending.addLast(it) }
            }
        }
        return frames.toSortedSet()
    }
}
