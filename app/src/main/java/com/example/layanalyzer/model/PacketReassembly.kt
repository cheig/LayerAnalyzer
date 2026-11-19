// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

import androidx.compose.runtime.Immutable

/** A single reassembly subtree, or a forward reference from an earlier fragment. */
@Immutable
data class PacketReassembly(
    val protocol: String,
    val frames: Set<Long> = emptySet(),
    val reassembledIn: Long? = null
) {
    companion object {
        fun fromNode(node: ProtocolNode): PacketReassembly? {
            val field = node.filter ?: return null
            val forwardSuffix = listOf(".reassembled_in", ".reassembled.in")
                .firstOrNull(field::endsWith)
            if (forwardSuffix != null) {
                return node.referencedFrame?.let {
                    PacketReassembly(field.removeSuffix(forwardSuffix), reassembledIn = it)
                }
            }
            val groupSuffix = listOf(".fragments", ".segments").firstOrNull(field::endsWith)
                ?: return null
            val memberField = field.dropLast(1)
            val frames = linkedSetOf<Long>()
            fun collect(current: ProtocolNode) {
                if (current.filter == memberField) current.referencedFrame?.let(frames::add)
                current.children.forEach(::collect)
            }
            node.children.forEach(::collect)
            return frames.takeIf { it.isNotEmpty() }?.let {
                PacketReassembly(field.removeSuffix(groupSuffix), it)
            }
        }

        /** Path keys match ProtocolTreeView, keeping separate PDUs in one frame separate. */
        fun actions(root: ProtocolNode): Map<String, PacketReassembly> = buildMap {
            fun visit(node: ProtocolNode, path: String, parent: PacketReassembly?) {
                val action = fromNode(node) ?: parent
                if (action != null) put(path, action)
                node.children.forEachIndexed { index, child -> visit(child, "$path.$index", action) }
            }
            visit(root, "0", null)
        }

        fun groups(root: ProtocolNode): List<PacketReassembly> = buildList {
            fun visit(node: ProtocolNode) {
                fromNode(node)?.takeIf { it.frames.isNotEmpty() }?.let(::add)
                node.children.forEach(::visit)
            }
            visit(root)
        }
    }
}
