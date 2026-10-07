// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.privacy.AgentFieldSensitivity
import com.example.layanalyzer.ai.tools.dto.AgentCredentialFields
import com.example.layanalyzer.ai.tools.dto.AgentFieldOccurrence
import com.example.layanalyzer.model.ProtocolNode

/**
 * Projects named protocol fields out of a dissected [ProtocolNode] tree.
 *
 * A field name is a *label to compare*, never an expression to evaluate.  The
 * projector walks the tree and compares [ProtocolNode.filter] to the requested
 * name with a case-insensitive string equality; there is no parser, no operator
 * handling and no display-filter compilation anywhere in this file.  That is
 * what makes `get_packet_fields` structurally unable to become a filter
 * back-door, regardless of what a model puts in the `fields` argument.
 */
object ProtocolFieldProjector {

    /**
     * Characters a protocol field abbreviation may contain: letters, digits,
     * underscore, hyphen and dot.
     *
     * Everything else — spaces, quotes, parentheses, comparison operators, path
     * separators and control characters — is rejected, so a name can never
     * carry filter syntax even into the comparison.
     */
    private val FIELD_NAME_PATTERN = Regex("^[A-Za-z0-9_.-]+$")

    /** Longest field name accepted; real Wireshark abbreviations are far shorter. */
    const val MAX_FIELD_NAME_LENGTH = 120

    /** Depth cap for the walk; capture-derived trees must not drive recursion. */
    private const val MAX_DEPTH = 64

    /** Occurrences kept for one field in one frame. */
    const val MAX_OCCURRENCES_PER_FIELD = 16

    fun isValidFieldName(name: String): Boolean =
        name.isNotEmpty() &&
            name.length <= MAX_FIELD_NAME_LENGTH &&
            FIELD_NAME_PATTERN.matches(name)

    /**
     * Collect every occurrence of each requested field.
     *
     * Multiple occurrences are preserved in document order, because the fields
     * this matters most for — SIP `Via`, SDP `m=`/`a=`, repeated DNS answers —
     * are exactly the ones where taking only the first would change the
     * analysis.  Per-field results are capped at [MAX_OCCURRENCES_PER_FIELD];
     * [ProjectionResult.truncated] reports when that cap removed anything.
     */
    fun project(
        root: ProtocolNode,
        requestedFields: List<String>,
        includeDisplayValue: Boolean = true
    ): ProjectionResult {
        // One lookup keyed by lowercase name, so a tree of any size costs a
        // single walk rather than one walk per requested field.
        val wanted = LinkedHashMap<String, String>(requestedFields.size)
        requestedFields.forEach { name -> wanted.putIfAbsent(name.lowercase(), name) }

        val found = LinkedHashMap<String, MutableList<AgentFieldOccurrence>>()
        var truncated = false

        fun visit(node: ProtocolNode, depth: Int) {
            if (depth > MAX_DEPTH) {
                truncated = true
                return
            }
            val abbreviation = node.filter
            if (!abbreviation.isNullOrBlank()) {
                val requestedName = wanted[abbreviation.lowercase()]
                if (requestedName != null) {
                    val occurrences = found.getOrPut(requestedName) { mutableListOf() }
                    if (occurrences.size < MAX_OCCURRENCES_PER_FIELD) {
                        occurrences += occurrence(node, requestedName, abbreviation, includeDisplayValue)
                    } else {
                        truncated = true
                    }
                }
            }
            node.children.forEach { child -> visit(child, depth + 1) }
        }
        visit(root, 0)

        val missing = requestedFields.filter { name -> !found.containsKey(name) }
        return ProjectionResult(
            fields = found.mapValues { (_, occurrences) -> occurrences.toList() },
            missingFields = missing,
            truncated = truncated
        )
    }

    /**
     * One matched node.  [ProtocolNode.start] and [ProtocolNode.length] are not
     * read here at all: AI-09 keeps byte ranges for local evidence navigation,
     * and a projection that never reads them cannot send one to a model.
     */
    private fun occurrence(
        node: ProtocolNode,
        requestedName: String,
        actualFieldName: String,
        includeDisplayValue: Boolean
    ): AgentFieldOccurrence {
        val rawFilterValue = node.filterValue?.takeIf { it.isNotBlank() }
        val rawDisplayValue = node.value?.takeIf { it.isNotBlank() } ?: node.label.takeIf { it.isNotBlank() }

        // A credential is reported as existence metadata only.  The scheme is
        // derived before the values are dropped, and both value fields are then
        // left out of the payload entirely by the DTO.
        if (AgentCredentialFields.isCredential(actualFieldName)) {
            return AgentFieldOccurrence(
                requestedName = requestedName,
                actualFieldName = actualFieldName,
                generated = node.generated,
                hidden = node.hidden,
                credential = true,
                present = true,
                scheme = AgentCredentialFields.scheme(rawDisplayValue ?: rawFilterValue)
            )
        }

        if (AgentFieldSensitivity.isPayload(actualFieldName)) {
            return AgentFieldOccurrence(
                requestedName = requestedName,
                actualFieldName = actualFieldName,
                generated = node.generated,
                hidden = node.hidden,
                payload = true,
                present = true
            )
        }

        return AgentFieldOccurrence(
            requestedName = requestedName,
            actualFieldName = actualFieldName,
            displayValue = if (includeDisplayValue) rawDisplayValue else null,
            filterValue = rawFilterValue,
            generated = node.generated,
            hidden = node.hidden
        )
    }

    /** Everything one frame's projection produced. */
    data class ProjectionResult(
        val fields: Map<String, List<AgentFieldOccurrence>>,
        val missingFields: List<String>,
        val truncated: Boolean
    )
}
