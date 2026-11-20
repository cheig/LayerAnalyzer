// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

import androidx.compose.runtime.Immutable

@Immutable
data class ProtocolNode(
    val label: String,       // Display text
    val value: String? = null, // Specific value
    val filter: String? = null,
    val filterValue: String? = null,
    val start: Int = 0,      // Start position in hex
    val length: Int = 0,     // Length
    val severity: String = "none",
    val generated: Boolean = false,
    val hidden: Boolean = false,
    val children: List<ProtocolNode> = emptyList(),
    val fieldType: String? = null,
    val dataSourceId: String? = null,
    val offsetValid: Boolean = false
) {
    /** A source-relative range, never inferred from the protocol name or offset alone. */
    fun byteRange(sourceId: String, availableLength: Int): IntRange? =
        if (offsetValid && !generated && dataSourceId == sourceId && start >= 0 &&
            length > 0 && start <= availableLength && length <= availableLength - start
        ) start until (start + length) else null

    /** Only Wireshark frame references are links; counts and offsets are not. */
    val referencedFrame: Long?
        get() = if (fieldType == "FT_FRAMENUM") {
            filterValue?.toLongOrNull()?.takeIf { it in 1..Int.MAX_VALUE.toLong() }
        } else null
}
