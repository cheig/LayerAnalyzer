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
    val children: List<ProtocolNode> = emptyList()
)
