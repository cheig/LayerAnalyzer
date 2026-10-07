package com.example.layanalyzer.model

import androidx.compose.runtime.Immutable

@Immutable
data class PacketSummary(
    val frameNumber: Long,
    val time: String,
    val source: String,
    val destination: String,
    val protocol: String,
    val length: Int,
    val sourcePort: Int? = null,
    val destinationPort: Int? = null,
    val info: String
)
