package com.example.layanalyzer.core

/**
 * DTO returned from JNI for packet list summaries.
 */
data class PacketSummary(
    val num: Int,
    val time: Double,
    val source: String,
    val destination: String,
    val protocol: String,
    val length: Int,
    val sourcePort: Int,
    val destinationPort: Int,
    val info: String
)
