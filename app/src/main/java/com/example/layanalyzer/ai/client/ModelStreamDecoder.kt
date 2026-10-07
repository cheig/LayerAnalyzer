// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentModelResponse

/** Provider decoder fed one complete SSE `data` event at a time. */
interface ModelStreamDecoder {
    suspend fun accept(data: String, onChunk: suspend (StreamChunk) -> Unit)

    fun finish(): AgentModelResponse
}

/** Incremental SSE framing that tolerates arbitrary transport chunk boundaries. */
internal class ServerSentEventDecoder(
    private val onEvent: suspend (String) -> Unit
) {
    private val line = StringBuilder()
    private val dataLines = mutableListOf<String>()

    suspend fun accept(chunk: String) {
        chunk.forEach { character ->
            when (character) {
                '\n' -> consumeLine()
                else -> line.append(character)
            }
        }
    }

    suspend fun finish() {
        if (line.isNotEmpty()) consumeLine()
        emitEvent()
    }

    private suspend fun consumeLine() {
        val value = line.toString().removeSuffix("\r")
        line.setLength(0)
        if (value.isEmpty()) {
            emitEvent()
            return
        }
        if (value.startsWith(":")) return
        if (value.startsWith("data:")) {
            dataLines += value.removePrefix("data:").removePrefix(" ")
        }
    }

    private suspend fun emitEvent() {
        if (dataLines.isEmpty()) return
        val data = dataLines.joinToString("\n")
        dataLines.clear()
        if (data != "[DONE]") onEvent(data)
    }
}
