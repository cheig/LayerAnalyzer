// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

/** Identifier families that must stay correlatable without leaving raw locally. */
enum class AgentAliasKind(val prefix: String) {
    Endpoint("EP"),
    CallId("CALL"),
    Ssrc("SSRC"),
    CoreSession("CORE"),
    Identifier("ID")
}

/** One local-only reverse mapping. It is never included in a tool result. */
data class AgentAliasEntry(
    val alias: String,
    val kind: AgentAliasKind,
    val localValue: String
)

/**
 * Stable short identifiers for one Agent run.
 *
 * The small per-session tag prevents a model from correlating `EP-1` between
 * runs, while the ordinal keeps aliases compact enough for reports. The reverse
 * map remains in process memory only for host-side evidence resolution.
 */
class AliasTable(sessionKey: String) {
    private val sessionTag = sessionKey.hashCode().toUInt().toString(36).takeLast(4)
    private val aliasesBySource = LinkedHashMap<Pair<AgentAliasKind, String>, String>()
    private val entriesByAlias = LinkedHashMap<String, AgentAliasEntry>()
    private val nextByKind = mutableMapOf<AgentAliasKind, Int>()

    @Synchronized
    fun alias(kind: AgentAliasKind, rawValue: String): String {
        val value = rawValue.trim()
        if (value.isEmpty()) return value
        if (entriesByAlias.containsKey(value)) return value
        val source = kind to value
        return aliasesBySource.getOrPut(source) {
            val next = (nextByKind[kind] ?: 0) + 1
            nextByKind[kind] = next
            "${kind.prefix}-$sessionTag-$next".also { alias ->
                entriesByAlias[alias] = AgentAliasEntry(alias, kind, value)
            }
        }
    }

    @Synchronized
    fun resolve(alias: String): AgentAliasEntry? = entriesByAlias[alias]

    /** Replace only exact values already seen in structured identifiers. */
    @Synchronized
    fun replaceKnown(text: String): String {
        if (text.isEmpty() || aliasesBySource.isEmpty()) return text

        // Do one regex pass. Replacing into an accumulating string lets a
        // newly emitted alias accidentally match a shorter source value that
        // is processed later, corrupting the alias/evidence mapping.
        val sourceToAlias = LinkedHashMap<String, String>()
        aliasesBySource.entries
            .sortedByDescending { it.key.second.length }
            .forEach { (source, alias) -> sourceToAlias.putIfAbsent(source.second, alias) }
        if (sourceToAlias.isEmpty()) return text

        val pattern = Regex(sourceToAlias.keys.joinToString("|") { Regex.escape(it) })
        return pattern.replace(text) { match -> sourceToAlias[match.value] ?: match.value }
    }

    @Synchronized
    fun entries(): List<AgentAliasEntry> = entriesByAlias.values.toList()
}
