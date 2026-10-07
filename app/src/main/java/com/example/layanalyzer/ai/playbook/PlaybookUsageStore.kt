// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * How often the user has picked each analysis scenario.
 *
 * Counts are keyed by [AgentPlaybook.id] rather than `versionedId`, so a
 * scenario package upgrade keeps the user's history instead of silently
 * resetting the order they have grown used to.
 *
 * This is a presentation-order signal only. Nothing here reaches the model, a
 * prompt, or a report: it cannot change which playbook is *selected* for a
 * question, which stays with [AgentPlaybookStore]'s intent matching.
 */
interface PlaybookUsageStore {
    val usage: StateFlow<Map<String, Int>>

    fun record(playbookId: String)

    /**
     * Removes the count for [playbookId], used when the scenario it belongs to
     * is deleted; an unknown id is a no-op.  As with [record], this only
     * affects the chips' ordering signal — nothing here reaches the model, a
     * prompt, or a report.
     */
    fun clear(playbookId: String)
}

/** In-memory counts. Used by JVM tests and by callers without a Context. */
class InMemoryPlaybookUsageStore(
    initial: Map<String, Int> = emptyMap()
) : PlaybookUsageStore {
    private val state = MutableStateFlow(initial)
    override val usage: StateFlow<Map<String, Int>> = state.asStateFlow()

    override fun record(playbookId: String) {
        val id = playbookId.trim()
        if (id.isEmpty()) return
        state.value = state.value.increment(id)
    }

    override fun clear(playbookId: String) {
        val id = playbookId.trim()
        if (id.isEmpty()) return
        // Removing an absent key yields an equal map, so the StateFlow stays
        // silent and the no-op contract holds without a membership check.
        state.value = state.value - id
    }
}

/** SharedPreferences-backed counts, one integer entry per playbook id. */
class SharedPreferencesPlaybookUsageStore(
    private val preferences: SharedPreferences
) : PlaybookUsageStore {
    constructor(context: Context, preferencesName: String = PREFERENCES_NAME) : this(
        context.getSharedPreferences(preferencesName, Context.MODE_PRIVATE)
    )

    private val state = MutableStateFlow(load())
    override val usage: StateFlow<Map<String, Int>> = state.asStateFlow()

    override fun record(playbookId: String) {
        val id = playbookId.trim()
        if (id.isEmpty()) return
        val updated = state.value.increment(id)
        state.value = updated
        // A lost count only misorders chips, so an async commit is enough.
        preferences.edit().putInt(keyFor(id), updated.getValue(id)).apply()
    }

    override fun clear(playbookId: String) {
        val id = playbookId.trim()
        if (id.isEmpty()) return
        if (state.value[id] == null) return
        state.value = state.value - id
        // A lost count only misorders chips, so an async commit is enough.
        preferences.edit().remove(keyFor(id)).apply()
    }

    private fun load(): Map<String, Int> = buildMap {
        preferences.all.forEach { (key, value) ->
            if (!key.startsWith(KEY_PREFIX)) return@forEach
            val id = key.removePrefix(KEY_PREFIX)
            val count = (value as? Int)?.takeIf { it > 0 } ?: return@forEach
            if (id.isNotEmpty()) put(id, count)
        }
    }

    private fun keyFor(playbookId: String): String = KEY_PREFIX + playbookId

    companion object {
        const val PREFERENCES_NAME = "agent_playbook_usage"
        private const val KEY_PREFIX = "count_"
    }
}

private fun Map<String, Int>.increment(id: String): Map<String, Int> {
    val next = (this[id] ?: 0) + 1
    return toMutableMap().apply { put(id, next) }
}

/**
 * Most-used scenarios first, everything else in package order.
 *
 * [sortedWith] is stable, so playbooks the user has never picked keep the
 * order the verified package declared them in — a new install still sees the
 * curated sequence rather than an arbitrary one.
 */
fun List<AgentPlaybook>.sortedByUsage(usage: Map<String, Int>): List<AgentPlaybook> =
    if (usage.isEmpty()) this else sortedWith(
        compareByDescending { usage[it.id] ?: 0 }
    )
