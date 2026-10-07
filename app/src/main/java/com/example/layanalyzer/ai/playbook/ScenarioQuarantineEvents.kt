// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow

/**
 * One user-scenario quarantine notice (OPT-QNT-01).
 *
 * The payload is a stable reason code — the same value
 * [UserScenarioPlaybookStore] hands to its `onQuarantine` sink, for example
 * [UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED].  It deliberately
 * carries nothing else: no file name, no path, no playbook content.  The
 * whole point of routing quarantine through this type instead of a free-form
 * message is that the value can cross the data-layer → UI boundary without
 * ever putting user content on screen or in a log line the UI renders
 * (SRE 通用完成定义第 5 条口径).
 */
data class ScenarioQuarantineEvent(val reasonCode: String)

/**
 * Application-scoped buffer between the user scenario layer's quarantine sink
 * and the Agent UI (OPT-QNT-01).
 *
 * The wiring is asymmetric in time on purpose: [UserScenarioPlaybookStore.load]
 * can quarantine a corrupt file during app assembly — while
 * `LayerAnalyzerApplication` builds the store graph, long before any
 * [com.example.layanalyzer.viewmodel.ProtocolAgentViewModel] exists — and a
 * plain hot stream (a `MutableSharedFlow` without replay) would silently drop
 * exactly that first event.  A [Channel] with a buffer keeps every published
 * code until a consumer collects it, so the ViewModel sees the notice when it
 * initializes.  Buffering is per-process, which matches the one-shot semantics:
 * the store quarantines each file at most once (a restart after a rename finds
 * no file to quarantine), and the consumer deduplicates by reason code on top
 * (see [nextQuarantineCodes]).
 *
 * [publish] is a non-blocking `trySend` on an overflow-dropping buffer: a
 * quarantine event must never block or fail the store's IO path, so in the
 * pathological case where nothing ever collects a full buffer, the oldest
 * unnoticed code is dropped rather than throwing.  Reaching that case needs
 * more quarantines than this layer can produce per process; the Android log
 * line the assembly sink writes alongside still records every one of them.
 *
 * This class is pure Kotlin (no Android types) so the buffering and payload
 * contracts stay JVM-testable.
 */
class ScenarioQuarantineEventChannel(capacity: Int = DEFAULT_CAPACITY) {

    private val channel = Channel<ScenarioQuarantineEvent>(
        capacity = capacity,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    /**
     * The buffered event stream.  Backed by [Channel.receiveAsFlow], so
     * events published before any collector exists are delivered to the first
     * one instead of being lost; a value is consumed once, which is what makes
     * a recreated ViewModel stop re-showing an already-announced notice.
     */
    val events: Flow<ScenarioQuarantineEvent> = channel.receiveAsFlow()

    /**
     * Queues [event] for the consumer.  Never blocks and never throws;
     * `false` means the buffer was full and the oldest queued code was dropped.
     */
    fun publish(event: ScenarioQuarantineEvent): Boolean = channel.trySend(event).isSuccess

    companion object {
        /** More quarantine codes than one process can plausibly produce. */
        const val DEFAULT_CAPACITY = 16
    }
}

/**
 * The consumer-side deduplication rule (OPT-QNT-01): the store already reports
 * a quarantine once per unreadable file, and this appends [event]'s reason code
 * to [seen] only when that code has not been announced yet, so one quarantine
 * surfaces exactly one notice even if the same reason code is published again
 * (a second unreadable file, a re-collected stream, a future second caller).
 *
 * A pure function over the accumulated code list so the dedupe contract is
 * testable without a ViewModel or a coroutine scope;
 * [com.example.layanalyzer.viewmodel.ProtocolAgentViewModel] keeps the list as
 * its published state.
 */
internal fun nextQuarantineCodes(
    seen: List<String>,
    event: ScenarioQuarantineEvent
): List<String> = if (event.reasonCode in seen) seen else seen + event.reasonCode
