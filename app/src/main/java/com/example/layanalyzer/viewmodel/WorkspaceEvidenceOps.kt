package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource

/**
 * Pure list transformations behind the workspace evidence write path.
 *
 * Extracted from `PacketListViewModel` so the provenance rules can be unit
 * tested without an Android `Context`. These functions never read a clock and
 * never mutate their input; callers pass `nowMillis` in.
 */
internal object WorkspaceEvidenceOps {
    /** Toggle: remove the frame if present, otherwise append a Manual item. */
    fun toggle(items: List<EvidenceItem>, frameNumber: Long, nowMillis: Long): List<EvidenceItem> =
        if (items.any { it.frameNumber == frameNumber }) {
            items.filterNot { it.frameNumber == frameNumber }
        } else {
            items + EvidenceItem(
                frameNumber = frameNumber,
                source = EvidenceSource.Manual,
                addedAtMillis = nowMillis
            )
        }

    /**
     * Append a frame with the given provenance, deduping by frame number.
     *
     * A frame already present keeps its existing entry exactly as it was; this
     * never rewrites the provenance of an existing item.
     */
    fun add(
        items: List<EvidenceItem>,
        frameNumber: Long,
        source: EvidenceSource,
        sourceFindingId: String?,
        nowMillis: Long
    ): List<EvidenceItem> =
        if (items.any { it.frameNumber == frameNumber }) {
            items
        } else {
            items + EvidenceItem(
                frameNumber = frameNumber,
                source = source,
                sourceFindingId = sourceFindingId,
                addedAtMillis = nowMillis
            )
        }

    /**
     * Append every missing frame in [frameNumbers], ascending, with the given provenance.
     *
     * Pre-existing entries are left untouched (no provenance upgrade); only newly
     * appended frames carry [source] / [sourceFindingId].
     */
    fun addAll(
        items: List<EvidenceItem>,
        frameNumbers: Collection<Long>,
        source: EvidenceSource,
        sourceFindingId: String?,
        nowMillis: Long
    ): List<EvidenceItem> {
        val existing = items.mapTo(HashSet()) { it.frameNumber }
        val appended = frameNumbers
            .filterNot { it in existing }
            .distinct()
            .sorted()
            .map { frame ->
                EvidenceItem(
                    frameNumber = frame,
                    source = source,
                    sourceFindingId = sourceFindingId,
                    addedAtMillis = nowMillis
                )
            }
        return if (appended.isEmpty()) items else items + appended
    }

    /**
     * Remove every entry whose frame number equals [frameNumber].
     *
     * All matches are dropped (including any theoretical duplicates); the
     * remaining entries keep their original relative order. When nothing
     * matches, the input list reference is returned unchanged so callers can
     * detect a no-op. This never touches notes, bookmarks, or findings — a
     * frame removed from evidence keeps any note it carries.
     */
    fun remove(items: List<EvidenceItem>, frameNumber: Long): List<EvidenceItem> {
        if (items.none { it.frameNumber == frameNumber }) return items
        return items.filterNot { it.frameNumber == frameNumber }
    }

    /**
     * Remove every entry whose frame number is in [frameNumbers], dropping all
     * matches (including any theoretical duplicates). The remaining entries keep
     * their original relative order.
     *
     * Frame numbers in [frameNumbers] that do not appear in [items] are ignored
     * — they are not an error and never throw. When [frameNumbers] is empty, or
     * when none of its members match, the input list reference is returned
     * unchanged so callers can detect a no-op. This never mutates [items] and
     * never touches notes, bookmarks, or findings.
     */
    fun removeAll(items: List<EvidenceItem>, frameNumbers: Collection<Long>): List<EvidenceItem> {
        if (frameNumbers.isEmpty()) return items
        val toRemove = frameNumbers.toSet()
        if (items.none { it.frameNumber in toRemove }) return items
        return items.filterNot { it.frameNumber in toRemove }
    }
}
