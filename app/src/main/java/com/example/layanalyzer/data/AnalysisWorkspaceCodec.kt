// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.AgentSavedFinding
import com.example.layanalyzer.model.AnalysisWorkspace
import com.example.layanalyzer.model.EvidenceItem
import com.example.layanalyzer.model.EvidenceSource
import com.example.layanalyzer.model.WorkspaceNote
import com.example.layanalyzer.model.WorkspaceNoteSourceType
import org.json.JSONArray
import org.json.JSONObject

/**
 * Pure JSON codec for [AnalysisWorkspace] persistence.
 *
 * Extracted from [AnalysisWorkspaceStore] so the migration rules can be unit
 * tested without an Android Context (this module has no Robolectric).
 */
internal object AnalysisWorkspaceCodec {

    fun encode(workspace: AnalysisWorkspace): JSONObject = JSONObject()
        .put("fileFingerprint", workspace.fileFingerprint)
        .put("displayName", workspace.displayName)
        .put("analysisConfigVersion", workspace.analysisConfigVersion)
        .put("displayFilter", workspace.displayFilter)
        .put("selectedFrame", workspace.selectedFrame ?: JSONObject.NULL)
        .put("bookmarks", JSONArray(workspace.bookmarks.sorted()))
        .put("evidenceItems", JSONArray().apply {
            workspace.evidenceItems.forEach { item ->
                put(
                    JSONObject()
                        .put("frameNumber", item.frameNumber)
                        .put("source", item.source.name)
                        .put("sourceFindingId", item.sourceFindingId ?: JSONObject.NULL)
                        .put("addedAtMillis", item.addedAtMillis)
                )
            }
        })
        // Dual-write: legacy apps can still restore the frames (provenance is lost).
        .put("evidenceFrames", JSONArray(workspace.evidenceFrames.sorted()))
        .put("tags", JSONArray(workspace.tags.sorted()))
        .put("filterHistory", JSONArray(workspace.filterHistory))
        .put("favoriteFilters", JSONArray(workspace.favoriteFilters.sorted()))
        .put("agentFindings", JSONArray().apply {
            workspace.agentFindings.forEach { finding ->
                put(
                    JSONObject()
                        .put("findingId", finding.findingId)
                        .put("title", finding.title)
                        .put("summary", finding.summary)
                        .put("sourceId", finding.sourceId)
                        .put("sourceToolCallIds", JSONArray(finding.sourceToolCallIds))
                        .put("evidenceFrames", JSONArray(finding.evidenceFrames.sorted()))
                        .put("savedAtMillis", finding.savedAtMillis)
                )
            }
        })
        .put("notes", JSONArray().apply {
            workspace.notes.forEach { note ->
                put(
                    JSONObject()
                        .put("frameNumber", note.frameNumber)
                        .put("text", note.text)
                        .put("updatedAtMillis", note.updatedAtMillis)
                        .put("sourceType", note.sourceType.name)
                        .put("sourceId", note.sourceId ?: JSONObject.NULL)
                )
            }
        })

    fun decode(json: JSONObject): AnalysisWorkspace = AnalysisWorkspace(
        fileFingerprint = json.getString("fileFingerprint"),
        displayName = json.optString("displayName"),
        analysisConfigVersion = json.optInt("analysisConfigVersion", 1),
        displayFilter = json.optString("displayFilter"),
        selectedFrame = json.optLong("selectedFrame").takeIf { it > 0 },
        bookmarks = json.optLongSet("bookmarks"),
        evidenceItems = decodeEvidenceItems(json),
        tags = json.optStringSet("tags"),
        filterHistory = json.optStringList("filterHistory"),
        favoriteFilters = json.optStringSet("favoriteFilters"),
        notes = json.optJSONArray("notes").let { array ->
            if (array == null) emptyList() else List(array.length()) { index ->
                val item = array.getJSONObject(index)
                WorkspaceNote(
                    frameNumber = item.optLong("frameNumber"),
                    text = item.optString("text"),
                    updatedAtMillis = item.optLong("updatedAtMillis"),
                    sourceType = item.optString("sourceType")
                        .let { raw -> WorkspaceNoteSourceType.entries.firstOrNull { it.name == raw } }
                        ?: WorkspaceNoteSourceType.Manual,
                    sourceId = item.optString("sourceId").takeIf { it.isNotBlank() }
                )
            }
        },
        agentFindings = json.optJSONArray("agentFindings").let { array ->
            if (array == null) emptyList() else List(array.length()) { index ->
                val item = array.getJSONObject(index)
                AgentSavedFinding(
                    findingId = item.optString("findingId"),
                    title = item.optString("title"),
                    summary = item.optString("summary"),
                    sourceId = item.optString("sourceId"),
                    sourceToolCallIds = item.optStringList("sourceToolCallIds"),
                    evidenceFrames = item.optLongSet("evidenceFrames"),
                    savedAtMillis = item.optLong("savedAtMillis")
                )
            }
        }
    )

    /**
     * `evidenceItems` is authoritative whenever the key is present; the legacy
     * `evidenceFrames` compatibility field is only used to migrate old files.
     * A disagreement is resolved silently in favour of `evidenceItems`.
     */
    private fun decodeEvidenceItems(json: JSONObject): List<EvidenceItem> {
        if (!json.has("evidenceItems")) {
            return json.optLongSet("evidenceFrames").sorted().map { EvidenceItem(frameNumber = it) }
        }
        val array = json.optJSONArray("evidenceItems") ?: return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            val item = array.optJSONObject(index) ?: return@mapNotNull null
            val frameNumber = item.optLong("frameNumber")
            if (frameNumber <= 0L) return@mapNotNull null
            EvidenceItem(
                frameNumber = frameNumber,
                source = item.optString("source")
                    .let { raw -> EvidenceSource.entries.firstOrNull { it.name == raw } }
                    ?: EvidenceSource.Manual,
                sourceFindingId = item.optString("sourceFindingId").takeIf { it.isNotBlank() },
                addedAtMillis = item.optLong("addedAtMillis")
            )
        }
    }

    private fun JSONObject.optLongSet(name: String): Set<Long> {
        val array = optJSONArray(name) ?: return emptySet()
        return buildSet { for (i in 0 until array.length()) add(array.optLong(i)) }
    }

    private fun JSONObject.optStringSet(name: String): Set<String> {
        val array = optJSONArray(name) ?: return emptySet()
        return buildSet { for (i in 0 until array.length()) array.optString(i).takeIf { it.isNotBlank() }?.let(::add) }
    }

    private fun JSONObject.optStringList(name: String): List<String> {
        val array = optJSONArray(name) ?: return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            array.optString(index).takeIf { it.isNotBlank() }
        }
    }
}
