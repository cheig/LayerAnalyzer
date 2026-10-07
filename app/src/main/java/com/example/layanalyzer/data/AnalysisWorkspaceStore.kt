// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import android.content.Context
import com.example.layanalyzer.model.AnalysisWorkspace
import org.json.JSONObject
import java.io.File

/** Local-only workspace persistence. A workspace is keyed by the capture SHA-256. */
class AnalysisWorkspaceStore(
    context: Context,
    private val fingerprintCalculator: CaptureFingerprintCalculator = CaptureFingerprintCalculator()
) {
    private val preferences = context.applicationContext
        .getSharedPreferences("analysis_workspaces", Context.MODE_PRIVATE)

    fun fingerprint(file: File): String = fingerprintCalculator.calculate(file)

    fun load(fingerprint: String): AnalysisWorkspace? {
        if (fingerprint.isBlank()) return null
        val raw = preferences.getString(key(fingerprint), null) ?: return null
        return runCatching { decode(JSONObject(raw)) }.getOrNull()
    }

    fun save(workspace: AnalysisWorkspace) {
        preferences.edit().putString(key(workspace.fileFingerprint), encode(workspace).toString()).apply()
    }

    fun clear(fingerprint: String) {
        preferences.edit().remove(key(fingerprint)).apply()
    }

    private fun key(fingerprint: String) = "workspace_$fingerprint"

    private fun encode(workspace: AnalysisWorkspace): JSONObject = AnalysisWorkspaceCodec.encode(workspace)

    private fun decode(json: JSONObject): AnalysisWorkspace = AnalysisWorkspaceCodec.decode(json)
}
