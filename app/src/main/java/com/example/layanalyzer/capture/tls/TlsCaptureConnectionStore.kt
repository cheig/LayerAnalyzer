// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.data.CaptureArtifactRepository
import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.File

/**
 * The service's capture-scoped ordinary-event journal. Disabled requests allocate
 * neither a writer nor a directory. Resolve and validate the path before starting
 * the writer; the coordinator owns the returned store and closes it on stop or
 * startup failure. This file contains C04 metadata, never C06 secret records.
 */
internal fun createTlsCaptureConnectionStore(
    capturesRoot: File,
    captureId: String,
    requested: TlsCaptureSettings
): TlsConnectionStore? {
    if (!requested.enabled) return null
    val journalFile = CaptureArtifactRepository(capturesRoot).connectionEventsFile(captureId)
    return TlsConnectionStore(captureId, journal = TlsConnectionJournal(journalFile, privateRoot = capturesRoot))
}
