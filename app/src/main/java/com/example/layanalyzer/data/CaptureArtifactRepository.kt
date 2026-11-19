// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import android.content.Context
import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.capture.tls.TlsAssetException
import com.example.layanalyzer.capture.tls.TlsAssetIdentity
import com.example.layanalyzer.model.CaptureArtifactManifest
import com.example.layanalyzer.model.CaptureMode
import com.example.layanalyzer.model.CaptureRetentionPolicy
import com.example.layanalyzer.model.CaptureSegmentRef
import com.example.layanalyzer.model.CaptureTlsAssets
import com.example.layanalyzer.model.PacketVantage
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

/** A non-fatal finding that makes a [CaptureArtifactState.Present] capture incomplete. */
enum class CaptureSegmentIssue {
    SEGMENT_NOT_FINALIZED,
    SEGMENT_FILE_MISSING,
    SEGMENT_LENGTH_MISMATCH,
    SEGMENT_HASH_MISMATCH
}

/**
 * What the local store knows about one [captureId], resolved without guessing
 * (C08): a validated manifest, a legacy single-file capture, an absent id, or a
 * manifest that must be rejected rather than partially trusted.
 */
sealed class CaptureArtifactState {
    abstract val captureId: String

    /** No manifest and no legacy PCAP under this id. */
    data class Missing(override val captureId: String) : CaptureArtifactState()

    /** No manifest, but a legacy `<captureId>.pcap` still opens (TLS-301 step 3). */
    data class Legacy(override val captureId: String, val captureFile: File) : CaptureArtifactState()

    /** The manifest exists but is unreadable, malformed, or structurally unsafe. */
    data class Corrupt(override val captureId: String, val reason: TlsAssetErrorCode) : CaptureArtifactState()

    /** A structurally valid manifest; [issues] lists content that is not trustworthy. */
    data class Present(
        override val captureId: String,
        val manifest: CaptureArtifactManifest,
        val issues: List<CaptureSegmentIssue>
    ) : CaptureArtifactState() {
        /** True only when the commit is complete and every segment verified. */
        val isComplete: Boolean get() = issues.isEmpty() && manifest.captureIsComplete
    }
}

/**
 * The single local entry point for one capture's persisted assets (TLS-301,
 * design §8.3, contract C08). It owns the `filesDir/captures/<captureId>/`
 * layout, the `capture.json` schema v1, and the atomic commit that promotes an
 * unfinalized manifest to a complete one.
 *
 * Guarantees:
 * - The capture id is validated with the same strict rule the secret assets use
 *   ([TlsAssetIdentity.validId]): no separators, no `..`, no absolute path, no
 *   empty or control character. Traversal is rejected, never normalised away.
 * - Segment entries are relative, flat, forward-slash names inside the capture
 *   directory; a manifest that is not is rejected as [CaptureArtifactState.Corrupt].
 * - The manifest is written unfinalized at capture start and only ever carries
 *   `complete = true` after [commit], which verifies every segment file's length
 *   and SHA-256 and never claims completeness on a missing segment.
 * - The manifest JSON contains no absolute secret path, no key material and no
 *   token; a PCAP being complete never implies its TLS decryption is complete.
 *
 * Blocking file I/O; call off the UI thread. Errors reuse [TlsAssetException] and
 * [TlsAssetErrorCode] rather than a parallel error vocabulary.
 */
class CaptureArtifactRepository internal constructor(
    private val capturesRoot: File,
    private val replaceFile: (source: Path, target: Path) -> Unit
) {
    /** Parses and merges a capture's segments into one read-only analysis PCAP. */
    private var assembler: CaptureSegmentAssembler = CaptureSegmentAssembler()

    constructor(capturesRoot: File) : this(capturesRoot, ::atomicReplace)

    constructor(context: Context) : this(File(context.applicationContext.filesDir, CAPTURES_DIRECTORY))

    /** Strict local-id rule shared with the encrypted secret assets. */
    fun isValidCaptureId(captureId: String): Boolean = TlsAssetIdentity.validId(captureId)

    /** `<capturesRoot>/<captureId>`. Validates the id; creates nothing. */
    fun captureDirectory(captureId: String): File {
        requireCaptureId(captureId)
        return CaptureFiles.child(capturesRoot, captureId)
    }

    /** `<capturesRoot>/<captureId>/capture.json`. */
    fun manifestFile(captureId: String): File = File(captureDirectory(captureId), MANIFEST_FILE_NAME)

    /** `<capturesRoot>/<captureId>.pcap`, the pre-manifest single-file layout. */
    fun legacyCaptureFile(captureId: String): File {
        val directory = captureDirectory(captureId)
        return CaptureFiles.child(directory.parentFile!!, "${directory.name}.pcap")
    }

    /** The default merged analysis file for [captureId], derived from its directory. */
    fun analysisFile(captureId: String): File {
        requireCaptureId(captureId)
        return File(captureDirectory(captureId), ANALYSIS_FILE_NAME)
    }

    /** Recognize only our own merged artifact path; never infer a sibling keylog. */
    fun captureIdForAnalysisFile(file: File): String? {
        val parent = file.absoluteFile.parentFile ?: return null
        if (!isValidCaptureId(parent.name) || parent.canonicalFile.parentFile != capturesRoot.canonicalFile) return null
        return parent.name.takeIf { file.canonicalFile == analysisFile(it).canonicalFile && manifestFile(it).isFile }
    }

    /** The append-only C04 ordinary connection-event journal, `<captureId>/tls-connections.jsonl`. */
    fun connectionEventsFile(captureId: String): File {
        requireCaptureId(captureId)
        return File(captureDirectory(captureId), CONNECTION_EVENTS_FILE_NAME)
    }

    /** Local capture identity also works after a merged file/manifest was deleted. */
    fun captureIdForFile(file: File): String? {
        val parent = file.absoluteFile.parentFile ?: return null
        if (parent.canonicalFile.parentFile == capturesRoot.canonicalFile && isValidCaptureId(parent.name)) {
            captureDirectory(parent.name) // reject redirected capture directories
            return parent.name
        }
        return null
    }

    internal fun captureIds(): List<String> = CaptureFiles.children(capturesRoot)
        .filter { it.isDirectory && isValidCaptureId(it.name) }.map { it.name }

    internal fun storeRecovered(manifest: CaptureArtifactManifest) {
        validateStructure(manifest)
        write(manifest.captureId, manifest)
    }

    /** Authenticate/repair secrets in the lifecycle service before publishing this view. */
    internal fun recoverPackets(manifest: CaptureArtifactManifest): CaptureArtifactManifest {
        var firstFrame = 1L
        val segments = manifest.segments.map { segment ->
            val file = resolveSegment(manifest.captureId, segment)
            if (!file.exists()) return@map segment.copy(firstGlobalFrame = firstFrame, finalized = false)
                .also { firstFrame += segment.frameCount }
            val frames = CapturePcapRecovery.recover(file)
            segment.copy(firstGlobalFrame = firstFrame, frameCount = frames,
                lengthBytes = file.length(), segmentSha256 = sha256Hex(file), finalized = true)
                .also { firstFrame += frames }
        }
        return manifest.copy(segments = segments, interrupted = true, complete = false, finalized = false,
            finalizedAtMillis = 0, tls = manifest.tls.copy(complete = false))
    }

    /**
     * The entry point for "open this capture for analysis" (design §8.5).
     *
     * A manifest-backed capture is merged, by parsing, into one read-only PCAP at
     * [analysisFile]; a legacy single-file capture is returned as [CaptureAnalysisSource.Legacy]
     * (its own PCAP is already whole) rather than being treated as a one-segment manifest.
     * A missing/corrupt capture is never partially trusted. Incompatible segment headers,
     * absurd record lengths, no space or an I/O failure throw [TlsAssetException] and leave
     * no file under the final name.
     */
    fun openForAnalysis(
        captureId: String,
        analysisFile: File = analysisFile(captureId),
        isCancelled: () -> Boolean = { false }
    ): CaptureAnalysisSource = openAnalysis(captureId, null, analysisFile, isCancelled)

    /**
     * Merges only one segment for analysis when the whole capture cannot be merged (e.g.
     * no space, requirement 5). The result always carries an explicit incomplete context.
     */
    fun openSingleSegmentForAnalysis(
        captureId: String,
        segmentFile: String,
        analysisFile: File = analysisFile(captureId),
        isCancelled: () -> Boolean = { false }
    ): CaptureAnalysisSource = openAnalysis(captureId, segmentFile, analysisFile, isCancelled)

    private fun openAnalysis(
        captureId: String,
        singleSegmentFile: String?,
        analysisFile: File,
        isCancelled: () -> Boolean
    ): CaptureAnalysisSource = CaptureFileAccess.retain(captureDirectory(captureId)).use {
        openAnalysisOwned(captureId, singleSegmentFile, analysisFile, isCancelled)
    }

    private fun openAnalysisOwned(
        captureId: String,
        singleSegmentFile: String?,
        analysisFile: File,
        isCancelled: () -> Boolean
    ): CaptureAnalysisSource {
        when (val state = read(captureId)) {
            is CaptureArtifactState.Missing -> return CaptureAnalysisSource.Missing(captureId)
            is CaptureArtifactState.Legacy -> return CaptureAnalysisSource.Legacy(captureId, state.captureFile)
            is CaptureArtifactState.Corrupt -> return CaptureAnalysisSource.Refused(captureId, state.reason)
            is CaptureArtifactState.Present -> {
                val manifest = state.manifest
                if (manifest.segments.isEmpty()) {
                    return CaptureAnalysisSource.Refused(captureId, TlsAssetErrorCode.INVALID_FORMAT)
                }
                ensureDirectory(captureDirectory(captureId))
                val chosen: List<CaptureSegmentRef>
                val single: Boolean
                if (singleSegmentFile == null) {
                    chosen = manifest.segments
                    single = false
                } else {
                    val segment = manifest.segments.firstOrNull { it.file == singleSegmentFile }
                        ?: return CaptureAnalysisSource.Refused(captureId, TlsAssetErrorCode.NOT_FOUND)
                    chosen = listOf(segment)
                    single = true
                }
                return assembler.merge(
                    repository = this,
                    captureId = captureId,
                    segments = chosen,
                    analysisFile = analysisFile,
                    manifestIssues = if (single) emptyList() else state.issues,
                    singleSegment = single,
                    isCancelled = isCancelled
                )
            }
        }
    }

    /** Test seam: replaces the segment assembler used by [openForAnalysis]. */
    internal fun installSegmentAssembler(value: CaptureSegmentAssembler) {
        assembler = value
    }

    /** Resolve one segment file, rejecting anything that is not a flat name inside the directory. */
    fun resolveSegment(captureId: String, segment: CaptureSegmentRef): File {
        val directory = captureDirectory(captureId)
        if (!isSafeSegmentName(segment.file)) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        val file = File(directory, segment.file)
        val canonicalDirectory = directory.canonicalFile
        val canonicalFile = file.canonicalFile
        if (canonicalFile.parentFile != canonicalDirectory || canonicalFile == canonicalDirectory) {
            throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        }
        return canonicalFile
    }

    /** The manifest-relative name of a segment file that already sits in the capture directory. */
    fun relativeSegmentFile(captureId: String, segmentFile: File): String {
        val directory = captureDirectory(captureId)
        val name = segmentFile.name
        if (!isSafeSegmentName(name)) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        if (segmentFile.absoluteFile.parentFile?.canonicalFile != directory.canonicalFile) {
            throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        }
        return name
    }

    /**
     * Reads the manifest for [captureId], or falls back to the legacy layout. Never
     * searches the directory for a keylog and never follows a path the manifest names
     * outside the capture directory.
     */
    fun read(captureId: String): CaptureArtifactState {
        val directory = captureDirectory(captureId)
        val manifest = File(directory, MANIFEST_FILE_NAME)
        if (!manifest.exists()) {
            // Legacy layout only: a single flat `<captureId>.pcap` with no manifest.
            // Never scan the directory for a keylog to pair with it (C08).
            val legacy = legacyCaptureFile(captureId)
            return if (legacy.isFile) {
                CaptureArtifactState.Legacy(captureId, legacy)
            } else {
                CaptureArtifactState.Missing(captureId)
            }
        }
        if (Files.isSymbolicLink(manifest.toPath()) || !manifest.isFile) {
            return CaptureArtifactState.Corrupt(captureId, TlsAssetErrorCode.INVALID_FORMAT)
        }
        val parsed = try {
            decode(captureId, readManifestText(manifest))
        } catch (error: TlsAssetException) {
            return CaptureArtifactState.Corrupt(captureId, error.code)
        } catch (_: Exception) {
            return CaptureArtifactState.Corrupt(captureId, TlsAssetErrorCode.INVALID_FORMAT)
        }
        return CaptureArtifactState.Present(captureId, parsed, verifySegments(parsed))
    }

    /**
     * Writes the start-of-capture manifest. `finalized` and `complete` are forced
     * false: a run that is still writing can never be read as a complete capture.
     */
    fun writeUnfinalized(manifest: CaptureArtifactManifest): CaptureArtifactManifest {
        requireCaptureId(manifest.captureId)
        validateStructure(manifest)
        val stored = manifest.copy(
            finalized = false,
            complete = false,
            finalizedAtMillis = 0L,
            segments = manifest.segments.map { it.copy(finalized = false) }
        )
        write(manifest.captureId, stored)
        return stored
    }

    /**
     * Promotes a drained capture to a complete manifest. Requires the caller to
     * already hold a complete, non-interrupted manifest; fills the real length and
     * SHA-256 of every segment and fails (writing nothing complete) if any segment
     * file is missing, so a writer failure can never be published as complete.
     */
    fun commit(manifest: CaptureArtifactManifest): CaptureArtifactManifest {
        requireCaptureId(manifest.captureId)
        validateStructure(manifest)
        if (!manifest.complete || manifest.interrupted) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        val finalizedSegments = manifest.segments.map { segment ->
            val file = resolveSegment(manifest.captureId, segment)
            if (!file.isFile) throw TlsAssetException(TlsAssetErrorCode.NOT_FOUND)
            segment.copy(lengthBytes = file.length(), segmentSha256 = sha256Hex(file), finalized = true)
        }
        val stored = manifest.copy(
            segments = finalizedSegments,
            finalized = true,
            complete = true,
            finalizedAtMillis = System.currentTimeMillis()
        )
        write(manifest.captureId, stored)
        return stored
    }

    private fun verifySegments(manifest: CaptureArtifactManifest): List<CaptureSegmentIssue> {
        val issues = ArrayList<CaptureSegmentIssue>()
        for (segment in manifest.segments) {
            if (!segment.finalized) {
                issues += CaptureSegmentIssue.SEGMENT_NOT_FINALIZED
                continue
            }
            val file = resolveSegment(manifest.captureId, segment)
            if (!file.isFile) {
                issues += CaptureSegmentIssue.SEGMENT_FILE_MISSING
                continue
            }
            if (segment.lengthBytes > 0L && file.length() != segment.lengthBytes) {
                issues += CaptureSegmentIssue.SEGMENT_LENGTH_MISMATCH
            }
            if (segment.segmentSha256.isNotEmpty() && sha256Hex(file) != segment.segmentSha256) {
                issues += CaptureSegmentIssue.SEGMENT_HASH_MISMATCH
            }
        }
        return issues
    }

    private fun write(captureId: String, manifest: CaptureArtifactManifest) {
        val directory = captureDirectory(captureId)
        ensureDirectory(directory)
        val target = File(directory, MANIFEST_FILE_NAME)
        storageOperation { writeManifestAtomic(target, encode(manifest).toString()) }
    }

    private fun writeManifestAtomic(target: File, text: String) {
        val directory = target.parentFile ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        val temporary = File.createTempFile(TEMP_PREFIX, TEMP_SUFFIX, directory)
        try {
            FileOutputStream(temporary).use { output ->
                output.write(text.toByteArray(Charsets.UTF_8))
                output.fd.sync()
            }
            // Stronger than delete-then-rename: swap the temp file into place in one
            // step, so a failure keeps the previous valid manifest byte-for-byte.
            replaceFile(temporary.toPath(), target.toPath())
        } finally {
            temporary.delete()
        }
    }

    internal fun encode(manifest: CaptureArtifactManifest): JSONObject {
        val segments = JSONArray()
        manifest.segments.forEach { segment ->
            segments.put(
                JSONObject()
                    .put("file", segment.file)
                    .put("firstGlobalFrame", segment.firstGlobalFrame)
                    .put("frameCount", segment.frameCount)
                    .put("lengthBytes", segment.lengthBytes)
                    .put("segmentSha256", segment.segmentSha256)
                    .put("finalized", segment.finalized)
            )
        }
        val tls = JSONObject()
            .put("enabled", manifest.tls.enabled)
            .put("caFingerprintSha256", manifest.tls.caFingerprintSha256 ?: JSONObject.NULL)
            .put("secretsAssetId", manifest.tls.secretsAssetId ?: JSONObject.NULL)
            .put("keylogFormat", manifest.tls.keylogFormat)
            .put("secretsGeneration", manifest.tls.secretsGeneration)
            .put("complete", manifest.tls.complete)
        return JSONObject()
            .put("schemaVersion", manifest.schemaVersion)
            .put("captureId", manifest.captureId)
            .put("captureMode", manifest.captureMode.wireName)
            .put("packetVantage", manifest.packetVantage.wireName)
            .put("segments", segments)
            .put("packetDrops", manifest.packetDrops)
            .put("interrupted", manifest.interrupted)
            .put("dissectionGeneration", manifest.dissectionGeneration)
            .put("secretsPersistedSequence", manifest.secretsPersistedSequence)
            .put("retentionPolicy", manifest.retentionPolicy.wireName)
            .put("finalizedAtMillis", manifest.finalizedAtMillis)
            .put("tls", tls)
            .put("finalized", manifest.finalized)
            .put("complete", manifest.complete)
    }

    private fun readManifestText(manifest: File): String {
        if (manifest.length() !in 1..MAX_MANIFEST_BYTES) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        return manifest.inputStream().use { input ->
            val bytes = ByteArray(MAX_MANIFEST_BYTES.toInt() + 1)
            var used = 0
            while (used < bytes.size) {
                val count = input.read(bytes, used, bytes.size - used)
                if (count == -1) break
                if (count == 0) throw TlsAssetException(TlsAssetErrorCode.IO_ERROR)
                used += count
            }
            if (used !in 1..MAX_MANIFEST_BYTES.toInt()) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            String(bytes, 0, used, Charsets.UTF_8)
        }
    }

    internal fun decode(captureId: String, text: String): CaptureArtifactManifest {
        val tokener = JSONTokener(text)
        requireCaptureId(captureId)
        val root = tokener.nextValue() as? JSONObject ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        if (tokener.nextClean() != '\u0000') throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        if (root.keys().asSequence().toSet() != MANIFEST_FIELDS) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        if (longOf(root, "schemaVersion") != CaptureArtifactManifest.SCHEMA_VERSION.toLong()) {
            throw TlsAssetException(TlsAssetErrorCode.UNSUPPORTED_VERSION)
        }
        if (root.get("captureId") != captureId) throw TlsAssetException(TlsAssetErrorCode.BINDING_MISMATCH)
        val captureMode = CaptureMode.fromWire(root.opt("captureMode") as? String)
            ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        val packetVantage = PacketVantage.fromWire(root.opt("packetVantage") as? String)
            ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        val retentionPolicy = CaptureRetentionPolicy.fromWire(root.opt("retentionPolicy") as? String)
            ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)

        val segmentsArray = root.get("segments") as? JSONArray ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        val segments = ArrayList<CaptureSegmentRef>(segmentsArray.length())
        val seen = HashSet<String>()
        for (index in 0 until segmentsArray.length()) {
            val item = segmentsArray.opt(index) as? JSONObject ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            if (item.keys().asSequence().toSet() != SEGMENT_FIELDS) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            val file = item.get("file") as? String ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            // Reject traversal instead of normalising it away; duplicates are unsafe.
            if (!isSafeSegmentName(file) || !seen.add(file)) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            val firstGlobalFrame = longOf(item, "firstGlobalFrame")
            val frameCount = longOf(item, "frameCount")
            val lengthBytes = longOf(item, "lengthBytes")
            if (firstGlobalFrame < 1L || frameCount < 0L || lengthBytes < 0L) {
                throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            }
            val hash = item.get("segmentSha256") as? String ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            if (hash.isNotEmpty() && !LOWER_HEX_64.matches(hash)) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            val finalized = item.get("finalized") as? Boolean ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            segments += CaptureSegmentRef(file, firstGlobalFrame, frameCount, lengthBytes, hash, finalized)
        }

        val tlsObject = root.get("tls") as? JSONObject ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        if (tlsObject.keys().asSequence().toSet() != TLS_FIELDS) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        val tls = CaptureTlsAssets(
            enabled = booleanOf(tlsObject, "enabled"),
            caFingerprintSha256 = nullableString(tlsObject, "caFingerprintSha256"),
            secretsAssetId = nullableString(tlsObject, "secretsAssetId"),
            keylogFormat = tlsObject.get("keylogFormat") as? String ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT),
            secretsGeneration = longOf(tlsObject, "secretsGeneration"),
            complete = booleanOf(tlsObject, "complete")
        )

        return CaptureArtifactManifest(
            captureId = captureId,
            schemaVersion = CaptureArtifactManifest.SCHEMA_VERSION,
            captureMode = captureMode,
            packetVantage = packetVantage,
            segments = segments,
            packetDrops = longOf(root, "packetDrops"),
            interrupted = booleanOf(root, "interrupted"),
            dissectionGeneration = longOf(root, "dissectionGeneration"),
            secretsPersistedSequence = longOf(root, "secretsPersistedSequence"),
            retentionPolicy = retentionPolicy,
            finalizedAtMillis = longOf(root, "finalizedAtMillis"),
            tls = tls,
            finalized = booleanOf(root, "finalized"),
            complete = booleanOf(root, "complete")
        ).also(::validateStructure)
    }

    /** Structural invariants shared by encode and decode; violations are rejected. */
    private fun validateStructure(manifest: CaptureArtifactManifest) {
        if (manifest.schemaVersion != CaptureArtifactManifest.SCHEMA_VERSION) {
            throw TlsAssetException(TlsAssetErrorCode.UNSUPPORTED_VERSION)
        }
        if (manifest.packetDrops < 0L || manifest.secretsPersistedSequence < 0L || manifest.dissectionGeneration < 0L) {
            throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        }
        val seen = HashSet<String>()
        for (segment in manifest.segments) {
            if (!isSafeSegmentName(segment.file) || !seen.add(segment.file)) {
                throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
            }
            if (segment.firstGlobalFrame < 1L || segment.frameCount < 0L || segment.lengthBytes < 0L) {
                throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
            }
        }
    }

    private fun requireCaptureId(captureId: String) {
        if (!isValidCaptureId(captureId)) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
    }

    private fun ensureDirectory(directory: File) {
        if (directory.exists()) {
            if (!directory.isDirectory || Files.isSymbolicLink(directory.toPath())) {
                throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            }
            return
        }
        if (!directory.mkdirs() && !directory.isDirectory) throw TlsAssetException(TlsAssetErrorCode.IO_ERROR)
    }

    private fun longOf(json: JSONObject, name: String): Long = when (val value = json.opt(name)) {
        is Int -> value.toLong()
        is Long -> value
        else -> throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
    }

    private fun booleanOf(json: JSONObject, name: String): Boolean =
        json.opt(name) as? Boolean ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)

    private fun nullableString(json: JSONObject, name: String): String? {
        if (!json.has(name) || json.isNull(name)) return null
        return json.opt(name) as? String ?: throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
    }

    private inline fun <T> storageOperation(operation: () -> T): T = try {
        operation()
    } catch (error: Exception) {
        throw sanitized(error)
    }

    private companion object {
        const val CAPTURES_DIRECTORY = "captures"
        const val MANIFEST_FILE_NAME = "capture.json"
        const val ANALYSIS_FILE_NAME = "merged-analysis.pcap"
        const val CONNECTION_EVENTS_FILE_NAME = "tls-connections.jsonl"
        const val TEMP_PREFIX = "capture-"
        const val TEMP_SUFFIX = ".json.tmp"
        const val MAX_MANIFEST_BYTES = 1024L * 1024L
        val MANIFEST_FIELDS = setOf(
            "schemaVersion", "captureId", "captureMode", "packetVantage", "segments", "packetDrops",
            "interrupted", "dissectionGeneration", "secretsPersistedSequence", "retentionPolicy",
            "finalizedAtMillis", "tls", "finalized", "complete"
        )
        val SEGMENT_FIELDS = setOf(
            "file", "firstGlobalFrame", "frameCount", "lengthBytes", "segmentSha256", "finalized"
        )
        val TLS_FIELDS = setOf(
            "enabled", "caFingerprintSha256", "secretsAssetId", "keylogFormat", "secretsGeneration", "complete"
        )
        val LOWER_HEX_64 = Regex("[0-9a-f]{64}")

        /** Flat relative name only: no separator, no `..`, no drive, no control char. */
        fun isSafeSegmentName(value: String): Boolean {
            if (value.isEmpty() || value.length > 128) return false
            if (value == "." || value == "..") return false
            if (value.any { it < ' ' || it == '\u007f' }) return false
            return value.none { it == '/' || it == '\\' || it == ':' }
        }

        fun sha256Hex(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    digest.update(buffer, 0, read)
                }
            }
            val bytes = digest.digest()
            val builder = StringBuilder(bytes.size * 2)
            for (byte in bytes) {
                val value = byte.toInt() and 0xff
                builder.append(HEX[value ushr 4]).append(HEX[value and 0x0f])
            }
            return builder.toString()
        }

        const val HEX = "0123456789abcdef"

        fun sanitized(error: Exception): Exception = when (error) {
            is TlsAssetException -> error
            is IOException -> {
                val message = error.message.orEmpty().lowercase()
                val full = "enospc" in message || "no space left" in message ||
                    "disk full" in message || "not enough space" in message
                TlsAssetException(if (full) TlsAssetErrorCode.DISK_FULL else TlsAssetErrorCode.IO_ERROR)
            }
            is SecurityException -> TlsAssetException(TlsAssetErrorCode.IO_ERROR)
            else -> error
        }
    }
}

/**
 * One-step replace of [target] by [source] on the same filesystem. Unlike
 * [writeJsonAtomically] it does not delete the target first, so a failure leaves the
 * previous valid version intact (contract C06's "failed replace keeps the old file").
 */
private fun atomicReplace(source: Path, target: Path) {
    Files.move(source, target, ATOMIC_MOVE, REPLACE_EXISTING)
}
