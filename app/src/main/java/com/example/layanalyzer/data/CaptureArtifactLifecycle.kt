// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import android.content.Context
import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.capture.tls.TlsAssetException
import com.example.layanalyzer.capture.tls.TlsSecretStore
import com.example.layanalyzer.model.CaptureRetentionPolicy
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.security.MessageDigest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject

enum class CaptureCleanupReason { Deleted, TransientSecretsExpired }
data class CaptureCleanupEvent(
    val captureId: String, val reason: CaptureCleanupReason, val completed: Boolean,
    val captureFingerprints: Set<String> = emptySet()
)
data class CaptureRecoveryResult(val captureId: String, val errorCode: TlsAssetErrorCode? = null)

/** Capture-scoped cleanup. The durable invalidation journal is TLS-313's history/cache
 * integration point; it contains IDs/reasons only, never secrets or decrypted content. */
class CaptureArtifactLifecycle internal constructor(
    private val files: File,
    private val noBackup: File,
    private val secrets: TlsSecretStore,
    private val clearRecords: (List<File>, Boolean, Set<String>) -> Unit = { _, _, _ -> }
) {
    constructor(context: Context) : this(context.applicationContext.filesDir,
        context.applicationContext.noBackupFilesDir, TlsSecretStore(context), { paths, deleted, fingerprints ->
            clearLocalRecords(context.applicationContext, paths, deleted, fingerprints)
        })

    private val captures = CaptureFiles.child(files, "captures")
    private val artifacts = CaptureArtifactRepository(captures)
    private val journal get() = CaptureFiles.child(noBackup, "capture-cleanup-events")

    fun identityForFile(file: File): String = artifacts.captureIdForFile(file) ?: "file-" +
        MessageDigest.getInstance("SHA-256").digest(file.canonicalPath.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 255) }

    fun exportDirectory(file: File): File {
        val root = CaptureFiles.child(files, "exports")
        val directory = CaptureFiles.child(root, identityForFile(file))
        check(directory.mkdirs() || directory.isDirectory)
        return directory
    }

    /** Explicit sharing copies only the generated report into its capture's export namespace. */
    fun exportIntegrityReport(captureFile: File): File {
        if (!captureFile.canonicalFile.toPath().startsWith(captures.canonicalFile.toPath()) ||
            captureFile.extension.lowercase(java.util.Locale.ROOT) !in setOf("pcap", "pcapng"))
            throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        val report = CaptureFiles.child(captureFile.absoluteFile.parentFile!!, "${captureFile.name}.report.json")
        return CaptureFileAccess.retain(captureFile, report).use {
            if (!report.isFile) throw TlsAssetException(TlsAssetErrorCode.NOT_FOUND)
            if (report.length() > 256 * 1024) throw TlsAssetException(TlsAssetErrorCode.CAPACITY_EXCEEDED)
            val directory = exportDirectory(captureFile)
            CaptureFileAccess.retain(directory).use {
                report.copyTo(CaptureFiles.child(directory, report.name), overwrite = true)
            }
        }
    }

    fun purgeFile(file: File) {
        val id = artifacts.captureIdForFile(file)
        if (id != null) purge(id) else {
            if (file.absoluteFile.parentFile?.canonicalFile != captures.canonicalFile)
                throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
            cleanup(identityForFile(file), CaptureCleanupReason.Deleted, file.name)
        }
    }

    fun purge(captureId: String) = cleanup(captureId, CaptureCleanupReason.Deleted)

    internal fun enforceQuota(maxBytes: Long, requiredBytes: Long, protectedFiles: List<File>): Boolean {
        require(maxBytes >= 0 && requiredBytes >= 0)
        if (requiredBytes > maxBytes) return false
        val availableBudget = maxBytes - requiredBytes
        val protectedPaths = protectedFiles.map { it.canonicalFile.toPath() }
        fun storedBytes(file: File): Long = if (file.isDirectory) {
            CaptureFiles.children(file).sumOf(::storedBytes)
        } else {
            file.length()
        }
        fun usageBytes(): Long = CaptureFiles.children(captures).sumOf(::storedBytes)

        var totalBytes = usageBytes()
        val candidates = CaptureFiles.children(captures)
            .filter {
                (it.isDirectory && artifacts.isValidCaptureId(it.name)) ||
                    (it.isFile && it.extension.lowercase() in setOf("pcap", "pcapng"))
            }
            .sortedBy { it.lastModified() }
        for (file in candidates) {
            if (totalBytes <= availableBudget) break
            if (!file.exists()) continue
            val targets = if (file.isDirectory) {
                listOf(file, artifacts.legacyCaptureFile(file.name))
            } else {
                listOf(file)
            }
            if (targets.any { target ->
                val targetPath = target.canonicalFile.toPath()
                protectedPaths.any { protected ->
                    protected.startsWith(targetPath) || targetPath.startsWith(protected)
                }
            }) continue
            try {
                if (file.isDirectory) purge(file.name) else purgeFile(file)
            } catch (_: java.io.IOException) {
                continue
            }
            totalBytes = usageBytes()
        }
        return totalBytes <= availableBudget
    }

    /** Called only after native close AND secret lease release, including file switches. */
    fun analysisClosed(file: File) {
        val id = artifacts.captureIdForFile(file) ?: return
        val state = artifacts.read(id) as? CaptureArtifactState.Present ?: return
        if (state.manifest.retentionPolicy == CaptureRetentionPolicy.KeepCaptureTransientSecrets) {
            publish(id, CaptureCleanupReason.TransientSecretsExpired, false, null)
            CaptureFileAccess.retryWhenReleased { cleanup(id, CaptureCleanupReason.TransientSecretsExpired) }
        }
    }

    private fun cleanup(id: String, reason: CaptureCleanupReason, legacyName: String? = null) {
        val directory = artifacts.captureDirectory(id)
        val legacy = legacyName?.let { CaptureFiles.child(captures, it) }
            ?: artifacts.legacyCaptureFile(id)
        if (legacyName != null && identityForFile(legacy) != id)
            throw TlsAssetException(TlsAssetErrorCode.BINDING_MISMATCH)
        val exported = CaptureFiles.child(CaptureFiles.child(files, "exports"), id)
        val report = CaptureFiles.child(captures, "${legacy.name}.report.json")
        val targets = listOf(directory, legacy, report, exported)
        CaptureFileAccess.idle(targets) {
            targets.forEach(CaptureFiles::checkTree)
            // purgeCapture reserves the secrets directory through this entire transaction.
            secrets.purgeCapture(id, beforePurge = {
                val paths = CaptureFiles.children(directory).filter { it.isFile } + legacy
                val fingerprints = paths.filter { it.isFile && it.extension in setOf("pcap", "pcapng") }
                    .map { CaptureFingerprintCalculator().calculate(it) }.toSet()
                publish(id, reason, false, legacyName, fingerprints)
                clearRecords(paths, reason == CaptureCleanupReason.Deleted, fingerprints)
            }) {
                CaptureFiles.deleteTree(exported)
                if (reason == CaptureCleanupReason.Deleted) {
                    CaptureFiles.deleteTree(directory)
                    CaptureFiles.deleteTree(legacy)
                    CaptureFiles.deleteTree(report)
                } else {
                    val state = artifacts.read(id) as? CaptureArtifactState.Present
                    state?.manifest?.let { manifest ->
                        artifacts.storeRecovered(manifest.copy(secretsPersistedSequence = 0,
                            tls = manifest.tls.copy(secretsAssetId = null, complete = false)))
                    }
                    CaptureFiles.deleteTree(artifacts.analysisFile(id))
                }
                publish(id, reason, true, legacyName)
            }
        }
    }

    /** Runs before engine restore. Active uses return IN_USE and are never swept by age. */
    fun recoverAtStartup(): List<CaptureRecoveryResult> {
        val results = mutableListOf<CaptureRecoveryResult>()
        TlsBundleWorkspaces.cleanup(CaptureFiles.child(noBackup, "tls-bundle-work"))
        secrets.cleanupPlaintextOrphans()
        // Pre-TLS-312 versions put unowned export caches directly in exports/.
        // Current packet/TLS exports use capture subdirectories, which this migration leaves intact.
        val oldExports = CaptureFiles.child(files, "exports")
        CaptureFiles.children(oldExports).filter { it.isFile && LEGACY_PLAINTEXT_EXPORT.matches(it.name) }
            .forEach { file -> CaptureFileAccess.idle(listOf(file)) { CaptureFiles.deleteTree(file) } }
        // A kill during deletion leaves a durable pending intent, replayed idempotently.
        CaptureFiles.children(journal).filter { it.extension == "json" }.forEach { file ->
            var pending = false
            val result = attempt(file.nameWithoutExtension) {
                val json = readEvent(file)
                pending = !json.getBoolean("completed")
                if (pending) cleanup(json.getString("captureId"), CaptureCleanupReason.valueOf(json.getString("reason")),
                    if (json.isNull("legacyName")) null else json.getString("legacyName"))
            }
            if (pending || result.errorCode != null) results += result
        }
        artifacts.captureIds().forEach { id ->
            results += attempt(id) {
                CaptureFileAccess.idle(listOf(artifacts.captureDirectory(id))) {
                    val state = when (val found = artifacts.read(id)) {
                        is CaptureArtifactState.Present -> found
                        is CaptureArtifactState.Corrupt -> throw TlsAssetException(found.reason)
                        else -> throw TlsAssetException(TlsAssetErrorCode.NOT_FOUND)
                    }
                    if (!state.manifest.finalized) {
                        val interrupted = state.manifest.copy(interrupted = true, complete = false,
                            tls = state.manifest.tls.copy(complete = false))
                        artifacts.storeRecovered(interrupted) // failure must still be visibly interrupted
                        val packets = artifacts.recoverPackets(interrupted)
                        artifacts.storeRecovered(packets)
                        if (packets.retentionPolicy == CaptureRetentionPolicy.KeepCaptureAndSecrets) {
                            val ref = secrets.recoverCapture(id)
                            artifacts.storeRecovered(packets.copy(secretsPersistedSequence = ref?.watermark?.sequence ?: 0,
                                tls = packets.tls.copy(secretsAssetId = ref?.assetId, complete = false)))
                        }
                    }
                }
                val state = artifacts.read(id) as? CaptureArtifactState.Present
                if (state?.manifest?.retentionPolicy == CaptureRetentionPolicy.KeepCaptureTransientSecrets)
                    cleanup(id, CaptureCleanupReason.TransientSecretsExpired)
            }
        }
        return results
    }

    /** Durable entries let TLS-313 invalidate historical records even after a process kill. */
    fun cleanupEvents(): List<CaptureCleanupEvent> = CaptureFiles.children(journal)
        .filter { it.extension == "json" }.map { file ->
            val json = readEvent(file)
            CaptureCleanupEvent(json.getString("captureId"), CaptureCleanupReason.valueOf(json.getString("reason")),
                json.getBoolean("completed"), fingerprints(json))
        }

    private fun readEvent(file: File): JSONObject = try {
        if (file.length() !in 1..MAX_EVENT_BYTES) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        val json = JSONObject(file.readText())
        if (json.getInt("schemaVersion") != 1 || json.getString("captureId") != file.nameWithoutExtension ||
            !artifacts.isValidCaptureId(json.getString("captureId")))
            throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        CaptureCleanupReason.valueOf(json.getString("reason"))
        json.getBoolean("completed")
        fingerprints(json)
        json
    } catch (error: TlsAssetException) { throw error }
      catch (_: Exception) { throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT) }

    private fun fingerprints(json: JSONObject): Set<String> {
        val values = json.optJSONArray("captureFingerprints") ?: return emptySet()
        return (0 until values.length()).map { values.getString(it) }.onEach {
            if (!it.matches(Regex("[0-9a-f]{64}"))) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        }.toSet()
    }

    private fun publish(id: String, reason: CaptureCleanupReason, completed: Boolean, legacyName: String?,
                        captureFingerprints: Set<String> = emptySet()) {
        if (!journal.mkdirs() && !journal.isDirectory) throw TlsAssetException(TlsAssetErrorCode.IO_ERROR)
        val target = CaptureFiles.child(journal, "$id.json")
        val allFingerprints = captureFingerprints + if (target.isFile) fingerprints(readEvent(target)) else emptySet()
        val temporary = File.createTempFile("event-", ".tmp", journal)
        try {
            val encoded = JSONObject().put("schemaVersion", 1).put("captureId", id)
                .put("reason", reason.name).put("completed", completed)
                .put("captureFingerprints", org.json.JSONArray(allFingerprints.sorted()))
                .put("legacyName", legacyName ?: JSONObject.NULL).toString().toByteArray(Charsets.UTF_8)
            if (encoded.size > MAX_EVENT_BYTES) throw TlsAssetException(TlsAssetErrorCode.CAPACITY_EXCEEDED)
            FileOutputStream(temporary).use { output ->
                output.write(encoded)
                output.fd.sync()
            }
            Files.move(temporary.toPath(), target.toPath(), ATOMIC_MOVE, REPLACE_EXISTING)
            synchronized(changes) { changes.value++ }
        } finally { temporary.delete() }
    }

    private fun attempt(id: String, block: () -> Unit): CaptureRecoveryResult = try {
        block(); CaptureRecoveryResult(id)
    } catch (error: TlsAssetException) { CaptureRecoveryResult(id, error.code) }
      catch (_: java.io.IOException) { CaptureRecoveryResult(id, TlsAssetErrorCode.IO_ERROR) }

    companion object {
        private const val MAX_EVENT_BYTES = 1024L * 1024 // same as the capture manifest metadata budget
        private val LEGACY_PLAINTEXT_EXPORT = Regex("(?:tls-stream-.*\\.bin|packet-.*-(?:details\\.txt|bytes\\.hex\\.txt)|http-objects-.*\\.zip|[0-9]+-.*)")
        private val changes = MutableStateFlow(0L)
        val cleanupRevision = changes.asStateFlow()

        private fun clearLocalRecords(context: Context, paths: List<File>, deleted: Boolean, fingerprints: Set<String>) {
            val workspaces = AnalysisWorkspaceStore(context)
            fingerprints.forEach(workspaces::clear)
            val bookmarks = context.getSharedPreferences("packet_bookmarks", Context.MODE_PRIVATE).edit()
            paths.forEach { file ->
                bookmarks.remove(file.absolutePath)
            }
            if (!bookmarks.commit()) throw TlsAssetException(TlsAssetErrorCode.IO_ERROR)
            if (deleted) {
                val prefs = context.getSharedPreferences("recent_captures", Context.MODE_PRIVATE)
                val old = org.json.JSONArray(prefs.getString("items", "[]"))
                val next = org.json.JSONArray()
                val removed = paths.map { it.canonicalPath }.toSet()
                for (index in 0 until old.length()) {
                    val row = old.getJSONObject(index)
                    if (File(row.getString("localPath")).canonicalPath !in removed) next.put(row)
                }
                if (!prefs.edit().putString("items", next.toString()).commit()) throw TlsAssetException(TlsAssetErrorCode.IO_ERROR)
            }
        }
    }
}
