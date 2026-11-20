// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import com.example.layanalyzer.capture.tls.KeyLogParseResult
import com.example.layanalyzer.capture.tls.KeyLogParser
import com.example.layanalyzer.capture.tls.TlsSecretAssetRef
import com.example.layanalyzer.capture.tls.TlsSecretStore
import com.example.layanalyzer.model.CaptureArtifactManifest
import com.example.layanalyzer.model.CaptureRetentionPolicy
import java.io.File
import java.io.FilterInputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import org.json.JSONObject

/** Initial archive budgets: bounded by the existing 1 GiB capture quota, 16 MiB keylog limit. */
internal data class TlsBundleLimits(
    val maxBytes: Long = 1024L * 1024 * 1024,
    val maxFiles: Int = 131,
    val maxMetadataBytes: Long = 1024L * 1024
) {
    // ZIP headers and incompressible DEFLATE overhead do not consume the extracted-file budget.
    val maxArchiveBytes: Long get() = maxBytes + maxBytes / 100 + maxFiles * 1024L
}

/**
 * Portable v1 bundle: manifest.json (C08 schema, no local secret asset id), flat PCAP
 * segments, keys.log (NSS), checksums.json (SHA-256 + length for every other entry).
 * Hashes detect corruption, not author authenticity. No CA material is an input.
 * All staging is scoped beneath noBackupFilesDir, outside FileProvider roots.
 */
class TlsCaptureBundle internal constructor(
    private val artifacts: CaptureArtifactRepository,
    private val secrets: TlsSecretStore,
    private val privateRoot: File,
    private val limits: TlsBundleLimits = TlsBundleLimits()
) {
    constructor(context: android.content.Context) : this(
        CaptureArtifactRepository(context), TlsSecretStore(context),
        File(context.applicationContext.noBackupFilesDir, "tls-bundle-work")
    )

    fun writeComplete(
        captureId: String, output: OutputStream, filtered: Boolean, confirmed: Boolean,
        checkCancelled: () -> Unit = {}
    ) = CaptureFileAccess.retain(artifacts.captureDirectory(captureId)).use {
        // Resolve authorization before a plaintext lease is created.
        val state = TlsCaptureExportPlan.requireCompleteSession(
            filtered, confirmed, artifacts.read(captureId), secrets.currentAsset(captureId)
        )
        val original = state.manifest
        require(original.segments.size + 3 <= limits.maxFiles)
        var totalBytes = 0L
        val checksums = JSONObject()
        var captureHeader: PcapGlobalHeader? = null
        ZipOutputStream(output).use { zip ->
            fun entry(name: String, write: (OutputStream) -> Unit): Pair<Long, String> {
                checkCancelled()
                zip.putNextEntry(ZipEntry(name))
                val digest = MessageDigest.getInstance("SHA-256")
                var count = 0L
                val sink = object : OutputStream() {
                    override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)
                    override fun write(bytes: ByteArray, offset: Int, length: Int) {
                        checkCancelled()
                        totalBytes += length
                        count += length
                        require(totalBytes <= limits.maxBytes) { "BUNDLE_BUDGET" }
                        digest.update(bytes, offset, length)
                        zip.write(bytes, offset, length)
                    }
                }
                write(sink)
                zip.closeEntry()
                val hash = hex(digest.digest())
                checksums.put(name, JSONObject().put("bytes", count).put("sha256", hash))
                return count to hash
            }
            val segments = original.segments.mapIndexed { index, segment ->
                val name = "packets-${(index + 1).toString().padStart(4, '0')}.pcap"
                val source = artifacts.resolveSegment(captureId, segment)
                val (length, hash) = entry(name) { sink ->
                    source.inputStream().buffered().use { input ->
                        input.mark(PcapGlobalHeader.SIZE)
                        val header = PcapGlobalHeader.parse(input.readBytesExactly(PcapGlobalHeader.SIZE))
                        require(captureHeader?.isCompatibleWith(header) != false) { "INCOMPATIBLE_SEGMENTS" }
                        captureHeader = header
                        input.reset()
                        val frames = TlsRawCaptureWriter.copy(input, sink, checkCancelled)
                        require(frames == segment.frameCount) { "FRAME_COUNT_MISMATCH" }
                    }
                }
                require(length == segment.lengthBytes && hash == segment.segmentSha256) { "SEGMENT_CHANGED" }
                segment.copy(file = name)
            }
            validateSegments(original.copy(segments = segments))
            secrets.acquireLease(captureId, original.tls.secretsAssetId, checkCancelled).use { lease ->
                require(lease.asset.watermark.sequence == original.secretsPersistedSequence) { "SECRETS_CHANGED" }
                entry(KEYS) { lease.copyForExplicitExport(it, checkCancelled) }
            }
            val portable = original.copy(segments = segments, dissectionGeneration = 0,
                tls = original.tls.copy(secretsAssetId = null, secretsGeneration = 0))
            val metadata = artifacts.encode(portable).toString().toByteArray(Charsets.UTF_8)
            require(metadata.size <= limits.maxMetadataBytes)
            entry(MANIFEST) { it.write(metadata) }
            val index = JSONObject().put("schemaVersion", 1).put("files", checksums)
                .toString().toByteArray(Charsets.UTF_8)
            require(index.size <= limits.maxMetadataBytes)
            require(totalBytes + index.size <= limits.maxBytes) { "BUNDLE_BUDGET" }
            // Do not add the checksums file to its own digest map.
            zip.putNextEntry(ZipEntry(CHECKSUMS))
            zip.write(index)
            zip.closeEntry()
            checkCancelled()
        }
    }

    /** A fresh local id is allocated only after the entire archive has passed validation. */
    fun importComplete(input: InputStream, checkCancelled: () -> Unit = {}): String =
        withWorkspace { workspace ->
            val files = extract(input, workspace, checkCancelled)
            val manifestText = File(workspace, MANIFEST).readText()
            val sourceId = JSONObject(manifestText).getString("captureId")
            val manifest = artifacts.decode(sourceId, manifestText)
            require(manifest.captureIsComplete && manifest.decryptionIsComplete && manifest.packetDrops == 0L)
            require(manifest.tls.secretsAssetId == null && manifest.tls.keylogFormat == "NSS")
            validateSegments(manifest)
            val expected = manifest.segments.map { it.file }.toSet() + setOf(MANIFEST, KEYS, CHECKSUMS)
            require(files == expected) { "UNEXPECTED_BUNDLE_FILE" }
            val checksum = JSONObject(File(workspace, CHECKSUMS).readText())
            require(checksum.keys().asSequence().toSet() == setOf("schemaVersion", "files"))
            require(checksum.get("schemaVersion") == 1)
            val entries = checksum.getJSONObject("files")
            require(entries.keys().asSequence().toSet() == expected - CHECKSUMS)
            for (name in expected - CHECKSUMS) {
                checkCancelled()
                val record = entries.getJSONObject(name)
                require(record.keys().asSequence().toSet() == setOf("bytes", "sha256"))
                val file = File(workspace, name)
                require(record.get("bytes") is Number && record.getLong("bytes") == file.length())
                require(record.getString("sha256") == hash(file, checkCancelled)) { "HASH_MISMATCH" }
            }
            var captureHeader: PcapGlobalHeader? = null
            for (segment in manifest.segments) {
                val file = File(workspace, segment.file)
                require(file.length() == segment.lengthBytes && hash(file, checkCancelled) == segment.segmentSha256)
                // Bundle v1 segments are classic PCAP; DSBs and arbitrary embedded blocks are excluded.
                val header = file.inputStream().use { PcapGlobalHeader.parse(it.readBytesExactly(PcapGlobalHeader.SIZE)) }
                require(captureHeader?.isCompatibleWith(header) != false) { "INCOMPATIBLE_SEGMENTS" }
                captureHeader = header
                file.inputStream().use {
                    require(TlsRawCaptureWriter.copy(it, discard, checkCancelled) == segment.frameCount)
                }
            }
            val parsed = File(workspace, KEYS).inputStream().use {
                KeyLogParser.parse(object : FilterInputStream(it) {
                    override fun read(): Int { checkCancelled(); return super.read() }
                    override fun read(b: ByteArray, off: Int, len: Int): Int {
                        checkCancelled()
                        return `in`.read(b, off, len)
                    }
                })
            } as? KeyLogParseResult.Success ?: error("INVALID_KEYLOG")
            require(parsed.stats.unsupportedLines == 0)
            require(parsed.records.size.toLong() + parsed.stats.duplicateLines == manifest.secretsPersistedSequence)
            val localId = "import-${UUID.randomUUID()}"
            val directory = artifacts.captureDirectory(localId)
            check(directory.parentFile!!.mkdirs() || directory.parentFile!!.isDirectory)
            require(directory.mkdir())
            var imported: TlsSecretAssetRef? = null
            var committed = false
            try {
                for (segment in manifest.segments) {
                    checkCancelled()
                    Files.move(File(workspace, segment.file).toPath(), File(directory, segment.file).toPath())
                }
                imported = secrets.importRecords(localId, parsed, checkCancelled)
                checkCancelled()
                artifacts.commit(manifest.copy(
                    captureId = localId, dissectionGeneration = 0,
                    retentionPolicy = CaptureRetentionPolicy.KeepCaptureAndSecrets,
                    secretsPersistedSequence = imported.watermark.sequence,
                    tls = manifest.tls.copy(secretsAssetId = imported.assetId, secretsGeneration = 0)
                ))
                committed = true
                localId
            } finally {
                if (!committed) {
                    try { imported?.let(secrets::discardUnattachedImport) }
                    finally { deleteFlatDirectory(directory) }
                }
            }
        }

    /** Used by the UI to build before writing to SAF; both success and failure remove staging. */
    internal fun <T> withWorkspace(block: (File) -> T): T {
        return TlsBundleWorkspaces.use(privateRoot, block)
    }

    private fun extract(input: InputStream, directory: File, check: () -> Unit): Set<String> {
        var compressed = 0L
        val bounded = object : FilterInputStream(input) {
            override fun read(): Int = super.read().also { if (it >= 0) checkBudget(1) }
            override fun read(b: ByteArray, off: Int, len: Int): Int =
                `in`.read(b, off, len).also { if (it > 0) checkBudget(it) }
            fun checkBudget(count: Int) { compressed += count; require(compressed <= limits.maxArchiveBytes) }
        }
        val names = HashSet<String>()
        var total = 0L
        ZipInputStream(bounded.buffered()).use { zip ->
            val buffer = ByteArray(64 * 1024)
            try {
                while (true) {
                    check()
                    val entry = zip.nextEntry ?: break
                    val name = entry.name
                    require(!entry.isDirectory && allowed(name) && names.add(name)) { "UNSAFE_BUNDLE_PATH" }
                    require(names.size <= limits.maxFiles)
                    val budget = when (name) {
                        MANIFEST, CHECKSUMS -> limits.maxMetadataBytes
                        KEYS -> KeyLogParser.MAX_TOTAL_BYTES
                        else -> limits.maxBytes
                    }
                    require(entry.size == -1L || entry.size <= budget)
                    var written = 0L
                    File(directory, name).outputStream().use { output ->
                        while (true) {
                            check()
                            val count = zip.read(buffer)
                            if (count < 0) break
                            total += count
                            written += count
                            require(total <= limits.maxBytes && written <= budget) { "BUNDLE_BUDGET" }
                            output.write(buffer, 0, count)
                        }
                    }
                    zip.closeEntry() // checks ZIP CRC as well as the SHA-256 checked later
                }
            } finally { buffer.fill(0) }
        }
        require(names.containsAll(setOf(MANIFEST, KEYS, CHECKSUMS)))
        return names
    }

    private fun validateSegments(manifest: CaptureArtifactManifest) {
        require(manifest.segments.isNotEmpty() && manifest.segments.size + 3 <= limits.maxFiles)
        var next = 1L
        manifest.segments.forEachIndexed { index, segment ->
            require(segment.file == "packets-${(index + 1).toString().padStart(4, '0')}.pcap")
            require(segment.finalized && segment.firstGlobalFrame == next && segment.frameCount >= 0)
            require(segment.frameCount <= limits.maxBytes / 16 && segment.lengthBytes in 24..limits.maxBytes)
            require(Regex("[0-9a-f]{64}").matches(segment.segmentSha256))
            next += segment.frameCount
        }
        val fingerprint = manifest.tls.caFingerprintSha256
        require(fingerprint == null || Regex("[0-9a-f]{64}").matches(fingerprint))
    }

    private fun allowed(name: String) = name in setOf(MANIFEST, KEYS, CHECKSUMS) ||
        Regex("packets-[0-9]{4}\\.pcap").matches(name)

    private fun hash(file: File, check: () -> Unit): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val bytes = ByteArray(64 * 1024)
            try {
                while (true) {
                    check()
                    val count = input.read(bytes)
                    if (count < 0) break
                    digest.update(bytes, 0, count)
                }
            } finally { bytes.fill(0) }
        }
        return hex(digest.digest())
    }

    private fun deleteFlatDirectory(directory: File) {
        require(directory.canonicalFile.parentFile == privateRoot.canonicalFile ||
            directory.name.startsWith("import-") && directory == artifacts.captureDirectory(directory.name))
        require(!Files.isSymbolicLink(directory.toPath()))
        directory.listFiles()?.forEach {
            require(!it.isDirectory && !Files.isSymbolicLink(it.toPath()))
            Files.delete(it.toPath())
        }
        Files.delete(directory.toPath())
    }

    private fun InputStream.readBytesExactly(length: Int): ByteArray =
        ByteArray(length).also { java.io.DataInputStream(this).readFully(it) }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }

    private companion object {
        const val MANIFEST = "manifest.json"
        const val KEYS = "keys.log"
        const val CHECKSUMS = "checksums.json"
        val discard = object : OutputStream() {
            override fun write(value: Int) = Unit
            override fun write(bytes: ByteArray, offset: Int, length: Int) = Unit
        }
    }
}
