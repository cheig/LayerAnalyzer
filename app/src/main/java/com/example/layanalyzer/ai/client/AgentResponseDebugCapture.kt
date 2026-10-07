package com.example.layanalyzer.ai.client

import com.example.layanalyzer.BuildConfig
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONObject

/**
 * Debug-only storage for bounded raw model-response dumps.
 *
 * This class deliberately has no request-body or header API.  The transport
 * gives it only hashes and response metadata, then tees bytes into the sink.
 * The sink is bounded independently of the business response reader.
 */
class AgentResponseDebugCapture(
    directory: File,
    private val buildDebug: Boolean = BuildConfig.DEBUG,
    private val continuousEnabledProvider: () -> Boolean = { false },
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    private val root = directory
    private val armed = AtomicBoolean(false)
    // The injected flag defaults to BuildConfig.DEBUG, so a release binary can
    // never arm this through the production construction path; tests may inject
    // either value regardless of the unit-test variant they run under.
    private val enabled = buildDebug

    val isAvailable: Boolean
        get() = enabled

    val isArmed: Boolean
        get() = enabled && armed.get()

    val isContinuousEnabled: Boolean
        get() = enabled && runCatching(continuousEnabledProvider).getOrDefault(false)

    /** Arm exactly one response. Release builds always reject this call. */
    fun armNextResponse(): Boolean {
        if (!enabled) return false
        cleanup()
        return armed.compareAndSet(false, true)
    }

    fun disarm() {
        armed.set(false)
    }

    /** Consume the one-shot switch or honor the debug setting for this request. */
    internal fun begin(request: AgentResponseDebugRequest): Session? {
        if (!enabled) return null
        val oneShot = armed.compareAndSet(true, false)
        if (!oneShot && !isContinuousEnabled) return null
        cleanup()
        root.mkdirs()
        val requestHash = request.requestIdHash.ifBlank { hash(request.requestId) }
        val reference = "${hash(request.runId).take(12)}-$requestHash-${clock()}"
        val base = File(root, "dump-$reference")
        val extension = if (request.streaming) "sse" else "json"
        val part = File(root, "${base.name}.$extension.part")
        return Session(
            root = root,
            reference = reference,
            partFile = part,
            finalFile = File(root, "${base.name}.$extension"),
            metadataFile = File(root, "${base.name}.metadata.json"),
            summaryFile = File(root, "${base.name}.summary.json"),
            request = request,
            clock = clock,
            onFinished = ::cleanup
        )
    }

    /** Apply TTL, count and aggregate-size limits. */
    fun cleanup(nowMillis: Long = clock()) {
        if (!root.isDirectory) return
        val files = root.listFiles()?.filter { it.isFile }.orEmpty()
        files.filter { nowMillis - it.lastModified() > RETENTION_MILLIS }
            .forEach(File::delete)

        val remaining = root.listFiles()?.filter { it.isFile }.orEmpty()
        val groups = remaining
            .groupBy(::dumpGroupKey)
            .toList()
            .sortedBy { (_, filesForDump) -> filesForDump.minOfOrNull(File::lastModified) ?: 0L }
        var total = remaining.sumOf(File::length)
        val removeGroup = { group: List<File> ->
            group.forEach { file ->
                total -= file.length()
                file.delete()
            }
        }
        groups.take((groups.size - MAX_DUMPS).coerceAtLeast(0))
            .forEach { (_, group) -> removeGroup(group) }

        if (total > MAX_TOTAL_BYTES) {
            groups.drop((groups.size - MAX_DUMPS).coerceAtLeast(0))
                .forEach { (_, group) ->
                    if (total <= MAX_TOTAL_BYTES) return@forEach
                    removeGroup(group)
                }
        }
    }

    fun clear() {
        root.listFiles()?.forEach { if (it.isFile) it.delete() }
        armed.set(false)
    }

    fun totalBytes(): Long = root.listFiles()?.filter { it.isFile }?.sumOf(File::length) ?: 0L

    data class Metadata(
        val dumpRef: String,
        val bodyFileName: String,
        val metadataFileName: String,
        val summaryFileName: String,
        val bytes: Long,
        val captureComplete: Boolean,
        val dumpTruncatedReason: String?,
        val processingFailure: String?
    )

    internal class Session internal constructor(
        private val root: File,
        val reference: String,
        private val partFile: File,
        private val finalFile: File,
        private val metadataFile: File,
        private val summaryFile: File,
        private val request: AgentResponseDebugRequest,
        private val clock: () -> Long,
        private val onFinished: () -> Unit
    ) {
        private val output = FileOutputStream(partFile, false)
        private val structure = ByteArrayOutputStreamLimited(STRUCTURE_SAMPLE_BYTES)
        private var writtenBytes = 0L
        private var sourceBytes = 0L
        private var finished = false
        private var truncatedReason: String? = null

        val isAtLimit: Boolean
            get() = truncatedReason != null

        fun write(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size): Int {
            if (finished || length <= 0) return 0
            sourceBytes += length.toLong()
            structure.append(bytes, offset, length)
            val available = (MAX_SINGLE_BYTES - writtenBytes).coerceAtLeast(0L).toInt()
            val count = minOf(length, available)
            try {
                if (count > 0) {
                    output.write(bytes, offset, count)
                    writtenBytes += count.toLong()
                }
                if (count < length) truncatedReason = "size_limit"
            } catch (_: java.io.IOException) {
                // A dump sink is best effort and must never turn a normal
                // model response into a transport failure.
                truncatedReason = "write_error"
            }
            return count
        }

        fun finish(
            httpStatus: Int? = null,
            contentType: String? = null,
            declaredContentLength: Long? = null,
            processingLimitBytes: Long,
            processingFailure: String? = null,
            cancelled: Boolean = false
        ): Metadata {
            if (finished) return readMetadata()
            finished = true
            output.flush()
            output.close()
            val complete = !cancelled && truncatedReason == null && processingFailure == null
            if (complete) partFile.renameTo(finalFile)
            val metadata = JSONObject()
                .put("schema", "AgentResponseDebugCapture")
                .put("schemaVersion", 1)
                .put("dumpRef", reference)
                .put("requestIdHash", request.requestIdHash.ifBlank { hash(request.requestId) })
                .put("runIdHash", hash(request.runId))
                .put("streaming", request.streaming)
                .put("httpStatus", httpStatus ?: JSONObject.NULL)
                .put("contentType", contentType?.take(80) ?: JSONObject.NULL)
                .put("declaredContentLength", declaredContentLength ?: JSONObject.NULL)
                .put("receivedBytes", sourceBytes)
                .put("dumpBytes", writtenBytes)
                .put("processingLimitBytes", processingLimitBytes)
                .put("dumpLimitBytes", MAX_SINGLE_BYTES)
                .put("captureComplete", complete)
                .put("processingFailure", processingFailure ?: JSONObject.NULL)
                .put("dumpTruncatedReason", truncatedReason ?: JSONObject.NULL)
                .put("bodyFile", (if (complete) finalFile else partFile).name)
            metadataFile.writeText(metadata.toString())
            summaryFile.writeText(structureSummary(structure.toByteArray(), request.streaming).toString())
            val result = Metadata(
                dumpRef = reference,
                bodyFileName = (if (complete) finalFile else partFile).name,
                metadataFileName = metadataFile.name,
                summaryFileName = summaryFile.name,
                bytes = writtenBytes,
                captureComplete = complete,
                dumpTruncatedReason = truncatedReason,
                processingFailure = processingFailure
            )
            onFinished()
            return result
        }

        fun abort(processingFailure: String?, cancelled: Boolean = false): Metadata = finish(
            processingLimitBytes = 0L,
            processingFailure = processingFailure,
            cancelled = cancelled
        )

        private fun readMetadata(): Metadata = Metadata(
            dumpRef = reference,
            bodyFileName = if (finalFile.isFile) finalFile.name else partFile.name,
            metadataFileName = metadataFile.name,
            summaryFileName = summaryFile.name,
            bytes = if (finalFile.isFile) finalFile.length() else partFile.length(),
            captureComplete = finalFile.isFile,
            dumpTruncatedReason = truncatedReason,
            processingFailure = null
        )
    }

    companion object {
        const val MAX_SINGLE_BYTES: Long = 8L * 1024 * 1024
        const val MAX_TOTAL_BYTES: Long = 32L * 1024 * 1024
        const val MAX_DUMPS: Int = 4
        const val RETENTION_MILLIS: Long = 24L * 60 * 60 * 1_000L
        private const val STRUCTURE_SAMPLE_BYTES = 256 * 1024

        private fun hash(value: String): String = MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { byte -> "%02x".format(byte) }

        private fun dumpGroupKey(file: File): String {
            val name = file.name.removePrefix("dump-")
            return when {
                name.endsWith(".metadata.json") -> name.removeSuffix(".metadata.json")
                name.endsWith(".summary.json") -> name.removeSuffix(".summary.json")
                name.endsWith(".json.part") -> name.removeSuffix(".json.part")
                name.endsWith(".sse.part") -> name.removeSuffix(".sse.part")
                name.endsWith(".json") -> name.removeSuffix(".json")
                name.endsWith(".sse") -> name.removeSuffix(".sse")
                else -> name
            }
        }

        private fun structureSummary(bytes: ByteArray, streaming: Boolean): JSONObject {
            val text = bytes.toString(Charsets.UTF_8)
            val root = runCatching { JSONObject(text) }.getOrNull()
            val keys = root?.keys()?.asSequence()?.toSet().orEmpty()
            return JSONObject()
                .put("streaming", streaming)
                .put("structureParseFailed", root == null && !streaming)
                .put("topLevelKeyCount", keys.size)
                .put("hasChoices", "choices" in keys)
                .put("hasOutput", "output" in keys)
                .put("hasError", "error" in keys)
                .put("hasReasoningContent", text.contains("reasoning_content"))
                .put("hasToolCalls", text.contains("tool_calls") || text.contains("function_call"))
                .put("sampleBytes", bytes.size)
        }
    }
}

data class AgentResponseDebugRequest(
    val runId: String,
    val requestId: String,
    val requestIdHash: String = "",
    val streaming: Boolean = false
)

private class ByteArrayOutputStreamLimited(private val limit: Int) {
    private val bytes = java.io.ByteArrayOutputStream()

    fun append(source: ByteArray, offset: Int, length: Int) {
        val remaining = (limit - bytes.size()).coerceAtLeast(0)
        if (remaining > 0) bytes.write(source, offset, minOf(remaining, length))
    }

    fun toByteArray(): ByteArray = bytes.toByteArray()
}
