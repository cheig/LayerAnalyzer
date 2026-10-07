package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.data.AgentAnalysisRepository
import com.example.layanalyzer.data.AgentReadSession
import com.example.layanalyzer.data.CaptureFingerprintCalculator
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.CaptureSessionDataSource
import com.example.layanalyzer.data.CaptureSessionToken
import com.example.layanalyzer.data.ScopedPacketSummaryQuery
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.DisplayFilterResult
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.FollowStreamResult
import com.example.layanalyzer.model.PacketSearchMode
import com.example.layanalyzer.model.PacketSummary
import com.example.layanalyzer.model.ProtocolNode
import kotlinx.coroutines.Dispatchers
import java.io.File

/** Shared JVM harness for the tool-framework tests; no Android or JNI. */
internal class AgentToolTestHarness private constructor(
    val source: FakeSource,
    val coordinator: CaptureSessionCoordinator,
    val repository: AgentAnalysisRepository,
    val token: CaptureSessionToken,
    val snapshot: AgentCaptureSnapshot,
    private val file: File
) : AutoCloseable {
    override fun close() {
        coordinator.invalidateSession()
        source.closeSession()
        file.delete()
    }

    companion object {
        suspend fun create(
            frameCount: Int = 10,
            scope: AnalysisScope = AnalysisScope.CompleteFile,
            configure: FakeSource.() -> Unit = {}
        ): AgentToolTestHarness {
            val source = FakeSource(frameCount)
            val file = File.createTempFile("agent-tool-framework", ".pcap")
            file.writeText("capture")
            source.switchSession(1L, file)
            source.configure()
            val coordinator = CaptureSessionCoordinator(
                dataSource = source,
                fingerprintCalculator = object : CaptureFingerprintCalculator() {
                    override fun calculate(file: File): String = "sha-${file.name}"
                },
                fingerprintDispatcher = Dispatchers.Unconfined
            )
            val token = coordinator.onSessionOpened(checkNotNull(source.currentFile()))
            check(coordinator.prepareFingerprint(token, file).isSuccess)
            val repository = AgentAnalysisRepository(source, coordinator)
            val snapshot = checkNotNull(
                repository.createSnapshot(scope).getOrNull()
            )
            return AgentToolTestHarness(source, coordinator, repository, token, snapshot, file)
        }
    }

    internal class FakeSource(private val frameCount: Int) : CaptureSessionDataSource, AgentReadSession {
        private var handle: Long = 0L
        private var visible: Int = frameCount
        private var filter: String = ""
        private var fileInfo: FileSessionInfo? = null

        /** Every filter this source was asked to apply, in order. */
        val appliedFilters = mutableListOf<String>()

        /** Filters rejected by [validateDisplayFilter]. */
        var invalidFilters: Set<String> = emptySet()

        /** Statistics returned per applied filter; the "" key is the unfiltered read. */
        var statisticsByFilter: Map<String, CaptureStatistics> = emptyMap()

        var expert: ExpertInfoSummary = ExpertInfoSummary()

        /** Bucket values [buildCaptureStatistics] was called with. */
        val requestedBuckets = mutableListOf<Double>()

        /** Visible frame count reported while a non-empty filter is applied. */
        var filteredVisibleCount: Int? = null

        override fun currentSessionHandle(): Long = handle
        override fun currentFile(): FileSessionInfo? = fileInfo
        override fun getFrameCount(): Int = if (handle == 0L) 0 else frameCount
        override fun getVisibleFrameCount(): Int = if (handle == 0L) 0 else visible
        override fun getAppliedDisplayFilter(): String = filter

        override fun applyDisplayFilter(
            filter: String,
            expectedSessionHandle: Long
        ): DisplayFilterResult {
            if (handle == 0L || handle != expectedSessionHandle) {
                return DisplayFilterResult(false, 0, "Session changed")
            }
            appliedFilters += filter
            this.filter = filter
            visible = if (filter.isBlank()) frameCount else filteredVisibleCount ?: frameCount
            return DisplayFilterResult(true, visible)
        }

        override fun validateDisplayFilter(filter: String): Result<Unit> =
            if (filter in invalidFilters) {
                Result.failure(IllegalArgumentException("invalid filter"))
            } else {
                Result.success(Unit)
            }

        override fun cancelLongRunningOperations() = Unit

        /** Summaries returned by frame number; empty unless a test supplies them. */
        var summaries: List<PacketSummary> = emptyList()

        /** Optional Native Scoped Query response used by capability tests. */
        var scopedQuery: ScopedPacketSummaryQuery? = null

        /** Frames returned by [searchPacketFrames], keyed by "mode:query". */
        var searchResults: Map<String, List<Long>> = emptyMap()

        /** Details per frame; a frame absent from the map dissects to null. */
        var details: Map<Long, ProtocolNode> = emptyMap()

        /** Frames whose details were actually read, in order. */
        val readDetailFrames = mutableListOf<Long>()

        override fun getPacketSummaries(start: Int, count: Int): List<PacketSummary> =
            getRawPacketSummaries(start, count)

        override fun queryPacketSummariesScoped(
            filter: String,
            start: Int,
            count: Int
        ): ScopedPacketSummaryQuery? = scopedQuery

        override fun getRawPacketSummaries(start: Int, count: Int): List<PacketSummary> {
            if (handle == 0L || start < 0 || count <= 0) return emptyList()
            // `frame.number==N` is honoured because FollowStreamMetadataTool
            // selects boundary frames that way; every other filter narrows to
            // `visible` as before.
            val frames = FRAME_NUMBER_FILTER.findAll(filter)
                .mapNotNull { match -> match.groupValues[1].toLongOrNull() }
                .toSet()
            val pool = if (frames.isEmpty()) {
                summaries.take(visible)
            } else {
                summaries.filter { it.frameNumber in frames }
            }
            return pool.drop(start).take(count)
        }

        override fun getFirstPacketTimestamp(): Double =
            summaries.firstOrNull()?.time?.toDoubleOrNull() ?: 0.0

        override fun searchPacketFrames(mode: PacketSearchMode, query: String): List<Long> =
            searchResults["${mode.nativeName}:$query"].orEmpty()

        override fun getPacketDetails(frameNumber: Long): ProtocolNode? {
            readDetailFrames += frameNumber
            if (details.isNotEmpty()) return details[frameNumber]
            return ProtocolNode(label = "Frame $frameNumber")
        }

        override fun getExpertInfoSummary(): ExpertInfoSummary = expert

        override fun buildCaptureStatistics(bucketSeconds: Double): CaptureStatistics {
            requestedBuckets += bucketSeconds
            return statisticsByFilter[filter]
                ?: CaptureStatistics(packetCount = visible)
        }

        override fun buildCommunicationAnalysis(): CommunicationAnalysis = communication

        /** Aggregated communication input; tests supply the raw message lists. */
        var communication: CommunicationAnalysis = CommunicationAnalysis()

        /** Follow-stream results keyed by "protocol:frameNumber". */
        var followStreams: Map<String, FollowStreamResult> = emptyMap()

        /** Follow-stream reads actually performed, in order. */
        val followedStreams = mutableListOf<String>()

        override fun followStream(frameNumber: Long, protocol: String): FollowStreamResult {
            val key = "$protocol:$frameNumber"
            followedStreams += key
            return followStreams[key] ?: FollowStreamResult(
                protocol = protocol,
                streamId = -1,
                records = emptyList()
            )
        }

        fun switchSession(newHandle: Long, file: File) {
            handle = newHandle
            filter = ""
            visible = frameCount
            fileInfo = FileSessionInfo(
                displayName = file.name,
                sizeBytes = file.length(),
                fileType = "pcap",
                frameCount = frameCount,
                localPath = file.absolutePath
            )
        }

        fun closeSession() {
            handle = 0L
            filter = ""
            visible = 0
            fileInfo = null
        }

        private companion object {
            val FRAME_NUMBER_FILTER = Regex("frame\\.number==(\\d+)")
        }
    }
}

/** Minimal tool used to exercise the runner without touching real analysis. */
internal class FakeTool(
    name: String,
    sensitivity: AgentDataSensitivity = AgentDataSensitivity.Aggregate,
    timeoutMillis: Long = 5_000L,
    version: String = "1",
    schema: AgentJsonObject = DEFAULT_SCHEMA,
    private val frameArgument: String? = null,
    private val body: suspend (Map<String, Any?>, AgentToolContext) -> AgentToolResult
) : AgentTool {
    override val definition = AgentToolDefinition(
        name = name,
        description = "Test tool.",
        inputSchema = schema,
        sensitivity = sensitivity,
        defaultTimeoutMillis = timeoutMillis,
        version = version
    )

    var executionCount: Int = 0
        private set

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        executionCount += 1
        return body(arguments, context)
    }

    override fun detailFrames(arguments: Map<String, Any?>): Collection<Long> {
        val key = frameArgument ?: return emptyList()
        val raw = arguments[key] as? Iterable<*> ?: return emptyList()
        return raw.mapNotNull { (it as? Number)?.toLong() }
    }

    companion object {
        val DEFAULT_SCHEMA: AgentJsonObject = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "properties" to mapOf(
                "filter" to mapOf("type" to "string", "maxLength" to 200),
                "limit" to mapOf("type" to "integer", "minimum" to 1, "maximum" to 100)
            )
        )

        val FRAMES_SCHEMA: AgentJsonObject = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "required" to listOf("frames"),
            "properties" to mapOf(
                "frames" to mapOf(
                    "type" to "array",
                    "maxItems" to 64,
                    "items" to mapOf("type" to "integer", "minimum" to 1)
                )
            )
        )
    }
}
