// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.model.TlsCaptureStats
import com.example.layanalyzer.model.TlsCaptureStatus
import com.example.layanalyzer.model.TlsConnectionEvent
import com.example.layanalyzer.model.TlsConnectionPhase
import com.example.layanalyzer.model.TlsError
import com.example.layanalyzer.model.TlsErrorCode
import com.example.layanalyzer.data.CaptureFileAccess
import com.example.layanalyzer.data.CaptureFiles
import java.io.BufferedOutputStream
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.StandardOpenOption.APPEND
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.PosixFilePermissions
import java.util.ArrayDeque
import java.util.LinkedHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import org.json.JSONException
import org.json.JSONObject
import org.json.JSONTokener

/**
 * Where accepted ordinary connection events are durably recorded (C04, design §8.3).
 *
 * A producer hands over an already-serialized C04 record and is never made to wait
 * for the disk: a relay must not block on its event log (§6.5). Implementations
 * therefore copy the text and return. The sink only ever receives ordinary events —
 * never a keylog line, a secret, a token or a private key (C03 6).
 */
interface TlsConnectionEventSink : AutoCloseable {
    /** Copies one bounded C04 record. Never waits for disk or queue space. */
    fun offer(line: String)

    /** Reads persisted records in write order, at most [limit]; a missing file reads as empty. */
    fun readLines(limit: Int = DEFAULT_HISTORY_LINES): List<String>

    /** Lines not persisted: overflow, closed/failed sink, invalid length or disk failure. */
    val droppedLines: Long get() = 0L

    val queueMetrics: TlsJournalMetrics? get() = null

    override fun close()

    companion object {
        /** History is read back lazily, never all at once (requirement 2). */
        const val DEFAULT_HISTORY_LINES = 4096
    }
}

/**
 * The default sink: one C04 record per line in `tls-connections.jsonl` (design §8.3).
 *
 * A single daemon thread drains a bounded queue, so [offer] never touches the file
 * and a stalled disk costs a bounded number of records (counted in [droppedLines])
 * instead of stalling the relay. [readLines] reads the file back lazily for history,
 * so a long capture is never held resident.
 */
data class TlsJournalMetrics(
    val queued: Int,
    val peakQueued: Long,
    val inFlight: Boolean,
    val persisted: Long,
    val notPersisted: Long,
    val writeFailures: Long,
    val closeTimedOut: Boolean,
    val workerAlive: Boolean,
    val fileBytes: Long = 0,
    val capacityDropped: Long = 0
)

class TlsConnectionJournal internal constructor(
    private val file: File,
    capacity: Int,
    private val maxFileBytes: Long,
    threadFactory: (Runnable) -> Thread,
    private val privateRoot: File? = null
) : TlsConnectionEventSink {
    constructor(file: File, capacity: Int = DEFAULT_CAPACITY, maxFileBytes: Long = MAX_FILE_BYTES,
        privateRoot: File? = null) :
        this(file, capacity, maxFileBytes, { Thread(it, "tls-connection-journal") }, privateRoot)

    init {
        require(capacity in 1..MAX_CAPACITY) { "connection journal capacity out of range" }
        require(maxFileBytes in 1..MAX_FILE_BYTES) { "connection journal file budget out of range" }
        require(privateRoot == null || file.absoluteFile.toPath().normalize().startsWith(
            privateRoot.absoluteFile.toPath().normalize())) { "connection journal escaped its private root" }
    }

    private val queue = LinkedBlockingQueue<String>(capacity)
    private val dropped = AtomicLong()
    private val peakQueued = AtomicLong()
    private val persisted = AtomicLong()
    private val writeFailures = AtomicLong()
    private val fileBytes = AtomicLong()
    private val capacityDropped = AtomicLong()
    private val offerGate = Object()
    @Volatile private var inFlight = false
    @Volatile private var failed = false
    @Volatile private var closeTimedOut = false
    @Volatile private var closed = false

    // Retain before starting the worker, including its directory-creation window.
    // A timed-out close cannot let capture deletion race a still-running writer.
    private val fileUse = CaptureFileAccess.retain(file)
    private val worker = threadFactory(Runnable { drain() }).apply {
        isDaemon = true
        try { start() } catch (error: Exception) { fileUse.close(); throw error }
    }

    override fun offer(line: String) {
        if (line.isEmpty()) return
        synchronized(offerGate) {
            if (closed || failed || line.length > MAX_LINE_CHARS || '\n' in line || '\r' in line || !queue.offer(line)) {
                dropped.incrementAndGet()
            } else {
                peakQueued.accumulateAndGet(queue.size.toLong(), ::maxOf)
                offerGate.notifyAll()
            }
        }
    }

    override val droppedLines: Long get() = dropped.get()
    override val queueMetrics: TlsJournalMetrics get() = synchronized(offerGate) {
        TlsJournalMetrics(queue.size, peakQueued.get(), inFlight, persisted.get(), dropped.get(),
            writeFailures.get(), closeTimedOut, worker.isAlive, fileBytes.get(), capacityDropped.get())
    }

    override fun readLines(limit: Int): List<String> {
        if (limit <= 0 || !Files.isRegularFile(file.toPath(), NOFOLLOW_LINKS) || file.length() > MAX_FILE_BYTES) return emptyList()
        val lines = ArrayList<String>()
        return try {
            validateAncestors()
            // readLine() would allocate an unbounded buffer for a damaged legacy
            // file. Read a bounded number of bounded records instead.
            Files.newInputStream(file.toPath(), NOFOLLOW_LINKS).bufferedReader().use { reader ->
                val line = StringBuilder()
                var readChars = 0L
                while (lines.size < minOf(limit, TlsConnectionEventSink.DEFAULT_HISTORY_LINES)) {
                    val next = reader.read()
                    if (next < 0) break // an incomplete crash tail is not a record
                    if (++readChars > MAX_FILE_BYTES) return emptyList()
                    if (next == '\n'.code) {
                        if (line.isNotBlank()) lines.add(line.toString())
                        line.setLength(0)
                    } else {
                        if (next == '\r'.code || line.length >= MAX_LINE_CHARS) return emptyList()
                        line.append(next.toChar())
                    }
                }
            }
            lines
        } catch (_: IOException) {
            emptyList()
        }
    }

    override fun close() {
        synchronized(offerGate) { closed = true; offerGate.notifyAll() }
        if (worker !== Thread.currentThread() && worker.isAlive) worker.join(JOIN_TIMEOUT_MILLIS)
        closeTimedOut = worker.isAlive
    }

    private fun drain() {
        try {
            preparePrivateFile()
            fileBytes.set(file.length())
            BufferedOutputStream(Files.newOutputStream(file.toPath(), WRITE, APPEND, NOFOLLOW_LINKS)).use { writer ->
                // Drain what is queued and keep draining until close() says stop and the
                // queue is empty; flush per record so history sees durable lines promptly.
                while (!closed || !queue.isEmpty()) {
                    val line = synchronized(offerGate) {
                        while (queue.isEmpty() && !closed) offerGate.wait(POLL_MILLIS)
                        queue.poll().also { if (it != null) inFlight = true }
                    } ?: continue
                    try {
                        val bytes = (line + "\n").toByteArray(StandardCharsets.UTF_8)
                        if (bytes.size > maxFileBytes - fileBytes.get()) {
                            capacityDropped.incrementAndGet()
                            dropped.incrementAndGet()
                            continue
                        }
                        writer.write(bytes)
                        writer.flush()
                        fileBytes.addAndGet(bytes.size.toLong())
                        persisted.incrementAndGet()
                    } catch (error: IOException) {
                        dropped.incrementAndGet()
                        throw error
                    } finally {
                        synchronized(offerGate) { inFlight = false }
                    }
                }
            }
        } catch (_: IOException) {
            writeFailures.incrementAndGet()
            // A failed journal must not take the capture down; every undelivered line is counted.
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } finally {
            synchronized(offerGate) {
                failed = true
                dropped.addAndGet(queue.size.toLong())
                queue.clear()
            }
            fileUse.close()
        }
    }

    private fun validateAncestors() {
        val parent = file.absoluteFile.parentFile ?: throw IOException("INVALID_ARGUMENT")
        // Android owns aliases above filesDir (e.g. /data/user/0). The factory
        // supplies its trusted private root; reject links from that root down.
        val boundary = privateRoot?.absoluteFile?.toPath()?.normalize()
        var ancestor = parent
        while (true) {
            val enclosing = ancestor.parentFile ?: break
            if (Files.isSymbolicLink(ancestor.toPath())) throw IOException("INVALID_ARGUMENT")
            // Windows junctions are not reported as symbolic links.
            if (ancestor.toPath().fileSystem.separator == "\\")
                CaptureFiles.child(enclosing, ancestor.name)
            if (ancestor.toPath().normalize() == boundary) break
            ancestor = enclosing
        }
    }

    private fun preparePrivateFile() {
        validateAncestors()
        val parent = file.absoluteFile.parentFile ?: throw IOException("INVALID_ARGUMENT")
        val posix = file.toPath().fileSystem.supportedFileAttributeViews().contains("posix")
        if (posix) {
            Files.createDirectories(parent.toPath(), PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")))
        } else Files.createDirectories(parent.toPath())
        CaptureFiles.child(parent, file.name)
        if (!Files.exists(file.toPath(), NOFOLLOW_LINKS)) {
            if (posix) Files.createFile(file.toPath(), PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rw-------")))
            else Files.createFile(file.toPath())
        }
        if (!Files.isRegularFile(file.toPath(), NOFOLLOW_LINKS)) throw IOException("INVALID_FORMAT")
        if (posix) Files.setPosixFilePermissions(file.toPath(), PosixFilePermissions.fromString("rw-------"))
    }

    private companion object {
        const val MAX_FILE_BYTES = 16L * 1024 * 1024
        const val MAX_LINE_CHARS = 8192
        const val DEFAULT_CAPACITY = 4096
        const val MAX_CAPACITY = 1 shl 20
        const val POLL_MILLIS = 50L
        const val JOIN_TIMEOUT_MILLIS = 2_000L
    }
}

/**
 * Budgets of the connection store. A value above a ceiling is rejected, not
 * clamped (C03 9): a store that silently accepted a larger queue would hold more
 * than the capture's budget allows.
 */
data class TlsConnectionStoreLimits(
    val maxEvents: Int = DEFAULT_MAX_EVENTS,
    val maxConnections: Int = DEFAULT_MAX_CONNECTIONS,
    val uiRefreshIntervalMillis: Long = DEFAULT_UI_REFRESH_MILLIS
) {
    init {
        if (maxEvents !in 1..MAX_EVENTS || maxConnections !in 1..MAX_CONNECTIONS ||
            uiRefreshIntervalMillis !in MIN_UI_REFRESH_MILLIS..MAX_UI_REFRESH_MILLIS
        ) {
            throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        }
    }

    companion object {
        /** C10's ordinary-event budget, the same one the engine's queue uses. */
        const val DEFAULT_MAX_EVENTS = 1024
        const val MAX_EVENTS = DEFAULT_MAX_EVENTS

        /** Retained per-connection states; bounded for the same reason. */
        const val DEFAULT_MAX_CONNECTIONS = 1024
        const val MAX_CONNECTIONS = DEFAULT_MAX_CONNECTIONS

        /**
         * C10's fastest UI refresh. It is a floor rather than a default: a reader
         * allowed to publish faster than that would spend the device's time
         * redrawing a list that is still being written, and the capture's own
         * event rate does not justify it.
         */
        const val DEFAULT_UI_REFRESH_MILLIS = 250L
        const val MIN_UI_REFRESH_MILLIS = DEFAULT_UI_REFRESH_MILLIS
        const val MAX_UI_REFRESH_MILLIS = 60_000L
    }
}

/** Counts derived from the events this store accepted. Integers only. */
data class TlsConnectionCounts(
    val accepted: Long = 0,
    val proxied: Long = 0,
    val passthrough: Long = 0,
    val closed: Long = 0,
    val failed: Long = 0,
    val handshakeFailed: Long = 0,
    val secretsIncomplete: Long = 0,
    val secretsSaved: Long = 0,
    val secretRecordsAccepted: Long = 0,
    val secretRecordsPersisted: Long = 0,
    val eventsDropped: Long = 0,
    val eventsRejected: Long = 0,
    /** Ordinary events the journal had to refuse because its bounded queue was full (C10 honesty). */
    val eventsNotPersisted: Long = 0,
    val connectionStatesEvicted: Long = 0,
    /** Applied events retired from the bounded history; counters/states are already updated. */
    val eventHistoryEvicted: Long = 0
)

/**
 * The two byte counters, which belong to the engine and not to this store.
 *
 * The relay is the only place that knows how many application bytes it copied
 * into each side (TLS-211's `Result`), and the SOCKS hop counts the same
 * connection from the app's side of the proxy, so a store that added the two
 * would report roughly double. [TlsConnectionStore.recordEngineStats] therefore
 * *replaces* these numbers and never accumulates them.
 */
data class TlsTrafficCounts(
    val bytesToUpstream: Long = 0,
    val bytesToDownstream: Long = 0,
    val engineEventsDropped: Long = 0
)

/** A reader's view of the store: counts, fixed strings and bounded lists only. */
data class TlsConnectionSnapshot(
    val captureId: String,
    val status: TlsCaptureStatus,
    /** The highest event sequence applied so far — the reader's own cursor. */
    val sequence: Long,
    val counts: TlsConnectionCounts,
    val traffic: TlsTrafficCounts,
    /** One retained state per connection, most recently updated first, bounded by [TlsConnectionStoreLimits.maxConnections]. */
    val connections: List<TlsConnectionEvent>,
    val runtimeMetrics: TlsRuntimeMetrics? = null,
    val engineDiagnostics: TlsEngineDiagnostics? = null
) {
    /**
     * The model the capture UI already renders. `decryptedConnections` stays
     * zero: only the analyser that actually recovered application data from a
     * capture may claim that (C03 7, §10.2), and reporting the proxy's own
     * success as "decryptable" is exactly the substitution the design forbids.
     * QUIC is not accounted for here either; it belongs to the UDP path.
     */
    fun toCaptureStats(): TlsCaptureStats = TlsCaptureStats(
        status = status,
        acceptedConnections = counts.accepted,
        proxiedConnections = counts.proxied,
        secretsSavedConnections = counts.secretsSaved,
        decryptedConnections = 0,
        passthroughConnections = counts.passthrough,
        failedConnections = counts.failed,
        quicUndecryptedConnections = 0,
        secretRecordsAccepted = counts.secretRecordsAccepted,
        secretRecordsPersisted = counts.secretRecordsPersisted
    )
}

/**
 * The UI-side view of one capture's TLS connections (TLS-212).
 *
 * The engine publishes connection events into a bounded queue and the ABI hands
 * them out through `getTlsProxyEvents`. This store is the reader: it parses that
 * envelope into [TlsConnectionEvent]s, keeps a bounded window of the most recent
 * ones, retains one state per connection so a finished connection does not
 * disappear under a burst of newer events, and folds each accepted event into
 * the capture's counters.
 *
 * Three properties are deliberate:
 *
 *  * **It never blocks its producer.** [TlsConnectionStore.recordPoll] and
 *    [TlsConnectionStore.append] copy into bounded structures and return. A
 *    reader that has stopped costs dropped events and nothing else, because a
 *    relay must never wait for a UI (§6.5).
 *  * **Sequence is monotonic.** The engine assigns `eventSequence`, so an event
 *    at or below the applied watermark is a duplicate or an old delivery and is
 *    refused (C04). A connection also has exactly one terminal state: a second
 *    `CLOSED`/`FAILED` for a connection is refused, so a late event cannot
 *    rewrite an outcome the user has already been shown.
 *  * **Counters are separate.** "Proxied", "bypassed", "handshake failed" and
 *    "secret records persisted" are counted independently, because §10.2 counts
 *    them independently and one joined-up number would hide exactly the
 *    difference the user needs — the connection that was intercepted but whose
 *    secrets never reached the disk.
 *
 * The counts are what this reader saw. If it falls behind, the engine drops
 * events and these totals understate the capture; the authoritative numbers stay
 * the engine's `getTlsProxyStats`, whose byte and drop counters
 * [TlsConnectionStore.recordEngineStats] folds in because the event stream
 * cannot carry them.
 */
class TlsConnectionStore(
    val captureId: String,
    private val limits: TlsConnectionStoreLimits = TlsConnectionStoreLimits(),
    private val nanoTime: () -> Long = System::nanoTime,
    /**
     * Where accepted ordinary events are persisted (C04, design §8.3). Optional so a
     * live-only reader is possible; when present, every applied event is copied to it
     * without ever blocking the producer, and rejected/stale events are never written.
     */
    private val journal: TlsConnectionEventSink? = null
) : AutoCloseable {

    /** One connection's retained state. Kept apart from the event so a counter never infers it from a neighbour. */
    private class Record {
        var event: TlsConnectionEvent? = null
        var reachedInterception = false
        var enteredRelay = false
        var bypassed = false
        var incompleteCounted = false
    }

    private val lock = ReentrantLock()
    private val pending = ArrayDeque<TlsConnectionEvent>()
    private val connections = LinkedHashMap<String, Record>()

    private var status = TlsCaptureStatus.DISABLED
    private var sequence = 0L
    private var stopped = false
    private var lastPublishNanos: Long? = null

    private var accepted = 0L
    private var proxied = 0L
    private var passthrough = 0L
    private var closedConnections = 0L
    private var failed = 0L
    private var handshakeFailed = 0L
    private var secretsIncomplete = 0L
    private var secretsSaved = 0L
    private var secretRecordsAccepted = 0L
    private var secretRecordsPersisted = 0L
    private var eventHistoryEvicted = 0L
    private var eventsRejected = 0L
    private var connectionStatesEvicted = 0L
    private var traffic = TlsTrafficCounts()

    init {
        if (!TlsAssetIdentity.validId(captureId)) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
    }

    /** Marks the capture this store follows as running. */
    fun begin(): TlsConnectionSnapshot {
        lock.withLock { if (!stopped) status = TlsCaptureStatus.RUNNING }
        return snapshot()
    }

    /**
     * Copies one event into the store. Returns true when it was applied; false
     * when it was stale, foreign, or arrived after its connection had already
     * ended, in which case nothing changes.
     */
    fun append(event: TlsConnectionEvent): Boolean = lock.withLock { applyLocked(event) }

    /**
     * Parses one `getTlsProxyEvents` response and appends every event in it,
     * returning how many were applied. A malformed envelope applies nothing; an
     * individual malformed or stale event is counted and skipped rather than
     * discarding the rest of the batch.
     */
    fun recordPoll(responseJson: String): Int {
        val events = try {
            val root = parseObject(responseJson)
            if (root.opt("success") == false) return 0
            root.optJSONArray("events") ?: return 0
        } catch (_: JSONException) {
            return 0
        }
        var applied = 0
        lock.withLock {
            for (index in 0 until events.length()) {
                val event = readEvent(events.optJSONObject(index))
                if (event == null) {
                    eventsRejected++
                    continue
                }
                if (applyLocked(event)) applied++
            }
        }
        return applied
    }

    /**
     * Folds the engine's own `getTlsProxyStats` response into the store. Only the
     * values the event stream cannot carry are taken — the relay's byte counts
     * and the engine's drop counter — and they replace the previous values
     * rather than accumulating, so reading the same stats twice cannot double
     * the upstream total. Returns false when the response is not a successful
     * envelope, in which case nothing changes.
     */
    private var runtimeMetrics: TlsRuntimeMetrics? = null
    private var engineDiagnostics: TlsEngineDiagnostics? = null

    fun recordEngineStats(responseJson: String, kotlinQueueBytes: Long? = null): Boolean {
        var metrics: TlsRuntimeMetrics? = null
        val diagnostics: TlsEngineDiagnostics
        val events = try {
            val root = parseObject(responseJson)
            if (root.opt("success") == false) return false
            diagnostics = TlsEngineDiagnostics.read(root)
            val raw = root.optJSONObject("runtimeMetrics")
            if (raw != null && kotlinQueueBytes != null && kotlinQueueBytes >= 0) {
                val entries = raw.optLong("certificateCacheEntries", -1)
                val hits = raw.optLong("certificateCacheHits", -1)
                val queued = raw.optLong("goSecretsQueueBytes", -1)
                if (entries in 0..256 && hits >= 0 && queued in 0..1_048_576 && kotlinQueueBytes <= 1_048_576) {
                    metrics = TlsRuntimeMetrics(entries, hits, queued, kotlinQueueBytes)
                }
            }
            root.optJSONObject("events") ?: return false
        } catch (_: JSONException) {
            return false
        }
        val upstream = events.optLong("bytesToUpstream", -1)
        val downstream = events.optLong("bytesToDownstream", -1)
        val dropped = events.optLong("eventsDropped", -1)
        if (upstream < 0 || downstream < 0 || dropped < 0) return false
        lock.withLock {
            traffic = TlsTrafficCounts(upstream, downstream, dropped)
            runtimeMetrics = metrics
            engineDiagnostics = diagnostics
        }
        return true
    }

    fun journalMetrics(): TlsJournalMetrics? = journal?.queueMetrics

    /** The events whose sequence is newer than [since], oldest first, bounded by the window. */
    fun eventsAfter(since: Long): List<TlsConnectionEvent> = lock.withLock {
        pending.filter { it.eventSequence > since }
    }

    /**
     * Reads persisted ordinary events back from the journal, oldest first (requirement 2).
     *
     * The bounded in-memory window is not the history: a long capture is read back from
     * disk on demand instead of being held resident. Returns an empty list when this store
     * has no journal, when [limit] is not positive, or when nothing newer is stored.
     */
    fun history(since: Long = 0L, limit: Int = TlsConnectionEventSink.DEFAULT_HISTORY_LINES): List<TlsConnectionEvent> {
        val sink = journal ?: return emptyList()
        if (limit <= 0) return emptyList()
        return sink.readLines(limit).mapNotNull { line ->
            try {
                readEvent(parseObject(line))
            } catch (_: JSONException) {
                null
            }
        }.filter { it.captureId == captureId && it.eventSequence > since }
    }

    fun snapshot(): TlsConnectionSnapshot = lock.withLock {
        TlsConnectionSnapshot(
            captureId = captureId,
            status = status,
            sequence = sequence,
            counts = countsLocked(),
            traffic = traffic,
            connections = connections.values.mapNotNull { it.event }.asReversed(),
            runtimeMetrics = runtimeMetrics,
            engineDiagnostics = engineDiagnostics
        )
    }

    /**
     * The C10 refresh gate: true at most once per [TlsConnectionStoreLimits.uiRefreshIntervalMillis].
     */
    fun dueForPublish(nowNanos: Long = nanoTime()): Boolean = lock.withLock {
        if (stopped) return false
        val interval = limits.uiRefreshIntervalMillis * 1_000_000
        val previous = lastPublishNanos
        // The first paint is never delayed, and the elapsed interval is what
        // gates the next one: an absent previous value is not a large number.
        if (previous == null || nowNanos - previous >= interval) {
            lastPublishNanos = nowNanos
            return true
        }
        false
    }

    /** Ends the capture this store was following. */
    override fun close() {
        lock.withLock {
            stopped = true
            status = TlsCaptureStatus.STOPPED
        }
        // Drain and close the journal outside the lock: the writer thread never touches
        // the store, and a slow flush must not hold the lock a reader needs.
        journal?.close()
    }

    /**
     * One C04 record for the journal, using the fixed field names and omitting absent
     * optional fields. It carries only ordinary event metadata: destination, phase,
     * counts and any client_random/SNI already in the event — no token, keylog line or
     * private key can reach this string (C03 6).
     */
    private fun serialize(event: TlsConnectionEvent): String {
        val json = JSONObject()
            .put("captureId", event.captureId)
            .put("connectionId", event.connectionId)
            .put("eventSequence", event.eventSequence)
            .put("monotonicNanos", event.monotonicNanos)
            .put("wallTimeMillis", event.wallTimeMillis)
            .put("destinationIp", event.destinationIp)
            .put("destinationPort", event.destinationPort)
            .put("networkGeneration", event.networkGeneration)
            .put("phase", event.phase.wireName)
            .put("secretRecordsAccepted", event.secretRecordsAccepted)
            .put("secretRecordsPersisted", event.secretRecordsPersisted)
            .put("secretsComplete", event.secretsComplete)
        event.sni?.let { json.put("sni", it) }
        event.downstreamClientRandom?.let { json.put("downstreamClientRandom", it) }
        event.downstreamTls?.let { json.put("downstreamTls", it) }
        event.upstreamTls?.let { json.put("upstreamTls", it) }
        event.alpn?.let { json.put("alpn", it) }
        event.decisionReason?.let { json.put("decisionReason", it) }
        event.error?.let { json.put("errorCode", it.code.wireName) }
        event.upstreamCertificateSha256?.let { json.put("upstreamCertificateSha256", it) }
        return json.toString()
    }

    private fun applyLocked(event: TlsConnectionEvent): Boolean {
        if (event.captureId != captureId) return false
        if (event.eventSequence <= sequence) {
            eventsRejected++
            return false
        }
        val record = connections[event.connectionId]
        if (record?.event?.phase?.isTerminal == true) {
            // A connection has one terminal state (C04). Anything after it is a
            // duplicate or a mistake, and applying it would let a late event
            // rewrite an outcome the user has already been shown.
            eventsRejected++
            return false
        }
        val target = record ?: Record().also {
            if (connections.size >= limits.maxConnections) {
                val victim = connections.entries.firstOrNull { it.value.event?.phase?.isTerminal == true }
                    ?: connections.entries.firstOrNull()
                victim?.key?.let {
                    connections.remove(it)
                    connectionStatesEvicted++
                }
            }
        }
        // Re-inserting on every event keeps the iteration order as "least
        // recently updated first", so the eviction above always drops the
        // connection that has been quiet longest.
        connections.remove(event.connectionId)
        connections[event.connectionId] = target
        accountLocked(target, event)
        target.event = event
        sequence = event.eventSequence
        if (pending.size >= limits.maxEvents) {
            pending.removeFirst()
            eventHistoryEvicted++
        }
        pending.addLast(event)
        // Persist only what was just applied. A stale, foreign or already-terminal
        // event returned above, so a rejected event can never be resurrected here or
        // written twice (requirement 3).
        journal?.offer(serialize(event))
        return true
    }

    /** Folds one accepted event into its connection's record and the capture counters. */
    private fun accountLocked(record: Record, event: TlsConnectionEvent) {
        if (record.event == null) accepted++
        when (event.phase) {
            TlsConnectionPhase.SNIFFING, TlsConnectionPhase.UPSTREAM_HANDSHAKE,
            TlsConnectionPhase.DOWNSTREAM_HANDSHAKE -> record.reachedInterception = true
            TlsConnectionPhase.RELAYING -> {
                record.reachedInterception = true
                if (!record.enteredRelay) {
                    record.enteredRelay = true
                    proxied++
                }
            }
            TlsConnectionPhase.PASSTHROUGH -> {
                // A bypassed connection is not being intercepted: a failure later
                // on is a forwarding failure, not a handshake failure.
                if (!record.bypassed) {
                    record.bypassed = true
                    passthrough++
                }
                record.reachedInterception = false
            }
            TlsConnectionPhase.CLOSED -> closedConnections++
            TlsConnectionPhase.FAILED -> {
                failed++
                if (!record.enteredRelay && !record.bypassed) handshakeFailed++
            }
            else -> Unit
        }
        // A connection's own counts are cumulative, so the capture total grows by
        // the difference and never by a value that is reported again.
        val previous = record.event
        val acceptedDelta = event.secretRecordsAccepted - (previous?.secretRecordsAccepted ?: 0L)
        if (acceptedDelta > 0) secretRecordsAccepted += acceptedDelta
        val persistedDelta = event.secretRecordsPersisted - (previous?.secretRecordsPersisted ?: 0L)
        if (persistedDelta > 0) secretRecordsPersisted += persistedDelta
        if (event.phase.isTerminal && event.secretsComplete && event.secretRecordsPersisted > 0) secretsSaved++
        if (event.phase.isTerminal && !event.secretsComplete && record.enteredRelay && !record.incompleteCounted) {
            record.incompleteCounted = true
            secretsIncomplete++
        }
    }

    private fun countsLocked() = TlsConnectionCounts(
        accepted = accepted,
        proxied = proxied,
        passthrough = passthrough,
        closed = closedConnections,
        failed = failed,
        handshakeFailed = handshakeFailed,
        secretsIncomplete = secretsIncomplete,
        secretsSaved = secretsSaved,
        secretRecordsAccepted = secretRecordsAccepted,
        secretRecordsPersisted = secretRecordsPersisted,
        eventsDropped = traffic.engineEventsDropped,
        eventsRejected = eventsRejected,
        eventsNotPersisted = journal?.droppedLines ?: 0L,
        connectionStatesEvicted = connectionStatesEvicted,
        eventHistoryEvicted = eventHistoryEvicted
    )

    private companion object {
        /**
         * One poll response is bounded by the engine (128 events, 256 KiB), so a
         * larger string is not one of ours and is refused before parsing.
         */
        const val MAX_RESPONSE_CHARS = 512 * 1024

        /** Parses one JSON object and rejects trailing content, like the settings reader. */
        fun parseObject(json: String): JSONObject {
            if (json.isEmpty() || json.length > MAX_RESPONSE_CHARS) throw JSONException("response unusable")
            val tokens = JSONTokener(json)
            val root = tokens.nextValue()
            if (root !is JSONObject || tokens.nextClean() != '\u0000') throw JSONException("not one object")
            return root
        }

        /**
         * Reads one engine event. A missing or wrongly typed required field makes
         * the whole event unusable rather than partially applied: a half-read
         * event would corrupt a counter, and silently defaulting a destination
         * would put a connection in the list that does not exist.
         */
        fun readEvent(json: JSONObject?): TlsConnectionEvent? {
            json ?: return null
            // `isNull` covers both an absent key and one written as null, so a
            // missing phase is never mistaken for a present one.
            val phase = if (json.isNull("phase")) TlsConnectionPhase.UNKNOWN else TlsConnectionPhase.fromWire(json.optString("phase"))
            if (phase == TlsConnectionPhase.UNKNOWN) return null
            val capture = json.optionalString("captureId") ?: return null
            val connection = json.optionalString("connectionId") ?: return null
            val sequence = json.optLong("eventSequence", 0L)
            if (sequence <= 0) return null
            val address = json.optionalString("destinationIp") ?: return null
            val port = json.optInt("destinationPort", 0)
            if (port !in 1..65535) return null
            val accepted = json.optLong("secretRecordsAccepted", 0L)
            val persisted = json.optLong("secretRecordsPersisted", 0L)
            if (accepted < 0 || persisted < 0 || persisted > accepted) return null
            return TlsConnectionEvent(
                captureId = capture,
                connectionId = connection,
                eventSequence = sequence,
                monotonicNanos = json.optLong("monotonicNanos", 0L),
                wallTimeMillis = json.optLong("wallTimeMillis", 0L),
                destinationIp = address,
                destinationPort = port,
                networkGeneration = json.optLong("networkGeneration", 0L),
                phase = phase,
                sni = json.optionalString("sni"),
                downstreamClientRandom = json.optionalString("downstreamClientRandom"),
                downstreamTls = json.optionalString("downstreamTls"),
                upstreamTls = json.optionalString("upstreamTls"),
                alpn = json.optionalString("alpn"),
                decisionReason = json.optionalString("decisionReason"),
                error = json.optionalString("errorCode")?.let { TlsError(TlsErrorCode.fromWire(it), null) },
                upstreamCertificateSha256 = json.optionalString("upstreamCertificateSha256"),
                secretRecordsAccepted = accepted,
                secretRecordsPersisted = persisted,
                secretsComplete = json.optBoolean("secretsComplete", false)
            )
        }

        /** The engine omits an optional field rather than writing null, and either way it means "absent". */
        fun JSONObject.optionalString(field: String): String? =
            if (isNull(field)) null else optString(field).takeIf { it.isNotEmpty() }
    }
}
