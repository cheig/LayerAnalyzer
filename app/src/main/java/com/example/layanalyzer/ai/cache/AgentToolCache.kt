package com.example.layanalyzer.ai.cache

import android.content.Context
import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.model.AgentCacheTier
import com.example.layanalyzer.model.AgentCachedToolResult
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentToolCacheKey
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.Locale

/** Counters exposed to the diagnostics recorder and the settings screen. */
data class AgentToolCacheStats(
    val hits: Long = 0L,
    val misses: Long = 0L,
    val writes: Long = 0L,
    val rejected: Long = 0L,
    val evictions: Long = 0L,
    val entryCount: Int = 0,
    val diskBytes: Long = 0L
)

/**
 * Cache for deterministic local tool results.
 *
 * Two rules shape everything here.
 *
 * First, the key is complete or the cache is wrong: capture fingerprint,
 * analysis configuration version, tool name, normalized argument hash, native
 * build marker and tool version all take part, so a Decode As change, a
 * rebuilt engine or a re-normalized argument all miss rather than serving a
 * result that no longer describes the file.  There is no partial-key lookup.
 *
 * Second, sensitivity decides *where* a result may live, and that decision is
 * made from the tool's declared sensitivity by [AgentCacheTier] rather than by
 * the caller.  Aggregate and Metadata may reach disk; Identifier stays in
 * memory for the process lifetime only; Payload, Credential and any
 * unrecognised sensitivity are refused outright, in both tiers.
 *
 * What is never cached, at any tier: a model request or response, hidden
 * reasoning, a raw tool argument, or anything a provider returned.  A cache
 * entry holds a local tool's own structured data and the counts needed to
 * replay its truncation semantics.
 */
class AgentToolCache(
    private val directory: File?,
    private val maxMemoryEntries: Int = DEFAULT_MAX_MEMORY_ENTRIES,
    private val maxDiskBytes: Long = DEFAULT_MAX_DISK_BYTES,
    private val maxEntryBytes: Int = DEFAULT_MAX_ENTRY_BYTES,
    private val ttlMillis: Long = DEFAULT_TTL_MILLIS,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    constructor(
        context: Context,
        clock: () -> Long = { System.currentTimeMillis() }
    ) : this(File(context.applicationContext.cacheDir, DIRECTORY_NAME), clock = clock)

    private val guard = Any()

    /**
     * Access-ordered so the eldest entry is the least recently *used*, not the
     * least recently written — the whole point of an LRU here is that a result
     * a run keeps re-reading survives while a one-off does not.
     */
    private val memory = object : LinkedHashMap<String, AgentCachedToolResult>(
        16,
        0.75f,
        true
    ) {
        override fun removeEldestEntry(
            eldest: MutableMap.MutableEntry<String, AgentCachedToolResult>
        ): Boolean {
            val evict = size > maxMemoryEntries
            if (evict) evictions += 1
            return evict
        }
    }

    private var hits = 0L
    private var misses = 0L
    private var writes = 0L
    private var rejected = 0L
    private var evictions = 0L

    /** The exact directory a clear action is allowed to remove. */
    val storageDirectory: File?
        get() = directory

    /**
     * Look up [key].  Returns null on a miss, an expired entry or a tier that
     * may not be cached at all.
     */
    fun get(key: AgentToolCacheKey, sensitivity: AgentDataSensitivity): AgentCachedToolResult? {
        val tier = AgentCacheTier.of(sensitivity)
        if (tier == AgentCacheTier.Never) return null
        val storageKey = storageKey(key)

        synchronized(guard) {
            memory[storageKey]?.let { cached ->
                if (isFresh(cached)) {
                    hits += 1
                    return cached
                }
                memory.remove(storageKey)
            }
        }

        if (tier != AgentCacheTier.Disk) {
            synchronized(guard) { misses += 1 }
            return null
        }

        val file = diskFile(storageKey) ?: run {
            synchronized(guard) { misses += 1 }
            return null
        }
        val decoded = readEntry(file, key)
        if (decoded == null || !isFresh(decoded)) {
            file.delete()
            synchronized(guard) { misses += 1 }
            return null
        }
        // A disk hit is promoted into memory so a second read in the same run
        // does not pay for the file again.
        synchronized(guard) {
            memory[storageKey] = decoded
            hits += 1
        }
        return decoded
    }

    /**
     * Store a result, if its sensitivity and size permit.
     *
     * Returns the tier actually used, so a caller — and the diagnostics log —
     * can tell "stored on disk" from "held in memory" from "refused".
     */
    fun put(
        key: AgentToolCacheKey,
        data: AgentJsonObject,
        sensitivity: AgentDataSensitivity,
        returnedCount: Long,
        totalCount: Long,
        truncated: Boolean,
        queryMode: String? = null,
        durationMillis: Long = 0L
    ): AgentCacheTier {
        val tier = AgentCacheTier.of(sensitivity)
        if (tier == AgentCacheTier.Never) {
            synchronized(guard) { rejected += 1 }
            return AgentCacheTier.Never
        }

        val encoded = runCatching { encodeData(data) }.getOrNull()
        if (encoded == null) {
            synchronized(guard) { rejected += 1 }
            return AgentCacheTier.Never
        }
        val sizeBytes = encoded.toByteArray(Charsets.UTF_8).size
        if (sizeBytes > maxEntryBytes) {
            // A single oversized projection would otherwise consume the whole
            // budget and evict everything useful.
            synchronized(guard) { rejected += 1 }
            return AgentCacheTier.Never
        }

        val entry = AgentCachedToolResult(
            key = key,
            data = data,
            sensitivity = sensitivity,
            returnedCount = returnedCount,
            totalCount = totalCount,
            truncated = truncated,
            queryMode = queryMode,
            createdAtMillis = clock(),
            sizeBytes = sizeBytes,
            originalDurationMillis = durationMillis
        )
        val storageKey = storageKey(key)
        synchronized(guard) {
            memory[storageKey] = entry
            writes += 1
        }

        if (tier == AgentCacheTier.Disk) {
            writeEntry(storageKey, entry)
            enforceDiskBudget()
        }
        return tier
    }

    fun stats(): AgentToolCacheStats = synchronized(guard) {
        val files = diskFiles()
        AgentToolCacheStats(
            hits = hits,
            misses = misses,
            writes = writes,
            rejected = rejected,
            evictions = evictions,
            entryCount = memory.size + files.size,
            diskBytes = files.sumOf { it.length() }
        )
    }

    fun diskBytes(): Long = diskFiles().sumOf { it.length() }

    fun diskEntryCount(): Int = diskFiles().size

    /** Drop every entry from both tiers.  Only this cache's own files. */
    fun clear(): Int {
        var removed: Int
        synchronized(guard) {
            removed = memory.size
            memory.clear()
        }
        diskFiles().forEach { if (it.delete()) removed += 1 }
        return removed
    }

    /** Drop every entry belonging to one capture, e.g. after it is closed. */
    fun invalidateCapture(captureFingerprint: String) {
        if (captureFingerprint.isBlank()) return
        synchronized(guard) {
            memory.entries.removeAll { it.value.key.captureFingerprint == captureFingerprint }
        }
        diskFiles().forEach { file ->
            val entry = runCatching { JSONObject(file.readText()) }.getOrNull()
            if (entry?.optString("captureFingerprint") == captureFingerprint) file.delete()
        }
    }

    // ---------------------------------------------------------------- storage

    private fun isFresh(entry: AgentCachedToolResult): Boolean {
        if (ttlMillis <= 0L) return true
        val age = clock() - entry.createdAtMillis
        return age in 0..ttlMillis
    }

    /**
     * Hash of the complete key.  Hashing rather than joining keeps a
     * fingerprint and an argument hash out of a filename, and guarantees the
     * name is a legal, bounded file name whatever a tool put in the key.
     */
    private fun storageKey(key: AgentToolCacheKey): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(key.canonical().toByteArray(Charsets.UTF_8))
        return digest.joinToString(separator = "") { byte -> "%02x".format(Locale.ROOT, byte) }
    }

    private fun diskFile(storageKey: String): File? {
        val root = directory ?: return null
        val file = File(root, "$storageKey$FILE_SUFFIX")
        return file.takeIf { it.isFile }
    }

    private fun diskFiles(): List<File> = directory?.listFiles()
        ?.filter { it.isFile && it.name.endsWith(FILE_SUFFIX) }
        .orEmpty()

    private fun writeEntry(storageKey: String, entry: AgentCachedToolResult) {
        val root = directory ?: return
        runCatching {
            if (!root.isDirectory) check(root.mkdirs()) { "Unable to create the Agent cache." }
            val target = File(root, "$storageKey$FILE_SUFFIX")
            val temporary = File(root, "$storageKey$TEMP_SUFFIX")
            try {
                temporary.writeText(encodeEntry(entry).toString())
                if (target.exists()) target.delete()
                if (!temporary.renameTo(target)) throw IllegalStateException("cache write failed")
            } finally {
                temporary.delete()
            }
        }
    }

    private fun readEntry(file: File, expected: AgentToolCacheKey): AgentCachedToolResult? =
        runCatching {
            val json = JSONObject(file.readText())
            require(json.optInt("schemaVersion", 1) <= SCHEMA_VERSION) { "future cache entry" }

            // The stored key is re-checked against the requested one, so a hash
            // collision or a file copied between directories can never be
            // served as a result for a different capture or tool.
            val storedKey = AgentToolCacheKey(
                captureFingerprint = json.getString("captureFingerprint"),
                analysisConfigVersion = json.getInt("analysisConfigVersion"),
                toolName = json.getString("toolName"),
                normalizedArgumentsHash = json.getString("normalizedArgumentsHash"),
                nativeBuildMarker = json.getString("nativeBuildMarker"),
                toolVersion = json.getString("toolVersion"),
                scopeKey = json.optString("scopeKey")
            )
            require(storedKey == expected) { "cache key mismatch" }

            val sensitivity = AgentDataSensitivity.entries
                .firstOrNull { it.name == json.optString("sensitivity") }
                ?: AgentDataSensitivity.Unknown
            // A file claiming a tier it may not occupy is discarded rather than
            // trusted; disk storage of an Identifier result is not permitted.
            require(AgentCacheTier.of(sensitivity) == AgentCacheTier.Disk) { "tier not allowed" }

            AgentCachedToolResult(
                key = storedKey,
                data = decodeData(json.getJSONObject("data")),
                sensitivity = sensitivity,
                returnedCount = json.optLong("returnedCount"),
                totalCount = json.optLong("totalCount"),
                truncated = json.optBoolean("truncated", false),
                queryMode = json.optString("queryMode").takeIf { it.isNotBlank() },
                createdAtMillis = json.optLong("createdAtMillis"),
                sizeBytes = json.optInt("sizeBytes"),
                originalDurationMillis = json.optLong("originalDurationMillis")
            )
        }.getOrNull()

    private fun encodeEntry(entry: AgentCachedToolResult): JSONObject = JSONObject()
        .put("schema", SCHEMA_NAME)
        .put("schemaVersion", SCHEMA_VERSION)
        .put("captureFingerprint", entry.key.captureFingerprint)
        .put("analysisConfigVersion", entry.key.analysisConfigVersion)
        .put("toolName", entry.key.toolName)
        .put("normalizedArgumentsHash", entry.key.normalizedArgumentsHash)
        .put("nativeBuildMarker", entry.key.nativeBuildMarker)
        .put("toolVersion", entry.key.toolVersion)
        .put("scopeKey", entry.key.scopeKey)
        .put("sensitivity", entry.sensitivity.name)
        .put("returnedCount", entry.returnedCount)
        .put("totalCount", entry.totalCount)
        .put("truncated", entry.truncated)
        .put("queryMode", entry.queryMode ?: JSONObject.NULL)
        .put("createdAtMillis", entry.createdAtMillis)
        .put("sizeBytes", entry.sizeBytes)
        .put("originalDurationMillis", entry.originalDurationMillis)
        .put("data", JSONObject(encodeData(entry.data)))

    /**
     * Keep the newest entries within the byte budget.
     *
     * Expired files go first, because deleting something that would have missed
     * anyway is free; only then does age decide.
     */
    private fun enforceDiskBudget() {
        val files = diskFiles().toMutableList()
        if (ttlMillis > 0L) {
            val cutoff = clock() - ttlMillis
            files.removeAll { file ->
                val expired = file.lastModified() < cutoff
                if (expired) file.delete()
                expired
            }
        }
        var total = files.sumOf { it.length() }
        if (total <= maxDiskBytes) return
        files.sortedBy { it.lastModified() }.forEach { file ->
            if (total <= maxDiskBytes) return
            val size = file.length()
            if (file.delete()) {
                total -= size
                synchronized(guard) { evictions += 1 }
            }
        }
    }

    // The tool payload is reused verbatim, so encoding goes through the same
    // JSON conversion the tool boundary already uses rather than a second one.
    private fun encodeData(data: AgentJsonObject): String =
        com.example.layanalyzer.ai.tools.AgentResultTruncator.encode(data)

    private fun decodeData(json: JSONObject): AgentJsonObject =
        AgentJsonCodec.decodeToolResult(
            JSONObject()
                .put("schema", AgentJsonCodec.TOOL_RESULT_SCHEMA)
                .put("schemaVersion", AgentJsonCodec.SCHEMA_VERSION)
                .put("data", json)
                .toString()
        ).getOrNull()?.data ?: throw IllegalArgumentException("Cached data could not be read.")

    companion object {
        const val DIRECTORY_NAME = "agent_cache"
        private const val SCHEMA_NAME = "AgentToolCacheEntry"
        private const val SCHEMA_VERSION = 1
        private const val FILE_SUFFIX = ".json"
        private const val TEMP_SUFFIX = ".tmp"
        private const val DEFAULT_MAX_MEMORY_ENTRIES = 64
        private const val DEFAULT_MAX_DISK_BYTES = 8L * 1024 * 1024
        private const val DEFAULT_MAX_ENTRY_BYTES = 256 * 1024
        private const val DEFAULT_TTL_MILLIS = 7L * 24 * 60 * 60 * 1000
    }
}
