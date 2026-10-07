package com.example.layanalyzer.ai.cache

import com.example.layanalyzer.model.AgentCacheTier
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentToolCacheKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** AI-24 sections 3 and 4: key completeness, tiers, LRU, TTL and size caps. */
class AgentToolCacheTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private var now: Long = 1_000L

    private fun cache(
        maxMemoryEntries: Int = 64,
        maxDiskBytes: Long = 8L * 1024 * 1024,
        maxEntryBytes: Int = 256 * 1024,
        ttlMillis: Long = 7L * 24 * 60 * 60 * 1000
    ) = AgentToolCache(
        directory = temporaryFolder.root,
        maxMemoryEntries = maxMemoryEntries,
        maxDiskBytes = maxDiskBytes,
        maxEntryBytes = maxEntryBytes,
        ttlMillis = ttlMillis,
        clock = { now }
    )

    // -------------------------------------------------------- key completeness

    @Test
    fun `an identical key hits and every changed key component misses`() {
        val subject = cache()
        subject.put(key(), payload(), AgentDataSensitivity.Aggregate, 3L, 9L, false)

        assertNotNull("same key must hit", subject.get(key(), AgentDataSensitivity.Aggregate))

        // Each of the six key components, changed one at a time.
        assertNull(subject.get(key(fingerprint = "other"), AgentDataSensitivity.Aggregate))
        assertNull(subject.get(key(configVersion = 2), AgentDataSensitivity.Aggregate))
        assertNull(subject.get(key(toolName = "other_tool"), AgentDataSensitivity.Aggregate))
        assertNull(subject.get(key(argumentsHash = "other-hash"), AgentDataSensitivity.Aggregate))
        assertNull(subject.get(key(nativeBuild = "wireshark-9"), AgentDataSensitivity.Aggregate))
        assertNull(subject.get(key(toolVersion = "2"), AgentDataSensitivity.Aggregate))
        assertNull(subject.get(key(scopeKey = "CurrentFilter|sip"), AgentDataSensitivity.Aggregate))
    }

    @Test
    fun `key components cannot be shuffled into an equivalent canonical string`() {
        // Without a separator, ("ab", "c") and ("a", "bc") would collide.
        val left = key(fingerprint = "ab", toolName = "c")
        val right = key(fingerprint = "a", toolName = "bc")

        assertFalse(left.canonical() == right.canonical())
    }

    @Test
    fun `a cached result preserves truncation, counts and query mode`() {
        val subject = cache()
        subject.put(
            key = key(),
            data = payload(),
            sensitivity = AgentDataSensitivity.Metadata,
            returnedCount = 4L,
            totalCount = 17L,
            truncated = true,
            queryMode = "native_scoped"
        )

        val hit = subject.get(key(), AgentDataSensitivity.Metadata)!!

        assertEquals(4L, hit.returnedCount)
        assertEquals(17L, hit.totalCount)
        assertTrue(hit.truncated)
        assertEquals("native_scoped", hit.queryMode)
        assertEquals(payload(), hit.data)
    }

    // ------------------------------------------------------------------ tiers

    @Test
    fun `payload and credential results are never cached in either tier`() {
        val subject = cache()

        assertEquals(
            AgentCacheTier.Never,
            subject.put(key(), payload(), AgentDataSensitivity.Payload, 1L, 1L, false)
        )
        assertEquals(
            AgentCacheTier.Never,
            subject.put(key(), payload(), AgentDataSensitivity.Credential, 1L, 1L, false)
        )

        assertNull(subject.get(key(), AgentDataSensitivity.Payload))
        assertNull(subject.get(key(), AgentDataSensitivity.Credential))
        assertEquals(0, subject.diskEntryCount())
    }

    @Test
    fun `an unknown sensitivity is refused rather than treated as aggregate`() {
        val subject = cache()

        assertEquals(
            AgentCacheTier.Never,
            subject.put(key(), payload(), AgentDataSensitivity.Unknown, 1L, 1L, false)
        )
        assertNull(subject.get(key(), AgentDataSensitivity.Unknown))
    }

    @Test
    fun `identifier results stay in memory and never reach disk`() {
        val subject = cache()

        val tier = subject.put(key(), payload(), AgentDataSensitivity.Identifier, 1L, 1L, false)

        assertEquals(AgentCacheTier.MemoryOnly, tier)
        assertNotNull(subject.get(key(), AgentDataSensitivity.Identifier))
        assertEquals(0, subject.diskEntryCount())
        assertEquals(0L, subject.diskBytes())
    }

    @Test
    fun `an identifier entry does not survive a new cache instance`() {
        cache().put(key(), payload(), AgentDataSensitivity.Identifier, 1L, 1L, false)

        // A fresh instance models an app restart: memory-only means gone.
        assertNull(cache().get(key(), AgentDataSensitivity.Identifier))
    }

    @Test
    fun `aggregate and metadata results survive a new cache instance`() {
        cache().put(key(), payload(), AgentDataSensitivity.Aggregate, 2L, 2L, false)

        val restarted = cache().get(key(), AgentDataSensitivity.Aggregate)

        assertNotNull(restarted)
        assertEquals(payload(), restarted!!.data)
    }

    @Test
    fun `a disk file claiming a memory-only tier is discarded rather than trusted`() {
        val subject = cache()
        subject.put(key(), payload(), AgentDataSensitivity.Aggregate, 1L, 1L, false)
        val file = temporaryFolder.root.listFiles()!!.single { it.name.endsWith(".json") }
        val tampered = org.json.JSONObject(file.readText())
            .put("sensitivity", AgentDataSensitivity.Identifier.name)
        file.writeText(tampered.toString())

        assertNull(cache().get(key(), AgentDataSensitivity.Identifier))
    }

    @Test
    fun `a disk file whose stored key differs is not served`() {
        val subject = cache()
        subject.put(key(), payload(), AgentDataSensitivity.Aggregate, 1L, 1L, false)
        val file = temporaryFolder.root.listFiles()!!.single { it.name.endsWith(".json") }
        val tampered = org.json.JSONObject(file.readText())
            .put("captureFingerprint", "someone-elses-capture")
        file.writeText(tampered.toString())

        // The file name still hashes to the requested key, but the stored key
        // no longer matches, so it must be refused.
        assertNull(cache().get(key(), AgentDataSensitivity.Aggregate))
    }

    // -------------------------------------------------------------- TTL / LRU

    @Test
    fun `an entry past its TTL misses instead of returning stale analysis`() {
        val subject = cache(ttlMillis = 1_000L)
        subject.put(key(), payload(), AgentDataSensitivity.Aggregate, 1L, 1L, false)

        now += 999L
        assertNotNull(subject.get(key(), AgentDataSensitivity.Aggregate))

        now += 2L
        assertNull(subject.get(key(), AgentDataSensitivity.Aggregate))
    }

    @Test
    fun `the least recently used memory entry is evicted first`() {
        val subject = AgentToolCache(
            directory = null,
            maxMemoryEntries = 2,
            clock = { now }
        )
        subject.put(key(toolName = "a"), payload(), AgentDataSensitivity.Identifier, 1L, 1L, false)
        subject.put(key(toolName = "b"), payload(), AgentDataSensitivity.Identifier, 1L, 1L, false)

        // Touch "a" so "b" becomes the least recently used.
        assertNotNull(subject.get(key(toolName = "a"), AgentDataSensitivity.Identifier))
        subject.put(key(toolName = "c"), payload(), AgentDataSensitivity.Identifier, 1L, 1L, false)

        assertNotNull(subject.get(key(toolName = "a"), AgentDataSensitivity.Identifier))
        assertNull(subject.get(key(toolName = "b"), AgentDataSensitivity.Identifier))
        assertNotNull(subject.get(key(toolName = "c"), AgentDataSensitivity.Identifier))
    }

    @Test
    fun `an oversized result is refused rather than evicting everything useful`() {
        val subject = cache(maxEntryBytes = 128)
        val large: AgentJsonObject = mapOf("rows" to List(500) { "row-$it" })

        val tier = subject.put(key(), large, AgentDataSensitivity.Aggregate, 500L, 500L, false)

        assertEquals(AgentCacheTier.Never, tier)
        assertEquals(0, subject.diskEntryCount())
    }

    @Test
    fun `the disk budget is enforced by dropping the oldest entries`() {
        val subject = cache(maxDiskBytes = 1_200L)
        repeat(8) { index ->
            subject.put(
                key = key(toolName = "tool_$index"),
                data = mapOf("value" to "x".repeat(100)),
                sensitivity = AgentDataSensitivity.Aggregate,
                returnedCount = 1L,
                totalCount = 1L,
                truncated = false
            )
            Thread.sleep(3)
        }

        assertTrue("disk budget exceeded: ${subject.diskBytes()}", subject.diskBytes() <= 1_200L)
        assertTrue("nothing was evicted", subject.diskEntryCount() < 8)

        // The oldest entry is gone from *disk*.  It may still answer from this
        // process's memory tier, which has its own budget, so the check is made
        // through a fresh instance — the same thing an app restart would see.
        assertNull(cache().get(key(toolName = "tool_0"), AgentDataSensitivity.Aggregate))
        assertNotNull(cache().get(key(toolName = "tool_7"), AgentDataSensitivity.Aggregate))
    }

    // ---------------------------------------------------------- invalidation

    @Test
    fun `invalidating one capture leaves the other capture's entries intact`() {
        val subject = cache()
        subject.put(key(fingerprint = "a"), payload(), AgentDataSensitivity.Aggregate, 1L, 1L, false)
        subject.put(key(fingerprint = "b"), payload(), AgentDataSensitivity.Aggregate, 1L, 1L, false)

        subject.invalidateCapture("a")

        assertNull(subject.get(key(fingerprint = "a"), AgentDataSensitivity.Aggregate))
        assertNotNull(subject.get(key(fingerprint = "b"), AgentDataSensitivity.Aggregate))
    }

    @Test
    fun `clear removes only this cache's files and leaves foreign ones alone`() {
        val subject = cache()
        subject.put(key(), payload(), AgentDataSensitivity.Aggregate, 1L, 1L, false)
        val foreign = temporaryFolder.newFile("not-ours.txt")
        foreign.writeText("keep me")

        subject.clear()

        assertEquals(0, subject.diskEntryCount())
        assertNull(subject.get(key(), AgentDataSensitivity.Aggregate))
        assertTrue(foreign.isFile)
    }

    @Test
    fun `stats count hits, misses and refusals`() {
        val subject = cache()
        subject.put(key(), payload(), AgentDataSensitivity.Aggregate, 1L, 1L, false)
        subject.get(key(), AgentDataSensitivity.Aggregate)
        subject.get(key(toolName = "absent"), AgentDataSensitivity.Aggregate)
        subject.put(key(), payload(), AgentDataSensitivity.Credential, 1L, 1L, false)

        val stats = subject.stats()

        assertEquals(1L, stats.hits)
        assertEquals(1L, stats.misses)
        assertEquals(1L, stats.writes)
        assertEquals(1L, stats.rejected)
    }

    @Test
    fun `a null directory disables disk storage without breaking memory caching`() {
        val subject = AgentToolCache(directory = null, clock = { now })

        subject.put(key(), payload(), AgentDataSensitivity.Aggregate, 1L, 1L, false)

        assertNotNull(subject.get(key(), AgentDataSensitivity.Aggregate))
        assertEquals(0L, subject.diskBytes())
    }

    private fun payload(): AgentJsonObject = mapOf(
        "protocol" to "sip",
        "count" to 12,
        "topTalkers" to listOf("host-1", "host-2")
    )

    private fun key(
        fingerprint: String = "fingerprint-a",
        configVersion: Int = 1,
        toolName: String = "get_statistics",
        argumentsHash: String = "hash-1",
        nativeBuild: String = "wireshark-4.0.10",
        toolVersion: String = "1",
        scopeKey: String = "CompleteFile|"
    ) = AgentToolCacheKey(
        captureFingerprint = fingerprint,
        analysisConfigVersion = configVersion,
        toolName = toolName,
        normalizedArgumentsHash = argumentsHash,
        nativeBuildMarker = nativeBuild,
        toolVersion = toolVersion,
        scopeKey = scopeKey
    )
}
