package com.example.layanalyzer.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class RtpMediaCacheTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private fun cache(): RtpMediaCache =
        RtpMediaCache(File(temporaryFolder.root, "rtp"))

    @Test
    fun `dirFor creates and reuses a request directory`() {
        val cache = cache()

        val created = cache.dirFor(11L, 22L)
        val reused = cache.dirFor(11L, 22L)
        val notCreated = cache.dirFor(11L, 23L, create = false)

        assertTrue(created.isDirectory)
        assertEquals(created.canonicalFile, reused)
        assertFalse(notCreated.exists())
    }

    @Test
    fun `deleteSession removes only the selected session`() {
        val cache = cache()
        val first = cache.dirFor(11L, 22L).resolve("s0.wav")
        val second = cache.dirFor(11L, 23L).resolve("s1.wav")
        val otherSession = cache.dirFor(12L, 22L).resolve("s0.wav")
        first.writeBytes(ByteArray(4))
        second.writeBytes(ByteArray(4))
        otherSession.writeBytes(ByteArray(4))

        cache.deleteSession(11L)
        cache.deleteSession(99L)

        assertFalse(File(temporaryFolder.root, "rtp/11").exists())
        assertTrue(otherSession.isFile)
    }

    @Test
    fun `clearAll removes the cache root`() {
        val cache = cache()
        cache.dirFor(11L, 22L).resolve("s0.wav").writeBytes(ByteArray(4))
        cache.dirFor(12L, 23L).resolve("s0.wav").writeBytes(ByteArray(4))

        cache.clearAll()

        assertFalse(File(temporaryFolder.root, "rtp").exists())
    }

    @Test
    fun `enforceMaxBytes deletes the oldest request directories first`() {
        val cache = cache()
        val oldest = cache.dirFor(11L, 22L)
        val middle = cache.dirFor(11L, 23L)
        val newest = cache.dirFor(12L, 24L)
        oldest.resolve("s0.wav").writeBytes(ByteArray(4))
        middle.resolve("s0.wav").writeBytes(ByteArray(5))
        newest.resolve("s0.wav").writeBytes(ByteArray(6))
        assertTrue(oldest.setLastModified(1_000L))
        assertTrue(middle.setLastModified(2_000L))
        assertTrue(newest.setLastModified(3_000L))

        val deleted = cache.enforceMaxBytes(maxBytes = 9L)

        assertEquals(9L, deleted)
        assertFalse(oldest.exists())
        assertFalse(middle.exists())
        assertTrue(newest.isDirectory)
    }

    @Test
    fun `canonical paths outside the cache root are rejected`() {
        val root = File(temporaryFolder.root, "rtp")
        val outside = File(temporaryFolder.root, "outside/request")
        assertThrows(IllegalArgumentException::class.java) {
            canonicalPathWithinRoot(root, outside)
        }
    }
}
