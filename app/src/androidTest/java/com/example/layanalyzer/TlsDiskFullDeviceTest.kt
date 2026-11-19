// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.RotatingPcapWriter
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.CaptureArtifactRepository
import com.example.layanalyzer.model.CaptureArtifactManifest
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyStore
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Real kernel ENOSPC on a host-mounted private 2 MiB tmpfs, never /data capacity.
 * This tests append/publication failures, not a delayed block-device fsync error.
 */
@RunWith(AndroidJUnit4::class)
class TlsDiskFullDeviceTest {
    @Test fun boundedTmpfsEnospcPreservesWatermarksAndOldManifestThenRecovers() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val root = File(requireNotNull(InstrumentationRegistry.getArguments().getString("failureStorage"))).canonicalFile
        require(root.path.matches(Regex("/data/local/tmp/layeranalyzer-tls403-[a-z0-9-]+")))
        val mount = File("/proc/mounts").readLines().single { it.split(' ').getOrNull(1) == root.path }
        require(mount.split(' ')[2] == "tmpfs")
        require(root.totalSpace in 1..(2L * 1024 * 1024))
        require(root.list()!!.isEmpty())
        val alias = "layeranalyzer.test.tls403.disk.${UUID.randomUUID()}"
        val filler = File(root, "filler")
        val evidence = JSONObject().put("filesystem", "tmpfs").put("capacityBytes", root.totalSpace)
        try {
            val writer = RotatingPcapWriter(File(root, "full.pcap"), 1024 * 1024)
            fill(filler)
            try {
                // Header + record exceed the writer's 64 KiB buffer, forcing an
                // actual write before writePacket returns.
                try { writer.writePacket(1, ByteArray(65_535), 65_535); fail("PCAP append must fail") }
                catch (error: IOException) { assertEnospc(error) }
                assertEquals(0L, writer.segmentInfo().single().frameCount)
            } finally { runCatching { writer.close() }; assertTrue(filler.delete()) }
            assertFalse("ENOSPC close leaked the PCAP descriptor", File("/proc/self/fd").listFiles()!!.any {
                runCatching { android.system.Os.readlink(it.path) == File(root, "full.pcap").path }.getOrDefault(false)
            })
            RotatingPcapWriter(File(root, "recovered.pcap"), 1024 * 1024).use {
                it.writePacket(2, ByteArray(32 * 1024), 32 * 1024)
                assertEquals(1L, it.segmentInfo().single().frameCount)
            }
            evidence.put("pcapAppendErrno", "ENOSPC").put("failedRecordCounted", false)

            val store = TlsSecretStore(root, AndroidTlsWrappingKeyProvider(alias))
            val sink = store.openLiveSecrets("disk-full")
            fill(filler)
            val began = SystemClock.elapsedRealtime()
            val result = try {
                // Existing header pages may accommodate several complete records
                // before the next allocation fails. Do not assume persisted=0.
                repeat(256) { i ->
                    val random = "%064x".format(i)
                    val line = "CLIENT_RANDOM $random ${"cd".repeat(48)}".toByteArray()
                    try { sink.offer("controlled", line) } finally { line.fill(0) }
                }
                try { sink.finish() } catch (error: TlsAssetException) {
                    // The authenticated prefix also cannot be published while
                    // the filesystem is full. Preserve the final sink counters.
                    assertEquals(TlsAssetErrorCode.DISK_FULL, error.code)
                    evidence.put("secretPublicationFailure", error.code.name)
                    sink.snapshot()
                }
            } finally { assertTrue(filler.delete()) }
            assertEquals(TlsAssetErrorCode.DISK_FULL, result.failure)
            assertTrue(result.accepted > result.persisted)
            assertFalse(result.complete)
            assertTrue(result.mitmSuspended)
            assertTrue(SystemClock.elapsedRealtime() - began < 6_000)
            evidence.put("secretAccepted", result.accepted).put("secretPersisted", result.persisted)
                .put("secretFailure", result.failure!!.name).put("secretComplete", result.complete)
                .put("finishMillis", SystemClock.elapsedRealtime() - began)
            val next = store.openLiveSecrets("disk-recovered")
            val line = "CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}".toByteArray()
            try { assertTrue(next.offer("controlled", line)) } finally { line.fill(0) }
            assertTrue(next.finish().complete)
            store.acquireLease("disk-recovered").close()

            val repository = CaptureArtifactRepository(File(root, "captures"))
            val old = CaptureArtifactManifest("manifest-full")
            repository.writeUnfinalized(old)
            val previous = repository.manifestFile(old.captureId).readBytes()
            fill(filler)
            try {
                try { repository.writeUnfinalized(old.copy(packetDrops = 1)); fail("manifest replacement must fail") }
                catch (error: TlsAssetException) { assertEquals(TlsAssetErrorCode.DISK_FULL, error.code) }
                assertArrayEquals(previous, repository.manifestFile(old.captureId).readBytes())
            } finally { assertTrue(filler.delete()) }
            repository.writeUnfinalized(old.copy(packetDrops = 1))
            evidence.put("manifestOldBytesPreserved", true).put("newWritesAfterFree", true)
            val output = File(instrumentation.targetContext.getExternalFilesDir(null), "tls-403/disk-full.json")
            output.parentFile!!.mkdirs(); output.writeText(evidence.toString(2))
        } finally {
            filler.delete()
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
        }
    }

    private fun fill(file: File) {
        FileOutputStream(file).use { out ->
            try {
                repeat(513) { out.write(ByteArray(4096)) }
                fail("The isolated 2 MiB filesystem did not enforce its capacity")
            } catch (error: IOException) { assertEnospc(error) }
        }
    }

    private fun assertEnospc(error: IOException) {
        assertTrue("Expected real kernel ENOSPC", generateSequence<Throwable>(error) { it.cause }
            .any { it.message.orEmpty().contains("ENOSPC") || it.message.orEmpty().contains("No space left") })
    }
}
