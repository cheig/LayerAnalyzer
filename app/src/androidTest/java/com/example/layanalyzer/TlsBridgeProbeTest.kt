package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Run in a fresh app process, with -PlayanalyzerTlsProbe=true. No Assume/skips. */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class TlsBridgeProbeTest {
    private var activeHandle = 0L

    @Before
    fun requireProbeBuild() {
        assertTrue("Rebuild with -PlayanalyzerTlsProbe=true", BuildConfig.TLS_PROBE_ENABLED)
    }

    @After
    fun releaseHandle() {
        if (activeHandle != 0L) success(NativeEngine.stopTlsBridgeProbe(activeHandle))
    }

    @Test
    fun a_libraryIsLazyAndUnavailableLibraryIsAnError() {
        // Merely initializing NativeEngine and asking Wireshark's version must not load Go.
        assertTrue(NativeEngine.getVersion().isNotEmpty())
        assertFalse(state().getBoolean("libraryLoaded"))
        error(NativeEngine.loadTlsBridgeProbe(true, 1), "NOT_READY")
        assertFalse(state().getBoolean("libraryLoaded"))
        error(NativeEngine.startTlsBridgeProbe { true }, "NOT_READY")
        error(NativeEngine.loadTlsBridgeProbe(false, 0), "INVALID_ARGUMENT")
    }

    @Test
    fun b_abiMismatchCannotStartAndCompatibleRetryWorks() {
        error(NativeEngine.loadTlsBridgeProbe(false, 2), "UNSUPPORTED")
        assertTrue(state().getBoolean("libraryLoaded"))
        assertFalse(state().getBoolean("ready"))
        error(NativeEngine.startTlsBridgeProbe { true }, "NOT_READY")
        load()
        assertEquals(1, state().getInt("abiVersion"))
        assertIdle()
    }

    @Test
    fun c_duplicateStartAndOldStopsPreserveCurrentOwnership() {
        load()
        val first = start()
        assertEquals(1, state().getInt("globalRefs"))
        error(NativeEngine.startTlsBridgeProbe { true }, "NOT_READY")
        error(NativeEngine.stopTlsBridgeProbe(0), "INVALID_ARGUMENT")
        error(NativeEngine.stopTlsBridgeProbe(Long.MAX_VALUE), "INVALID_ARGUMENT")
        success(NativeEngine.stopTlsBridgeProbe(first))
        success(NativeEngine.stopTlsBridgeProbe(first))
        assertIdle()
        val second = start()
        assertTrue(second > first)
        success(NativeEngine.stopTlsBridgeProbe(first))
        assertEquals(1, state().getInt("activeHandles"))
        assertEquals(1, state().getInt("globalRefs"))
    }

    @Test
    fun d_callbackExceptionAndRejectionReleaseHandleAndGlobalRef() {
        load()
        error(NativeEngine.startTlsBridgeProbe(null), "INVALID_ARGUMENT")
        val response = NativeEngine.startTlsBridgeProbe {
            throw IllegalStateException("synthetic-exception-must-not-cross-jni")
        }
        error(response, "IO_ERROR")
        assertFalse(response.contains("synthetic-exception-must-not-cross-jni"))
        assertIdle()
        error(NativeEngine.startTlsBridgeProbe { false }, "CANCELLED")
        assertIdle()
        start() // Neither exception is pending on this JNI thread.
    }

    @Test(timeout = 15_000)
    fun e_callbackRunsAttachedWithoutLockAndStopCannotRaceIt() {
        load()
        val callingThread = Thread.currentThread().id
        activeHandle = success(NativeEngine.startTlsBridgeProbe { handle ->
            assertNotEquals(callingThread, Thread.currentThread().id)
            assertEquals(1, state().getInt("attachedThreads"))
            error(NativeEngine.stopTlsBridgeProbe(handle), "NOT_READY")
            error(NativeEngine.startTlsBridgeProbe { true }, "NOT_READY")
            true
        }).getLong("engineHandle")
        assertEquals(0, state().getInt("attachedThreads"))
    }

    @Test(timeout = 30_000)
    fun f_concurrentStartsHaveOneWinner() {
        load()
        val pool = Executors.newFixedThreadPool(8)
        try {
            val responses = pool.invokeAll((1..16).map {
                Callable { JSONObject(NativeEngine.startTlsBridgeProbe { true }) }
            }).map { it.get(10, TimeUnit.SECONDS) }
            val winners = responses.filter { it.getBoolean("success") }
            // Retain the handle before assertions so teardown still closes it on failure.
            activeHandle = winners.firstOrNull()?.getLong("engineHandle") ?: 0L
            assertEquals(1, winners.size)
            responses.filterNot { it.getBoolean("success") }.forEach {
                error(it.toString(), "NOT_READY")
            }
            assertEquals(1, state().getInt("globalRefs"))
        } finally {
            pool.shutdownNow()
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test(timeout = 60_000)
    fun g_hundredCyclesReturnHandlesReferencesAndThreadsToWarmBaseline() {
        load()
        // Go's runtime stays resident. Warm it before measuring lifecycle growth.
        repeat(20) { cycle() }
        val before = state()
        val threadBaseline = settledThreadCount()
        repeat(100) { cycle() }
        val after = state()
        assertEquals(100L, after.getLong("callbacksStarted") - before.getLong("callbacksStarted"))
        assertEquals(after.getLong("callbacksStarted"), after.getLong("callbacksCompleted"))
        val threadsAfter = settledThreadCount()
        assertTrue("Threads grew from $threadBaseline to $threadsAfter", threadsAfter <= threadBaseline)
        assertIdle()
    }

    private fun settledThreadCount(): Int {
        // ART/runtime activity can disappear while settling; compare stable minima.
        return (1..10).minOf {
            Thread.sleep(100)
            File("/proc/self/task").list()?.size ?: error("Cannot inspect native threads")
        }
    }

    private fun cycle() {
        val handle = start()
        success(NativeEngine.stopTlsBridgeProbe(handle))
        success(NativeEngine.stopTlsBridgeProbe(handle))
        activeHandle = 0
        assertIdle()
    }

    private fun start(): Long = success(NativeEngine.startTlsBridgeProbe { true })
        .getLong("engineHandle").also { activeHandle = it }

    private fun load() = success(NativeEngine.loadTlsBridgeProbe(false, 1))
    private fun state() = success(NativeEngine.getTlsBridgeProbeState())

    private fun assertIdle() {
        val current = state()
        assertEquals(0, current.getInt("activeHandles"))
        assertEquals(0, current.getInt("globalRefs"))
        assertEquals(0, current.getInt("attachedThreads"))
    }

    private fun success(text: String): JSONObject = JSONObject(text).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertTrue(text, it.getBoolean("success"))
        assertTrue(it.isNull("errorCode"))
        assertTrue(it.isNull("error"))
    }

    private fun error(text: String, code: String) = JSONObject(text).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertFalse(text, it.getBoolean("success"))
        assertEquals(text, code, it.getString("errorCode"))
        assertFalse(it.getString("error").isBlank())
        assertFalse("Failure must not expose a usable handle", it.has("engineHandle"))
    }
}
