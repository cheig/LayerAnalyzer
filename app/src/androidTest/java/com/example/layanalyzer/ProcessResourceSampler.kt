// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.os.Debug
import android.os.Process
import android.os.SystemClock
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.SocksBudgetStats
import com.example.layanalyzer.capture.SocksSessionStats
import org.json.JSONObject
import java.io.Closeable
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/** Same-process sampler, shared by P0 load fixtures. Never included in the app APK.
 * Process values include instrumentation/client threads and all native runtimes.
 * Each budget is atomic independently; the whole row is not a stop-the-world snapshot.
 */
internal class ProcessResourceSampler(
    private val output: File,
    private val runId: String,
    private val intervalMillis: Long = 5_000,
    private val sessions: () -> SocksSessionStats? = { LiveCaptureVpnService.socksResourceSnapshot() }
) : Closeable {
    private var previous: Pair<Long, Long>? = null
    private val stopped = AtomicBoolean(false)
    private var worker: Thread? = null
    private var count = 0
    @Volatile private var workerError: String? = null

    init {
        require(runId.matches(Regex("[a-f0-9]{32}")))
        require(intervalMillis >= 100)
        output.parentFile?.mkdirs()
        check(output.createNewFile()) { "RESOURCE_OUTPUT_ALREADY_EXISTS" }
        append(JSONObject().put("type", "start").put("schema", 1).put("runId", runId)
            .put("intervalMillis", intervalMillis).put("pid", Process.myPid())
            .put("api", android.os.Build.VERSION.SDK_INT).put("abi", android.os.Build.SUPPORTED_ABIS.first())
            .put("scope", "app process including instrumentation, fixture clients, JNI and Go"))
    }

    @Synchronized
    fun sample(phase: String): JSONObject {
        check(!stopped.get()) { "RESOURCE_SAMPLER_CLOSED" }
        val missing = JSONObject()
        fun <T : Any> read(name: String, block: () -> T): Any = try {
            block()
        } catch (error: Exception) {
            missing.put(name, "unavailable:${error.javaClass.simpleName}")
            JSONObject.NULL
        }
        val now = SystemClock.elapsedRealtimeNanos()
        val cpu = read("cpuMillis") { Process.getElapsedCpuTime().also { check(it >= 0) } }
        val process = JSONObject()
            .put("pid", Process.myPid())
            .put("startTicks", read("startTicks") {
                // comm may contain spaces and parentheses: split only after its last ')'.
                File("/proc/self/stat").readText().substringAfterLast(") ").trim().split(Regex("\\s+"))[19].toLong()
            })
            .put("threads", read("threads") { requireNotNull(File("/proc/self/task").list()).size })
            .put("fds", read("fds") { requireNotNull(File("/proc/self/fd").list()).size })
            .put("pssKiB", read("pssKiB") { Debug.getPss().also { check(it > 0) } })
            .put("cpuMillis", cpu)
        val limits = read("fdLimits") {
            val match = requireNotNull(Regex("(?m)^Max open files\\s+(\\S+)\\s+(\\S+)")
                .find(File("/proc/self/limits").readText()))
            JSONObject().put("soft", limitValue(match.groupValues[1])).put("hard", limitValue(match.groupValues[2]))
        }
        process.put("fdLimits", limits)
        val before = previous
        if (cpu is Long && before != null && now > before.first && cpu >= before.second) {
            process.put("cpuPercentOneCore", (cpu - before.second) * 100_000_000.0 / (now - before.first))
        } else {
            process.put("cpuPercentOneCore", JSONObject.NULL)
            missing.put("cpuPercentOneCore", if (before == null) "first_sample" else "cpu_counter_unavailable_or_reset")
        }
        previous = if (cpu is Long) now to cpu else null
        val snapshot = read("socks") { sessions() ?: JSONObject.NULL }
        if (snapshot === JSONObject.NULL && !missing.has("socks")) {
            missing.put("socks", "no_server_observed_in_this_process")
        }
        val socks = if (snapshot is SocksSessionStats) {
            JSONObject().put("serverId", snapshot.serverId).put("running", snapshot.running)
                .put("scope", "one SOCKS server lifetime; TCP includes gateway candidates; admission includes setup")
                .put("peakKind", "event_time_admission_high_water_mark")
                .put("handshakes", budget(snapshot.handshakes)).put("tcp", budget(snapshot.tcp)).put("udp", budget(snapshot.udp))
                .put("rejectedHandshakes", snapshot.rejectedHandshakes)
                .put("rejectedTcpSessions", snapshot.rejectedTcp).put("rejectedUdpSessions", snapshot.rejectedUdp)
                .put("expiredUdpAssociations", snapshot.expiredUdp)
                .put("failureEvents", JSONObject(snapshot.failureEvents))
        } else JSONObject.NULL
        val row = JSONObject().put("type", "sample").put("runId", runId).put("phase", phase)
            .put("monotonicNanos", now).put("epochMillis", System.currentTimeMillis())
            .put("process", process).put("socks", socks).put("unavailable", missing)
        append(row)
        count++
        return row
    }

    /** Call sample() at phase boundaries too. One observer thread; no per-session tasks. */
    @Synchronized
    fun startPeriodic(phase: () -> String) {
        check(worker == null && !stopped.get())
        worker = thread(name = "LayerAnalyzer-ResourceSampler", isDaemon = true) {
            try {
                while (!stopped.get()) {
                    Thread.sleep(intervalMillis)
                    synchronized(this) { if (!stopped.get()) sample(phase()) }
                }
            } catch (_: InterruptedException) {
                // close() interrupts only this owned sampler thread.
            } catch (error: Exception) {
                workerError = error.javaClass.simpleName
            }
        }
    }

    override fun close() {
        val owned = synchronized(this) {
            if (!stopped.compareAndSet(false, true)) return
            worker?.also { it.interrupt() }
        }
        if (owned !== Thread.currentThread()) owned?.join(5_000)
        check(owned?.isAlive != true) { "RESOURCE_SAMPLER_NOT_STOPPED" }
        synchronized(this) {
            append(JSONObject().put("type", "end").put("runId", runId).put("samples", count)
                .put("samplerError", workerError ?: JSONObject.NULL))
        }
        check(workerError == null) { "RESOURCE_SAMPLER_FAILED:$workerError" }
    }

    private fun append(row: JSONObject) = output.appendText(row.toString() + "\n")
    private fun budget(value: SocksBudgetStats) = JSONObject().put("current", value.current)
        .put("peak", value.peak).put("limit", value.limit)
    private fun limitValue(value: String): Any = if (value == "unlimited") value else value.toLong()
}
