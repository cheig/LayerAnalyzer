// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.capture.socks.SocksRuntimeLimits
import com.example.layanalyzer.BuildConfig
import com.example.layanalyzer.capture.CaptureStartupChecks
import com.example.layanalyzer.capture.tls.SocksNioTlsGateway
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureStatus
import com.example.layanalyzer.model.TlsErrorCode
import java.io.IOException
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import org.json.JSONException
import org.json.JSONObject
import org.json.JSONTokener

/**
 * The C ABI surface one capture run uses (TLS-201). Production is [TlsProxyBridge];
 * the JVM lifecycle suite substitutes it, because the native library only exists
 * on a device.
 */
internal interface TlsEngineBridge {
    fun capabilities(): String
    fun start(
        configJson: String,
        certificateDer: ByteArray,
        privateKeyPkcs8: ByteArray,
        callbacks: TlsPlatformCallbacks
    ): String
    fun stop(handle: Long, timeoutMillis: Int): String
    fun poll(handle: Long, maxEvents: Int): String
    fun stats(handle: Long): String
    fun gatewayToken(handle: Long): ByteArray
}

/** C05's upstream chain-and-name verification, as the coordinator installs it (TLS-204). */
internal fun interface TlsUpstreamVerification {
    fun verify(chainDer: Array<ByteArray>, identity: String, authType: String, tlsVersion: String): String
}

/**
 * The captured physical network as one TLS run may use it (design §5.3).
 *
 * [generation] is frozen for the run: it goes into the engine's config, into the
 * `LAT1` frame of every connection and into every event. [upstream] is the
 * platform half the engine calls before it connects; [prepareHopSocket] prepares
 * the loopback hop, which is protected but never bound.
 *
 * Closing it is how a stopping capture refuses late callbacks: the generation
 * stays what it was, but nothing may be prepared on this network any more, so an
 * in-flight preparation fails with `NETWORK_CHANGED` instead of being served on
 * a network the capture no longer owns.
 */
internal interface TlsNetworkAccess : AutoCloseable {
    val generation: Long

    val upstream: TlsUpstreamCallbacks

    fun prepareHopSocket(socket: Socket)
}

/**
 * One run's start outcome: fixed codes only, and never a claim of a running
 * engine that does not exist.
 */
internal sealed class TlsCaptureStart {
    /** The request does not enable interception; the capture proceeds untouched. */
    object Disabled : TlsCaptureStart() {
        override fun toString(): String = "TlsCaptureStart.Disabled"
    }

    /** Nothing is running; [errorCode] is one of C04's fixed names. */
    data class Failed(val errorCode: TlsErrorCode) : TlsCaptureStart()

    /** The engine is running and [gateway] owns the run's channel to it. */
    data class Started(val gateway: SocksNioTlsGateway, val port: Int) : TlsCaptureStart()
}

/**
 * A reader's view of one TLS run: fixed codes and counters, never a token, a
 * secret byte or a private key.
 */
internal data class TlsCaptureState(
    val status: TlsCaptureStatus,
    val errorCode: TlsErrorCode? = null,
    val gatewayPort: Int? = null,
    val caId: String? = null,
    val caGeneration: Long? = null,
    val connections: TlsConnectionCounts = TlsConnectionCounts(),
    val traffic: TlsTrafficCounts = TlsTrafficCounts(),
    val secrets: TlsSecretPersistence? = null,
    val engineDiagnostics: TlsEngineDiagnostics? = null,
    val secretQueue: TlsSecretQueueMetrics? = null,
    val journal: TlsJournalMetrics? = null
) {
    /**
     * True only when the run produced no secrets problem at all: nothing was
     * refused and everything accepted reached the disk. A run with no connection
     * is vacuously complete, and incompleteness is never reported as a clean
     * capture just because the stop finished.
     */
    val secretsComplete: Boolean get() = secrets?.complete ?: true

    override fun toString(): String =
        "TlsCaptureState(status=$status, errorCode=$errorCode, port=$gatewayPort, " +
            "connections=$connections, secrets=$secrets)"
}

/**
 * The whole TLS half of one live capture (TLS-216, design §5.3, §8.2, §10.3).
 *
 * One instance owns exactly one run: the live secrets sink, the CA lease, the Go
 * engine and the gateway channel the SOCKS hop dispatches through. [start] and
 * [stop] follow the design's start/stop order, and **every** exit path releases
 * what it opened in reverse order — a failure at any stage must leave no engine
 * running, no port listening and no unsealed root.
 *
 * The class is deliberately not a Service: it knows nothing about the VPN, HEV,
 * the packet writer or the notification, so the same lifecycle can be driven by
 * the VPN service in production and by a JVM suite without a device. It also
 * never logs and never puts key material into a value of its own: everything a
 * caller can read is a fixed code, a counter or a bounded event list.
 *
 * Failure is separated from bypass on purpose. `enabled = false` (and settings
 * the validator rejects, which C04 migrates to TLS off) is
 * [TlsCaptureStart.Disabled] and the capture runs exactly as it did before this
 * feature existed. A request that *does* ask for interception and cannot get it
 * is [TlsCaptureStart.Failed]: silently forwarding such a capture would produce
 * an evidence file the user believes is decryptable (C03 7, §10.2).
 */
internal class TlsCaptureCoordinator(
    val captureId: String,
    private val settings: TlsCaptureSettings,
    private val allowedApplications: Collection<String> = emptyList(),
    /** Null when the device has no physical network to intercept on. */
    private val network: TlsNetworkAccess?,
    /** Created on first use: a capture that does not intercept must not touch the Keystore. */
    private val certificates: () -> TlsCertificateManager,
    /** Created on first use: a capture that does not intercept must not create a secrets directory. */
    private val secretStore: () -> TlsSecretStore,
    private val bridge: TlsEngineBridge = TlsProxyBridge(),
    private val verification: TlsUpstreamVerification = AndroidUpstreamVerification,
    private val connectionStore: TlsConnectionStore = TlsConnectionStore(captureId),
    private val secretLimits: TlsLiveSecretLimits = TlsLiveSecretLimits(),
    private val buildSupportsTls: Boolean = BuildConfig.TLS_ENABLED,
    /** The owning capture's stop intent; checked between every start stage. */
    private val cancellationRequested: () -> Boolean = { false },
    private val stopBudgetMillis: Long = DEFAULT_STOP_BUDGET_MILLIS,
    private val eventDrainBudgetMillis: Long = DEFAULT_EVENT_DRAIN_BUDGET_MILLIS,
    private val socksRuntime: SocksRuntimeLimits =
        SocksRuntimeLimits()
) : AutoCloseable {

    private enum class Phase { New, Starting, Running, Stopping, Stopped }

    private val lock = Any()
    private val finished = CountDownLatch(1)
    private val stopRequested = AtomicBoolean(false)

    @Volatile
    private var phase = Phase.New

    @Volatile
    private var status = TlsCaptureStatus.DISABLED

    @Volatile
    private var handle = 0L

    @Volatile
    private var port: Int? = null

    @Volatile
    private var gateway: TlsGatewayChannel? = null

    @Volatile
    private var lease: TlsCaLease? = null

    @Volatile
    private var sink: TlsLiveSecretSink? = null

    @Volatile
    private var errorCode: TlsErrorCode? = null

    @Volatile
    private var secretsState: TlsSecretPersistence? = null
    @Volatile private var finalSecretQueue: TlsSecretQueueMetrics? = null

    /** The store a reader folds this run's events into; the capture UI reads it in P3. */
    val connections: TlsConnectionStore get() = connectionStore

    private val caManager by lazy { certificates() }

    private val secrets by lazy { secretStore() }

    /**
     * Runs the start sequence once. Settings that do not enable interception
     * return [TlsCaptureStart.Disabled] without touching the engine, the CA or
     * the secrets store.
     */
    fun start(): TlsCaptureStart {
        synchronized(lock) {
            check(phase == Phase.New) { "This TLS capture run has already been started." }
            phase = Phase.Starting
            status = TlsCaptureStatus.STARTING
        }
        val result = try {
            startStages()
        } catch (_: TlsStartCancelled) {
            TlsCaptureStart.Failed(TlsErrorCode.CANCELLED)
        } catch (_: Throwable) {
            // An unexpected throw is still a refusal to run, never a half-started engine.
            TlsCaptureStart.Failed(TlsErrorCode.IO_ERROR)
        }
        if (result !is TlsCaptureStart.Started) {
            // The start failure is recorded before the release, so a release that
            // also fails cannot replace the reason the capture never ran.
            (result as? TlsCaptureStart.Failed)?.let { recordError(it.errorCode) }
            teardown()
            synchronized(lock) {
                phase = Phase.Stopped
                status = when {
                    result == TlsCaptureStart.Disabled -> TlsCaptureStatus.DISABLED
                    result == TlsCaptureStart.Failed(TlsErrorCode.UNSUPPORTED) -> TlsCaptureStatus.UNSUPPORTED
                    else -> TlsCaptureStatus.FAILED
                }
            }
            finished.countDown()
        }
        return result
    }

    private fun startStages(): TlsCaptureStart {
        val policy = TlsRoutingPolicy.freeze(settings, allowedApplications)
        // C04: a configuration the validator rejects migrates to TLS off — never
        // to "intercept everything" — and a disabled policy intercepts nothing.
        if (!policy.enabled) return TlsCaptureStart.Disabled
        if (!buildSupportsTls) return TlsCaptureStart.Failed(TlsErrorCode.UNSUPPORTED)
        val networkAccess = network ?: return TlsCaptureStart.Failed(TlsErrorCode.NETWORK_CHANGED)

        ensureNotCancelled()
        // TLS-201's capability query deliberately does not load the Go library, so
        // this reads the build property rather than a readiness that only a start
        // can produce; the start itself answers UNSUPPORTED/NOT_READY honestly.
        val capabilities = readEnvelope(bridge.capabilities()) ?: return TlsCaptureStart.Failed(TlsErrorCode.IO_ERROR)
        if (!capabilities.optBoolean("buildEnabled")) return TlsCaptureStart.Failed(TlsErrorCode.UNSUPPORTED)
        CaptureStartupChecks.reached("tls-capabilities")

        // C06/design §10.3: the root exists (or is minted once) before any engine
        // can sign, and the lease is what makes `reset` refuse to replace it while
        // this capture runs.
        ensureNotCancelled()
        val rootStatus = try {
            caManager.ensureGenerated { ensureNotCancelled() }
        } catch (error: TlsCertificateException) {
            return TlsCaptureStart.Failed(certificateCode(error.code))
        }
        if (!rootStatus.usable) return TlsCaptureStart.Failed(certificateCode(rootStatus.state))
        val opened = try {
            caManager.openEngineLease()
        } catch (error: TlsCertificateException) {
            return TlsCaptureStart.Failed(certificateCode(error.code))
        }
        lease = opened
        CaptureStartupChecks.reached("tls-ca")

        // §8.1: the sink has to exist before the engine can offer anything, and
        // it never blocks the handshake that produced the record.
        ensureNotCancelled()
        val openedSink = try {
            secrets.openLiveSecrets(captureId, secretLimits)
        } catch (error: TlsAssetException) {
            return TlsCaptureStart.Failed(assetCode(error.code))
        }
        sink = openedSink
        CaptureStartupChecks.reached("tls-secrets")

        ensureNotCancelled()
        val config = JSONObject()
            .put("schemaVersion", CONFIG_SCHEMA_VERSION)
            .put("captureId", captureId)
            .put("networkGeneration", networkAccess.generation)
            .put("settings", JSONObject(policy.encode()))
            .put("socksRuntime", socksRuntime.encode())
            .toString()
        val callbacks = platformCallbacks(networkAccess)
        // The root is borrowed for the duration of one JNI call: the C ABI copies
        // it into native memory, and this class never keeps a second reference.
        val started = try {
            opened.withPrivateKeyPkcs8 { privateKey ->
                bridge.start(config, opened.certificateDer, privateKey, callbacks)
            }
        } catch (error: TlsCertificateException) {
            return TlsCaptureStart.Failed(certificateCode(error.code))
        }
        val response = readEnvelope(started) ?: return TlsCaptureStart.Failed(TlsErrorCode.IO_ERROR)
        if (!response.optBoolean("success")) return TlsCaptureStart.Failed(codeOf(response.optStringOrNull("errorCode")))
        val engineHandle = response.optLong("engineHandle", 0L)
        val enginePort = response.optInt("port", 0)
        if (engineHandle <= 0 || enginePort !in 1..65535) {
            // A success that names no usable endpoint is not a running engine; the
            // handle is recorded first so the release can still stop it.
            if (engineHandle > 0) handle = engineHandle
            return TlsCaptureStart.Failed(TlsErrorCode.IO_ERROR)
        }
        handle = engineHandle
        CaptureStartupChecks.reached("tls-engine")
        ensureNotCancelled()

        val channel = try {
            buildChannel(enginePort, policy, networkAccess)
        } catch (error: IllegalStateException) {
            // A token the ABI would not hand out is not a configuration mistake to
            // paper over: the run stops here with the ABI's own fixed code.
            return TlsCaptureStart.Failed(codeOf(error.message))
        } catch (_: IllegalArgumentException) {
            return TlsCaptureStart.Failed(TlsErrorCode.INVALID_ARGUMENT)
        } catch (_: IOException) {
            return TlsCaptureStart.Failed(TlsErrorCode.INVALID_ARGUMENT)
        }

        // The last checkpoint: a stop that arrived during the start must not be
        // answered with a running engine nobody will ever stop.
        gateway = channel
        port = enginePort
        // Own the channel before cancellation can throw: teardown must wipe the
        // channel's token even when Stop wins just after buildChannel returns.
        CaptureStartupChecks.reached("tls-gateway")
        ensureNotCancelled()
        connectionStore.begin()
        synchronized(lock) {
            phase = Phase.Running
            status = TlsCaptureStatus.RUNNING
        }
        return TlsCaptureStart.Started(channel, enginePort)
    }

    /**
     * The run's channel: the port, the token and the frozen policy the engine was
     * started with, so a connection can only ever be dispatched to the engine that
     * owns it. The token copy read from the ABI is wiped here — the channel keeps
     * its own, and wipes that when it closes (TLS-215).
     */
    private fun buildChannel(
        enginePort: Int,
        policy: TlsRoutingPolicy,
        networkAccess: TlsNetworkAccess
    ): TlsGatewayChannel {
        val token = bridge.gatewayToken(handle)
        return try {
            CaptureStartupChecks.reached("tls-token")
            ensureNotCancelled()
            TlsGatewayChannel(
                gatewayPort = enginePort,
                token = token,
                captureId = captureId,
                networkGeneration = networkAccess.generation,
                policy = policy,
                prepareHopSocket = networkAccess::prepareHopSocket
            )
        } finally {
            token.fill(0)
        }
    }

    /**
     * The C05 platform composite: the captured network's socket half, the
     * platform's chain-and-name verification, and the live secret sink.
     */
    private fun platformCallbacks(networkAccess: TlsNetworkAccess): TlsPlatformCallbacks =
        object : TlsPlatformCallbacks {
            override fun prepareSocket(fd: Int, networkGeneration: Long): String =
                networkAccess.upstream.prepareSocket(fd, networkGeneration)

            override fun resolveHost(host: String, networkGeneration: Long): String =
                networkAccess.upstream.resolveHost(host, networkGeneration)

            override fun verifyUpstream(
                chainDer: Array<ByteArray>,
                identity: String,
                authType: String,
                tlsVersion: String
            ): String = verification.verify(chainDer, identity, authType, tlsVersion)

            /**
             * Copies one NSS line into the bounded queue and returns without any
             * I/O. The buffer the engine handed over is wiped here — the sink keeps
             * only its own canonical copy — and a refusal is reported to the engine
             * as such instead of being hidden, because it is what suspends new
             * interception (§8.2).
             */
            override fun offerSecret(captureId: String, connectionId: String, line: ByteArray): Boolean {
                val accepted = captureId == this@TlsCaptureCoordinator.captureId &&
                    sink?.offer(connectionId, line) == true
                line.fill(0)
                return accepted
            }
        }

    private val eventLock = ReentrantLock()

    /** Poll/apply is ordered with teardown; the capture loop never waits for a stop. */
    fun pump() {
        if (!eventLock.tryLock()) return
        try {
            val engineHandle = handle
            if (engineHandle <= 0L || phase == Phase.Stopped) return
            runCatching { connectionStore.recordPoll(bridge.poll(engineHandle, MAX_POLL_EVENTS)) }
            runCatching {
                connectionStore.recordEngineStats(bridge.stats(engineHandle), sink?.queuedBytes())
            }
        } finally {
            eventLock.unlock()
        }
    }

    /**
     * Stops accepting new connections and releases everything the run opened, in
     * the reverse of the start order, inside C10's budgets. Idempotent and safe
     * from any thread: a caller that arrives while the start or another stop is
     * still in flight waits for that one instead of racing it.
     */
    fun stop(): TlsCaptureState {
        stopRequested.set(true)
        val owner = synchronized(lock) {
            when (phase) {
                // Nothing was ever started, so there is nothing to release; the
                // run is over without having touched a resource.
                Phase.New -> {
                    phase = Phase.Stopped
                    finished.countDown()
                    false
                }
                // A start is in flight: its own thread sees the same flag between
                // stages, releases the partial run and counts the latch down.
                Phase.Starting -> false
                Phase.Running -> {
                    phase = Phase.Stopping
                    true
                }
                Phase.Stopping, Phase.Stopped -> false
            }
        }
        if (owner) {
            try {
                teardown()
            } finally {
                synchronized(lock) {
                    phase = Phase.Stopped
                    // A run that ended with any recorded lifecycle error — an engine
                    // that would not come down, secrets that never reached the disk —
                    // is not reported as a clean stop (C03 7).
                    if (status != TlsCaptureStatus.DISABLED) {
                        status = if (errorCode == null) TlsCaptureStatus.STOPPED else TlsCaptureStatus.FAILED
                    }
                }
                finished.countDown()
            }
        } else {
            awaitFinished()
        }
        return state()
    }

    override fun close() {
        stop()
    }

    /** Fixed codes, counters and bounded events only; safe to read while running or after a stop. */
    fun state(): TlsCaptureState {
        val snapshot = connectionStore.snapshot()
        return TlsCaptureState(
            status = currentStatus(),
            errorCode = errorCode,
            gatewayPort = port,
            caId = lease?.caId,
            caGeneration = lease?.caGeneration,
            connections = snapshot.counts,
            traffic = snapshot.traffic,
            secrets = secretsState ?: sink?.snapshot(),
            engineDiagnostics = snapshot.engineDiagnostics,
            secretQueue = sink?.queueMetrics() ?: finalSecretQueue,
            journal = connectionStore.journalMetrics()
        )
    }

    /**
     * The release half of the design's stop order. It runs the same sequence
     * whether a start failed halfway or a running capture is being stopped:
     *
     * 1. the channel — no connection may be admitted any more, and its token goes;
     * 2. the network — a late callback is refused instead of being prepared;
     * 3. the engine's events, while its handle is still valid;
     * 4. the engine itself, inside the stop budget;
     * 5. the secret sink, inside the C10 drain budget;
     * 6. the root lease, which wipes the unsealed private key.
     *
     * Every step is bounded: a step that runs out of budget records a fixed code
     * and the release continues, because C10 forbids waiting indefinitely and a
     * capture must never leave the device's traffic behind an unusable proxy.
     */
    private fun teardown() {
        val channel = gateway
        gateway = null
        runCatching { channel?.close() }
        runCatching { network?.close() }
        // Serialize the last poll/apply with shutdown: applying a newer batch
        // first would reject older terminal events by capture-wide sequence.
        eventLock.withLock {
            drainEvents()
            stopEngine()
        }
        finishSecrets()
        val opened = lease
        lease = null
        runCatching { opened?.close() }
        connectionStore.close()
    }

    /** Emptying the queue while the handle is still valid is what makes a terminal state reachable. */
    private fun drainEvents(engineHandle: Long = handle) {
        if (engineHandle <= 0L) return
        val deadline = System.nanoTime() + eventDrainBudgetMillis * NANOS_PER_MILLI
        while (true) {
            val applied = try {
                connectionStore.recordPoll(bridge.poll(engineHandle, MAX_POLL_EVENTS))
            } catch (_: Throwable) {
                return
            }
            if (applied <= 0 || System.nanoTime() >= deadline) return
        }
    }

    private fun stopEngine() {
        val engineHandle = handle
        if (engineHandle <= 0L) return
        handle = 0L
        val deadline = System.nanoTime() + stopBudgetMillis * NANOS_PER_MILLI
        while (true) {
            val response = try {
                readEnvelope(bridge.stop(engineHandle, stopTimeoutMillis()))
            } catch (_: Throwable) {
                null
            }
            if (response != null && response.optBoolean("success")) {
                response.optJSONObject("finalStats")?.let { final ->
                    connectionStore.recordEngineStats(final.toString(), sink?.queuedBytes())
                }
                // Go retains unread events after join, including CLOSED/FAILED
                // published by cancellation of live connections during Stop.
                drainEvents(engineHandle)
                return
            }
            val code = if (response == null) TlsErrorCode.IO_ERROR else codeOf(response.optStringOrNull("errorCode"))
            when (code) {
                // The ABI's own "shutdown is still draining" answer: retrying is the
                // documented response (TLS-213), inside C10's budget.
                TlsErrorCode.NOT_READY -> if (System.nanoTime() >= deadline) {
                    runCatching { connectionStore.recordEngineStats(bridge.stats(engineHandle), sink?.queuedBytes()) }
                    recordError(TlsErrorCode.NOT_READY)
                    return
                }
                // A handle that is not this run's means this run no longer exists,
                // which is exactly the state stopping was trying to reach.
                TlsErrorCode.STALE_GENERATION -> return
                else -> {
                    recordError(code)
                    return
                }
            }
            sleepQuietly()
        }
    }

    /**
     * Ends admission and publishes the watermark the sink actually reached. The
     * budget is the sink's own C10 drain budget; records that did not make it stay
     * unpersisted and are reported as incomplete rather than flushed away.
     */
    private fun finishSecrets() {
        val opened = sink
        sink = null
        if (opened == null) return
        secretsState = try {
            opened.finish()
        } catch (error: Throwable) {
            // Publication may fail AFTER the consumer drained more records. Use
            // its final watermark counters, and retain the fixed storage cause.
            val after = opened.snapshot()
            after.copy(
                failure = after.failure ?: (error as? TlsAssetException)?.code ?: TlsAssetErrorCode.IO_ERROR,
                asset = null
            )
        }
        finalSecretQueue = opened.queueMetrics()
        if (secretsState?.complete == false) recordError(TlsErrorCode.SECRETS_INCOMPLETE)
    }

    private fun currentStatus(): TlsCaptureStatus {
        val base = status
        // The engine is the one that suspends interception when a secret could not
        // be saved, so a run whose sink reports that is reported as PAUSED and
        // never as a healthy proxy (§8.2, C03 7).
        return if (base == TlsCaptureStatus.RUNNING && sink?.snapshot()?.mitmSuspended == true) {
            TlsCaptureStatus.PAUSED
        } else {
            base
        }
    }

    private fun recordError(code: TlsErrorCode) {
        if (errorCode == null) errorCode = code
    }

    private fun ensureNotCancelled() {
        if (stopRequested.get() || cancellationRequested()) throw TlsStartCancelled()
    }

    private fun awaitFinished() {
        var interrupted = false
        while (true) {
            try {
                finished.await()
                break
            } catch (_: InterruptedException) {
                interrupted = true
            }
        }
        if (interrupted) Thread.currentThread().interrupt()
    }

    /** The ABI refuses a timeout above its own maximum; the budget can only be smaller. */
    private fun stopTimeoutMillis(): Int = stopBudgetMillis.coerceIn(1L, MAX_ABI_STOP_MILLIS).toInt()

    private fun sleepQuietly() {
        try {
            Thread.sleep(POLL_INTERVAL_MILLIS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    /** A class of its own so a cancellation cannot be mistaken for a start failure code. */
    private class TlsStartCancelled : Exception()

    private companion object {
        const val CONFIG_SCHEMA_VERSION = 2

        /** C10's per-poll ceiling, the same one the ABI enforces. */
        const val MAX_POLL_EVENTS = 128

        /** C10's stop-writer budget: the engine is given this long to come down. */
        const val DEFAULT_STOP_BUDGET_MILLIS = 5_000L

        /** Draining the last events is bounded and separate from the engine's own stop. */
        const val DEFAULT_EVENT_DRAIN_BUDGET_MILLIS = 1_000L

        const val POLL_INTERVAL_MILLIS = 50L
        const val NANOS_PER_MILLI = 1_000_000L

        /** The ABI refuses a larger stop timeout (TLS-201). */
        const val MAX_ABI_STOP_MILLIS = 5_000L

        /**
         * One JSON object and nothing else: a reply with trailing content is not
         * one of ours and must not be read as a verdict.
         */
        fun readEnvelope(text: String): JSONObject? = try {
            val tokens = JSONTokener(text)
            val root = tokens.nextValue()
            if (root !is JSONObject || tokens.nextClean() != '\u0000') null else root
        } catch (_: JSONException) {
            null
        }

        fun JSONObject.optStringOrNull(name: String): String? =
            if (isNull(name)) null else optString(name).takeIf { it.isNotEmpty() }

        /** An unknown code is never a pass; it is reported as the fixed IO_ERROR. */
        fun codeOf(name: String?): TlsErrorCode {
            val code = TlsErrorCode.fromWire(name)
            return if (code == TlsErrorCode.UNKNOWN) TlsErrorCode.IO_ERROR else code
        }

        /** Root states a caller has to act on, mapped onto C04's fixed codes. */
        fun certificateCode(state: TlsCaState): TlsErrorCode = when (state) {
            TlsCaState.READY -> TlsErrorCode.NOT_READY
            TlsCaState.MISSING, TlsCaState.NOT_YET_VALID, TlsCaState.EXPIRED -> TlsErrorCode.NOT_READY
            TlsCaState.KEY_UNAVAILABLE -> TlsErrorCode.KEY_UNAVAILABLE
            TlsCaState.INVALID_FORMAT, TlsCaState.IO_ERROR -> TlsErrorCode.IO_ERROR
        }

        fun certificateCode(code: TlsCertificateErrorCode): TlsErrorCode = when (code) {
            TlsCertificateErrorCode.KEY_UNAVAILABLE -> TlsErrorCode.KEY_UNAVAILABLE
            TlsCertificateErrorCode.NOT_READY,
            TlsCertificateErrorCode.EXPIRED,
            TlsCertificateErrorCode.NOT_YET_VALID,
            TlsCertificateErrorCode.IN_USE,
            TlsCertificateErrorCode.CAPTURE_ACTIVE -> TlsErrorCode.NOT_READY
            TlsCertificateErrorCode.UNSUPPORTED -> TlsErrorCode.UNSUPPORTED
            TlsCertificateErrorCode.CAPACITY_EXCEEDED -> TlsErrorCode.CAPACITY_EXCEEDED
            TlsCertificateErrorCode.INVALID_ARGUMENT -> TlsErrorCode.INVALID_ARGUMENT
            TlsCertificateErrorCode.ALREADY_EXISTS,
            TlsCertificateErrorCode.INVALID_FORMAT,
            TlsCertificateErrorCode.DISK_FULL,
            TlsCertificateErrorCode.IO_ERROR -> TlsErrorCode.IO_ERROR
        }

        fun assetCode(code: TlsAssetErrorCode): TlsErrorCode = when (code) {
            TlsAssetErrorCode.KEY_UNAVAILABLE -> TlsErrorCode.KEY_UNAVAILABLE
            TlsAssetErrorCode.CAPACITY_EXCEEDED -> TlsErrorCode.CAPACITY_EXCEEDED
            TlsAssetErrorCode.INVALID_ARGUMENT -> TlsErrorCode.INVALID_ARGUMENT
            TlsAssetErrorCode.IN_USE -> TlsErrorCode.NOT_READY
            TlsAssetErrorCode.NOT_FOUND -> TlsErrorCode.CAPTURE_CONTEXT_MISSING
            else -> TlsErrorCode.IO_ERROR
        }
    }
}

/**
 * Production upstream verification (TLS-204). Built on first use, so a capture
 * that never verifies an upstream certificate resolves no trust manager; the
 * class itself refuses to skip verification, so there is no permissive variant to
 * fall back to.
 */
private object AndroidUpstreamVerification : TlsUpstreamVerification {
    private val verifier by lazy { AndroidUpstreamTrustVerifier() }

    override fun verify(chainDer: Array<ByteArray>, identity: String, authType: String, tlsVersion: String): String =
        verifier.verifyUpstream(chainDer, identity, authType, tlsVersion)
}
