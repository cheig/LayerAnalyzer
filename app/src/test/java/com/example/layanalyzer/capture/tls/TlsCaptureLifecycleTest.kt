// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.capture.socks.SocksRuntimeLimits
import com.example.layanalyzer.data.CaptureArtifactRepository
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureStatus
import com.example.layanalyzer.model.TlsErrorCode
import java.io.File
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The capture lifecycle of TLS-216, driven without a device (J=TlsCaptureLifecycleTest).
 *
 * What is real here and what is not: the CA manager, the secrets store, the live
 * sink and the connection store are the production classes, with the Keystore
 * wrapping key replaced by a JVM AES-GCM key and the Go material source replaced
 * by the committed synthetic fixture — the same substitution TLS-206's and
 * TLS-210's JVM suites make. The C ABI and the captured network are doubles,
 * because the native library and `android.net.Network` only exist on a device;
 * the device gate for the assembled service is `TlsVpnLifecycleTest`.
 *
 * Every case asserts the same property from a different angle: whatever a start
 * stage does, the run either has an engine that its own stop takes down, or no
 * engine at all — and the root lease and the secrets asset are never left behind.
 */
class TlsCaptureLifecycleTest {
    @get:Rule val temporary = TemporaryFolder()

    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val provider = AesGcmTlsWrappingKeyProvider { key }
    private val fixture = listOf(
        File("app/src/test/resources/tls/certificate-manager"),
        File("src/test/resources/tls/certificate-manager")
    ).firstOrNull { it.isDirectory } ?: error("certificate-manager fixture directory not found")
    private val fixtureCertificate: ByteArray = File(fixture, "ca-certificate.der").readBytes()
    private val fixturePrivateKey: ByteArray = File(fixture, "ca-private-key.pkcs8").readBytes()

    /** Counts generations so "nothing was minted" is assertable. */
    private var generated = 0
    private val material = object : TlsCaMaterialSource {
        override fun generate(): Array<ByteArray> {
            generated++
            return arrayOf(fixtureCertificate.copyOf(), fixturePrivateKey.copyOf())
        }
    }

    /** Shared by the test and the coordinator on purpose: `activeLeases` is per instance (TLS-206). */
    private val caManager by lazy { TlsCertificateManager(noBackup, provider, material) }
    private val store by lazy { TlsSecretStore(noBackup, provider) }

    /** The start order both doubles record into, so "released in reverse" is assertable. */
    private val order = mutableListOf<String>()
    private val bridge = FakeBridge(order)
    private val network = FakeNetwork(GENERATION, order)

    private val noBackup get() = File(temporary.root, "nobackup")
    private val caRoot get() = File(noBackup, "tls-ca")
    private val secretsRoot get() = File(noBackup, "capture-secrets")

    private val enabled = TlsCaptureSettings(enabled = true, candidatePorts = setOf(CANDIDATE_PORT))

    // ------------------------------------------------------------------ cases

    @Test fun successfulStopRecordsFinalCountersAfterEngineJoin() {
        val run = coordinator()
        assertTrue(run.start() is TlsCaptureStart.Started)
        bridge.statsEnvelope = statsEnvelope(10, 20)
        run.pump()
        assertEquals(10L, run.state().traffic.bytesToUpstream)
        bridge.finalStats = JSONObject(statsEnvelope(30, 40)).put("state", "STOPPED")
            .put("gateway", JSONObject().put("active", 0).put("ready", 9))
        val final = run.stop()
        assertEquals(30L, final.traffic.bytesToUpstream)
        assertEquals(40L, final.traffic.bytesToDownstream)
        assertEquals("STOPPED", final.engineDiagnostics?.state)
        assertEquals(9L, final.engineDiagnostics?.gateway?.get("ready"))
        assertFalse(final.secretQueue!!.consumerAlive)
    }

    @Test fun stopDrainsTerminalsCreatedDuringJoinIntoCountersAndJournal() {
        val capturesRoot = File(temporary.root, "captures")
        val journalFile = CaptureArtifactRepository(capturesRoot).connectionEventsFile(CAPTURE_ID)
        val connections = requireNotNull(createTlsCaptureConnectionStore(capturesRoot, CAPTURE_ID, enabled))
        val run = coordinator(connectionStore = connections)
        assertTrue(run.start() is TlsCaptureStart.Started)
        val live = JSONObject(eventEnvelope()).apply {
            getJSONArray("events").getJSONObject(0).put("phase", "RELAYING")
        }
        bridge.pollEnvelope = live.toString()
        run.pump()
        assertEquals(1L, run.state().connections.proxied)
        bridge.pollEnvelope = emptyEnvelope()
        bridge.onStop = {
            bridge.pollEnvelope = JSONObject(eventEnvelope()).apply {
                getJSONArray("events").getJSONObject(0)
                    .put("eventSequence", 2L).put("phase", "CLOSED")
                    .put("secretRecordsAccepted", 2L).put("secretRecordsPersisted", 2L)
                    .put("secretsComplete", true)
            }.toString()
        }
        val stopped = run.stop()
        assertEquals(1L, stopped.connections.closed)
        assertEquals(1L, stopped.connections.secretsSaved)
        assertEquals(2L, stopped.connections.secretRecordsPersisted)
        assertEquals("CLOSED", connections.snapshot().connections.single().phase.wireName)
        val history = journalFile.readLines().map(::JSONObject)
        assertEquals(listOf("RELAYING", "CLOSED"), history.map { it.getString("phase") })
        assertEquals(2L, stopped.journal!!.persisted)
        assertEquals(0L, stopped.journal.notPersisted)
        assertFalse(stopped.journal.workerAlive)
        assertFalse(stopped.journal.closeTimedOut)
    }

    @Test fun journalWorkerIsClosedWhenAnEnabledCaptureCannotStart() {
        val capturesRoot = File(temporary.root, "captures")
        val connections = requireNotNull(createTlsCaptureConnectionStore(capturesRoot, CAPTURE_ID, enabled))
        val run = coordinator(connectionStore = connections, buildSupportsTls = false)

        assertEquals(TlsCaptureStart.Failed(TlsErrorCode.UNSUPPORTED), run.start())
        val stopped = run.stop()
        assertFalse(stopped.journal!!.workerAlive)
        assertFalse(stopped.journal.closeTimedOut)
        assertEquals(0L, stopped.journal.persisted)
        assertFalse(caRoot.exists())
        assertFalse(secretsRoot.exists())
    }

    @Test fun aCaptureWithoutInterceptionTouchesNoEngineRootOrSecretDirectory() {
        val coordinator = coordinator(settings = TlsCaptureSettings())

        assertEquals(TlsCaptureStart.Disabled, coordinator.start())
        assertEquals("a disabled request must not even ask the engine", 0, bridge.capabilityCalls)
        assertEquals(0, bridge.startCalls)
        assertEquals("no CA may be minted for a capture that does not intercept", 0, generated)
        assertFalse(caRoot.exists())
        assertFalse(secretsRoot.exists())

        assertEquals(TlsCaptureStatus.DISABLED, coordinator.state().status)
        assertNull(coordinator.state().errorCode)
        coordinator.stop()
        assertEquals(0, bridge.stopCalls)
        assertEquals(TlsCaptureStatus.DISABLED, coordinator.state().status)
    }

    @Test fun aBuildWithoutTheTlsEngineRefusesAnEnabledRequest() {
        val coordinator = coordinator(buildSupportsTls = false)

        assertEquals(TlsCaptureStart.Failed(TlsErrorCode.UNSUPPORTED), coordinator.start())
        assertEquals("the build switch short-circuits before any native call", 0, bridge.capabilityCalls)
        assertEquals(0, generated)
        assertFalse(secretsRoot.exists())
        assertEquals(TlsCaptureStatus.UNSUPPORTED, coordinator.state().status)
        assertEquals(TlsErrorCode.UNSUPPORTED, coordinator.stop().errorCode)
    }

    @Test fun anEngineThatReportsNoTlsSupportRefusesTheRequest() {
        bridge.buildEnabled = false
        val coordinator = coordinator()

        assertEquals(TlsCaptureStart.Failed(TlsErrorCode.UNSUPPORTED), coordinator.start())
        assertEquals(0, bridge.startCalls)
        assertEquals(0, generated)
        assertEquals(TlsCaptureStatus.UNSUPPORTED, coordinator.state().status)
    }

    @Test fun aStartedRunFreezesItsIdentityAndHandsOverItsGateway() {
        val coordinator = coordinator()
        val started = coordinator.start()

        assertTrue("the run must start: $started", started is TlsCaptureStart.Started)
        val gateway = (started as TlsCaptureStart.Started).gateway
        assertEquals(PORT, started.port)
        assertTrue("a candidate port is admitted", (gateway.route(CANDIDATE_PORT) == SocksNioTlsGateway.Route.GATEWAY))
        assertFalse("a port outside the frozen set is not", (gateway.route(NON_CANDIDATE_PORT) == SocksNioTlsGateway.Route.GATEWAY))

        val config = JSONObject(requireNotNull(bridge.config))
        assertEquals(2, config.getInt("schemaVersion"))
        assertEquals("NIO", config.getJSONObject("socksRuntime").getString("mode"))
        assertEquals(1024, config.getJSONObject("socksRuntime").getInt("tcp"))
        assertEquals(256, config.getJSONObject("socksRuntime").getInt("udp"))
        assertEquals(128, config.getJSONObject("socksRuntime").getInt("authentication"))
        assertEquals(8, config.getJSONObject("socksRuntime").getInt("tlsHandshakes"))
        assertEquals(CAPTURE_ID, config.getString("captureId"))
        assertEquals(GENERATION, config.getLong("networkGeneration"))
        val policy = config.getJSONObject("settings")
        assertTrue(policy.getBoolean("enabled"))
        assertEquals(listOf(CANDIDATE_PORT), policy.getJSONArray("candidatePorts").ints())
        assertArrayEquals("the engine gets the root certificate", fixtureCertificate, bridge.certificate)
        assertArrayEquals("and the unsealed private key", fixturePrivateKey, bridge.privateKey)
        assertTrue(
            "the coordinator wipes the token copy it read from the ABI",
            requireNotNull(bridge.publishedToken).all { it == 0.toByte() }
        )

        val state = coordinator.state()
        assertEquals(TlsCaptureStatus.RUNNING, state.status)
        assertEquals(PORT, state.gatewayPort)
        assertEquals(caId(), state.caId)
        assertEquals(1L, state.caGeneration)
        assertTrue(state.secretsComplete)
        assertEquals("exactly one root was minted", 1, generated)

        // A held lease is what keeps the root from being replaced under a run.
        expect(TlsCertificateErrorCode.CAPTURE_ACTIVE) { caManager.reset() }
        coordinator.stop()
        assertEquals(TlsCaptureStatus.STOPPED, coordinator.state().status)
        assertEquals("the released lease lets the root be replaced", TlsCaState.READY, caManager.reset().state)
    }

    @Test fun stoppingReleasesTheChannelTheEngineTheSinkAndTheRoot() {
        val coordinator = coordinator()
        val gateway = (coordinator.start() as TlsCaptureStart.Started).gateway

        val state = coordinator.stop()
        assertEquals(TlsCaptureStatus.STOPPED, state.status)
        assertNull(state.errorCode)
        assertEquals(1, bridge.stopCalls)
        assertTrue(
            "the network is taken away before the engine stops: $order",
            order.indexOf("network-closed") < order.indexOf("engine-stop")
        )
        assertFalse("the channel wiped its token", (gateway as TlsGatewayChannel).carriesTokenMaterial())
        assertFalse("and admits nothing any more", (gateway.route(CANDIDATE_PORT) == SocksNioTlsGateway.Route.GATEWAY))

        // Idempotent: a second stop is the same stop, not a second engine stop.
        val again = coordinator.stop()
        assertEquals(state.status, again.status)
        assertEquals(1, bridge.stopCalls)
        assertEquals("no unpublished secrets directory is left behind", 0, store.cleanupOrphans())
    }

    @Test fun offeredSecretsArePersistedAndTheStopReportsTheRunComplete() {
        val coordinator = coordinator()
        coordinator.start()
        val callbacks = requireNotNull(bridge.callbacks)
        val line = line("CLIENT_RANDOM", "ab".repeat(32), "cd".repeat(48))

        assertEquals("a valid downstream record is accepted", true, callbacks.offerSecret(CAPTURE_ID, "c-1", line))
        assertTrue("the coordinator wipes the engine's buffer", line.all { it == 0.toByte() })
        assertEquals(TlsCaptureStatus.RUNNING, coordinator.state().status)

        val state = coordinator.stop()
        val persistence = requireNotNull(state.secrets)
        assertEquals(1L, persistence.accepted)
        assertEquals(1L, persistence.persisted)
        assertEquals(0L, persistence.rejected)
        assertTrue(persistence.complete)
        assertTrue(state.secretsComplete)
        assertNull(state.errorCode)
        assertEquals(TlsCaptureStatus.STOPPED, state.status)

        val asset = requireNotNull(store.currentAsset(CAPTURE_ID)) { "the finished sink published no asset" }
        assertEquals(1L, asset.watermark.sequence)
    }

    @Test fun anOfferForAnotherCaptureIsRefused() {
        val coordinator = coordinator()
        coordinator.start()
        val callbacks = requireNotNull(bridge.callbacks)
        val line = line("CLIENT_RANDOM", "ab".repeat(32), "cd".repeat(48))

        assertFalse(callbacks.offerSecret("some-other-capture", "c-1", line))
        assertTrue("the refused buffer is wiped too", line.all { it == 0.toByte() })
        val state = coordinator.stop()
        assertEquals(0L, requireNotNull(state.secrets).accepted)
        assertTrue("nothing was offered at all, so nothing is incomplete", state.secretsComplete)
    }

    @Test fun aSecretThatCannotBeQueuedMarksTheRunIncompleteAndPausesIt() {
        val coordinator = coordinator()
        coordinator.start()
        val callbacks = requireNotNull(bridge.callbacks)
        val garbage = "NOT AN NSS LINE".toByteArray(StandardCharsets.US_ASCII)

        assertFalse(callbacks.offerSecret(CAPTURE_ID, "c-1", garbage))
        assertEquals("new interception is suspended while a secret cannot be saved", TlsCaptureStatus.PAUSED, coordinator.state().status)

        val state = coordinator.stop()
        val persistence = requireNotNull(state.secrets)
        assertEquals(1L, persistence.rejected)
        assertFalse(persistence.complete)
        assertFalse(state.secretsComplete)
        assertEquals(TlsErrorCode.SECRETS_INCOMPLETE, state.errorCode)
        assertEquals(TlsCaptureStatus.FAILED, state.status)
    }

    @Test fun aConnectionEventAndTheEngineCountersReachTheStore() {
        bridge.pollEnvelope = eventEnvelope()
        bridge.statsEnvelope = statsEnvelope(bytesToUpstream = 4096, bytesToDownstream = 2048)
        val coordinator = coordinator()
        coordinator.start()

        coordinator.pump()

        val snapshot = coordinator.connections.snapshot()
        assertEquals(1L, snapshot.counts.accepted)
        assertEquals(1, snapshot.connections.size)
        assertEquals("the engine's own byte counters replace, never accumulate", 4096L, snapshot.traffic.bytesToUpstream)
        assertEquals(2048L, snapshot.traffic.bytesToDownstream)
        assertEquals(MAX_POLL_EVENTS, bridge.lastMaxEvents)
        coordinator.stop()
    }

    @Test fun anEngineRefusalBecomesAFixedCodeAndReleasesTheRoot() {
        bridge.startFailure = "NOT_READY"
        val coordinator = coordinator()

        assertEquals(TlsCaptureStart.Failed(TlsErrorCode.NOT_READY), coordinator.start())
        assertEquals(1, bridge.startCalls)
        assertEquals("a failed start still stops nothing it never started", 0, bridge.stopCalls)
        assertEquals("the root was minted and released again", TlsCaState.READY, caManager.reset().state)
        assertEquals(0, store.cleanupOrphans())

        val state = coordinator.stop()
        assertEquals(TlsCaptureStatus.FAILED, state.status)
        assertEquals(TlsErrorCode.NOT_READY, state.errorCode)
    }

    @Test fun aTokenTheAbiWouldNotHandOutStopsTheEngineThatWasJustStarted() {
        bridge.tokenFailure = "STALE_GENERATION"
        val coordinator = coordinator()

        assertEquals(TlsCaptureStart.Failed(TlsErrorCode.STALE_GENERATION), coordinator.start())
        assertEquals("an engine that started is always stopped, even when the run is abandoned", 1, bridge.stopCalls)
        assertEquals("the root is released with it", TlsCaState.READY, caManager.reset().state)
    }

    @Test fun aTokenOfTheWrongShapeIsAConfigurationFailureAndStopsTheEngine() {
        bridge.token = "short"
        val coordinator = coordinator()

        assertEquals(TlsCaptureStart.Failed(TlsErrorCode.INVALID_ARGUMENT), coordinator.start())
        assertEquals(1, bridge.stopCalls)
        assertEquals(0, store.cleanupOrphans())
    }

    @Test fun aLostKeystoreRefusesTheStartWithoutAnEngineOrASecretDirectory() {
        val manager = TlsCertificateManager(
            noBackup,
            AesGcmTlsWrappingKeyProvider { throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE) },
            material
        )
        val coordinator = coordinator(certificates = manager)

        assertEquals(TlsCaptureStart.Failed(TlsErrorCode.KEY_UNAVAILABLE), coordinator.start())
        assertEquals(0, bridge.startCalls)
        assertFalse("the secrets stage is never reached", secretsRoot.exists())
        assertEquals(TlsCaptureStatus.FAILED, coordinator.state().status)
        coordinator.stop()
    }

    @Test fun anUnexpectedFailureWhileMintingTheRootIsStillARefusal() {
        val failing = object : TlsCaMaterialSource {
            override fun generate(): Array<ByteArray> = throw IllegalStateException("provider detail must not escape")
        }
        val manager = TlsCertificateManager(noBackup, provider, failing)
        val coordinator = coordinator(certificates = manager)

        val started = coordinator.start()
        assertEquals(TlsCaptureStart.Failed(TlsErrorCode.IO_ERROR), started)
        assertFalse("a raw exception message must not become the refusal", "$started".contains("provider detail"))
        assertEquals(0, bridge.startCalls)
        coordinator.stop()
    }

    @Test fun aCancelledStartBeforeTheFirstStageTouchesNothing() {
        val coordinator = coordinator(cancellationRequested = { true })

        assertEquals(TlsCaptureStart.Failed(TlsErrorCode.CANCELLED), coordinator.start())
        assertEquals(0, bridge.capabilityCalls)
        assertEquals(0, generated)
        assertFalse(secretsRoot.exists())
        coordinator.stop()
    }

    @Test fun aCancelDuringTheEngineStartLeavesNoRunningEngine() {
        val cancelled = booleanArrayOf(false)
        bridge.onStart = { order += "engine-started"; cancelled[0] = true }
        val coordinator = coordinator(cancellationRequested = { cancelled[0] })

        assertEquals(TlsCaptureStart.Failed(TlsErrorCode.CANCELLED), coordinator.start())
        assertEquals("the engine that came up is taken down again", 1, bridge.stopCalls)
        assertTrue("the network is invalidated too: $order", "network-closed" in order)
        assertEquals("and the root lease is released", TlsCaState.READY, caManager.reset().state)
        assertEquals(0, store.cleanupOrphans())
    }

    @Test fun cancellationAfterChannelCreationWipesBothTokenCopies() {
        var channel: TlsGatewayChannel? = null
        lateinit var coordinator: TlsCaptureCoordinator
        val gatewayField = TlsCaptureCoordinator::class.java.getDeclaredField("gateway").apply {
            isAccessible = true
        }
        // Use the real cancellation predicate after ownership transfer rather
        // than the DEBUG-only observer, which deliberately never runs in Release.
        coordinator = this.coordinator(cancellationRequested = {
            val created = gatewayField.get(coordinator) as? TlsGatewayChannel
            if (created != null) {
                channel = created
                assertTrue(created.carriesTokenMaterial())
                true
            } else {
                false
            }
        })
        try {
            assertEquals(TlsCaptureStart.Failed(TlsErrorCode.CANCELLED), coordinator.start())
            assertTrue("channel checkpoint must actually execute", channel != null)
            assertFalse("cancelled channel must wipe its private token copy", channel!!.carriesTokenMaterial())
            assertTrue(bridge.publishedToken!!.all { it == 0.toByte() })
            assertEquals(1, bridge.stopCalls)
            assertEquals(TlsCaState.READY, caManager.reset().state)
        } finally {
            coordinator.stop()
        }
    }

    @Test fun failedSecretPublicationRetainsFinalPersistedCountAndStorageCode() {
        val restricted = TlsSecretStore(noBackup, provider, TlsSecretStoreLimits(maxKeyLogBytes = 1))
        val coordinator = coordinator(secretStore = restricted)
        assertTrue(coordinator.start() is TlsCaptureStart.Started)
        val bytes = line("CLIENT_RANDOM", "ab".repeat(32), "cd".repeat(48))
        try { assertTrue(bridge.callbacks!!.offerSecret(CAPTURE_ID, "c-1", bytes)) }
        finally { bytes.fill(0) }
        val result = coordinator.stop().secrets!!
        assertEquals(1L, result.accepted)
        assertEquals("the consumer drained before publication failed", 1L, result.persisted)
        assertEquals(TlsAssetErrorCode.CAPACITY_EXCEEDED, result.failure)
        assertNull(result.asset)
        assertFalse(result.complete)
        assertEquals(0, store.cleanupOrphans())
    }

    @Test fun aStopThatIsRefusedOnceIsRetriedInsideItsBudget() {
        bridge.stopFailures = 3
        val coordinator = coordinator()
        coordinator.start()

        val state = coordinator.stop()
        assertEquals("a NOT_READY stop is retried until the engine comes down", 4, bridge.stopCalls)
        assertEquals(TlsCaptureStatus.STOPPED, state.status)
        assertNull(state.errorCode)
    }

    @Test fun aStopThatNeverCompletesGivesUpInsideItsBudget() {
        bridge.stopFailures = Int.MAX_VALUE
        val coordinator = coordinator(stopBudgetMillis = 150L)
        coordinator.start()
        val started = System.nanoTime()

        val state = coordinator.stop()

        val elapsedMillis = (System.nanoTime() - started) / 1_000_000
        assertTrue("the stop must not wait indefinitely: ${elapsedMillis}ms", elapsedMillis < 5_000)
        assertEquals(TlsCaptureStatus.FAILED, state.status)
        assertEquals(TlsErrorCode.NOT_READY, state.errorCode)
        assertTrue("the retry is bounded and repeated, not abandoned: ${bridge.stopCalls}", bridge.stopCalls >= 2)
        assertEquals("the root is released even then", TlsCaState.READY, caManager.reset().state)
    }

    @Test fun aStoppedCaptureCanStartAgainAndTheOldRunsCallbacksAreRefused() {
        val first = coordinator()
        first.start()
        first.stop()
        assertTrue("a stopped run no longer prepares any socket", network.closed)
        assertEquals(
            "NETWORK_CHANGED",
            JSONObject(network.upstream.prepareSocket(9, GENERATION)).getString("errorCode")
        )

        val secondNetwork = FakeNetwork(GENERATION + 1, order)
        val secondBridge = FakeBridge(order)
        val second = coordinator(network = secondNetwork, bridge = secondBridge)

        val restarted = second.start()
        assertTrue("a restartable capture starts again: $restarted", restarted is TlsCaptureStart.Started)
        assertEquals("the second run carries its own generation", GENERATION + 1, JSONObject(requireNotNull(secondBridge.config)).getLong("networkGeneration"))
        assertEquals(TlsCaptureStatus.RUNNING, second.state().status)
        assertEquals(TlsCaptureStatus.STOPPED, second.stop().status)
        assertEquals(TlsCaptureStatus.STOPPED, first.state().status)
    }

    @Test fun aStaleGenerationCallbackIsRefusedByTheRunThatOwnsIt() {
        val coordinator = coordinator()
        coordinator.start()

        assertEquals(
            "an older generation is not this run's network",
            "STALE_GENERATION",
            JSONObject(network.upstream.prepareSocket(4, GENERATION - 1)).getString("errorCode")
        )
        assertTrue(
            "this run's generation is prepared",
            JSONObject(network.upstream.prepareSocket(4, GENERATION)).optBoolean("success")
        )
        assertEquals(listOf(4), network.prepared)
        coordinator.stop()
    }

    @Test fun exceptionsAtEachTlsStartBoundaryReleaseOwnershipAndAllowAnotherCapture() {
        // These are TLS coordinator boundaries; SOCKS/HEV/PCAP/VPN startup is
        // deliberately a separate device requirement in the TLS-403 matrix.
        for (stage in listOf("capabilities", "certificates", "secrets", "engine", "token")) {
            val failedBridge = FakeBridge(mutableListOf())
            val failedNetwork = FakeNetwork(GENERATION, mutableListOf())
            fun fault(): Nothing = throw IllegalStateException("injected private provider detail")
            val instrumented = object : TlsEngineBridge by failedBridge {
                override fun capabilities(): String = if (stage == "capabilities") fault() else failedBridge.capabilities()
                override fun start(configJson: String, certificateDer: ByteArray, privateKeyPkcs8: ByteArray,
                                   callbacks: TlsPlatformCallbacks): String =
                    if (stage == "engine") fault()
                    else failedBridge.start(configJson, certificateDer, privateKeyPkcs8, callbacks)
                override fun gatewayToken(handle: Long): ByteArray =
                    if (stage == "token") fault() else failedBridge.gatewayToken(handle)
            }
            val run = TlsCaptureCoordinator(
                captureId = "failure-$stage", settings = enabled, network = failedNetwork,
                certificates = { if (stage == "certificates") fault() else caManager },
                secretStore = { if (stage == "secrets") fault() else store },
                bridge = instrumented, buildSupportsTls = true
            )
            assertTrue(stage, run.start() is TlsCaptureStart.Failed)
            assertTrue(stage, failedNetwork.closed)
            assertEquals(stage, if (stage == "token") 1 else 0, failedBridge.stopCalls)
            repeat(3) { assertEquals(TlsCaptureStatus.FAILED, run.stop().status) }
            assertFalse(run.state().toString().contains("private provider detail"))
            // Reset checks that no CA engine lease survived the failure.
            assertEquals(stage, TlsCaState.READY, caManager.reset().state)
            val recovered = coordinator(
                captureId = "recovered-$stage", bridge = FakeBridge(mutableListOf()),
                network = FakeNetwork(GENERATION + 1, mutableListOf())
            )
            assertTrue(stage, recovered.start() is TlsCaptureStart.Started)
            assertEquals(TlsCaptureStatus.STOPPED, recovered.stop().status)
            assertEquals(stage, 0, store.cleanupOrphans())
        }
    }

    @Test(timeout = 15_000) fun concurrentStopDuringStartupRejectsLateSecretsAndCanRestart() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        bridge.onStart = {
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
        }
        val run = coordinator()
        val workers = Executors.newFixedThreadPool(5)
        try {
            val starting = workers.submit<TlsCaptureStart> { run.start() }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val stopEntered = CountDownLatch(4)
            val stops = (0 until 4).map {
                workers.submit<TlsCaptureState> { stopEntered.countDown(); run.stop() }
            }
            assertTrue(stopEntered.await(5, TimeUnit.SECONDS))
            // Both scheduler outcomes are valid: cancellation during start, or
            // a start immediately followed by stop. Every caller must finish.
            release.countDown()
            val start = starting.get(5, TimeUnit.SECONDS)
            assertTrue(start is TlsCaptureStart.Started || start == TlsCaptureStart.Failed(TlsErrorCode.CANCELLED))
            stops.forEach { assertTrue(it.get(5, TimeUnit.SECONDS).status in
                setOf(TlsCaptureStatus.STOPPED, TlsCaptureStatus.FAILED)) }
            assertEquals(1, bridge.stopCalls)
            val oldCallbacks = requireNotNull(bridge.callbacks)
            val late = line("CLIENT_RANDOM", "ab".repeat(32), "cd".repeat(48))
            assertFalse(oldCallbacks.offerSecret(CAPTURE_ID, "late", late))
            assertTrue(late.all { it == 0.toByte() })
            assertEquals(TlsCaState.READY, caManager.reset().state)
            val recovered = coordinator(
                captureId = "after-race", bridge = FakeBridge(mutableListOf()),
                network = FakeNetwork(GENERATION + 1, mutableListOf())
            )
            assertTrue(recovered.start() is TlsCaptureStart.Started)
            assertEquals(TlsCaptureStatus.STOPPED, recovered.stop().status)
        } finally {
            release.countDown()
            workers.shutdownNow()
            assertTrue(workers.awaitTermination(5, TimeUnit.SECONDS))
            run.stop()
        }
    }

    @Test fun controlledNioRuntimeIsFrozenIntoTheActualEngineStartEnvelope() {
        val limits = SocksRuntimeLimits(
            tcp = 1024, udp = 256, authentication = 128)
        coordinator(socksRuntime = limits).use { coordinator ->
            assertTrue(coordinator.start() is TlsCaptureStart.Started)
            val config = JSONObject(requireNotNull(bridge.config))
            assertEquals(2, config.getInt("schemaVersion"))
            assertEquals(limits.encode().toMap(), config.getJSONObject("socksRuntime").toMap())
            assertEquals(GENERATION, config.getLong("networkGeneration"))
        }
    }

    // ------------------------------------------------------------------ helpers

    private fun coordinator(
        settings: TlsCaptureSettings = enabled,
        network: TlsNetworkAccess? = this.network,
        bridge: TlsEngineBridge = this.bridge,
        buildSupportsTls: Boolean = true,
        cancellationRequested: () -> Boolean = { false },
        stopBudgetMillis: Long = 5_000L,
        captureId: String = CAPTURE_ID,
        certificates: TlsCertificateManager = caManager,
        secretStore: TlsSecretStore = store,
        connectionStore: TlsConnectionStore = TlsConnectionStore(captureId),
        socksRuntime: SocksRuntimeLimits =
            SocksRuntimeLimits()
    ): TlsCaptureCoordinator = TlsCaptureCoordinator(
        captureId = captureId,
        settings = settings,
        allowedApplications = emptyList(),
        network = network,
        certificates = { certificates },
        secretStore = { secretStore },
        bridge = bridge,
        verification = TlsUpstreamVerification { _, _, _, _ -> successEnvelope() },
        connectionStore = connectionStore,
        buildSupportsTls = buildSupportsTls,
        cancellationRequested = cancellationRequested,
        stopBudgetMillis = stopBudgetMillis,
        socksRuntime = socksRuntime
    )

    private fun caId(): String =
        JSONObject(File(caRoot, "current.json").readText()).getString("caId")

    private fun line(label: String, random: String, secret: String): ByteArray =
        "$label $random $secret".toByteArray(StandardCharsets.US_ASCII)

    private fun eventEnvelope(): String = JSONObject()
        .put("schemaVersion", 1).put("success", true)
        .put("errorCode", JSONObject.NULL).put("error", JSONObject.NULL)
        .put(
            "events",
            JSONArray().put(
                JSONObject()
                    .put("captureId", CAPTURE_ID).put("connectionId", "c-1").put("eventSequence", 1L)
                    .put("monotonicNanos", 1L).put("wallTimeMillis", 2L)
                    .put("destinationIp", "203.0.113.7").put("destinationPort", CANDIDATE_PORT)
                    .put("networkGeneration", GENERATION).put("phase", "ACCEPTED")
            )
        )
        .toString()

    private fun statsEnvelope(bytesToUpstream: Long, bytesToDownstream: Long): String = JSONObject()
        .put("schemaVersion", 1).put("success", true)
        .put("errorCode", JSONObject.NULL).put("error", JSONObject.NULL)
        .put(
            "events",
            JSONObject().put("bytesToUpstream", bytesToUpstream)
                .put("bytesToDownstream", bytesToDownstream).put("eventsDropped", 0L)
        )
        .toString()

    private fun expect(code: TlsCertificateErrorCode, block: () -> Unit) {
        try {
            block()
        } catch (failure: TlsCertificateException) {
            assertEquals("expected $code", code, failure.code)
            return
        }
        throw AssertionError("expected $code but the operation succeeded")
    }

    private fun JSONArray.ints(): List<Int> = (0 until length()).map { optInt(it) }

    /** A strict stand-in for the C ABI: envelopes only, and every answer recorded. */
    private class FakeBridge(private val order: MutableList<String>) : TlsEngineBridge {
        var capabilityCalls = 0
        var startCalls = 0
        var stopCalls = 0
        var pollCalls = 0
        var statsCalls = 0
        var lastMaxEvents = 0
        var buildEnabled = true
        var startFailure: String? = null
        var tokenFailure: String? = null
        var stopFailures = 0
        var port = PORT
        var handle = 7L
        var token = "A".repeat(43)
        var publishedToken: ByteArray? = null
        var config: String? = null
        var certificate: ByteArray? = null
        var privateKey: ByteArray? = null
        var callbacks: TlsPlatformCallbacks? = null
        var pollEnvelope = emptyEnvelope()
        var statsEnvelope = emptyEnvelope()
        var finalStats: JSONObject? = null
        var onStart: (() -> Unit)? = null
        var onStop: (() -> Unit)? = null

        override fun capabilities(): String {
            capabilityCalls++
            return JSONObject()
                .put("schemaVersion", 1).put("success", true)
                .put("errorCode", JSONObject.NULL).put("error", JSONObject.NULL)
                .put("buildEnabled", buildEnabled)
                .toString()
        }

        override fun start(
            configJson: String,
            certificateDer: ByteArray,
            privateKeyPkcs8: ByteArray,
            callbacks: TlsPlatformCallbacks
        ): String {
            startCalls++
            order += "engine-start"
            config = configJson
            certificate = certificateDer.copyOf()
            privateKey = privateKeyPkcs8.copyOf()
            this.callbacks = callbacks
            onStart?.invoke()
            startFailure?.let { return failureEnvelope(it) }
            return JSONObject()
                .put("schemaVersion", 1).put("success", true)
                .put("errorCode", JSONObject.NULL).put("error", JSONObject.NULL)
                .put("engineHandle", handle).put("port", port)
                .toString()
        }

        override fun stop(handle: Long, timeoutMillis: Int): String {
            stopCalls++
            order += "engine-stop"
            if (stopFailures > 0) {
                stopFailures--
                return failureEnvelope("NOT_READY")
            }
            onStop?.invoke()
            return JSONObject(successEnvelope()).apply { finalStats?.let { put("finalStats", it) } }.toString()
        }

        override fun poll(handle: Long, maxEvents: Int): String {
            pollCalls++
            lastMaxEvents = maxEvents
            return pollEnvelope
        }

        override fun stats(handle: Long): String {
            statsCalls++
            return statsEnvelope
        }

        override fun gatewayToken(handle: Long): ByteArray {
            tokenFailure?.let { throw IllegalStateException(it) }
            val bytes = token.toByteArray(StandardCharsets.US_ASCII)
            publishedToken = bytes
            return bytes
        }
    }

    /** The captured network as one run may use it, with the close that refuses late callbacks. */
    private class FakeNetwork(
        override val generation: Long,
        private val order: MutableList<String>
    ) : TlsNetworkAccess {
        var closed = false
        val prepared = mutableListOf<Int>()
        var hopPrepared = 0

        override val upstream = object : TlsUpstreamCallbacks {
            override fun prepareSocket(fd: Int, networkGeneration: Long): String {
                if (closed) return failureEnvelope("NETWORK_CHANGED")
                if (networkGeneration != generation) return failureEnvelope("STALE_GENERATION")
                prepared += fd
                return successEnvelope()
            }

            override fun resolveHost(host: String, networkGeneration: Long): String =
                if (closed || networkGeneration != generation) failureEnvelope("NETWORK_CHANGED") else successEnvelope()
        }

        override fun prepareHopSocket(socket: Socket) {
            hopPrepared++
        }

        override fun close() {
            closed = true
            order += "network-closed"
        }
    }

    private companion object {
        const val CAPTURE_ID = "capture-live"
        const val CANDIDATE_PORT = 443
        const val NON_CANDIDATE_PORT = 8_443
        const val PORT = 41_234
        const val GENERATION = 1_600_000_000_000L

        const val MAX_POLL_EVENTS = 128

        fun emptyEnvelope(): String = JSONObject()
            .put("schemaVersion", 1).put("success", true)
            .put("errorCode", JSONObject.NULL).put("error", JSONObject.NULL)
            .put("events", JSONArray())
            .toString()

        fun successEnvelope(): String = JSONObject()
            .put("schemaVersion", 1).put("success", true)
            .put("errorCode", JSONObject.NULL).put("error", JSONObject.NULL)
            .toString()

        fun failureEnvelope(code: String): String = JSONObject()
            .put("schemaVersion", 1).put("success", false)
            .put("errorCode", code).put("error", JSONObject.NULL)
            .toString()
    }
}
