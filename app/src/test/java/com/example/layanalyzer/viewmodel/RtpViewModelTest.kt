// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.model.RtpOverrideResult
import com.example.layanalyzer.model.RtpPayloadOverride
import com.example.layanalyzer.model.RtpProgress
import com.example.layanalyzer.model.RtpScanResult
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [RtpViewModel] 的纯 JVM 单测（RTP1-KT-02）。
 *
 * 没有 Main dispatcher，也没有 kotlinx-coroutines-test，所以统一用
 * `runBlocking` + `Dispatchers.Unconfined`（`ioDispatcher` 与 `externalScope`
 * 都注入 Unconfined，扫描因此是同步完成的、可断言的）。
 */
class RtpViewModelTest {

    @Test
    fun `a scan publishes a done result carrying the discovered streams`() {
        val repository = FakeRtpRepository()
        val viewModel = viewModel(repository)
        assertEquals(RtpScanUiState.Idle, viewModel.state.value)

        repository.result = scanResult(streamId = "s0")
        viewModel.scan()

        val state = viewModel.state.value
        assertTrue("expected Done but was $state", state is RtpScanUiState.Done)
        val result = (state as RtpScanUiState.Done).result
        assertTrue(result.isSuccess)
        assertEquals("s0", result.streams.single().id)
        assertEquals(listOf(false), repository.scannedWith)
    }

    @Test
    fun `a scan that reports cancelled becomes the cancelled state`() {
        val repository = FakeRtpRepository()
        repository.result = scanResult(cancelled = true)
        val viewModel = viewModel(repository)

        viewModel.scan()

        assertEquals(RtpScanUiState.Cancelled, viewModel.state.value)
    }

    @Test
    fun `cancelling from inside the progress callback becomes the cancelled state`() {
        val repository = FakeRtpRepository()
        val viewModel = viewModel(repository)
        repository.progressScript = listOf(RtpProgress(4, 10))
        repository.onProgressDelivered = { viewModel.cancel() }

        viewModel.scan()

        assertEquals(RtpScanUiState.Cancelled, viewModel.state.value)
        assertEquals(1, repository.calls)
    }

    @Test
    fun `a stale scan result is discarded when a newer scan finished first`() {
        val repository = FakeRtpRepository()
        val viewModel = viewModel(repository)
        repository.responder = { call ->
            if (call == 1) {
                // 第一次扫描：在自己的结果返回之前先让第二次扫描完整跑完，
                // 于是第一次的结果「晚于」第二次返回，必须被丢弃。
                viewModel.scan()
                scanResult(streamId = "first")
            } else {
                scanResult(streamId = "second")
            }
        }

        viewModel.scan()

        val state = viewModel.state.value
        assertTrue("expected Done but was $state", state is RtpScanUiState.Done)
        assertEquals("second", (state as RtpScanUiState.Done).result.streams.single().id)
        assertEquals(2, repository.calls)
    }

    @Test
    fun `closing the capture session returns the state to idle`() {
        val repository = FakeRtpRepository()
        val coordinator = coordinatorWithoutSession()
        val viewModel = viewModel(repository, coordinator)
        repository.result = scanResult(streamId = "s0")
        viewModel.scan()
        viewModel.setPayloadOverrides(listOf(RtpPayloadOverride(96, "opus", 48000, 2)))
        assertTrue(viewModel.state.value is RtpScanUiState.Done)
        assertEquals(1, viewModel.overrides.value.size)

        coordinator.invalidateSession()

        assertEquals(RtpScanUiState.Idle, viewModel.state.value)
        assertTrue(viewModel.overrides.value.isEmpty())
    }

    @Test
    fun `bumping the analysis config version returns the state to idle`() {
        val repository = FakeRtpRepository()
        val coordinator = coordinatorWithoutSession()
        val viewModel = viewModel(repository, coordinator)
        repository.result = scanResult(streamId = "s0")
        viewModel.scan()
        assertTrue(viewModel.state.value is RtpScanUiState.Done)

        coordinator.bumpAnalysisConfigVersion()

        assertEquals(RtpScanUiState.Idle, viewModel.state.value)
    }

    @Test
    fun `a rejected override write rolls the override list back`() {
        val repository = FakeRtpRepository()
        val viewModel = viewModel(repository)
        val accepted = listOf(RtpPayloadOverride(96, "opus", 48000, 2))
        viewModel.setPayloadOverrides(accepted)
        assertEquals(accepted, viewModel.overrides.value)

        repository.overrideResult = RtpOverrideResult(error = "pt 97 is reserved", count = 0)
        val rejected = listOf(RtpPayloadOverride(97, "g711A", 8000, 1))
        viewModel.setPayloadOverrides(rejected)

        assertEquals(accepted, viewModel.overrides.value)
        assertEquals(listOf(accepted, rejected), repository.overrideCalls)
        val state = viewModel.state.value
        assertTrue("expected Error but was $state", state is RtpScanUiState.Error)
        assertEquals("pt 97 is reserved", (state as RtpScanUiState.Error).message)
    }

    @Test
    fun `a successful override write rescans with the last filter flag`() {
        val repository = FakeRtpRepository()
        val viewModel = viewModel(repository)

        viewModel.scan(limitToDisplayFilter = true)
        viewModel.setPayloadOverrides(listOf(RtpPayloadOverride(96, "opus", 48000, 2)))

        assertEquals(listOf(true, true), repository.scannedWith)
    }

    @Test
    fun `a filter revision change resets a filtered scan but not an unfiltered one`() = runBlocking {
        val coordinator = coordinatorWithSession()
        val filteredRepository = FakeRtpRepository()
        val filtered = viewModel(filteredRepository, coordinator)
        filtered.scan(limitToDisplayFilter = true)
        assertTrue(filtered.state.value is RtpScanUiState.Done)

        val unfilteredRepository = FakeRtpRepository()
        val unfiltered = viewModel(unfilteredRepository, coordinator)
        unfiltered.scan()
        assertTrue(unfiltered.state.value is RtpScanUiState.Done)

        coordinator.applyUserFilter("ip.addr==10.0.0.1", coordinator.currentToken())

        assertEquals(RtpScanUiState.Idle, filtered.state.value)
        assertTrue(unfiltered.state.value is RtpScanUiState.Done)
    }

    // ---- helpers ----------------------------------------------------------

    private fun viewModel(
        repository: RtpRepository,
        coordinator: CaptureSessionCoordinator = coordinatorWithoutSession()
    ): RtpViewModel = RtpViewModel(
        repository = repository,
        sessionCoordinator = coordinator,
        ioDispatcher = Dispatchers.Unconfined,
        externalScope = CoroutineScope(Dispatchers.Unconfined)
    )

    /** 没有打开任何会话的协调器：只用来驱动失效规则。 */
    private fun coordinatorWithoutSession(): CaptureSessionCoordinator =
        CaptureSessionCoordinator(
            dataSource = AgentToolTestHarness.FakeSource(FRAME_COUNT),
            fingerprintDispatcher = Dispatchers.Unconfined,
            nativeDispatcher = Dispatchers.Unconfined
        )

    /** 打开了一个假会话的协调器：`applyUserFilter` 会自增 `filterRevision`。 */
    private fun coordinatorWithSession(): CaptureSessionCoordinator {
        val source = AgentToolTestHarness.FakeSource(FRAME_COUNT)
        val file = File.createTempFile("rtp-viewmodel-test", ".pcap")
        file.writeText("capture")
        source.switchSession(SESSION_HANDLE, file)
        val coordinator = CaptureSessionCoordinator(
            dataSource = source,
            fingerprintDispatcher = Dispatchers.Unconfined,
            nativeDispatcher = Dispatchers.Unconfined
        )
        coordinator.onSessionOpened(checkNotNull(source.currentFile()))
        file.delete()
        return coordinator
    }

    private companion object {
        const val FRAME_COUNT = 10
        const val SESSION_HANDLE = 1L
    }
}

/**
 * 真的 [RtpRepository] 的假实现：`RtpRepository` 被打开成 `open` 就是为了
 * JVM 单测能在不触碰 JNI 的前提下决定扫描的返回值与时序。
 */
private class FakeRtpRepository : RtpRepository(PacketRepository()) {

    /** 默认返回值；[responder] 为 null 时使用。 */
    var result: RtpScanResult = scanResult()

    /** 按调用序号（从 1 起）决定返回值；用于制造过期结果。 */
    var responder: ((call: Int) -> RtpScanResult)? = null

    /** 依次投递给 ViewModel 的进度事件。 */
    var progressScript: List<RtpProgress> = emptyList()

    /** 每次进度投递之后触发（模拟「进度回调里取消」）。 */
    var onProgressDelivered: ((RtpProgress) -> Unit)? = null

    var overrideResult: RtpOverrideResult = RtpOverrideResult(error = "", count = 0)

    var calls: Int = 0
        private set
    val scannedWith = mutableListOf<Boolean>()
    val overrideCalls = mutableListOf<List<RtpPayloadOverride>>()

    override fun scanRtpStreams(
        limitToDisplayFilter: Boolean,
        onProgress: ((RtpProgress) -> Boolean)?
    ): RtpScanResult {
        calls += 1
        scannedWith += limitToDisplayFilter
        progressScript.forEach { progress ->
            val keep = onProgress?.invoke(progress) ?: true
            onProgressDelivered?.invoke(progress)
            if (!keep) return scanResult(cancelled = true)
        }
        return responder?.invoke(calls) ?: result
    }

    override fun setRtpPayloadOverrides(overrides: List<RtpPayloadOverride>): RtpOverrideResult {
        overrideCalls += overrides
        return overrideResult
    }
}

/**
 * 造一个 [RtpScanResult]；[streamId] 非空时带一条只有 `id` 的流，其余字段走解析默认值。
 */
private fun scanResult(
    streamId: String? = null,
    cancelled: Boolean = false,
    error: String = ""
): RtpScanResult {
    val streams = if (streamId == null) "[]" else """[ { "id": "$streamId" } ]"""
    return RtpRepository(PacketRepository()).parseScanResult(
        """
        { "schemaVersion": 1, "error": "$error", "cancelled": $cancelled,
          "scanGeneration": 1, "framesScanned": 10, "heuristicEnabled": false,
          "streamsTruncated": false, "streams": $streams }
        """.trimIndent()
    )
}
