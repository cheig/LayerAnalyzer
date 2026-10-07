package com.example.layanalyzer.media

import android.view.Surface
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RTP5-KT-03：预览播放器状态机的单测。
 *
 * `MediaPlayer` 本身在这台机器上碰不了（本模块的 JVM 单测里 `android.*` 是 not mocked 的
 * 桩），所以控制器跟 `MediaPlayer` 之间隔着一层 [VideoPreviewPlayerFacade]：这个 fake 把
 * 「什么时候准备好了」「什么时候 seek 回来」变成测试可以按的按钮，于是「拖动在准备期间被
 * 记下来了没有」「上一次拖动还没回来时会不会重复下发」这类规则**可以真的断言**。
 *
 * 三样东西**没有**断言，原因说清楚而不是含糊过去：
 *  - Surface 的挂载/释放：`android.view.Surface` 没有能在纯 JVM 里构造出来的构造器
 *    （`Surface(SurfaceTexture)` 需要图形栈），所以 `attachSurface`/`detachSurface` 这一路
 *    只有编译保证，真机行为归 RTP5-QA-03。
 *  - 真的解码：有没有解码器是 RTP5-KT-02 探针与 RTP5-QA-02 的事。
 *  - 100 ms 之后 `MediaPlayer` 自己报什么位置：ticker 只是把 `currentPosition` 读出来。
 */
class RtpVideoPreviewControllerTest {

    @Test
    fun `load prepares and starts once the facade is ready`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        assertEquals(RtpPlayerState.Idle, controller.state.value)

        controller.load(PATH)
        assertEquals(RtpPlayerState.Preparing, controller.state.value)
        assertEquals(listOf(PATH), facade.dataSources)

        facade.prepare()
        assertEquals(RtpPlayerState.Playing, controller.state.value)
        assertEquals(1, facade.startCalls)

        controller.release()
    }

    @Test
    fun `loading the same path is a no-op`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.load(PATH)
        facade.prepare()
        controller.load(PATH)

        assertEquals(1, facade.dataSourceCalls)
        assertEquals(1, facade.prepareCalls)
        controller.release()
    }

    @Test
    fun `loading another path releases the previous player first`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.load(PATH)
        facade.prepare()
        controller.load(OTHER_PATH)

        assertEquals(listOf(PATH, OTHER_PATH), facade.dataSources)
        assertEquals(1, facade.releaseCalls)
        assertEquals(RtpPlayerState.Preparing, controller.state.value)
        controller.release()
    }

    @Test
    fun `pause while preparing keeps it paused after prepare`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.load(PATH)
        controller.pause()
        facade.prepare()

        assertEquals(RtpPlayerState.Paused, controller.state.value)
        assertEquals(0, facade.startCalls)
        controller.release()
    }

    @Test
    fun `a seek before prepare is remembered, reported, and applied on prepare`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.load(PATH)
        controller.seekTo(500L)

        // 位置立刻发布（用户拖动的位置要马上看到），但**没有**下发给还不会收 seek 的播放器。
        assertEquals(500L, controller.positionMs.value)
        assertTrue(facade.seeks.isEmpty())

        facade.prepare()

        // 准备好之后先补上欠账，再开始播。
        assertEquals(listOf(500L), facade.seeks)
        assertEquals(RtpPlayerState.Playing, controller.state.value)
        controller.release()
    }

    @Test
    fun `the last seek before prepare wins`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.load(PATH)
        controller.seekTo(300L)
        controller.seekTo(700L)
        facade.prepare()

        assertEquals(listOf(700L), facade.seeks)
        assertEquals(700L, controller.positionMs.value)
        controller.release()
    }

    @Test
    fun `a seek while a previous seek is in flight is coalesced and then applied`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.load(PATH)
        facade.prepare()

        controller.seekTo(100L)
        assertEquals(listOf(100L), facade.seeks)

        // 上一次还没回来：不重复下发，只把最后那个位置记下来。
        controller.seekTo(200L)
        controller.seekTo(250L)
        assertEquals(listOf(100L), facade.seeks)
        assertEquals(250L, controller.positionMs.value)

        facade.seekComplete()
        assertEquals(listOf(100L, 250L), facade.seeks)

        // 补上的这一次自己也要等回调，否则下一次会又被当成「空闲」。
        controller.seekTo(400L)
        assertEquals(listOf(100L, 250L), facade.seeks)
        facade.seekComplete()
        assertEquals(listOf(100L, 250L, 400L), facade.seeks)

        controller.release()
    }

    @Test
    fun `a seek with no debt re-reads the position from the player`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.load(PATH)
        facade.prepare()

        controller.seekTo(100L)
        facade.currentPositionMs = 123L
        facade.seekComplete()

        assertEquals(123L, controller.positionMs.value)
        controller.release()
    }

    @Test
    fun `a seek is clamped to the duration once it is known`() {
        val facade = FakeVideoPreviewFacade()
        facade.durationMs = 2_000L
        val controller = controller(facade)

        controller.load(PATH)
        facade.prepare()

        controller.seekTo(9_000L)
        assertEquals(listOf(2_000L), facade.seeks)
        assertEquals(2_000L, controller.positionMs.value)

        controller.seekTo(-5L)
        facade.seekComplete()
        assertEquals(listOf(2_000L, 0L), facade.seeks)
        controller.release()
    }

    @Test
    fun `a seek before anything is loaded does not touch the player`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.seekTo(500L)

        assertTrue(facade.seeks.isEmpty())
        assertEquals(0L, controller.positionMs.value)
    }

    @Test
    fun `position follows the player while playing and freezes on pause`() = runBlocking {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade, tickMillis = 10_000L)

        controller.load(PATH)
        facade.prepare()

        facade.currentPositionMs = 120L
        // ticker 只按自己的节奏读；这里手动等一次，让那一轮跑完。
        delay(10L)
        controller.pause()
        assertEquals(120L, controller.positionMs.value)

        facade.currentPositionMs = 900L
        delay(10L)
        assertEquals(120L, controller.positionMs.value)
        controller.release()
    }

    @Test
    fun `completion moves to the end and play restarts from zero`() {
        val facade = FakeVideoPreviewFacade()
        facade.durationMs = 4_000L
        val controller = controller(facade)

        controller.load(PATH)
        facade.prepare()
        facade.complete()

        assertEquals(RtpPlayerState.Completed, controller.state.value)
        assertEquals(4_000L, controller.positionMs.value)

        controller.play()
        assertEquals(listOf(0L), facade.seeks)
        assertEquals(RtpPlayerState.Playing, controller.state.value)
        controller.release()
    }

    @Test
    fun `an error from the player becomes the error state with its message`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.load(PATH)
        facade.fail("MediaPlayer error (1, -2147483648)")

        assertEquals(
            RtpPlayerState.Error("MediaPlayer error (1, -2147483648)"),
            controller.state.value
        )
        controller.release()
    }

    @Test
    fun `a thrown data source failure is an error, not a crash`() {
        val facade = FakeVideoPreviewFacade()
        facade.dataSourceError = IllegalStateException("no such file")
        val controller = controller(facade)

        controller.load(PATH)

        assertEquals(RtpPlayerState.Error("no such file"), controller.state.value)
        controller.release()
    }

    @Test
    fun `release is idempotent and nothing plays after it`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.load(PATH)
        facade.prepare()
        controller.release()
        controller.release()
        controller.play()
        controller.seekTo(500L)

        assertEquals(1, facade.releaseCalls)
        assertEquals(1, facade.startCalls)
        assertTrue(facade.seeks.isEmpty())
        assertEquals(RtpPlayerState.Idle, controller.state.value)
    }

    @Test
    fun `an error clears the pending seek instead of applying it later`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.load(PATH)
        controller.seekTo(500L)
        facade.fail("MediaPlayer error (1, -1)")

        assertEquals(RtpPlayerState.Error("MediaPlayer error (1, -1)"), controller.state.value)
        // 失败之后再「准备好」也不能把上一次的欠账补上：那会播到一个刚刚报错的位置。
        // 而且这一次加载已经结束了，迟到的回调连状态都不许改。
        facade.prepare()
        assertTrue(facade.seeks.isEmpty())
        assertEquals(RtpPlayerState.Error("MediaPlayer error (1, -1)"), controller.state.value)
        controller.release()
    }

    @Test
    fun `a failed load can be retried with the same path`() {
        val facade = FakeVideoPreviewFacade()
        val controller = controller(facade)

        controller.load(PATH)
        facade.fail("MediaPlayer error (1, -1)")
        controller.load(PATH)

        // 错误状态不吞掉重试：同一条路径再 load 一次真的会重新准备。
        assertEquals(listOf(PATH, PATH), facade.dataSources)
        assertEquals(2, facade.prepareCalls)
        assertEquals(RtpPlayerState.Preparing, controller.state.value)
        controller.release()
    }

    private fun controller(
        facade: FakeVideoPreviewFacade,
        tickMillis: Long = 10_000L
    ): RtpVideoPreviewController = RtpVideoPreviewController(
        facade = facade,
        scope = CoroutineScope(Dispatchers.Unconfined),
        tickMillis = tickMillis
    )

    private companion object {
        const val PATH = "/tmp/rtp-video.mp4"
        const val OTHER_PATH = "/tmp/rtp-video-2.mp4"
    }
}

/**
 * 记录每一次调用的假播放器。
 *
 * `seekTo` 不自己回调 `onSeekComplete`：回调的时机是播放器说了算的，测试必须能决定
 * 「上一次 seek 回来了没有」。
 */
private class FakeVideoPreviewFacade : VideoPreviewPlayerFacade {
    var dataSourceCalls = 0
    var prepareCalls = 0
    var startCalls = 0
    var pauseCalls = 0
    var releaseCalls = 0
    var currentPositionMs = 0L
    var dataSourceError: Exception? = null

    override var durationMs: Long = 1_000L
    override var isPlaying: Boolean = false
        private set

    val dataSources = mutableListOf<String>()
    val seeks = mutableListOf<Long>()
    val surfaces = mutableListOf<Surface?>()

    override var onPrepared: (() -> Unit)? = null
    override var onCompletion: (() -> Unit)? = null
    override var onError: ((String) -> Unit)? = null
    override var onSeekComplete: (() -> Unit)? = null

    override val positionMs: Long
        get() = currentPositionMs

    override fun setDataSource(path: String) {
        dataSourceError?.let { throw it }
        dataSourceCalls += 1
        dataSources += path
    }

    override fun setSurface(surface: Surface?) {
        surfaces += surface
    }

    override fun prepareAsync() {
        prepareCalls += 1
    }

    override fun start() {
        startCalls += 1
        isPlaying = true
    }

    override fun pause() {
        pauseCalls += 1
        isPlaying = false
    }

    override fun seekTo(ms: Long) {
        seeks += ms
        currentPositionMs = ms
    }

    override fun release() {
        releaseCalls += 1
        isPlaying = false
    }

    fun prepare() {
        isPlaying = false
        onPrepared?.invoke()
    }

    fun complete() {
        isPlaying = false
        onCompletion?.invoke()
    }

    fun seekComplete() {
        onSeekComplete?.invoke()
    }

    fun fail(message: String) {
        isPlaying = false
        onError?.invoke(message)
    }
}
