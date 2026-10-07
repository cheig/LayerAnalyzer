package com.example.layanalyzer

object NativeEngine {
    // Load libraries in dependency order
    init {
        // Static libs (ffi, pcre2-8, z, iconv) are already linked into liblayanalyzer.so
        // c++_shared is auto-loaded by the system
        // Only load shared dependencies explicitly
        System.loadLibrary("gpg-error")
        System.loadLibrary("gcrypt")
        System.loadLibrary("cares")
        
        // GLib
        System.loadLibrary("glib-2.0")
        System.loadLibrary("gmodule-2.0")
        System.loadLibrary("gobject-2.0")
        System.loadLibrary("gthread-2.0")
        
        // Wireshark Core
        System.loadLibrary("wsutil")
        System.loadLibrary("wiretap")
        System.loadLibrary("wireshark")
        
        // Main JNI Library
        System.loadLibrary("layanalyzer")
    }

    /**
     * Initialize Wireshark engine
     * @param appDataDir App private data directory path (files dir)
     */
    external fun initEngine(appDataDir: String): Boolean

    /**
     * Get Wireshark version
     */
    external fun getVersion(): String
    
    /**
     * Cleanup resources
     */
    external fun cleanup()

    /**
     * 初始化 c-ares Android 支持（Android 8+ 必需）
     * 必须在 initEngine 之前调用
     * @param connectivityManager Android ConnectivityManager 实例
     * @return 是否初始化成功
     */
    external fun initCaresAndroid(connectivityManager: Any): Boolean

    fun interface IndexProgressCallback {
        fun onProgress(framesIndexed: Int, bytesRead: Long, totalBytes: Long): Boolean
    }

    /**
     * RTP 流扫描进度回调（RTP1-ARCH-01）。
     * 与 [IndexProgressCallback] 分开是因为语义不同：这里只报告"已扫描帧数 / 总帧数"，
     * 返回 false 表示请求取消（原生层收到后停止遍历并返回 `cancelled=true`）。
     */
    fun interface RtpProgressCallback {
        fun onProgress(done: Int, total: Int): Boolean // false = 取消
    }

    // ========== Task 3.2: Packet List Interface ==========

    /**
     * 打开抓包文件
     * @param path pcap 文件绝对路径
     * @return Native 层的不透明 Session 句柄，失败返回 0
     */
    external fun openFile(path: String, progressCallback: IndexProgressCallback?): Long

    external fun getLastError(): String

    external fun cancelLongRunningOperations()

    external fun cancelSearch(sessionPtr: Long)

    /**
     * 关闭并释放资源
     * @param sessionPtr openFile 返回的不透明句柄
     */
    external fun closeFile(sessionPtr: Long)

    /**
     * 获取文件中的总帧数
     * @param sessionPtr 会话句柄
     * @return 总帧数
     */
    external fun getFrameCount(sessionPtr: Long): Int

    external fun getCaptureEncapsulation(sessionPtr: Long): String

    /**
     * 批量获取包摘要列表
     * @param sessionPtr 会话句柄
     * @param startIndex 起始包索引 (0-based)
     * @param count 读取数量
     * @return PacketSummary 数组
     */
    external fun getPacketSummaries(
        sessionPtr: Long,
        startIndex: Int,
        count: Int
    ): Array<com.example.layanalyzer.core.PacketSummary>

    /**
     * Query packet summaries under a temporary native-only display filter.
     * The query never changes the session's active UI filter or visible list.
     */
    external fun queryPacketSummaries(
        sessionPtr: Long,
        displayFilter: String,
        start: Int,
        count: Int
    ): String

    external fun getSummaryCacheStats(sessionPtr: Long): String

    // ========== Task 4.1: Protocol Tree JSON Serialization ==========

    /**
     * Get full protocol tree details for a packet
     * @param sessionPtr Opaque session handle
     * @param packetIndex 0-based packet index
     * @return JSON string representing the protocol tree
     */
    external fun getPacketDetails(sessionPtr: Long, packetIndex: Int): String

    external fun getPacketBytes(sessionPtr: Long, packetIndex: Int): ByteArray

    external fun applyDisplayFilter(sessionPtr: Long, filter: String): String

    external fun validateDisplayFilter(sessionPtr: Long, filter: String): String

    external fun getFilteredFrameCount(sessionPtr: Long): Int

    external fun searchPackets(sessionPtr: Long, mode: String, query: String): IntArray

    external fun getExpertInfoSummary(sessionPtr: Long): String

    /** Builds all statistics in one native traversal. */
    external fun buildStatistics(sessionPtr: Long, bucketSeconds: Double): String

    /** Builds SIP call-chain and RTP packet metrics for the visible scope. */
    external fun buildCommunicationAnalysis(sessionPtr: Long): String

    /** Exports visible frames and their reassembly dependencies in capture order. */
    external fun exportVisibleCapture(sessionPtr: Long, outputPath: String): String

    external fun followStream(sessionPtr: Long, packetIndex: Int, protocol: String): String

    external fun getHttpObjects(sessionPtr: Long): String

    external fun getHttpObjectPayload(sessionPtr: Long, objectIndex: Int): ByteArray

    external fun setNameResolutionEnabled(sessionPtr: Long, enabled: Boolean)

    external fun applyDecodeAs(sessionPtr: Long, tableName: String, port: Int, dissectorName: String): String

    external fun resetDecodeAs(sessionPtr: Long, tableName: String, port: Int): String

    /**
     * [PERF-export] T0 基线任务：G4 对拍结果一键导出（Debug 构建专用）。
     * 对当前会话依次导出过滤/搜索/统计/Expert/Follow Stream/HTTP 对象/可见帧 pcap
     * 到 [outputDir]，供改动前后 diff 对拍。Release 构建不包含此符号。
     */
    external fun exportPerfResults(sessionPtr: Long, outputDir: String): String

    // ========== RTP Stream Discovery (RTP1-ARCH-01) ==========

    /**
     * Scans the capture for RTP streams and returns the M1 JSON contract
     * (layanalyzer/jni/RtpJni.cpp).
     * @param sessionPtr Opaque session handle from [openFile]
     * @param requestJson `{"limitToDisplayFilter": false}`
     * @param progress Optional progress callback; returning false cancels the scan
     */
    external fun scanRtpStreams(
        sessionPtr: Long,
        requestJson: String,
        progress: RtpProgressCallback?
    ): String

    /**
     * Reads SIP/SDP setup details from at most 64 physical, one-based frames
     * (RTP3-NAT-04). No RTP scan or display-filter match is required.
     * @param framesJson `{"frames":[20,22]}`; order and duplicates are preserved;
     *   an empty array is valid. Invalid input, closure or cancellation returns
     *   no partial frames. The envelope has schemaVersion/error/cancelled/frames.
     *
     * Each frame has frame/sipMethod/fromUser/fromUri/toUser/toUri/callId and
     * sdp entries with payloadType/encodingName/clockRate/channels/fmtp. SDP
     * rows from different media sections stay separate even when PTs repeat;
     * unknown rates/channels are 0, unresolvable PT associations are -1.
     * Sensitive values are for local RTP features only, never logs or AI tools.
     */
    external fun readRtpSetupInfo(sessionPtr: Long, framesJson: String): String

    /** Same bounded read as [readRtpSetupInfo], returning only frame/sdp per row. */
    external fun readSdpFmtpValues(sessionPtr: Long, framesJson: String): String

    /**
     * Decodes selected RTP audio streams into WAV/peaks/map files.
     * Returns the RTP2-NAT-06 JSON contract.
     */
    external fun decodeRtpAudio(
        sessionPtr: Long,
        requestJson: String,
        outDir: String,
        progress: RtpProgressCallback?
    ): String

    /**
     * Exports one RTP stream's payload bytes in sequence or arrival order.
     * Returns the RTP2-NAT-07 JSON contract.
     */
    external fun exportRtpPayloadRaw(
        sessionPtr: Long,
        requestJson: String,
        outPath: String
    ): String

    /**
     * Extracts one AMR / AMR-WB / Opus stream into `<streamId>.frames` plus the
     * `<streamId>.fidx` frame index for the MediaCodec pipeline (RTP4-NAT-06).
     * @param requestJson `{"scanGeneration":7,"streamId":"s3","amrMode":"auto"}`
     * @param outDir Directory the two output files are written into
     * @param progress Optional progress callback; returning false cancels
     */
    external fun extractRtpCodecFrames(
        sessionPtr: Long,
        requestJson: String,
        outDir: String,
        progress: RtpProgressCallback?
    ): String

    /**
     * Writes one AMR / AMR-WB / Opus container file into [outDir]
     * (`#!AMR\n` + storage frames, `#!AMR-WB\n` + storage frames, or Ogg Opus).
     * Returns the RTP4-NAT-06 JSON contract.
     */
    external fun exportRtpContainer(
        sessionPtr: Long,
        requestJson: String,
        outDir: String
    ): String

    /**
     * Renders PCM that was already decoded off-device (`MediaCodec`) back onto
     * the RTP timeline, writing the same WAV/peaks/map files and answering with
     * the same item shape as [decodeRtpAudio] (RTP4-NAT-07).
     * @param requestJson `{"scanGeneration":7,"streamId":"s3",
     *   "pcmPath":".../s3.pcmchunks","sampleRate":16000,"channels":1,
     *   "timing":"jitter","jitterMs":50}`
     * @param outDir Directory the three output files are written into
     */
    external fun renderRtpAudioFromPcm(
        sessionPtr: Long,
        requestJson: String,
        outDir: String
    ): String

    // ========== RTP Video Export (RTP5-NAT-05) ==========

    /**
     * Exports one H.264 / H.265 RTP stream as a raw Annex-B elementary stream
     * (`<streamId>.h264` / `<streamId>.h265`) plus its `<streamId>.vidx`
     * access-unit index, and answers with the RTP5-NAT-05 JSON contract
     * (layanalyzer/jni/RtpJni.cpp): `esPath`,
     * `indexPath`, `codec`, `width`/`height`/`profile`/`level`, `csd`, `frames`,
     * `keyframes`, `corruptFrames`, `firstKeyframeIndex`, `durationMs`,
     * `fpsEstimate` and `unsupportedNalCounts`. RTP5-KT-01 muxes the two files
     * into an MP4.
     *
     * @param requestJson `{"scanGeneration":7,"streamId":"s4","codec":"H264",
     *   "paramSets":{"sps":["base64"],"pps":["base64"],"vps":[]},
     *   "startAtKeyframe":true,"dropCorrupt":false}` — `paramSets` (the SDP
     *   `sprop-parameter-sets` etc., RTP5-KT-00) is optional, and so are
     *   `"tsRate"` (90000), `"donDiff"` (0) and `"paramSetsPresentInStream"`
     *   (false). A stream with no parameter sets in the SDP *and* none in band
     *   comes back as `error` 缺少参数集（SDP 与带内均未找到）with no file
     *   written, and a size that could not be read out of an SPS is
     *   `"widthSource":"unknown"` with `width`/`height` 0.
     * @param outDir Directory the two output files are written into; it is
     *   removed again on cancel and on failure (the caller is expected to give
     *   this export a directory of its own)
     * @param progress Optional progress callback; returning false cancels the
     *   export and the answer carries `cancelled=true`
     */
    external fun exportRtpVideo(
        sessionPtr: Long,
        requestJson: String,
        outDir: String,
        progress: RtpProgressCallback?
    ): String

    /** Enables/disables the `rtp_udp` family heuristics process-wide. */
    external fun setRtpHeuristicEnabled(enabled: Boolean): String

    external fun isRtpHeuristicEnabled(): Boolean

    /**
     * Applies one of `"off"` / `"probe"` / `"all"` to ESP NULL-encryption
     * decryption (Wireshark's `esp.enable_null_encryption_decode_heuristic`).
     *
     * `"probe"` needs [sessionPtr] to sample the open capture — it switches the
     * preference on, looks for a decodable ESP payload, and switches it back off
     * when it finds none. `"off"` / `"all"` ignore the handle. The reply is
     * `{"schemaVersion":1,"mode":<m>,"enabled":<b>,"decoded":<b>,
     * "framesScanned":<n>,"error":""}`, where `enabled` is the state that
     * actually took effect.
     */
    external fun setEspDecryptionMode(sessionPtr: Long, mode: String): String

    /** The effective process-wide ESP NULL decryption state. */
    external fun isEspNullDecryptionEnabled(): Boolean

    /** Replaces the session-level dynamic payload type override table. */
    external fun setRtpPayloadOverrides(sessionPtr: Long, json: String): String

    /**
     * The codecs **this build** can decode (RTP4-KT-05).
     *
     * Process-wide and session-less: both answers are compile-time facts about
     * the shipped library, so there is no `sessionPtr` to hand in. The reply is
     * `{"schemaVersion":1,"error":"","audio":["g711A",...],"video":["H264",...],
     * "g729":true,"ilbc":false}` — `audio` / `video` are the native lists
     * (`core/RtpCodecNames.h` `kSupportedAudioCodes` / `kSupportedVideoCodecs`),
     * and `g729` / `ilbc` say whether the optional codec was linked in, which is
     * what [com.example.layanalyzer.ui.components.rtp.RtpCodecMapDialog] greys
     * entries out on. `RtpCodecCatalog.entries[i].idSupported` is *not* this:
     * that flag means "the app supports decoding this codec at all" and cannot
     * see the build switches from a JVM test (`model/RtpCodecCatalog.kt`).
     */
    external fun getRtpCodecCapabilities(): String
}
