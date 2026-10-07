// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

/**
 * JNI boundary for the live-capture forwarding engine. The engine fd passed to
 * [start] is consumed by native code regardless of whether startup succeeds.
 */
internal object Tun2SocksBridge {
    init {
        System.loadLibrary("layanalyzer_tunnel")
    }

    external fun createPacketSocketPair(): IntArray?

    external fun start(engineFd: Int, config: String): Boolean

    external fun stop()

    external fun isRunning(): Boolean

    /** Returns HEV tunnel counters as [txPackets, txBytes, rxPackets, rxBytes]. */
    external fun getStats(): LongArray
}
