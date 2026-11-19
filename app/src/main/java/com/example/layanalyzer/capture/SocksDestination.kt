// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import java.net.InetAddress

/** Wire address only. Constructing a domain never resolves it or applies routing policy. */
internal sealed class SocksDestination {
    data class Ip(val address: InetAddress) : SocksDestination()
    data class Domain(val name: String) : SocksDestination()
}

internal data class SocksRequest(
    val command: Int,
    val destination: SocksDestination,
    val port: Int
)

internal data class SocksUdpRequest(
    val destination: SocksDestination,
    val port: Int,
    val payload: ByteArray
)
