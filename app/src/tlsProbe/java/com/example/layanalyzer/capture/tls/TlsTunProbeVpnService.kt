package com.example.layanalyzer.capture.tls

import android.net.Network
import android.util.Base64
import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.UdpDestinationPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.IOException
import java.net.InetAddress

/** Compiled/registered only with TLS probe ON, never installed in release. */
class TlsTunProbeVpnService : LiveCaptureVpnService() {
    private var fixtureGateway: SocksNioTlsGateway? = null

    internal override fun createDirectSocksServer(
        underlyingNetwork: Network?,
        tlsGateway: SocksNioTlsGateway?,
        udpPolicy: UdpDestinationPolicy
    ): DirectSocks5Server {
        check(tlsGateway == null) { "The P0 fixture owns its synthetic gateway" }
        val config = checkNotNull(configuration) { "Install the fixture before starting the test VPN" }
        val token = synchronized(config) {
            Base64.encode(config.token, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        }
        val channel = try {
            TlsGatewayChannel(config.port, token, "tls-008", 0,
                TlsRoutingPolicy.freeze(TlsCaptureSettings(enabled = true, candidatePorts = setOf(443))),
                prepareHopSocket = { if (!protect(it)) throw IOException("Gateway protect failed") },
                connectionIds = { "fixture" })
        } finally { token.fill(0) }
        val gateway = object : SocksNioTlsGateway {
            override fun route(destinationPort: Int) = if (destinationPort == 443) channel.route(destinationPort)
                else SocksNioTlsGateway.Route.UNAVAILABLE
            override fun describe(destinationAddress: InetAddress, destinationPort: Int): TlsGatewayConnection {
                if (destinationAddress.hostAddress != "198.18.0.8" || destinationPort != 443) {
                    throw IOException("Not the synthetic fixture")
                }
                return channel.describe(destinationAddress, destinationPort)
            }
            override fun close() = channel.close()
        }
        fixtureGateway = gateway
        return DirectSocks5Server(
            prepareTcp = { throw IOException("Not the synthetic fixture") },
            prepareUdp = { socket ->
                if (!protect(socket)) throw IOException("Protect failed")
                underlyingNetwork?.bindSocket(socket)
            },
            resolveHost = { host -> underlyingNetwork?.getAllByName(host) ?: InetAddress.getAllByName(host) },
            tlsGateway = gateway, udpPolicy = udpPolicy
        )
    }

    override fun onDestroy() {
        try { super.onDestroy() } finally {
            fixtureGateway?.close()
            fixtureGateway = null
            clear()
        }
    }

    companion object {
        private class Configuration(val port: Int, val token: ByteArray)
        @Volatile private var configuration: Configuration? = null

        @JvmStatic fun isInstalled(): Boolean = configuration != null

        @JvmStatic @Synchronized fun install(port: Int, token: ByteArray) {
            require(port in 1..65535 && token.size == 32)
            check(configuration == null) { "Previous fixture was not released" }
            configuration = Configuration(port, token.copyOf())
        }

        @JvmStatic @Synchronized fun clear() {
            configuration?.let { config -> synchronized(config) { config.token.fill(0) } }
            configuration = null
        }
    }
}
