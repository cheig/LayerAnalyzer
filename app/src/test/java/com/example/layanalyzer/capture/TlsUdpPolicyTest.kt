// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import com.example.layanalyzer.model.LiveCaptureSettings
import com.example.layanalyzer.model.QuicPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureSettingsJson
import com.example.layanalyzer.model.TlsCaptureSettingsValidator
import com.example.layanalyzer.model.TlsHostScope
import com.example.layanalyzer.model.TlsSettingsIssueCode
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * TLS-314: the optional UDP/443 intervention.
 *
 * Two halves, both on the host. The first is the decision — what the default is,
 * which scopes the forwarding layer can express at all, and which configurations
 * are refused rather than widened. The second drives the real [DirectSocks5Server]
 * over real loopback sockets with the rule the production policy object builds, so
 * the verdict is applied to a datagram that is genuinely about to leave the
 * device: a forwarded one is delivered, a blocked one never reaches its
 * destination and is counted.
 *
 * Nothing here logs (the JVM `android.util.Log` stub would throw), and there is no
 * VPN, no TUN, no Go engine and no decryption claim: a blocked datagram is
 * dropped, and no case asserts a decrypted payload. `D=TlsQuicPolicyTest` owns the
 * device half.
 */
class TlsUdpPolicyTest {
    private val loopback: InetAddress = InetAddress.getByName("127.0.0.1")

    // A dedicated loopback address for the port-443 receiver: every 127/8 address
    // is loopback, so this is the path a QUIC datagram takes, while the port can
    // never collide with a service bound to 127.0.0.1:443.
    private val udp443Address: InetAddress = InetAddress.getByName(UDP_443_ADDRESS)

    private val payload = ByteArray(48) { (it * 5 + 3).toByte() }

    // ------------------------------------------------------------------
    // Step 1: the default, and what the rule decides
    // ------------------------------------------------------------------

    @Test
    fun theDefaultConfigurationAppliesNoInterventionAtAll() {
        // Nothing configured: no rule, and no port of any address family is
        // refused (C03 1 — TLS off keeps the original forwarding).
        val rule = TlsInterceptionPolicy.udpPolicy(TlsCaptureSettings())
        assertEquals(QuicPolicy.Preserve, TlsInterceptionPolicy.appliedQuicPolicy(TlsCaptureSettings()))
        listOf(UDP_443, UDP_53, UDP_8443).forEach { port ->
            assertEquals(UdpVerdict.Forward, rule.decide(loopback, port))
            assertEquals(UdpVerdict.Forward, rule.decide(IPV6_LOOPBACK, port))
        }
        // A remembered block applies to nothing while TLS is off: it is a choice
        // for the next enabled run, not a standing device-wide rule.
        val remembered = TlsCaptureSettings(enabled = false, quicPolicy = QuicPolicy.BlockSelectedUdp443)
        assertEquals(QuicPolicy.Preserve, TlsInterceptionPolicy.appliedQuicPolicy(remembered))
        assertEquals(UdpVerdict.Forward, TlsInterceptionPolicy.udpPolicy(remembered).decide(loopback, UDP_443))
    }

    @Test
    fun theBlockedPolicyOnlyTouchesUdp443AndBothAddressFamilies() {
        val tls = expressibleBlockedCapture().tls
        val rule = TlsInterceptionPolicy.udpPolicy(tls)

        assertEquals(QuicPolicy.BlockSelectedUdp443, TlsInterceptionPolicy.appliedQuicPolicy(tls))
        // The same verdict for both families: the rule is a destination port, and
        // it makes no distinction the user did not make.
        assertEquals(UdpVerdict.BlockSelectedUdp443, rule.decide(loopback, UDP_443))
        assertEquals(UdpVerdict.BlockSelectedUdp443, rule.decide(IPV6_LOOPBACK, UDP_443))
        assertEquals(UdpVerdict.BlockSelectedUdp443, rule.decide(InetAddress.getByName("2001:db8::1"), UDP_443))
        // DNS, HTTPS over UDP on another port, and every other port are untouched.
        listOf(UDP_53, UDP_8443, 1, 65_535).forEach { port ->
            assertEquals("UDP/$port must not be blocked", UdpVerdict.Forward, rule.decide(loopback, port))
            assertEquals("UDP/$port must not be blocked", UdpVerdict.Forward, rule.decide(IPV6_LOOPBACK, port))
        }
    }

    // ------------------------------------------------------------------
    // Step 2: a scope the forwarding layer cannot express is refused
    // ------------------------------------------------------------------

    @Test
    fun aBlockedScopeThatCannotBeExpressedIsRefusedInsteadOfWidened() {
        // Each names a partial scope that a destination-port rule cannot honour:
        // an explicit host list (the user hopes for per-domain precision), a
        // bypass rule (C04: an explicit bypass always wins), no selected
        // applications at all, or no port 443 left to fall back to.
        val refused = listOf(
            Triple(
                "explicit hosts",
                expressibleBlockedCapture(hostScope = TlsHostScope.ExplicitHosts),
                listOf(TlsSettingsIssueCode.QUIC_SCOPE_UNDECIDABLE)
            ),
            Triple(
                "bypass rule",
                expressibleBlockedCapture(bypassHosts = listOf("bypass.example.test")),
                listOf(TlsSettingsIssueCode.QUIC_SCOPE_UNDECIDABLE)
            ),
            Triple(
                "no candidate 443",
                expressibleBlockedCapture(candidatePorts = setOf(UDP_8443)),
                listOf(TlsSettingsIssueCode.QUIC_SCOPE_UNDECIDABLE)
            ),
            // An empty application allowlist already fails on its own; the UDP rule
            // adds its own reason beside it rather than instead of it.
            Triple(
                "empty application scope",
                expressibleBlockedCapture(allowedApplications = emptyList()),
                listOf(TlsSettingsIssueCode.APPLICATION_SCOPE_REQUIRED, TlsSettingsIssueCode.QUIC_SCOPE_UNDECIDABLE)
            ),
            Triple(
                "blank application scope",
                expressibleBlockedCapture(allowedApplications = listOf("", "  ")),
                listOf(TlsSettingsIssueCode.APPLICATION_SCOPE_REQUIRED, TlsSettingsIssueCode.QUIC_SCOPE_UNDECIDABLE)
            )
        )
        refused.forEach { (name, settings, expectedCodes) ->
            val validation = TlsCaptureSettingsValidator.validate(settings.tls, settings.allowedApplications)
            assertFalse("$name must be refused", validation.isValid)
            assertEquals(
                "$name must report the undecidable scope",
                expectedCodes,
                validation.issues.map { it.code }
            )
            assertFalse("$name must not start", TlsInterceptionPolicy.canStart(settings))
            assertNull("$name must not freeze a config", TlsInterceptionPolicy.frozenForCapture(settings))
            assertEquals(
                "$name must name the blocked reason",
                expectedCodes.map { it.wireName },
                TlsInterceptionPolicy.blockedReasonCodes(settings)
            )
        }

        // The one shape that is expressible is accepted and survives freezing.
        val frozen = TlsInterceptionPolicy.frozenForCapture(expressibleBlockedCapture())
        assertNotNull(frozen)
        assertEquals(QuicPolicy.BlockSelectedUdp443, frozen!!.tls.quicPolicy)
        assertEquals(QuicPolicy.BlockSelectedUdp443, TlsInterceptionPolicy.appliedQuicPolicy(frozen.tls))
        assertEquals(
            UdpVerdict.BlockSelectedUdp443,
            TlsInterceptionPolicy.udpPolicy(frozen.tls).decide(loopback, UDP_443)
        )
    }

    @Test
    fun aDisabledConfigurationKeepsItsRememberedBlockWithoutApplyingIt() {
        // Turning interception off must not erase the user's rules, and must not
        // leave a standing device-wide rule behind either.
        val remembered = expressibleBlockedCapture(
            enabled = false,
            hostScope = TlsHostScope.ExplicitHosts,
            bypassHosts = listOf("bypass.example.test"),
            candidatePorts = setOf(UDP_8443)
        )
        val validation = TlsCaptureSettingsValidator.validate(remembered.tls, remembered.allowedApplications)
        assertTrue(validation.isValid)
        assertEquals(remembered.tls, validation.settings)
        assertTrue(TlsInterceptionPolicy.canStart(remembered))
        assertEquals(QuicPolicy.Preserve, TlsInterceptionPolicy.appliedQuicPolicy(validation.settings))
        assertEquals(UdpVerdict.Forward, TlsInterceptionPolicy.udpPolicy(validation.settings).decide(loopback, UDP_443))
    }

    @Test
    fun theWireFormatCarriesThePolicyAndNeverInventsANewRule() {
        val decoded = TlsCaptureSettingsJson.decode(
            TlsCaptureSettingsJson.encode(expressibleBlockedCapture().tls),
            listOf("com.example.fixture")
        )
        assertTrue(decoded.isValid)
        assertEquals(QuicPolicy.BlockSelectedUdp443, decoded.settings.quicPolicy)
        assertEquals(
            UdpVerdict.BlockSelectedUdp443,
            TlsInterceptionPolicy.udpPolicy(decoded.settings).decide(loopback, UDP_443)
        )

        // An unknown policy value is not a broader rule: the whole block decodes to
        // off, which is the preserved default and not "intervene anyway".
        val unknown = TlsCaptureSettingsJson.decode(
            """{"enabled":true,"quicPolicy":"BlockEverythingUdp"}""",
            listOf("com.example.fixture")
        )
        assertFalse(unknown.isValid)
        assertEquals(QuicPolicy.Preserve, TlsInterceptionPolicy.appliedQuicPolicy(unknown.settings))
        assertEquals(UdpVerdict.Forward, TlsInterceptionPolicy.udpPolicy(unknown.settings).decide(loopback, UDP_443))
    }

    // ------------------------------------------------------------------
    // Steps 1 and 3 on the wire: the real SOCKS server, the real rule
    // ------------------------------------------------------------------

    @Test
    fun udp443StillPassesByDefaultAndNon443UdpSurvivesTheBlock() {
        DatagramSocket(InetSocketAddress(udp443Address, UDP_443)).use { onUdp443 ->
            onUdp443.soTimeout = REPLY_TIMEOUT_MILLIS
            DatagramSocket(InetSocketAddress(udp443Address, 0)).use { onOtherPort ->
                onOtherPort.soTimeout = REPLY_TIMEOUT_MILLIS
                // Each destination answers from its own thread: the association is
                // only alive while the client is, so the echo has to be waiting
                // when the datagram is relayed.
                val answers = Executors.newSingleThreadExecutor()
                try {
                    // Default policy: a datagram to UDP/443 is forwarded, which is
                    // what "DNS, QUIC and any UDP still pass" means at this layer.
                    val heardOn443 = answers.submit<ByteArray> { echoOnce(onUdp443) }
                    withAssociation(TlsInterceptionPolicy.udpPolicy(TlsCaptureSettings())) { association ->
                        association.sendUdp(udp443Address, UDP_443)
                        assertEquals(payload.reversed().toList(), association.reply()?.toList())
                    }
                    assertEquals(
                        "the UDP/443 destination must have received it",
                        payload.toList(),
                        heardOn443.get(REPLY_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS).toList()
                    )

                    // Blocked policy: the same destination address on a port that is
                    // not 443 is delivered unchanged, and nothing is counted.
                    val otherPort = onOtherPort.localPort
                    val heardOnOtherPort = answers.submit<ByteArray> { echoOnce(onOtherPort) }
                    withAssociation(TlsInterceptionPolicy.udpPolicy(expressibleBlockedCapture().tls)) { association ->
                        association.sendUdp(udp443Address, otherPort)
                        assertEquals(payload.reversed().toList(), association.reply()?.toList())
                        assertEquals(0L, association.server.udpInterventionStats().blockedDatagrams)
                    }
                    assertEquals(
                        "UDP/$otherPort must have received it",
                        payload.toList(),
                        heardOnOtherPort.get(REPLY_TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS).toList()
                    )
                } finally {
                    answers.shutdownNow()
                }
            }
        }
    }

    @Test
    fun theBlockedPolicyDropsUdp443AtTheForwardingLayerAndCountsIt() {
        DatagramSocket(InetSocketAddress(udp443Address, UDP_443)).use { receiver ->
            receiver.soTimeout = REPLY_TIMEOUT_MILLIS
            withAssociation(TlsInterceptionPolicy.udpPolicy(expressibleBlockedCapture().tls)) { association ->
                association.sendUdp(udp443Address, UDP_443)

                // The verdict is counted on the datagram that was about to leave,
                // and nothing was relayed upstream.
                val stats = association.awaitBlocked(1L)
                assertEquals(1L, stats.blockedDatagrams)
                assertEquals(payload.size.toLong(), stats.blockedBytes)
                assertEquals("a blocked datagram is never sent upstream", 0L, association.server.stats().sentBytes)
                assertNull("a blocked datagram is never answered", association.reply(DROP_WAIT_MILLIS))
            }

            // Nothing was sent, so the destination never saw it — proved against
            // the same receiver, which is alive on exactly that address and port.
            val probe = ByteArray(8) { 7 }
            DatagramSocket().use { direct ->
                direct.send(DatagramPacket(probe, probe.size, InetSocketAddress(udp443Address, UDP_443)))
            }
            val received = ByteArray(16)
            val packet = DatagramPacket(received, received.size)
            receiver.receive(packet)
            assertEquals(probe.size, packet.length)
        }
    }

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    /**
     * The one scope the forwarding layer can express: the selected applications,
     * no bypass rule, and port 443 among the candidate ports. Every pure case
     * above is this object with exactly one thing changed, so a refusal can only
     * be attributed to that one change.
     */
    private fun expressibleBlockedCapture(
        enabled: Boolean = true,
        allowedApplications: List<String> = listOf(SELECTED_APPLICATION),
        candidatePorts: Set<Int> = setOf(UDP_443),
        hostScope: TlsHostScope = TlsHostScope.SelectedApplicationsCandidates,
        bypassHosts: List<String> = emptyList()
    ): LiveCaptureSettings = LiveCaptureSettings(
        allowedApplications = allowedApplications,
        tls = TlsCaptureSettings(
            enabled = enabled,
            candidatePorts = candidatePorts,
            hostScope = hostScope,
            bypassHosts = bypassHosts,
            quicPolicy = QuicPolicy.BlockSelectedUdp443
        )
    )

    /**
     * One live RFC 1928 UDP association against a real [DirectSocks5Server], with
     * the production credentials handshake in front of it. The control socket and
     * the relay client live for exactly as long as [body].
     */
    private fun withAssociation(policy: UdpDestinationPolicy, body: (Association) -> Unit) {
        DirectSocks5Server(
            prepareTcp = {},
            prepareUdp = {},
            resolveHost = { arrayOf(InetAddress.getByName(it)) },
            generateCredentials = { SocksCredentials.of("UdpPolicyTestUsr", "UdpPolicyTestPasswordValue") },
            udpPolicy = policy
        ).use { server ->
            val port = server.start()
            Socket(loopback, port).use { control ->
                control.soTimeout = REPLY_TIMEOUT_MILLIS
                val output = DataOutputStream(control.getOutputStream())
                val input = DataInputStream(control.getInputStream())

                output.write(byteArrayOf(5, 1, METHOD_USERNAME_PASSWORD.toByte()))
                output.flush()
                assertEquals(5, input.readUnsignedByte())
                assertEquals(METHOD_USERNAME_PASSWORD, input.readUnsignedByte())
                val credentials = server.credentials
                val user = credentials.username.toByteArray(Charsets.US_ASCII)
                val secret = credentials.password.toByteArray(Charsets.US_ASCII)
                output.writeByte(1)
                output.writeByte(user.size)
                output.write(user)
                output.writeByte(secret.size)
                output.write(secret)
                output.flush()
                assertEquals(1, input.readUnsignedByte())
                assertEquals(AUTH_SUCCESS, input.readUnsignedByte())

                output.write(byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0))
                output.flush()
                assertEquals(5, input.readUnsignedByte())
                assertEquals(REPLY_SUCCEEDED, input.readUnsignedByte())
                input.readUnsignedByte() // Reserved.
                val addressType = input.readUnsignedByte()
                val addressLength = if (addressType == ADDRESS_TYPE_IPV4) 4 else 16
                InetAddress.getByAddress(ByteArray(addressLength).also(input::readFully))
                val relayPort = (input.readUnsignedByte() shl 8) or input.readUnsignedByte()

                DatagramSocket().use { client ->
                    client.soTimeout = REPLY_TIMEOUT_MILLIS
                    body(Association(client, relayPort, server, payload, loopback))
                }
            }
        }
    }

    /** The client half of one association: one SOCKS-framed datagram, one answer. */
    private class Association(
        private val client: DatagramSocket,
        private val relayPort: Int,
        val server: DirectSocks5Server,
        private val payload: ByteArray,
        private val loopback: InetAddress
    ) {
        /** Sends exactly one datagram, the way HEV frames it for the relay. */
        fun sendUdp(address: InetAddress, destinationPort: Int) {
            require(address.address.size == 4) { "this fixture frames IPv4 destinations only" }
            val header = byteArrayOf(0, 0, 0, 1) + address.address +
                byteArrayOf((destinationPort ushr 8).toByte(), destinationPort.toByte())
            val framed = header + payload
            client.send(DatagramPacket(framed, framed.size, InetSocketAddress(loopback, relayPort)))
        }

        /** The datagram the client got back, or null when none arrived in time. */
        fun reply(waitMillis: Int = REPLY_TIMEOUT_MILLIS): ByteArray? {
            client.soTimeout = waitMillis
            val buffer = ByteArray(MAX_DATAGRAM)
            val response = DatagramPacket(buffer, buffer.size)
            if (!runCatching { client.receive(response) }.isSuccess) return null
            return buffer.copyOfRange(UDP_HEADER_IPV4, response.length)
        }

        /** Waits (bounded) for the rule's counter, so the relay thread is never raced. */
        fun awaitBlocked(expected: Long, timeoutMillis: Long = REPLY_TIMEOUT_MILLIS.toLong()): UdpInterventionStats {
            val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
            var stats = server.udpInterventionStats()
            while (stats.blockedDatagrams < expected && System.nanoTime() < deadline) {
                Thread.sleep(20)
                stats = server.udpInterventionStats()
            }
            return stats
        }
    }

    /** Receives one datagram and answers it reversed, from the destination itself. */
    private fun echoOnce(receiver: DatagramSocket): ByteArray {
        val buffer = ByteArray(MAX_DATAGRAM)
        val request = DatagramPacket(buffer, buffer.size)
        receiver.receive(request)
        val datagram = buffer.copyOfRange(request.offset, request.offset + request.length)
        receiver.send(DatagramPacket(datagram.reversedArray(), datagram.size, request.address, request.port))
        return datagram
    }

    private companion object {
        const val REPLY_TIMEOUT_MILLIS = 5_000
        const val DROP_WAIT_MILLIS = 500
        const val MAX_DATAGRAM = 2_048
        const val UDP_HEADER_IPV4 = 10
        const val UDP_443 = 443
        const val UDP_53 = 53
        const val UDP_8443 = 8_443
        const val METHOD_USERNAME_PASSWORD = 2
        const val AUTH_SUCCESS = 0
        const val REPLY_SUCCEEDED = 0
        const val ADDRESS_TYPE_IPV4 = 1
        const val UDP_443_ADDRESS = "127.0.0.9"
        const val SELECTED_APPLICATION = "com.example.fixture"

        val IPV6_LOOPBACK: InetAddress = InetAddress.getByName("::1")
    }
}
