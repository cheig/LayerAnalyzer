package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.NativeEngine

/** The upstream network half of the C05 platform boundary (TLS-203): every real
 * outbound socket is protected and bound before connect, and names are resolved
 * only on the captured network.
 *
 * Calls are synchronous and arrive on Go worker threads. Implementations must
 * not reenter start/stop, retain a borrowed FD, queue the FD for later use, log
 * a destination or a token, or wait for the UI thread.
 */
interface TlsUpstreamCallbacks {
    fun prepareSocket(fd: Int, networkGeneration: Long): String
    fun resolveHost(host: String, networkGeneration: Long): String
}

/** Full C05 boundary. The JNI start path requires all four methods, so the
 * assembled engine (TLS-216) implements this: TLS-204 adds upstream chain and
 * name verification, TLS-210 the downstream secret hand-off. Neither is
 * implemented by the socket half alone. */
interface TlsPlatformCallbacks : TlsUpstreamCallbacks {
    fun verifyUpstream(chainDer: Array<ByteArray>, identity: String, authType: String, tlsVersion: String): String

    /** Copy into a bounded queue before returning; true means accepted, not persisted. */
    fun offerSecret(captureId: String, connectionId: String, line: ByteArray): Boolean
}

/**
 * The production [TlsEngineBridge]: a thin wrapper over the C ABI's own entry
 * points, with no lifecycle of its own. Constructing it starts no native work;
 * the assembled capture (TLS-216) is what decides when a run begins.
 *
 * In-module only: the JNI surface is reached through this class by the capture
 * coordinator, so nothing outside the app module can drive the engine's lifetime.
 */
internal class TlsProxyBridge : TlsEngineBridge {
    override fun capabilities(): String = NativeEngine.getTlsProxyCapabilities()

    override fun start(configJson: String, certificateDer: ByteArray, privateKeyPkcs8: ByteArray, callbacks: TlsPlatformCallbacks): String =
        NativeEngine.startTlsProxy(configJson, certificateDer, privateKeyPkcs8, callbacks)

    override fun stop(handle: Long, timeoutMillis: Int): String = NativeEngine.stopTlsProxy(handle, timeoutMillis)

    override fun poll(handle: Long, maxEvents: Int): String = NativeEngine.pollTlsProxyEvents(handle, maxEvents)

    override fun stats(handle: Long): String = NativeEngine.getTlsProxyStats(handle)

    /**
     * The running run's gateway token — the 43 ASCII characters the `LAT1` frame
     * carries (TLS-215).
     *
     * It is read separately from [start]'s JSON result on purpose: C05 keeps the
     * token out of every ordinary envelope, so the only way to it is this
     * dedicated buffer. The caller copies it into a [TlsGatewayChannel] (or wipes
     * its own copy) and never logs, stores or serializes it.
     *
     * @throws IllegalStateException with one fixed code name: `UNSUPPORTED`
     *   without the TLS build, `STALE_GENERATION` for a handle that is not the
     *   running run, `INVALID_ARGUMENT`, or `NOT_READY` off a Go callback thread.
     */
    override fun gatewayToken(handle: Long): ByteArray = NativeEngine.getTlsProxyToken(handle)
}
