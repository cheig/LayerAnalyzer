package com.example.layanalyzer.capture.tls

import android.net.Network
import android.os.ParcelFileDescriptor
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileDescriptor
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Production TLS-203 platform callbacks: the socket and DNS half of C05, shared
 * by the gateway hop and the TLS upstream.
 *
 * [prepareSocket] runs synchronously inside Go's `net.Dialer.Control`, after the
 * descriptor exists and before `connect()`. The descriptor always belongs to Go:
 * Android's public `Network.bindSocket` needs a `FileDescriptor`, so the original
 * is duplicated with [ParcelFileDescriptor.fromFd] and only the duplicate is
 * closed here. The original is never retained, adopted or closed, and nothing is
 * queued for an asynchronous thread.
 *
 * [resolveHost] uses only the captured [Network], which is also the only resolver
 * reachable from here: there is no fallback to the process default resolver, so an
 * answer can never come from another network and bypass the capture. It is not
 * used for a numeric destination at all - Go keeps an original destination IP.
 *
 * Nothing in this class logs a destination, descriptor or token. The class
 * performs no work until the engine calls it; the feature gate belongs to the
 * engine entry point (TLS-216), not to these callbacks.
 */
class UpstreamSocketProtector(
    private val currentNetwork: () -> NetworkSnapshot?,
    private val protect: (Int) -> Boolean,
    private val bind: (Network, FileDescriptor) -> Unit = { network, fd -> network.bindSocket(fd) },
    private val resolveName: (Network, String) -> Array<InetAddress>? = { network, host -> network.getAllByName(host) }
) : TlsUpstreamCallbacks {
    data class NetworkSnapshot(val network: Network, val generation: Long)

    // Diagnostic stages contain no FD, destination, token or user bytes.
    enum class Stage { Validated, Protected, Duplicated, Bound, DuplicateClosed, Ready }

    @Volatile
    var lastStages: List<Stage> = emptyList()
        private set

    override fun prepareSocket(fd: Int, networkGeneration: Long): String {
        val stages = mutableListOf<Stage>()
        fun reply(code: String? = null): String {
            lastStages = stages.toList()
            return envelope(code, "Socket preparation failed")
        }
        if (fd < 0 || networkGeneration < 0) return reply("INVALID_ARGUMENT")
        try {
            val snapshot = currentNetwork() ?: return reply("NETWORK_CHANGED")
            if (snapshot.generation != networkGeneration) return reply("STALE_GENERATION")
            stages += Stage.Validated
            if (!protect(fd)) return reply("PROTECT_FAILED")
            stages += Stage.Protected
            // fromFd duplicates. Never adoptFd/close the Go-owned original, and
            // never retain either descriptor after this synchronous callback.
            val duplicate = ParcelFileDescriptor.fromFd(fd)
            stages += Stage.Duplicated
            try {
                // A failed bind must abort the attempt: Go never continues to
                // connect on a socket that was not bound to the capture network.
                bind(snapshot.network, duplicate.fileDescriptor)
                stages += Stage.Bound
            } finally {
                duplicate.close()
                stages += Stage.DuplicateClosed
            }
            if (currentNetwork() != snapshot) return reply("NETWORK_CHANGED")
            stages += Stage.Ready
            return reply()
        } catch (_: Exception) {
            // Do not serialize platform exception messages or raw descriptors.
            return reply("IO_ERROR")
        }
    }

    /**
     * Returns the schemaVersion=1 envelope C05 defines, with `addresses` only on
     * success. Resolution failure is reported as IO_ERROR and never retried
     * through another resolver.
     */
    override fun resolveHost(host: String, networkGeneration: Long): String {
        fun reply(code: String? = null, addresses: List<String> = emptyList()): String {
            val json = envelope(code, "Name resolution failed")
            return if (code == null) JSONObject(json).put("addresses", JSONArray(addresses)).toString() else json
        }
        if (networkGeneration < 0) return reply("INVALID_ARGUMENT")
        val name = canonicalName(host) ?: return reply("INVALID_ARGUMENT")
        val snapshot = currentNetwork() ?: return reply("NETWORK_CHANGED")
        if (snapshot.generation != networkGeneration) return reply("STALE_GENERATION")
        val resolved = try {
            resolveName(snapshot.network, name)
        } catch (_: UnknownHostException) {
            return reply("IO_ERROR")
        } catch (_: Exception) {
            // SecurityException, a platform resolver error and an empty answer
            // are all explicit failures, not a reason to try somewhere else.
            return reply("IO_ERROR")
        }
        if (currentNetwork() != snapshot) return reply("NETWORK_CHANGED")
        // A scoped IPv6 address cannot be dialed without its scope and the ABI
        // does not carry one, so it is not offered as a usable result.
        val addresses = resolved.orEmpty().mapNotNull { address -> address.hostAddress }
            .filter { it.isNotBlank() && !it.contains('%') }
            .distinct()
        if (addresses.isEmpty()) return reply("IO_ERROR")
        return reply(addresses = addresses)
    }

    private fun envelope(code: String?, error: String): String = JSONObject()
        .put("schemaVersion", 1)
        .put("success", code == null)
        .put("errorCode", code ?: JSONObject.NULL)
        .put("error", if (code == null) JSONObject.NULL else error)
        .toString()

    /**
     * Mirrors the Go side's validation: one trailing dot is removed and every
     * remaining label must begin and end ASCII alphanumeric with at most 63
     * bytes. Rejecting a malformed name here keeps it away from the resolver;
     * case is left to the policy layer and forwarded unchanged.
     */
    private fun canonicalName(host: String): String? {
        if (host.isEmpty() || host.length > MAX_NAME_LENGTH) return null
        val name = host.removeSuffix(".")
        if (name.isEmpty() || name.length > MAX_NAME_LENGTH) return null
        for (label in name.split('.')) {
            if (label.isEmpty() || label.length > MAX_LABEL_LENGTH) return null
            if (!label.first().isAsciiAlphanumeric() || !label.last().isAsciiAlphanumeric()) return null
            if (label.any { !it.isAsciiAlphanumeric() && it != '-' && it != '_' }) return null
        }
        return name
    }

    private fun Char.isAsciiAlphanumeric(): Boolean =
        this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9'

    private companion object {
        const val MAX_NAME_LENGTH = 253
        const val MAX_LABEL_LENGTH = 63
    }
}
