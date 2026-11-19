// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksDestination

/**
 * Direct TCP only, AFTER the route decision. TLS candidates must never enter this adapter as a
 * fallback. Assembly supplies one frozen-network scope per capture run and closes it on stop or
 * network invalidation. Session close independently detaches its own subscription immediately.
 */
internal class SocksNioTcpResolve(
    private val scope: SocksResolver.Scope,
    private val connector: SocksNioTcpConnect,
    private val resolver: SocksResolver = scope.resolver,
    private val establishmentTimeoutNanos: Long = SocksNioTcpConnect.CONNECT_TIMEOUT_NANOS,
    private val dnsTimeoutNanos: Long = DNS_TIMEOUT_NANOS
) {
    init {
        require(scope.resolver === resolver)
        require(establishmentTimeoutNanos in 1..SocksNioTcpConnect.CONNECT_TIMEOUT_NANOS)
        require(dnsTimeoutNanos in 1..DNS_TIMEOUT_NANOS)
    }

    fun connect(client: SocksNioHandshake.AdmittedRequest) {
        val session = client.session
        check(session.owner.inEventLoop())
        check(client.request.command == SocksProtocol.COMMAND_CONNECT)
        check(session.snapshot().state == SocksSession.State.ADMITTED)
        val deadline = session.ownerNowNanos() + establishmentTimeoutNanos
        if (!scope.isOpen || scope.captureGeneration != session.captureGeneration) {
            connector.fail(client, SocksResolver.ResolveException(SocksResolver.Failure.SCOPE_CLOSED))
            return
        }
        when (val destination = client.request.destination) {
            is SocksDestination.Ip -> connector.connectResolved(client, listOf(destination.address), deadline)
            is SocksDestination.Domain -> {
                client.interestOps(0)
                client.onReady { _, _ -> error("DNS client must remain idle") }
                val timeout = {
                    resolver.recordTimeout()
                    connector.fail(client, SocksSession.DeadlineExceededException())
                }
                if (!session.enterResolving(deadline, timeout)) return
                val token = session.beginOperation(dnsTimeoutNanos, timeout) ?: return
                val submitted = resolver.resolve(scope, destination.name) { result ->
                    val completion = session.complete(token, onDiscard = { resolver.recordDiscard() }) {
                        if (!scope.isOpen || scope.captureGeneration != it.captureGeneration) {
                            resolver.recordDiscard()
                            it.close(SocksResolver.ResolveException(SocksResolver.Failure.SCOPE_CLOSED))
                        } else when (result) {
                            is SocksResolver.Result.Addresses -> connector.connectResolved(client, result.addresses, deadline)
                            is SocksResolver.Result.Failed -> connector.fail(client, result.error)
                        }
                    }
                    // Rejection never touches the session from a worker. Its existing DNS/phase
                    // timer still bounds cleanup and writes a failure if the loop remains alive.
                    if (completion != SocksEventLoop.Submission.ACCEPTED) resolver.recordCompletionRejection()
                }
                submitted.subscription?.let { session.attachOperationCleanup(token, it) }
                submitted.failure?.let { connector.fail(client, it) }
            }
        }
    }

    companion object { const val DNS_TIMEOUT_NANOS = 10_000_000_000L }
}
