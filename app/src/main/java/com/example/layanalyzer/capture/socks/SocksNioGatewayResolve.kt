package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksDestination

/**
 * Bounded DNS for an already selected TLS candidate. Queue time, lookup, hop, LAT1 and READY
 * share the absolute deadline frozen before submission. A resolved domain uses the blocking
 * gateway's first literal address; application SNI cannot change it. Scope closure, stale
 * completion, rejection and timeout detach the session subscription without a direct retry.
 */
internal class SocksNioGatewayResolve(
    private val scope: SocksResolver.Scope,
    private val connector: SocksNioGatewayConnect,
    private val establishmentTimeoutNanos: Long = SocksNioGatewayConnect.ESTABLISHMENT_TIMEOUT_NANOS,
    private val dnsTimeoutNanos: Long = SocksNioTcpResolve.DNS_TIMEOUT_NANOS
) {
    init {
        require(establishmentTimeoutNanos in 1..SocksNioGatewayConnect.MAX_ESTABLISHMENT_TIMEOUT_NANOS)
        require(dnsTimeoutNanos in 1..SocksNioTcpResolve.DNS_TIMEOUT_NANOS)
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
            is SocksDestination.Ip -> connector.connectResolved(client, destination.address, deadline)
            is SocksDestination.Domain -> {
                client.interestOps(0)
                client.onReady { _, _ -> error("Gateway DNS client must remain idle") }
                val timeout = {
                    scope.resolver.recordTimeout()
                    connector.fail(client, SocksSession.DeadlineExceededException())
                }
                if (!session.enterResolving(deadline, timeout)) return
                val token = session.beginOperation(dnsTimeoutNanos, timeout) ?: return
                val submitted = scope.resolver.resolve(scope, destination.name) { result ->
                    val completion = session.complete(token, onDiscard = { scope.resolver.recordDiscard() }) {
                        if (!scope.isOpen || scope.captureGeneration != it.captureGeneration) {
                            scope.resolver.recordDiscard()
                            it.close(SocksResolver.ResolveException(SocksResolver.Failure.SCOPE_CLOSED))
                        } else when (result) {
                            is SocksResolver.Result.Addresses -> connector.connectResolved(client, result.addresses.first(), deadline)
                            is SocksResolver.Result.Failed -> connector.fail(client, result.error)
                        }
                    }
                    if (completion != SocksEventLoop.Submission.ACCEPTED) scope.resolver.recordCompletionRejection()
                }
                submitted.subscription?.let { session.attachOperationCleanup(token, it) }
                submitted.failure?.let { connector.fail(client, it) }
            }
        }
    }
}
