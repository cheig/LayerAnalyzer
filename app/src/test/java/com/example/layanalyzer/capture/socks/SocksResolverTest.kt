// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class SocksResolverTest {
    private val address = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    @Test fun boundsRejectInvalidConfiguration() {
        assertThrows(IllegalArgumentException::class.java) { SocksResolver.Limits(workers = 5) }
        assertThrows(IllegalArgumentException::class.java) { SocksResolver.Limits(queuedQueries = 129) }
        assertThrows(IllegalArgumentException::class.java) { SocksResolver.Limits(subscribers = 1025) }
        assertThrows(IllegalArgumentException::class.java) { SocksResolver.Limits(subscribersPerQuery = 257) }
    }

    @Test fun duplicateNamesShareLookupAndDeliverBothSubscribers() = withResolver { resolver, release ->
        val started = CountDownLatch(1); val results = ConcurrentLinkedQueue<SocksResolver.Result>()
        val names = ConcurrentLinkedQueue<String>()
        val scope = resolver.newScope(1, 2) {
            assertTrue(Thread.currentThread().name.startsWith("SocksDns-"))
            names.add(it); started.countDown(); awaitLatch(release); arrayOf(address)
        }
        assertNotNull(resolver.resolve(scope, "ExAmPlE.test") { results.add(it) }.subscription)
        awaitLatch(started)
        assertNotNull(resolver.resolve(scope, "example.test") { results.add(it) }.subscription)
        assertEquals(1, resolver.stats().activeLookups); assertEquals(1L, resolver.stats().merged)
        release.countDown(); await { results.size == 2 }
        assertEquals(listOf("example.test"), names.toList())
        assertTrue(results.all { (it as SocksResolver.Result.Addresses).addresses == listOf(address) })
        assertEmpty(resolver)
    }

    @Test fun distinctScopesWithSameGenerationsNeverShareAndNetworkChangesAreIsolated() = withResolver { resolver, release ->
        val started = CountDownLatch(3); val results = ConcurrentLinkedQueue<SocksResolver.Result>()
        fun scope(network: Long) = resolver.newScope(1, network) { started.countDown(); awaitLatch(release); arrayOf(address) }
        listOf(scope(8), scope(8), scope(9)).forEach { resolver.resolve(it, "same.test") { result -> results.add(result) } }
        awaitLatch(started)
        assertEquals(3, resolver.stats().activeLookups); assertEquals(0L, resolver.stats().merged)
        release.countDown(); await { results.size == 3 }; assertEmpty(resolver)
    }

    @Test fun fourWorkersAnd128QueuedQueriesAreHardBoundsAndRecoverAfterOneCancel() = withResolver { resolver, release ->
        val started = CountDownLatch(4)
        val scope = resolver.newScope(1, 1) { started.countDown(); awaitLatch(release); arrayOf(address) }
        repeat(4) { assertNotNull(resolver.resolve(scope, "running-$it.test") {}.subscription) }
        awaitLatch(started)
        val queued = (0 until 128).map { checkNotNull(resolver.resolve(scope, "queued-$it.test") {}.subscription) }
        val stats = resolver.stats()
        assertEquals(4, stats.workers); assertEquals(4, stats.activeLookups)
        assertEquals(128, stats.queuedQueries); assertEquals(132, stats.inFlightQueries)
        assertEquals(SocksResolver.Failure.QUEUE_FULL, resolver.resolve(scope, "overflow.test") {}.failure!!.reason)
        queued.first().close()
        assertEquals(127, resolver.stats().queuedQueries)
        assertNotNull(resolver.resolve(scope, "replacement.test") {}.subscription)
        scope.close()
        assertEquals(0, resolver.stats().subscribers); assertEquals(0, resolver.stats().queuedQueries)
        assertEquals(4, resolver.stats().activeLookups); assertEquals(4, resolver.stats().inFlightQueries)
        release.countDown(); await { resolver.stats().activeLookups == 0 }; assertEmpty(resolver)
    }

    @Test fun duplicateSubscriptionsHavePerQueryAndGlobalBounds() =
        withResolver(SocksResolver.Limits(subscribers = 3, subscribersPerQuery = 2)) { resolver, release ->
            val started = CountDownLatch(1)
            val scope = resolver.newScope(1, 1) { started.countDown(); awaitLatch(release); arrayOf(address) }
            val first = resolver.resolve(scope, "same.test") {}
            awaitLatch(started)
            resolver.resolve(scope, "same.test") {}
            assertEquals(SocksResolver.Failure.SUBSCRIBER_LIMIT, resolver.resolve(scope, "same.test") {}.failure!!.reason)
            resolver.resolve(scope, "other.test") {}
            assertEquals(SocksResolver.Failure.SUBSCRIBER_LIMIT, resolver.resolve(scope, "third.test") {}.failure!!.reason)
            first.subscription!!.close()
            assertNotNull(resolver.resolve(scope, "same.test") {}.subscription)
            assertEquals(3, resolver.stats().peakSubscribers)
            scope.close(); release.countDown(); await { resolver.stats().activeLookups == 0 }; assertEmpty(resolver)
        }

    @Test fun oneCancellationDoesNotCancelOtherSubscriberAndIsIdempotent() = withResolver { resolver, release ->
        val started = CountDownLatch(1); val calls = AtomicInteger()
        val scope = resolver.newScope(1, 1) { started.countDown(); awaitLatch(release); arrayOf(address) }
        val cancelled = resolver.resolve(scope, "same.test") { fail("cancelled callback") }.subscription!!
        awaitLatch(started)
        resolver.resolve(scope, "same.test") { calls.incrementAndGet() }
        cancelled.close(); cancelled.close()
        assertEquals(1, resolver.stats().subscribers); assertEquals(1L, resolver.stats().cancelled)
        release.countDown(); await { calls.get() == 1 }; assertEmpty(resolver)
    }

    @Test fun closedScopeReleasesCallbacksButHungLookupStaysCountedAcrossTwentyRestarts() = withResolver { resolver, release ->
        val started = CountDownLatch(4); val callbacks = AtomicInteger()
        val scope = resolver.newScope(1, 1) {
            started.countDown()
            // Models Android/system resolution ignoring interrupt; teardown never assumes interrupt works.
            while (release.count != 0L) try { release.await() } catch (_: InterruptedException) { }
            arrayOf(address)
        }
        repeat(4) { resolver.resolve(scope, "hung-$it.test") { callbacks.incrementAndGet() } }
        awaitLatch(started)
        val start = System.nanoTime(); scope.close()
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 500)
        repeat(20) {
            val next = resolver.newScope(1, it.toLong()) { fail("queued restart must never execute"); emptyArray() }
            assertNotNull(resolver.resolve(next, "restart.test") { callbacks.incrementAndGet() }.subscription)
            next.close()
            assertEquals(4, resolver.stats().workers); assertEquals(4, resolver.stats().activeLookups)
            assertEquals(4, resolver.stats().inFlightQueries); assertEquals(0, resolver.stats().queuedQueries)
            assertEquals(0, resolver.stats().subscribers)
        }
        assertNull(scope.lookup)
        release.countDown(); await { resolver.stats().activeLookups == 0 }
        assertEquals(0, callbacks.get()); assertEquals(4L, resolver.stats().abandonedResults); assertEmpty(resolver)
    }

    @Test fun lookupExceptionsEmptyAndOversizeResultsAreExplicitFailures() = withResolver { resolver, _ ->
        val expected = listOf(SocksResolver.Failure.LOOKUP_FAILED, SocksResolver.Failure.EMPTY_RESULT, SocksResolver.Failure.TOO_MANY_ADDRESSES)
        val lookups: List<(String) -> Array<InetAddress>> = listOf(
            { throw UnknownHostException("controlled") }, { emptyArray() }, { Array(65) { address } })
        lookups.zip(expected).forEach { (lookup, reason) ->
            val results = ConcurrentLinkedQueue<SocksResolver.Result>()
            resolver.resolve(resolver.newScope(1, 1, lookup), "failure.test") { results.add(it) }
            await { results.isNotEmpty() }
            assertEquals(reason, (results.poll() as SocksResolver.Result.Failed).error.reason)
        }
        assertEquals(3L, resolver.stats().failed); assertEmpty(resolver)
    }

    @Test fun closedScopeAndInvalidNamesAreRejectedBeforeQueueing() = withResolver { resolver, _ ->
        val scope = resolver.newScope(1, 1) { fail("lookup must not run"); emptyArray() }
        listOf("", "x y", "x\u0000y", "x".repeat(256)).forEach {
            assertEquals(SocksResolver.Failure.INVALID_NAME, resolver.resolve(scope, it) {}.failure!!.reason)
        }
        scope.close()
        assertEquals(SocksResolver.Failure.SCOPE_CLOSED, resolver.resolve(scope, "valid.test") {}.failure!!.reason)
        assertEquals(0, resolver.stats().workers); assertEmpty(resolver)
    }

    @Test fun completedResultsAreNotCachedAcrossNewQueries() = withResolver { resolver, _ ->
        val scope = resolver.newScope(1, 1) { arrayOf(address) }
        val count = AtomicInteger()
        repeat(2) { target ->
            resolver.resolve(scope, "same.test") { count.incrementAndGet() }
            await { count.get() == target + 1 }
        }
        assertEquals(2L, resolver.stats().lookups); assertEquals(0L, resolver.stats().merged); assertEmpty(resolver)
    }

    @Test fun fatalLookupAndCallbackFailureDoNotLeakOrStarveSharedSubscribers() = withResolver { resolver, release ->
        val started = CountDownLatch(1); val results = ConcurrentLinkedQueue<SocksResolver.Result>()
        val scope = resolver.newScope(1, 1) { started.countDown(); awaitLatch(release); throw AssertionError("controlled lookup") }
        resolver.resolve(scope, "same.test") { throw AssertionError("controlled callback") }
        awaitLatch(started)
        resolver.resolve(scope, "same.test") { results.add(it) }
        release.countDown(); await { results.isNotEmpty() }
        assertEquals(SocksResolver.Failure.LOOKUP_FAILED, (results.poll() as SocksResolver.Result.Failed).error.reason)
        assertEquals(1L, resolver.stats().callbackFailures); assertEquals(0, resolver.stats().activeLookups)
        assertEmpty(resolver)
    }

    private fun withResolver(limits: SocksResolver.Limits = SocksResolver.Limits(),
        action: (SocksResolver, CountDownLatch) -> Unit) {
        val resolver = SocksResolver.forTest(limits); val release = CountDownLatch(1)
        try { action(resolver, release) } finally { release.countDown(); assertTrue(resolver.shutdownForTest()) }
    }
    private fun assertEmpty(resolver: SocksResolver) {
        await { resolver.stats().inFlightQueries == 0 }
        assertEquals(0, resolver.stats().subscribers); assertEquals(0, resolver.stats().queuedQueries)
    }
    private fun awaitLatch(latch: CountDownLatch) { assertTrue(latch.await(3, TimeUnit.SECONDS)) }
    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!condition()) { assertTrue("condition deadline", System.nanoTime() < deadline); Thread.sleep(2) }
    }
}
