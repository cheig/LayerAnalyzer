// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GatewaySessionStoreTest {
    @Test
    fun expiredSessionIsNotReturnedAsAnAuthorizationCredential() {
        var now = 1_000L
        val store = InMemoryGatewaySessionStore(clock = { now })
        val session = GatewayAuthSession(
            accessToken = "short-lived-token",
            userId = "user-1",
            organizationId = "org-1",
            expiresAtMillis = 2_000L
        )

        assertTrue(store.save(session).isSuccess)
        assertEquals("short-lived-token", store.accessToken())

        now = 2_000L

        assertNull(store.accessToken())
        assertNull(store.session)
    }

    @Test
    fun expiredSessionsCannotBeSavedAndLogoutClearsTheSession() {
        val store = InMemoryGatewaySessionStore(clock = { 10_000L })
        val expired = GatewayAuthSession(
            accessToken = "expired",
            userId = "user-1",
            expiresAtMillis = 9_999L
        )

        assertTrue(store.save(expired).isFailure)
        assertNull(store.session)

        val active = GatewayAuthSession(
            accessToken = "active",
            userId = "user-1",
            expiresAtMillis = 20_000L
        )
        store.save(active)
        store.clear()
        assertNull(store.accessToken())
    }
}
