// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AliasTableTest {
    @Test
    fun aliasesAreStablePerRunAndResolvableOnlyLocally() {
        val table = AliasTable("capture-a|run-1")
        val first = table.alias(AgentAliasKind.Endpoint, "192.0.2.10")
        val repeated = table.alias(AgentAliasKind.Endpoint, "192.0.2.10")
        val call = table.alias(AgentAliasKind.CallId, "call-1@example.test")

        assertEquals(first, repeated)
        assertNotEquals(first, call)
        assertEquals("192.0.2.10", table.resolve(first)?.localValue)
        assertTrue(table.replaceKnown("traffic from 192.0.2.10").contains(first))
    }

    @Test
    fun replaceKnownDoesNotRewriteAliasesInsertedEarlier() {
        val sessionKey = "capture-a|run-1"
        val sessionTag = sessionKey.hashCode().toUInt().toString(36).takeLast(4)
        val table = AliasTable(sessionKey)
        val endpoint = table.alias(AgentAliasKind.Endpoint, "10.0.0.1")
        val shortIdentifier = table.alias(AgentAliasKind.Ssrc, sessionTag)

        val replaced = table.replaceKnown("endpoint=10.0.0.1 id=$sessionTag")

        assertTrue("endpoint alias was corrupted: $replaced", replaced.contains(endpoint))
        assertTrue("short identifier was not replaced: $replaced", replaced.contains(shortIdentifier))
        assertEquals("10.0.0.1", table.resolve(endpoint)?.localValue)
        assertEquals(sessionTag, table.resolve(shortIdentifier)?.localValue)
    }
}
