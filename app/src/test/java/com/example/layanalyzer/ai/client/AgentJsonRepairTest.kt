// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The repair layer's contract is narrow on purpose: fix delimiters, change no
 * data, and refuse anything it cannot fix without guessing.  These tests pin all
 * three, because a repair that silently altered a report would be worse than the
 * parse failure it replaced.
 */
class AgentJsonRepairTest {

    @Test
    fun restoresAKeyWhoseClosingQuoteWasDropped() {
        val broken = """{"a":["x"],"recommendations ["y"],"b":1}"""

        val repaired = AgentJsonRepair.repair(broken)

        assertNotNull(repaired)
        val json = JSONObject(repaired!!.json)
        assertEquals("y", json.getJSONArray("recommendations").getString(0))
        assertEquals(1, json.getInt("b"))
        assertTrue(repaired.repairs.contains("closed_key"))
    }

    @Test
    fun closesAnArrayThatWasNeverClosed() {
        val broken = """{"findings":[{"id":"a","notes":["n"}],"summary":"s"}"""

        val repaired = AgentJsonRepair.repair(broken)

        assertNotNull(repaired)
        val json = JSONObject(repaired!!.json)
        assertEquals("s", json.getString("summary"))
        assertEquals("a", json.getJSONArray("findings").getJSONObject(0).getString("id"))
    }

    @Test
    fun closesContainersLeftOpenAtEndOfInput() {
        val broken = """{"a":{"b":[1,2"""

        val repaired = AgentJsonRepair.repair(broken)

        assertNotNull(repaired)
        val json = JSONObject(repaired!!.json)
        assertEquals(2, json.getJSONObject("a").getJSONArray("b").getInt(1))
    }

    /**
     * The real failure this layer was built for: a 6 KB report from the device
     * that needed exactly two characters.  A bracket inside a string value in the
     * same document must survive untouched.
     */
    @Test
    fun repairsTheObservedFieldPatternWithoutTouchingStringContents() {
        val broken = """{"summary":"proxy sent BYE [unanswered] to 5061",""" +
            """"alternatives":["a"],"recommendations ["check 5061"],""" +
            """"timeline":[{"stage":"BYE"}]}"""

        val repaired = AgentJsonRepair.repair(broken)

        assertNotNull(repaired)
        val json = JSONObject(repaired!!.json)
        assertEquals("proxy sent BYE [unanswered] to 5061", json.getString("summary"))
        assertEquals("check 5061", json.getJSONArray("recommendations").getString(0))
        assertEquals("BYE", json.getJSONArray("timeline").getJSONObject(0).getString("stage"))
    }

    @Test
    fun leavesValidJsonExactlyAsItWas() {
        listOf(
            """{"a":1}""",
            """{"a":[1,2],"b":{"c":"d"}}""",
            """{"s":"has [ bracket and { brace inside"}""",
            """{"k":"a\"b","n":[{"x":1}]}""",
            """{"note":"值 [ 中文"}""",
            """{"nested":{"deep":[{"k":"v [ x"}]}}"""
        ).forEach { valid ->
            assertNull("must not touch $valid", AgentJsonRepair.repair(valid))
        }
    }

    /**
     * Appending the missing quote would fold the trailing `}` into the value and
     * hand back data the model never emitted, so a cut-off string is refused.
     */
    @Test
    fun refusesToCloseATruncatedString() {
        assertNull(AgentJsonRepair.repair("""{"summary":"unterminated}"""))
    }

    @Test
    fun refusesContentThatIsNotJsonAtAll() {
        assertNull(AgentJsonRepair.repair("plain text only"))
    }

    /** A bracket after a space inside a *value* is content, not a broken key. */
    @Test
    fun doesNotTreatABracketInsideAValueAsABrokenKey() {
        assertNull(AgentJsonRepair.repair("""{"detail":"saw [ then more text"}"""))
    }
}
