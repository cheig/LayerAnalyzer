// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.privacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Report-text hardening, per AI-11 section 4.
 *
 * The threat is indirect rather than direct: capture text is attacker-controlled
 * and a model may repeat it, so a Markdown renderer downstream would happily
 * turn `[tap here](intent://…)` into something the user can tap.  AI-11 allows
 * exactly two things to become actionable — a frame number and a host-validated
 * display filter — so everything else is reduced to inert text at this layer,
 * rather than in a UI that a second renderer could forget to replicate.
 */
class AgentPrivacyPolicySanitizationTest {

    @Test
    fun `a markdown link keeps its label and loses its target`() {
        val out = AgentPrivacyPolicy.sanitizeReportText("See [tap here](intent://evil/launch) for details.")

        assertTrue("label was dropped: $out", out.contains("tap here"))
        assertFalse("target survived: $out", out.contains("intent://evil"))
        assertFalse("target survived: $out", out.contains("]("))
    }

    @Test
    fun `an image target is removed too`() {
        // An image src is a network call the moment the report renders.
        val out = AgentPrivacyPolicy.sanitizeReportText("![beacon](http://tracker.example.com/x.png)")

        assertFalse("image target survived: $out", out.contains("tracker.example.com"))
    }

    @Test
    fun `schemes the os can act on are blocked`() {
        val cases = listOf(
            "intent://scan/#Intent;scheme=zxing;end",
            "file:///data/data/com.example/secret.db",
            "content://com.android.contacts/data",
            "javascript:alert(document.cookie)",
            "adb://shell",
            "smb://share/x"
        )

        for (case in cases) {
            val out = AgentPrivacyPolicy.sanitizeReportText("Open $case now")
            assertTrue("scheme survived for $case: $out", out.contains(AgentPrivacyPolicy.BLOCKED_URI))
        }
    }

    @Test
    fun `a shell fence is flattened into plain text`() {
        val out = AgentPrivacyPolicy.sanitizeReportText("Run:\n```bash\nadb shell rm -rf /data\n```\ndone")

        assertFalse("fence survived: $out", out.contains("```"))
        assertTrue("flattened text was not marked: $out", out.contains("code:"))
    }

    @Test
    fun `local filesystem paths are blocked`() {
        val out = AgentPrivacyPolicy.sanitizeReportText(
            "Capture at /sdcard/Download/x.pcap and C:\\Users\\bob\\x.pcap"
        )

        assertFalse("unix path survived: $out", out.contains("/sdcard/Download"))
        assertFalse("windows path survived: $out", out.contains("C:\\Users\\bob"))
        assertTrue(out.contains(AgentPrivacyPolicy.BLOCKED_PATH))
    }

    @Test
    fun `frame numbers display filters and domain vocabulary survive`() {
        // Sanitizing must not cost the report its meaning.  These are precisely
        // the strings the analysis is made of.
        val text = "Frame 42 matches tcp.analysis.retransmission for " +
            "sip:user-abc@host-def.invalid over https://example.com"
        val out = AgentPrivacyPolicy.sanitizeReportText(text)

        assertTrue("frame reference lost: $out", out.contains("Frame 42"))
        assertTrue("display filter lost: $out", out.contains("tcp.analysis.retransmission"))
        assertTrue("sip alias lost: $out", out.contains("sip:user-abc@host-def.invalid"))
        assertTrue("http reference lost: $out", out.contains("https://example.com"))
    }

    @Test
    fun `empty text is returned unchanged`() {
        assertEquals("", AgentPrivacyPolicy.sanitizeReportText(""))
    }

    @Test
    fun `sanitizing is stable when applied twice`() {
        val once = AgentPrivacyPolicy.sanitizeReportText("[x](file:///data/y) and /sdcard/z")
        val twice = AgentPrivacyPolicy.sanitizeReportText(once)

        assertEquals(once, twice)
    }
}
