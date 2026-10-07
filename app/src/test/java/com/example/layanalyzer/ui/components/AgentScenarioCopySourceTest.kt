package com.example.layanalyzer.ui.components

import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.playbook.ScenarioOrigin
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * JVM tests for the copied-scenario source label (OPT-COPY-01): the editor
 * shows a copy's source by title — resolved from the host's merged playbook
 * list — and falls back to the raw source id when no entry carries it, so
 * "Copied from …" never silently drops a copy whose source was deleted or
 * whose built-in id was retired by a package switch.
 */
class AgentScenarioCopySourceTest {

    private fun playbook(
        id: String,
        title: String,
        origin: ScenarioOrigin
    ): AgentPlaybook = AgentPlaybook.generalCaptureHealth().copy(
        id = id,
        title = title,
        origin = origin
    )

    // ------------------------------------------- ① 内置 id 命中：显示内置标题

    @Test
    fun `copy of a builtin source resolves to the builtin title`() {
        val playbooks = listOf(
            playbook(
                id = AgentPlaybook.GENERAL_CAPTURE_HEALTH_ID,
                title = "General capture health",
                origin = ScenarioOrigin.BuiltIn
            )
        )

        assertEquals(
            "General capture health",
            scenarioCopySourceLabel("user-general-capture-health-copy", playbooks)
        )
    }

    // ----------------------------------- ② 正常命中：用户源去前缀后仍能查到

    @Test
    fun `copy of a user source resolves to the user scenario title`() {
        // generateCopyId strips one `user-` prefix, so copying `user-sip`
        // mints `user-sip-copy` whose remainder `sip` names the source by
        // its prefix-stripped id.
        val playbooks = listOf(
            playbook(id = "user-sip", title = "SIP quality review", origin = ScenarioOrigin.User)
        )

        assertEquals(
            "SIP quality review",
            scenarioCopySourceLabel("user-sip-copy", playbooks)
        )
    }

    // ------------------------------------- ③ 查不到：回落显示来源 id 而非消失

    @Test
    fun `copy with an absent source falls back to the raw source id`() {
        val playbooks = listOf(
            playbook(id = "user-sip", title = "SIP quality review", origin = ScenarioOrigin.User)
        )

        // The source was deleted (or was a built-in id a package switch
        // retired): the remainder is shown verbatim, id included.
        assertEquals("long-gone", scenarioCopySourceLabel("user-long-gone-copy", playbooks))
    }

    // ------------------------------------------------ ④ 非副本 id：无来源标签

    @Test
    fun `non-copy ids carry no source label`() {
        val playbooks = listOf(
            playbook(id = "user-sip", title = "SIP quality review", origin = ScenarioOrigin.User)
        )

        // Plain user scenarios and any id outside the `user-` namespace
        // render as "user-owned" / built-in rather than "copied from".
        assertEquals(null, scenarioCopySourceLabel("user-sip", playbooks))
        assertEquals(null, scenarioCopySourceLabel("user-scenario-2", playbooks))
        assertEquals(null, scenarioCopySourceLabel("general-copy", playbooks))
    }

    // ------------------------------ ⑤ 双层同 rest 的残余歧义：内置优先，仅显示

    @Test
    fun `remainder present in both layers prefers the builtin title`() {
        val playbooks = listOf(
            playbook(id = "user-sip", title = "My SIP review", origin = ScenarioOrigin.User),
            playbook(id = "sip", title = "SIP preset", origin = ScenarioOrigin.BuiltIn)
        )

        // The id shape cannot tell which was the source; the documented
        // display-only tie-break is built-in first.
        assertEquals("SIP preset", scenarioCopySourceLabel("user-sip-copy", playbooks))
    }

    // -------------------------------- ⑥ copySourceRemainder：规范副本形状的直钉

    @Test
    fun `canonical copy ids peel to the source remainder`() {
        // The shape generateCopyId mints: `user-<rest>-copy` from a built-in
        // `<rest>` or from a user `user-<rest>` (one prefix comes off).
        assertEquals("sip", copySourceRemainder("user-sip-copy"))
        assertEquals("general-capture-health", copySourceRemainder("user-general-capture-health-copy"))
        // A copy of a copy keeps the inner suffix inside the remainder; the
        // resolution above still finds the intermediate source.
        assertEquals("sip-copy", copySourceRemainder("user-sip-copy-copy"))
        // Numbered collision suffixes live before `-copy`?  They do not: the
        // store's uniqueId fallback mints different shapes entirely, and
        // whatever `user-…-copy` survives is read by the same grammar.
        assertEquals("x-2", copySourceRemainder("user-x-2-copy"))
    }

    // -------------------------------- ⑦ 非副本形状：无来源可反解

    @Test
    fun `ids outside the copy shape have no source remainder`() {
        // Missing either side of the shape is not a copy: plain user ids,
        // ids outside the `user-` namespace, and the namespace alone.
        assertEquals(null, copySourceRemainder("user-sip"))
        assertEquals(null, copySourceRemainder("sip-copy"))
        assertEquals(null, copySourceRemainder("general-capture-health"))
        assertEquals(null, copySourceRemainder("user-"))
        assertEquals(null, copySourceRemainder(""))
        assertEquals(null, copySourceRemainder("-copy"))
        // The grammar is exact, not fuzzy: wrong case or stray padding is
        // simply not a copy id.
        assertEquals(null, copySourceRemainder("user-sip-Copy"))
        assertEquals(null, copySourceRemainder("User-sip-copy"))
        assertEquals(null, copySourceRemainder(" user-sip-copy"))
    }

    // -------------------- ⑧ 畸形与歧义边界：空 rest 拒绝，前后缀重叠读作 copy

    @Test
    fun `degenerate copy ids resolve by the documented shape trade`() {
        // `user--copy` is an empty-rest copy, which generateCopyId never
        // mints (empty rest falls to the numbered id): it resolves to no
        // source rather than inventing one.
        assertEquals(null, copySourceRemainder("user--copy"))
        // `user-copy` is the residual ambiguity the KDoc accepts: prefix and
        // suffix do not overlap-check, so it reads as a copy of source
        // `copy`.  Pinning the current reading keeps any change deliberate.
        assertEquals("copy", copySourceRemainder("user-copy"))
        // Even that ambiguous remainder keeps the label surface honest: no
        // matching entry shows the raw remainder.
        assertEquals("copy", scenarioCopySourceLabel("user-copy", emptyList()))
    }
}
