package com.example.layanalyzer.ui.components

import com.example.layanalyzer.ai.playbook.ScenarioOrigin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AgentScenarioMenuTest {

    // ------------------------------------- ① 内置剧本：仅复制与查看详情

    @Test
    fun `builtin scenarios offer only duplicate and details in that order`() {
        assertEquals(
            listOf(
                AgentScenarioMenuAction.CopyAsDuplicate,
                AgentScenarioMenuAction.ViewDetails
            ),
            agentScenarioMenuActions(ScenarioOrigin.BuiltIn)
        )
    }

    // ------------------------------------- ② 用户剧本：编辑、复制、删除

    @Test
    fun `user scenarios offer edit duplicate delete in that order`() {
        assertEquals(
            listOf(
                AgentScenarioMenuAction.Edit,
                AgentScenarioMenuAction.CopyAsDuplicate,
                AgentScenarioMenuAction.Delete
            ),
            agentScenarioMenuActions(ScenarioOrigin.User)
        )
    }

    // ------------------------------- ③ 预设锁定：内置永不出现编辑或删除

    @Test
    fun `builtin scenarios never expose edit or delete`() {
        // The preset lock is structural: even if the menu list evolves, a
        // built-in chip must not surface the mutating affordances.
        val builtin = agentScenarioMenuActions(ScenarioOrigin.BuiltIn)

        assertFalse(AgentScenarioMenuAction.Edit in builtin)
        assertFalse(AgentScenarioMenuAction.Delete in builtin)
    }

    // ----------------------- ④ 门控矩阵：复制是两侧唯一共有动作，其余各归一侧

    @Test
    fun `copy as duplicate is the only action offered to both origins`() {
        // Matrix invariant behind the per-origin lists: duplicating is safe
        // for presets and owned alike, so it is the single shared affordance;
        // every other menu action belongs to exactly one origin — details to
        // the read-only built-in side, edit and delete to the user side.
        val builtin = agentScenarioMenuActions(ScenarioOrigin.BuiltIn).toSet()
        val user = agentScenarioMenuActions(ScenarioOrigin.User).toSet()

        assertEquals(
            setOf(AgentScenarioMenuAction.CopyAsDuplicate),
            builtin intersect user
        )
        assertEquals(
            "Every menu action must be offered by some origin",
            AgentScenarioMenuAction.entries.toSet(),
            builtin union user
        )
        assertFalse(AgentScenarioMenuAction.CopyAsDuplicate in (builtin union user) - (builtin intersect user))
    }
}
