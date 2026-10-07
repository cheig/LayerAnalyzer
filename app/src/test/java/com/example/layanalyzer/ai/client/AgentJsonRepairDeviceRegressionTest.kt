package com.example.layanalyzer.ai.client

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Regression for the exact payload that failed on-device on 2026-08-17.
 *
 * The model streamed a complete four-finding SIP analysis and dropped two
 * delimiters in ~6.5 KB of nested JSON: a key's closing quote and one array
 * terminator. The run was reported as failed and the analysis discarded. This
 * fixture is a reduced form of that document — same two defect shapes, same
 * relative positions, same Chinese prose and bracket-bearing string values —
 * and it must survive both repairs with its data intact.
 */
class AgentJsonRepairDeviceRegressionTest {

    @Test
    fun repairsTheTwoDefectsObservedOnDevice() {
        val onDeviceShape = """
            {"summary":"本次抓包包含一个SIP会话，BYE消息未正常转发/响应。",
            "findings":[
            {"id":"BYE-TO-PORT5061-NO-RESPONSE","title":"BYE经代理转发至端口5061后收件端无应答",
            "severity":"Error","confidence":"High",
            "conclusion":"代理将BYE经5060→6060→5061转发，但端口5061从未回复200 OK。",
            "evidence":[{"type":"Frame","frameNumber":79,"observation":"BYE [转发] 至5061"}],
            "alternatives":["主叫可能已清除本地Call Leg状态"],
            "recommendations ["检查10.241.131.50的SIP UA状态机"],
            "timeline":[{"stage":"被叫侧BYE发起","frameNumber":171}]},
            {"id":"TIMING-RACE","title":"BYE与200 OK存在时序竞争",
            "severity":"Notice","confidence":"Medium","conclusion":"存在时序竞争。",
            "evidence":[{"type":"Frame","frameNumber":181,"observation":"200 OK"}],
            "recommendations":["检查是否会话状态机因时序竞争导致状态不一致"}],
            "limitations":["Request-URI字段值在隐私模式下被屏蔽（PRIVACY_BLOCKED）"],
            "recommendedNextSteps":["在端口5061上的SIP实体侧抓包"]}
        """.trimIndent().replace("\n", "")

        val repaired = AgentJsonRepair.repair(onDeviceShape)

        assertNotNull("the on-device payload must be repairable", repaired)
        val json = JSONObject(repaired!!.json)

        // Both findings survived, with their evidence.
        val findings = json.getJSONArray("findings")
        assertEquals(2, findings.length())
        assertEquals(
            "BYE-TO-PORT5061-NO-RESPONSE",
            findings.getJSONObject(0).getString("id")
        )
        assertEquals("TIMING-RACE", findings.getJSONObject(1).getString("id"))

        // Defect 1: the key whose closing quote was dropped.
        assertEquals(
            "检查10.241.131.50的SIP UA状态机",
            findings.getJSONObject(0).getJSONArray("recommendations").getString(0)
        )

        // Defect 2: the array that was never closed.
        assertEquals(
            "检查是否会话状态机因时序竞争导致状态不一致",
            findings.getJSONObject(1).getJSONArray("recommendations").getString(0)
        )

        // A bracket inside a string value must not have been treated as syntax.
        assertEquals(
            "BYE [转发] 至5061",
            findings.getJSONObject(0)
                .getJSONArray("evidence")
                .getJSONObject(0)
                .getString("observation")
        )

        // Surrounding report fields are untouched.
        assertEquals(1, json.getJSONArray("limitations").length())
        assertEquals(1, json.getJSONArray("recommendedNextSteps").length())
    }
}
