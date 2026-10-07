package com.example.layanalyzer.ai.playbook

import org.junit.Assert.assertEquals
import org.junit.Test

class PlaybookUsageStoreTest {
    @Test
    fun recordAccumulatesPerPlaybookCounts() {
        val store = InMemoryPlaybookUsageStore()

        store.record("ims-one-way-audio")
        store.record("ims-registration-failure")
        store.record("ims-one-way-audio")

        assertEquals(
            mapOf("ims-one-way-audio" to 2, "ims-registration-failure" to 1),
            store.usage.value
        )
    }

    @Test
    fun blankPlaybookIdIsIgnored() {
        val store = InMemoryPlaybookUsageStore()

        store.record("   ")

        assertEquals(emptyMap<String, Int>(), store.usage.value)
    }

    @Test
    fun clearRemovesOnlyTheTargetedPlaybooksCount() {
        val store = InMemoryPlaybookUsageStore()
        store.record("ims-one-way-audio")
        store.record("ims-registration-failure")

        store.clear("ims-one-way-audio")

        assertEquals(mapOf("ims-registration-failure" to 1), store.usage.value)
    }

    @Test
    fun clearOfAnUnknownIdIsANoOp() {
        val store = InMemoryPlaybookUsageStore()
        store.record("ims-one-way-audio")

        store.clear("user-never-recorded")

        assertEquals(mapOf("ims-one-way-audio" to 1), store.usage.value)
    }

    @Test
    fun clearAcceptsABlankIdWithoutPublishing() {
        val store = InMemoryPlaybookUsageStore()
        store.record("ims-one-way-audio")

        store.clear("   ")

        assertEquals(mapOf("ims-one-way-audio" to 1), store.usage.value)
    }

    @Test
    fun mostUsedScenariosSortFirstAndTiesKeepPackageOrder() {
        val playbooks = listOf(
            playbook("first"),
            playbook("second"),
            playbook("third"),
            playbook("fourth")
        )

        val sorted = playbooks.sortedByUsage(
            mapOf("third" to 5, "first" to 1, "second" to 1)
        )

        assertEquals(
            listOf("third", "first", "second", "fourth"),
            sorted.map { it.id }
        )
    }

    @Test
    fun withoutUsageThePackageOrderIsPreserved() {
        val playbooks = listOf(playbook("a"), playbook("b"), playbook("c"))

        assertEquals(playbooks, playbooks.sortedByUsage(emptyMap()))
    }

    private fun playbook(id: String): AgentPlaybook =
        AgentPlaybook.generalCaptureHealth().copy(id = id, title = id)
}
