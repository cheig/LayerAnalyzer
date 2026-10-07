package com.example.layanalyzer.ai.playbook

import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class AgentPlaybookStoreTest {
    @Test
    fun imsPlaybooksLoadWithKnownToolsAndFields() {
        val playbooks = AgentPlaybookStore.decode(playbooksJson, availableTools)

        assertEquals(12, playbooks.size)
        assertEquals(
            "ims-registration-failure",
            playbooks.first { it.matchesIntent("为什么 IMS 注册失败") }.id
        )
        assertEquals(
            "ims-one-way-audio",
            playbooks.first { it.matchesIntent("单向无声") }.id
        )
        val store = AgentPlaybookStore(
            assetLoader = { playbooksJson },
            availableTools = availableTools
        )
        assertEquals("ims-registration-failure", store.select("Analyze capture: IMS register failure").id)
    }

    @Test
    fun unsupportedRequiredFieldIsRejectedAtLoadTime() {
        val json = """
            {"schemaVersion":1,"playbooks":[{
              "id":"invalid-field","version":1,"title":"Invalid",
              "intentHints":["invalid"],"protocols":["sip"],"initialTools":["get_capture_overview"],
              "requiredFields":["sip.untrusted-field"],"checks":[],"successPath":["read"],"failureBranches":[],
              "requiredLimitations":["limited"],"outputSections":["summary"]
            }]}
        """.trimIndent()

        assertTrue(runCatching { AgentPlaybookStore.decode(json, availableTools) }.isFailure)
    }

    /**
     * SRE-EDITOR-03: the read-only whitelist accessor returns exactly the set
     * the store was constructed with, so the scenario editor's Initial tools
     * chips offer only tools a save will accept.
     */
    @Test
    fun availableToolNamesExposesTheConstructorWhitelist() {
        val store = AgentPlaybookStore(
            assetLoader = { playbooksJson },
            availableTools = availableTools
        )

        assertEquals(availableTools, store.availableToolNames)
    }

    @Test
    fun operatorOverlayAddsThresholdsWithoutRewritingTheBasePlaybook() {
        val base = AgentPlaybookStore.decode(playbooksJson, availableTools)
            .first { it.id == "ims-call-setup-delay" }
        val overlay = ScenarioRulesOverlay(
            thresholds = listOf(
                ScenarioThreshold(
                    id = "sip.call-setup.attentionmillis",
                    playbookId = "ims-call-setup-delay",
                    value = 3_000,
                    unit = "milliseconds",
                    region = "any",
                    notes = "Review signal only."
                )
            ),
            recommendedFilters = mapOf("ims-call-setup-delay" to listOf("sip.CSeq.method == \"INVITE\""))
        )

        val merged = AgentPlaybookStore.decode(playbooksJson, availableTools, overlay)
            .first { it.id == "ims-call-setup-delay" }

        assertEquals(base.initialTools, merged.initialTools)
        assertEquals(base.requiredLimitations, merged.requiredLimitations)
        assertEquals(1, merged.thresholds.size)
        assertEquals(listOf("sip.CSeq.method == \"INVITE\""), merged.recommendedFilters)
        assertTrue(merged.promptSection().contains("Review thresholds"))
        assertTrue(merged.promptSection().contains("never conclusions"))
    }

    @Test
    fun anOverlayCannotReferenceAnUnknownPlaybook() {
        val overlay = ScenarioRulesOverlay(
            recommendedFilters = mapOf("operator-injected-playbook" to listOf("tcp"))
        )

        val failure = runCatching { AgentPlaybookStore.decode(playbooksJson, availableTools, overlay) }

        assertTrue(failure.isFailure)
    }

    @Test
    fun anOverlayCannotAddToolsOrFields() {
        val overlayFields = AgentPlaybookStore.decode(
            playbooksJson,
            availableTools,
            ScenarioRulesOverlay(
                aliases = listOf(
                    ScenarioFieldAlias("sip.call_id", "sip.Call-ID", "any", "Lowercase spelling.")
                )
            )
        )

        // Aliases are carried by the package for display and query help; they
        // never widen a playbook's audited tool or field set.
        overlayFields.forEach { playbook ->
            assertTrue(playbook.initialTools.all(availableTools::contains))
            assertTrue(playbook.requiredFields.all(AgentPlaybookStore.SUPPORTED_REQUIRED_FIELDS::contains))
            assertFalse(playbook.requiredFields.contains("sip.call_id"))
        }
    }

    private companion object {
        val playbooksJson: String = TestScenarioPackages.builtInAsset(
            VersionedScenarioPackageStore.PLAYBOOKS_FILE
        )
        val availableTools = TestScenarioPackages.availableTools
    }

    // -----------------------------------------------------------------
    // SRE-MERGE-01: merging the user scenario layer into the store.
    // -----------------------------------------------------------------

    @Test
    fun withoutAUserScenarioLayerTheMergeEqualsTheBuiltInLayerAlone() {
        val store = AgentPlaybookStore(
            assetLoader = { TestScenarioPackages.MINIMAL_PLAYBOOKS },
            availableTools = availableTools
        )

        assertEquals(
            AgentPlaybookStore.decode(TestScenarioPackages.MINIMAL_PLAYBOOKS, availableTools),
            store.load()
        )
    }

    @Test
    fun userScenariosAppendAfterTheBuiltInLayerKeepingEachLayersOrder() {
        val store = AgentPlaybookStore(
            assetLoader = { TestScenarioPackages.MINIMAL_PLAYBOOKS },
            availableTools = availableTools,
            userScenarios = FakeUserScenarioStore(
                UserScenarioStore.decode(userLayerFile("user-alpha", "user-beta"), availableTools)
            )
        )

        val merged = store.load()

        assertEquals(
            listOf("general-capture-health", "user-alpha", "user-beta"),
            merged.map { it.id }
        )
        assertEquals(ScenarioOrigin.BuiltIn, merged.first().origin)
        assertEquals(
            listOf(ScenarioOrigin.User, ScenarioOrigin.User),
            merged.drop(1).map { it.origin }
        )
    }

    @Test
    fun aFailingUserLayerDegradesToEmptyAndKeepsTheBuiltInLayer() {
        val store = AgentPlaybookStore(
            assetLoader = { TestScenarioPackages.MINIMAL_PLAYBOOKS },
            availableTools = availableTools,
            userScenarios = FakeUserScenarioStore(failLoad = true)
        )

        assertEquals(
            AgentPlaybookStore.decode(TestScenarioPackages.MINIMAL_PLAYBOOKS, availableTools),
            store.load()
        )
    }

    @Test
    fun reloadRereadsTheUserLayerWhileLoadKeepsServingTheCachedMerge() {
        val fake = FakeUserScenarioStore()
        val store = AgentPlaybookStore(
            assetLoader = { TestScenarioPackages.MINIMAL_PLAYBOOKS },
            availableTools = availableTools,
            userScenarios = fake
        )

        assertEquals(listOf("general-capture-health"), store.load().map { it.id })

        // The user layer gains a scenario after the first load: load() keeps
        // serving the cached merge until reload() re-reads both layers.
        fake.save(
            UserScenarioStore.decode(userLayerFile("user-after-save"), availableTools).single()
        )

        assertEquals(listOf("general-capture-health"), store.load().map { it.id })
        assertEquals(
            listOf("general-capture-health", "user-after-save"),
            store.reload().map { it.id }
        )
        assertEquals(
            listOf("general-capture-health", "user-after-save"),
            store.load().map { it.id }
        )
    }

    /**
     * A user-layer file in the strict [UserScenarioStore] envelope holding the
     * [TestScenarioPackages.MINIMAL_PLAYBOOKS] entry re-identified into the
     * `user-` namespace, one entry per given id in file order.
     */
    private fun userLayerFile(vararg ids: String): String = JSONObject()
        .put(
            "playbooks",
            JSONArray().apply {
                ids.forEach { id ->
                    put(
                        JSONObject(TestScenarioPackages.MINIMAL_PLAYBOOKS)
                            .getJSONArray("playbooks")
                            .getJSONObject(0)
                            .put("id", id)
                    )
                }
            }
        )
        .put("schemaVersion", UserScenarioStore.USER_SCHEMA_VERSION)
        .toString()

    /**
     * Minimal in-memory [UserScenarioStore] fake for the merge tests.
     * [failLoad] turns [load] into a throwing call to pin the fail-closed
     * second line of defense at the merge boundary; the remaining members are
     * the smallest implementations the interface needs.
     */
    private class FakeUserScenarioStore(
        scenarios: List<AgentPlaybook> = emptyList(),
        private val failLoad: Boolean = false
    ) : UserScenarioStore {
        private val stored = scenarios.toMutableList()

        override fun load(): List<AgentPlaybook> {
            if (failLoad) throw IllegalStateException("corrupt user scenario layer")
            return stored.toList()
        }

        override fun save(scenario: AgentPlaybook): Map<String, ScenarioValidationError> {
            stored += scenario
            return emptyMap()
        }

        override fun delete(playbookId: String) {
            stored.removeAll { it.id == playbookId }
        }

        override fun generateScenarioId(title: String): String = "user-fake"

        override fun generateCopyId(sourceId: String): String = "user-fake-copy"
    }

    // -----------------------------------------------------------------
    // SRE-MERGE-02: explicit playbook selection for the chip path.
    // -----------------------------------------------------------------

    @Test
    fun anExplicitUserIdWinsEvenWhenTheQuestionTextWouldMatchABuiltInFirst() {
        val store = AgentPlaybookStore(
            assetLoader = { playbooksJson },
            availableTools = availableTools,
            userScenarios = FakeUserScenarioStore(
                UserScenarioStore.decode(userLayerFile("user-alpha"), availableTools)
            )
        )

        // The question text alone matches the built-in layer first, in merged
        // order, even with the user scenario present...
        assertEquals(
            "ims-registration-failure",
            store.select("Analyze capture: IMS register failure").id
        )
        // ...but the explicit chip id returns the user playbook directly.
        val selected = store.select("Analyze capture: IMS register failure", "user-alpha")
        assertEquals("user-alpha", selected.id)
        assertEquals(ScenarioOrigin.User, selected.origin)
    }

    @Test
    fun anExplicitBuiltInIdIsReturnedDirectlyAheadOfTextMatching() {
        val store = AgentPlaybookStore(
            assetLoader = { playbooksJson },
            availableTools = availableTools
        )

        assertEquals(
            "ims-registration-failure",
            store.select("Analyze capture: IMS register failure").id
        )
        // The explicit chip id wins immediately — the general playbook, which
        // the text path skips by id, is just as reachable explicitly.
        assertEquals(
            AgentPlaybook.GENERAL_CAPTURE_HEALTH_ID,
            store.select(
                "Analyze capture: IMS register failure",
                AgentPlaybook.GENERAL_CAPTURE_HEALTH_ID
            ).id
        )
    }

    @Test
    fun anUnknownExplicitIdFallsBackToQuestionTextMatching() {
        val store = AgentPlaybookStore(
            assetLoader = { playbooksJson },
            availableTools = availableTools,
            userScenarios = FakeUserScenarioStore(
                UserScenarioStore.decode(userLayerFile("user-alpha"), availableTools)
            )
        )

        // A stale id (the playbook was just deleted) degrades to the unchanged
        // text match over the merged list.
        assertEquals(
            "ims-registration-failure",
            store.select("Analyze capture: IMS register failure", "user-deleted").id
        )
        // The fallback still sees the user layer: a question no built-in
        // non-general playbook matches hits the user playbook by text.
        assertEquals(
            "user-alpha",
            store.select("Tell me about capture health", "user-deleted").id
        )
    }

    // -----------------------------------------------------------------
    // SRE-MERGE-03: defensive id-namespace filtering of the user layer.
    // -----------------------------------------------------------------

    @Test
    fun nonUserPrefixedEntriesAreFilteredOutOfTheMergedLayer() {
        // A hand-edited `user_playbooks.json` can carry ids the save gate
        // would never accept: `builtin-style` passes the pure format boundary
        // (the shared syntax pattern) but fails the merge's namespace gate.
        val drops = mutableListOf<Int>()
        val store = AgentPlaybookStore(
            assetLoader = { TestScenarioPackages.MINIMAL_PLAYBOOKS },
            availableTools = availableTools,
            userScenarios = FakeUserScenarioStore(
                UserScenarioStore.decode(userLayerFile("builtin-style", "user-alpha"), availableTools)
            ),
            // The default sink would hit android.util.Log, unavailable on the JVM.
            onUserPlaybooksFiltered = drops::add
        )

        val merged = store.load()

        assertEquals(
            listOf("general-capture-health", "user-alpha"),
            merged.map { it.id }
        )
        assertEquals(ScenarioOrigin.BuiltIn, merged.first().origin)
        assertEquals(ScenarioOrigin.User, merged.last().origin)
        assertEquals(listOf(1), drops)
    }

    @Test
    fun theFilterSinkCountsDropsAndStaysSilentWhenEveryUserEntryIsValid() {
        val drops = mutableListOf<Int>()
        val mixed = AgentPlaybookStore(
            assetLoader = { TestScenarioPackages.MINIMAL_PLAYBOOKS },
            availableTools = availableTools,
            userScenarios = FakeUserScenarioStore(
                UserScenarioStore.decode(
                    userLayerFile("builtin-style", "user-a", "user-b"), availableTools
                )
            ),
            onUserPlaybooksFiltered = drops::add
        )

        assertEquals(
            listOf("general-capture-health", "user-a", "user-b"),
            mixed.load().map { it.id }
        )
        // One call per merge carrying the drop total, not one call per entry.
        assertEquals(listOf(1), drops)

        val allValid = AgentPlaybookStore(
            assetLoader = { TestScenarioPackages.MINIMAL_PLAYBOOKS },
            availableTools = availableTools,
            userScenarios = FakeUserScenarioStore(
                UserScenarioStore.decode(userLayerFile("user-a", "user-b"), availableTools)
            ),
            onUserPlaybooksFiltered = drops::add
        )

        assertEquals(
            listOf("general-capture-health", "user-a", "user-b"),
            allValid.load().map { it.id }
        )
        // A clean load never invokes the sink — not even with a zero count —
        // which is what keeps the default sink's Log call out of JVM tests.
        assertEquals(listOf(1), drops)
    }

    @Test
    fun theFilterNeverTouchesTheBuiltInLayer() {
        val drops = mutableListOf<Int>()
        val store = AgentPlaybookStore(
            assetLoader = { playbooksJson },
            availableTools = availableTools,
            userScenarios = FakeUserScenarioStore(
                UserScenarioStore.decode(userLayerFile("builtin-style"), availableTools)
            ),
            // The default sink would hit android.util.Log, unavailable on the JVM.
            onUserPlaybooksFiltered = drops::add
        )

        val merged = store.load()

        // Built-in ids (general-capture-health included) legitimately carry no
        // `user-` prefix and are never filtered; the merge equals the built-in
        // layer exactly once the single hand-edited user entry is dropped.
        assertEquals(
            AgentPlaybookStore.decode(playbooksJson, availableTools).map { it.id },
            merged.map { it.id }
        )
        assertEquals(ScenarioOrigin.BuiltIn, merged.first().origin)
        // The count proves the filter acted on the user layer while every
        // prefix-less built-in id above survived untouched.
        assertEquals(listOf(1), drops)
    }

    // -----------------------------------------------------------------
    // SRE-MERGE-04: the real storage chain behind the merge.  The
    // fake-store tests above pin the merge boundary itself; these two run
    // the same boundary against a real filesDir-backed
    // [UserScenarioPlaybookStore] inside a [TemporaryFolder], so the save →
    // reload round trip and the corrupt-file quarantine path are exercised
    // end to end.  The clock and the quarantine sink are injected because
    // the defaults touch the wall clock and the Android log.
    // -----------------------------------------------------------------

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    /** The fixed quarantine stamp every real-store test here pins. */
    private val quarantineClockMillis = 1_234_567_890_123L

    @Test
    fun theRealUserScenarioStoreServesSavedScenariosAfterReloadAndExplicitSelection() {
        val quarantineEvents = mutableListOf<String>()
        val userStore = UserScenarioPlaybookStore(
            directory = scenarioDirectory(),
            availableTools = availableTools,
            clock = { quarantineClockMillis },
            onQuarantine = { reason -> quarantineEvents.add(reason) },
            builtInPlaybookIds = { setOf(AgentPlaybook.GENERAL_CAPTURE_HEALTH_ID) }
        )
        val store = AgentPlaybookStore(
            assetLoader = { TestScenarioPackages.MINIMAL_PLAYBOOKS },
            availableTools = availableTools,
            userScenarios = userStore
        )

        // The first load caches the built-in layer alone; the user directory
        // holds no file yet.
        assertEquals(listOf("general-capture-health"), store.load().map { it.id })

        // A real save lands user_playbooks.json on disk, yet the cached merge
        // keeps serving the old list until reload() re-reads both layers.
        assertEquals(emptyMap<String, ScenarioValidationError>(), userStore.save(userScenario()))
        assertTrue(storedUserFile().isFile)
        assertEquals(listOf("general-capture-health"), store.load().map { it.id })

        // reload() appends the saved scenario after the built-in layer, with
        // the store-assigned version and origin surviving the round trip.
        val merged = store.reload()
        assertEquals(
            listOf("general-capture-health", "user-retransmission-check"),
            merged.map { it.id }
        )
        assertEquals(ScenarioOrigin.BuiltIn, merged.first().origin)
        assertEquals(
            userScenario().copy(version = 1, origin = ScenarioOrigin.User),
            merged.last()
        )

        // The explicit chip id hits the on-disk user playbook directly...
        val selected = store.select(
            "Analyze capture: IMS register failure", "user-retransmission-check"
        )
        assertEquals("user-retransmission-check", selected.id)
        assertEquals(ScenarioOrigin.User, selected.origin)
        // ...the default text path still resolves over the merged list, and a
        // stale explicit id falls back to the text match, which reaches the
        // user layer through its intent hints.
        assertEquals("general-capture-health", store.select("capture health").id)
        assertEquals(
            "user-retransmission-check",
            store.select("Tell me about the retransmission check", "user-deleted").id
        )
        // The happy path never quarantines.
        assertTrue(quarantineEvents.isEmpty())
    }

    @Test
    fun aCorruptUserScenarioFileDegradesTheMergeToTheBuiltInLayerAndGetsQuarantined() {
        val quarantineEvents = mutableListOf<String>()
        scenarioDirectory().mkdirs()
        val corrupt = "{ not valid json"
        storedUserFile().writeText(corrupt)
        val userStore = UserScenarioPlaybookStore(
            directory = scenarioDirectory(),
            availableTools = availableTools,
            clock = { quarantineClockMillis },
            onQuarantine = { reason -> quarantineEvents.add(reason) }
        )
        val store = AgentPlaybookStore(
            assetLoader = { playbooksJson },
            availableTools = availableTools,
            userScenarios = userStore
        )

        // The user layer degrades to empty while the merged list comes out
        // exactly as the built-in package declares it, origin marks included.
        assertEquals(
            AgentPlaybookStore.decode(playbooksJson, availableTools),
            store.load()
        )

        // Both selection paths keep serving the built-in layers: the default
        // text match, an explicit built-in id, and a stale user id that falls
        // back to the text match.
        assertEquals(
            "ims-registration-failure",
            store.select("Analyze capture: IMS register failure").id
        )
        assertEquals(
            AgentPlaybook.GENERAL_CAPTURE_HEALTH_ID,
            store.select(
                "Analyze capture: IMS register failure",
                AgentPlaybook.GENERAL_CAPTURE_HEALTH_ID
            ).id
        )
        assertEquals(
            "ims-registration-failure",
            store.select("Analyze capture: IMS register failure", "user-never-saved").id
        )

        // The unreadable file was renamed aside, not deleted: one reason code
        // reached the sink and the quarantined copy keeps the data recoverable
        // by hand under the pinned test clock.
        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), quarantineEvents)
        assertFalse(storedUserFile().exists())
        assertEquals(corrupt, quarantineUserFile().readText())
    }

    private fun scenarioDirectory(): File =
        File(temporaryFolder.root, UserScenarioStore.DIRECTORY_NAME)

    private fun storedUserFile(): File =
        File(scenarioDirectory(), UserScenarioStore.FILE_NAME)

    /** The quarantine copy the store writes under the pinned test clock. */
    private fun quarantineUserFile(): File = File(
        scenarioDirectory(),
        UserScenarioStore.FILE_NAME + ".quarantine-" + quarantineClockMillis
    )

    /**
     * A caller-side user scenario draft for the real store; its version and
     * origin are store-assigned on save.  Every tool comes from the whitelist
     * and every text stays inside the user-layer declarative limits.
     */
    private fun userScenario(
        id: String = "user-retransmission-check",
        title: String = "TCP retransmission check"
    ): AgentPlaybook = AgentPlaybook(
        id = id,
        version = 42,
        title = title,
        intentHints = listOf("retransmission check"),
        protocols = listOf("tcp"),
        initialTools = listOf("get_capture_overview"),
        requiredFields = emptyList(),
        checks = listOf(
            AgentPlaybookCheck("retransmissions", "Count retransmissions", listOf("get_statistics"))
        ),
        successPath = listOf("Read the overview first"),
        failureBranches = listOf(
            AgentPlaybookFailureBranch("A query fails", emptyList(), "State the incomplete coverage.")
        ),
        requiredLimitations = listOf("Conclusions require tool evidence."),
        outputSections = listOf("summary", "limitations")
    )
}
