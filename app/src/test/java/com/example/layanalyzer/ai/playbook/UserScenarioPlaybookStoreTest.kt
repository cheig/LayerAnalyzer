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

/**
 * Pins the SRE-STORE-01 file format contract for [UserScenarioStore]: the
 * strict envelope, the supported schema-version window, and the guarantee
 * that stored playbook objects are isomorphic to the package `playbooks.json`
 * entries and come out marked [ScenarioOrigin.User].
 *
 * The filesDir-backed [UserScenarioPlaybookStore] tests pin the SRE-STORE-02
 * persistence behavior on top: atomic rewrite, store-owned versions, and the
 * handling of unreadable files.  The SRE-STORE-03 tests pin the store-owned
 * id policy: slug and copy id minting, uniqueness against the current layer,
 * and the `user-` namespace guarantee.  The SRE-STORE-04 tests pin the
 * user-layer validation gate: every rejection comes back as a field path →
 * [ScenarioValidationError] map (stable reason code + args, never prose —
 * OPT-ERR-01), nothing reaches the disk while any field is rejected, and
 * write failures stay exceptional.  The SRE-STORE-05 tests pin the
 * quarantine of an unreadable file: it is renamed aside for hand recovery
 * with one stable reason code reported, and every path degrades to an empty
 * layer instead of throwing or blocking.  Every quarantine-triggering test
 * injects a recording sink, because the default sink touches the Android log
 * that JVM tests cannot invoke.
 */
class UserScenarioPlaybookStoreTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun userScenarioFileDecodesWithUserOrigin() {
        val playbooks = UserScenarioStore.decode(userFile(), availableTools)

        val playbook = playbooks.single()
        assertEquals("user-general-capture-health", playbook.id)
        assertEquals("General capture health", playbook.title)
        assertEquals(listOf("get_capture_overview"), playbook.initialTools)
        assertEquals(ScenarioOrigin.User, playbook.origin)
    }

    @Test
    fun highestSupportedSchemaVersionIsAccepted() {
        val playbooks = UserScenarioStore.decode(
            userFile(schemaVersion = UserScenarioStore.USER_SCHEMA_VERSION),
            availableTools
        )

        assertEquals(1, playbooks.size)
    }

    @Test
    fun schemaVersionsOutsideTheSupportedWindowAreRejected() {
        listOf(0, UserScenarioStore.USER_SCHEMA_VERSION + 1).forEach { version ->
            val failure = runCatching {
                UserScenarioStore.decode(userFile(schemaVersion = version), availableTools)
            }

            assertEquals(
                "Unsupported user scenario schema version $version.",
                failure.exceptionOrNull()!!.message
            )
        }
    }

    @Test
    fun unknownRootPropertiesAreRejected() {
        val json = JSONObject(userFile()).put("overlay", JSONObject()).toString()

        val failure = runCatching { UserScenarioStore.decode(json, availableTools) }

        assertEquals("root has unknown properties: overlay", failure.exceptionOrNull()!!.message)
    }

    @Test
    fun missingRootPropertiesAreRejected() {
        val json = JSONObject(userFile()).also { it.remove("playbooks") }.toString()

        val failure = runCatching { UserScenarioStore.decode(json, availableTools) }

        assertEquals("root is missing properties: playbooks", failure.exceptionOrNull()!!.message)
    }

    @Test
    fun emptyPlaybookListIsAccepted() {
        val playbooks = UserScenarioStore.decode(userFile(playbooks = JSONArray()), availableTools)

        assertTrue(playbooks.isEmpty())
    }

    @Test
    fun nonObjectPlaybookEntriesAreRejected() {
        val failure = runCatching {
            UserScenarioStore.decode(
                userFile(playbooks = JSONArray().put("general-capture-health")),
                availableTools
            )
        }

        assertEquals("playbooks[0] must be an object.", failure.exceptionOrNull()!!.message)
    }

    @Test
    fun duplicatePlaybookIdsAreRejected() {
        val entries = JSONArray().put(playbookEntry()).put(playbookEntry())

        val failure = runCatching {
            UserScenarioStore.decode(userFile(playbooks = entries), availableTools)
        }

        assertEquals("Playbook ids must be unique.", failure.exceptionOrNull()!!.message)
    }

    @Test
    fun playbookEntriesFollowThePackagePlaybookShape() {
        // Overlay extras and the store-assigned origin are structural unknowns:
        // stored content can never carry them, at any layer.
        val overlayExtra = JSONArray().put(playbookEntry().put("thresholds", JSONArray()))
        val missingTitle = JSONArray().put(playbookEntry().also { it.remove("title") })

        runCatching { UserScenarioStore.decode(userFile(playbooks = overlayExtra), availableTools) }
            .exceptionOrNull()!!.let { failure ->
                assertEquals("playbooks[0] has unknown properties: thresholds", failure.message)
            }
        runCatching { UserScenarioStore.decode(userFile(playbooks = missingTitle), availableTools) }
            .exceptionOrNull()!!.let { failure ->
                assertEquals("playbooks[0] is missing properties: title", failure.message)
            }
    }

    @Test
    fun playbookEntriesReuseTheSharedValidationBoundary() {
        val failure = runCatching {
            UserScenarioStore.decode(
                userFile(playbooks = JSONArray().put(playbookEntry().put("version", 0))),
                availableTools
            )
        }

        assertEquals("playbooks[0].version must be positive.", failure.exceptionOrNull()!!.message)
    }

    private fun userFile(
        schemaVersion: Int = UserScenarioStore.USER_SCHEMA_VERSION,
        playbooks: JSONArray = JSONArray().put(playbookEntry())
    ): String = JSONObject()
        .put("schemaVersion", schemaVersion)
        .put("playbooks", playbooks)
        .toString()

    private fun playbookEntry(): JSONObject =
        JSONObject(TestScenarioPackages.MINIMAL_PLAYBOOKS)
            .getJSONArray("playbooks")
            .getJSONObject(0)
            .put("id", "user-general-capture-health")

    private companion object {
        val availableTools = TestScenarioPackages.availableTools

        /** The fixed quarantine stamp every SRE-STORE-05 test pins. */
        const val QUARANTINE_CLOCK_MILLIS = 1_234_567_890_123L
    }

    // -----------------------------------------------------------------
    // SRE-STORE-02: the filesDir-backed implementation.
    // -----------------------------------------------------------------

    @Test
    fun savePersistsAndLoadsBackRoundTrip() {
        val store = filesStore()

        assertEquals(emptyMap<String, ScenarioValidationError>(), store.save(userPlaybook()))

        assertEquals(
            userPlaybook().copy(version = 1, origin = ScenarioOrigin.User),
            store.load().single()
        )
    }

    @Test
    fun storedFileKeepsTheStrictEnvelopeWithoutStoreAssignedFields() {
        val store = filesStore()
        val draft = userPlaybook().copy(
            thresholds = listOf(
                ScenarioThreshold(
                    id = "capture.health.percent",
                    playbookId = "user-general-capture-health",
                    value = 5L,
                    unit = "percent",
                    region = "any",
                    notes = "Review signal only."
                )
            ),
            recommendedFilters = listOf("tcp.port == 5060")
        )

        store.save(draft)

        val raw = storedFile().readText()
        // The envelope survives its own decode boundary, and the store-assigned
        // origin plus the overlay extras never reach the file.
        assertEquals(1, UserScenarioStore.decode(raw, availableTools).size)
        assertFalse(raw.contains("\"origin\""))
        assertFalse(raw.contains("\"thresholds\""))
        assertFalse(raw.contains("\"recommendedFilters\""))
        assertTrue(store.load().single().thresholds.isEmpty())
        assertTrue(store.load().single().recommendedFilters.isEmpty())
    }

    @Test
    fun firstSaveStoresVersionOneAndEveryLaterSaveIncrementsIt() {
        val store = filesStore()

        store.save(userPlaybook(version = 42))
        assertEquals(1, store.load().single().version)

        store.save(userPlaybook(version = 42, title = "Renamed health"))
        assertEquals(2, store.load().single().version)

        store.save(userPlaybook(version = 42, title = "Renamed again"))
        assertEquals(3, store.load().single().version)
    }

    @Test
    fun saveReplacesAnExistingIdInPlaceAndAppendsNewIds() {
        val store = filesStore()

        store.save(userPlaybook(id = "user-first"))
        store.save(userPlaybook(id = "user-second"))
        store.save(userPlaybook(id = "user-first", title = "First, edited"))

        val loaded = store.load()
        assertEquals(listOf("user-first", "user-second"), loaded.map { it.id })
        assertEquals("First, edited", loaded.first().title)
        assertEquals(2, loaded.first().version)
        assertEquals(1, loaded.last().version)
    }

    @Test
    fun deleteRemovesOnlyTheTargetScenario() {
        val store = filesStore()
        store.save(userPlaybook(id = "user-first"))
        store.save(userPlaybook(id = "user-second"))

        store.delete("user-first")

        assertEquals(listOf("user-second"), store.load().map { it.id })
    }

    @Test
    fun deleteOfAnUnknownIdWritesNothing() {
        val store = filesStore()
        store.save(userPlaybook())

        store.delete("user-never-saved")

        assertEquals(1, store.load().size)
    }

    @Test
    fun deleteBeforeTheFirstSaveCreatesNoFile() {
        filesStore().delete("user-never-saved")

        assertFalse(storedFile().exists())
    }

    @Test
    fun loadWithoutAFileIsEmpty() {
        val store = filesStore()

        assertTrue(store.load().isEmpty())
        assertFalse(storedFile().exists())
    }

    @Test
    fun anUnreadableFileDegradesToAnEmptyLayerAndStaysRecoverable() {
        val events = mutableListOf<String>()
        scenarioDirectory().mkdirs()
        val corrupt = "{ not json"
        storedFile().writeText(corrupt)
        val store = quarantiningStore(events)

        assertTrue(store.load().isEmpty())

        // The unreadable file is renamed aside, not deleted: the quarantined
        // copy keeps the data recoverable by hand and the layer continues
        // empty, so the built-in layers keep working.
        assertFalse(storedFile().exists())
        assertEquals(corrupt, quarantineFile().readText())
        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), events)
    }

    @Test
    fun aFailedWriteKeepsThePreviousFile() {
        val store = filesStore()
        store.save(userPlaybook())
        // Occupying the temporary-file path makes the next write fail after
        // the payload was validated — the mid-write window the atomic rename
        // is supposed to cover.
        File(scenarioDirectory(), UserScenarioStore.FILE_NAME + ".tmp").mkdirs()

        val failure = runCatching { store.save(userPlaybook(id = "user-second")) }

        assertTrue(failure.isFailure)
        assertEquals(listOf("user-general-capture-health"), store.load().map { it.id })
    }

    @Test
    fun contentRejectedByTheStoredBoundaryIsNeverPersisted() {
        val store = filesStore()
        store.save(userPlaybook())

        val errors = store.save(userPlaybook(id = "user-second", initialTools = listOf("not_a_real_tool")))

        assertTrue(errors.containsKey("initialTools"))
        assertEquals(
            ScenarioValidationError(
                ScenarioValidationCodes.TOOL_NOT_ALLOWED,
                mapOf("tool" to "not_a_real_tool")
            ),
            errors["initialTools"]
        )
        assertEquals(listOf("user-general-capture-health"), store.load().map { it.id })
    }

    // -----------------------------------------------------------------
    // SRE-STORE-03: the store-owned id policy.
    // -----------------------------------------------------------------

    @Test
    fun scenarioIdSlugsAnAsciiTitle() {
        val store = filesStore()

        assertEquals("user-my-rtp-check", store.generateScenarioId("My RTP Check!"))
        assertEquals("user-voip-qos-95-audio", store.generateScenarioId("VoIP  QoS: 95% (audio)"))
    }

    @Test
    fun aLongTitleTruncatesTheSlugToFiftyCharacters() {
        val store = filesStore()

        assertEquals("user-" + "x".repeat(50), store.generateScenarioId("x".repeat(60)))
        // A cut landing on a separator re-trims the trailing separator.
        assertEquals(
            "user-" + "a".repeat(49),
            store.generateScenarioId("a".repeat(49) + " b")
        )
    }

    @Test
    fun scenarioIdAppendsANumberWhenTheSlugIsTaken() {
        val store = filesStore()

        val first = store.generateScenarioId("My RTP Check")
        store.save(userPlaybook(id = first))
        val second = store.generateScenarioId("My RTP Check")

        assertEquals("user-my-rtp-check", first)
        assertEquals("user-my-rtp-check-2", second)
    }

    @Test
    fun aNonAsciiTitleFallsBackToANumberedScenarioId() {
        val store = filesStore()

        // Any non-ASCII character sends the whole title to the fallback; a
        // mixed title is not partially slugged.
        assertEquals("user-scenario-1", store.generateScenarioId("抓包健康检查"))
        assertEquals("user-scenario-1", store.generateScenarioId("RTP 检查"))

        val first = store.generateScenarioId("抓包健康检查")
        store.save(userPlaybook(id = first))
        val second = store.generateScenarioId("语音质量排查")

        assertEquals("user-scenario-1", first)
        assertEquals("user-scenario-2", second)
    }

    @Test
    fun aBlankTitleFallsBackToANumberedScenarioId() {
        val store = filesStore()

        assertEquals("user-scenario-1", store.generateScenarioId("   "))
        assertEquals("user-scenario-1", store.generateScenarioId(""))
    }

    @Test
    fun copyIdWrapsABuiltInIdInTheUserNamespace() {
        val store = filesStore()

        assertEquals(
            "user-general-capture-health-copy",
            store.generateCopyId("general-capture-health")
        )
    }

    @Test
    fun copyIdDoesNotStackTheUserPrefix() {
        val store = filesStore()

        assertEquals("user-my-rtp-check-copy", store.generateCopyId("user-my-rtp-check"))
    }

    @Test
    fun copyIdAppendsANumberWhenTheCopyIdIsTaken() {
        val store = filesStore()
        store.save(userPlaybook(id = "user-my-rtp-check"))

        assertEquals("user-my-rtp-check-copy", store.generateCopyId("user-my-rtp-check"))

        store.save(userPlaybook(id = "user-my-rtp-check-copy"))

        assertEquals("user-my-rtp-check-copy-2", store.generateCopyId("user-my-rtp-check"))
    }

    @Test
    fun aDegenerateOrIllegalCopySourceFallsBackToANumberedScenarioId() {
        val store = filesStore()

        assertEquals("user-scenario-1", store.generateCopyId("user"))
        assertEquals("user-scenario-1", store.generateCopyId("user-"))
        assertEquals("user-scenario-1", store.generateCopyId("user-my_rtp"))
        assertEquals("user-scenario-1", store.generateCopyId(""))
    }

    @Test
    fun everyGeneratedIdStaysInsideTheUserNamespace() {
        val store = filesStore()
        val titles = listOf(
            "My RTP Check!", "VoIP  QoS: 95% (audio)", "TCP retransmission???",
            "123 456", "a", "x".repeat(80), "Ünïcode", "RTP 检查", "   ", ""
        )

        titles.forEach { title ->
            val id = store.generateScenarioId(title)
            assertTrue("Unexpected id '$id' for title '$title'", id.startsWith("user-"))
            assertTrue(id.matches(PlaybookParsing.ID_PATTERN))
        }
    }

    // -----------------------------------------------------------------
    // SRE-STORE-04: user-layer validation with field error mapping.
    // -----------------------------------------------------------------

    @Test
    fun saveRejectsAnIdWithoutTheUserPrefixAndWritesNothing() {
        val store = filesStore()

        val errors = store.save(userPlaybook(id = "foo-bar"))

        assertEquals(setOf("id"), errors.keys)
        assertEquals(
            ScenarioValidationError(ScenarioValidationCodes.ID_PREFIX_REQUIRED),
            errors["id"]
        )
        assertTrue(store.load().isEmpty())
        assertFalse(storedFile().exists())
    }

    @Test
    fun saveRejectsAnIdThatConflictsWithABuiltInPlaybook() {
        val store = UserScenarioPlaybookStore(scenarioDirectory(), availableTools) {
            setOf("general-capture-health")
        }

        val errors = store.save(userPlaybook(id = "general-capture-health"))

        assertEquals(setOf("id"), errors.keys)
        // The built-in conflict is the more specific rejection on the shared
        // `id` slot (OPT-ERR-01): a stable code, not the namespace message.
        assertEquals(
            ScenarioValidationError(ScenarioValidationCodes.ID_BUILTIN_CONFLICT),
            errors["id"]
        )
        assertFalse(storedFile().exists())
    }

    @Test
    fun saveRejectsScenarioWithoutIntentHints() {
        val store = filesStore()

        val errors = store.save(userPlaybook().copy(intentHints = emptyList()))

        assertEquals(setOf("intentHints"), errors.keys)
        assertEquals(
            ScenarioValidationError(ScenarioValidationCodes.INTENT_HINTS_REQUIRED),
            errors["intentHints"]
        )
        assertFalse(storedFile().exists())
    }

    @Test
    fun saveRejectsAnOverlongTitle() {
        val store = filesStore()

        val errors = store.save(
            userPlaybook(title = "x".repeat(ScenarioTextRules.USER_MAX_TITLE_LENGTH + 1))
        )

        assertEquals(setOf("title"), errors.keys)
        assertEquals(
            ScenarioValidationError(
                ScenarioValidationCodes.TEXT_TOO_LONG,
                mapOf("max" to ScenarioTextRules.USER_MAX_TITLE_LENGTH.toString())
            ),
            errors["title"]
        )
        assertFalse(storedFile().exists())
    }

    @Test
    fun saveRejectsAnOverlongIntentHint() {
        val store = filesStore()

        val errors = store.save(
            userPlaybook().copy(intentHints = listOf("x".repeat(ScenarioTextRules.USER_MAX_HINT_LENGTH + 1)))
        )

        assertEquals(setOf("intentHints[0]"), errors.keys)
        assertEquals(
            ScenarioValidationError(
                ScenarioValidationCodes.TEXT_TOO_LONG,
                mapOf("max" to ScenarioTextRules.USER_MAX_HINT_LENGTH.toString())
            ),
            errors["intentHints[0]"]
        )
        assertFalse(storedFile().exists())
    }

    @Test
    fun saveRejectsOverlongFreeTextAtTheUserLimit() {
        val store = filesStore()
        val longText = "x".repeat(ScenarioTextRules.USER_MAX_TEXT_LENGTH + 1)

        val errors = store.save(
            userPlaybook().copy(
                checks = listOf(AgentPlaybookCheck("health", longText, listOf("get_statistics"))),
                successPath = listOf(longText),
                failureBranches = listOf(AgentPlaybookFailureBranch(longText, emptyList(), longText)),
                requiredLimitations = listOf(longText),
                outputSections = listOf(longText)
            )
        )

        assertEquals(
            setOf(
                "checks[0].description", "successPath[0]", "failureBranches[0].condition",
                "failureBranches[0].limitation", "requiredLimitations[0]", "outputSections[0]"
            ),
            errors.keys
        )
        // Every over-long path carries the same code with its own limit arg.
        val expectedTextTooLong = ScenarioValidationError(
            ScenarioValidationCodes.TEXT_TOO_LONG,
            mapOf("max" to ScenarioTextRules.USER_MAX_TEXT_LENGTH.toString())
        )
        errors.forEach { (path, error) ->
            assertEquals("Unexpected error on $path", expectedTextTooLong, error)
        }
        assertFalse(storedFile().exists())
    }

    @Test
    fun saveRejectsUrlsInFreeTextFields() {
        val store = filesStore()

        val errors = store.save(
            userPlaybook().copy(
                title = "See http://example.com",
                checks = listOf(
                    AgentPlaybookCheck("health", "Visit https://example.com", listOf("get_statistics"))
                ),
                requiredLimitations = listOf("Details at http://example.invalid")
            )
        )

        assertTrue(errors.containsKey("title"))
        assertTrue(errors.containsKey("checks[0].description"))
        assertTrue(errors.containsKey("requiredLimitations[0]"))
        val forbidden = ScenarioValidationError(ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT)
        assertEquals(forbidden, errors["title"])
        assertEquals(forbidden, errors["checks[0].description"])
        assertEquals(forbidden, errors["requiredLimitations[0]"])
        assertFalse(storedFile().exists())
    }

    @Test
    fun saveRejectsExecutableLookingFreeText() {
        val store = filesStore()

        val errors = store.save(
            userPlaybook().copy(
                intentHints = listOf("run ```py"),
                successPath = listOf("eval(payload)"),
                failureBranches = listOf(AgentPlaybookFailureBranch("<script>", emptyList(), "State the gap."))
            )
        )

        assertTrue(errors.containsKey("intentHints[0]"))
        assertTrue(errors.containsKey("successPath[0]"))
        assertTrue(errors.containsKey("failureBranches[0].condition"))
        val forbidden = ScenarioValidationError(ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT)
        assertEquals(forbidden, errors["intentHints[0]"])
        assertEquals(forbidden, errors["successPath[0]"])
        assertEquals(forbidden, errors["failureBranches[0].condition"])
        assertFalse(storedFile().exists())
    }

    @Test
    fun saveMapsAnUnknownCheckToolToTheCheckPath() {
        val store = filesStore()

        val errors = store.save(
            userPlaybook().copy(
                checks = listOf(AgentPlaybookCheck("health", "Read the overview", listOf("not_a_real_tool")))
            )
        )

        assertEquals(setOf("checks[0].recommendedTools"), errors.keys)
        assertEquals(
            ScenarioValidationError(
                ScenarioValidationCodes.TOOL_NOT_ALLOWED,
                mapOf("tool" to "not_a_real_tool")
            ),
            errors["checks[0].recommendedTools"]
        )
        assertFalse(storedFile().exists())
    }

    @Test
    fun saveRejectsRequiredFieldsOutsideTheFieldTable() {
        val store = filesStore()

        val errors = store.save(userPlaybook().copy(requiredFields = listOf("not.a.field")))

        assertEquals(setOf("requiredFields"), errors.keys)
        assertEquals(
            ScenarioValidationError(
                ScenarioValidationCodes.FIELD_NOT_SUPPORTED,
                mapOf("field" to "not.a.field")
            ),
            errors["requiredFields"]
        )
        assertFalse(storedFile().exists())
    }

    @Test
    fun saveRejectsTooManyRequiredFields() {
        val store = filesStore()

        val errors = store.save(userPlaybook().copy(requiredFields = List(33) { "tcp.stream" }))

        assertEquals(setOf("requiredFields"), errors.keys)
        assertEquals(
            ScenarioValidationError(
                ScenarioValidationCodes.REQUIRED_FIELDS_CAP,
                mapOf("max" to AgentPlaybookStore.MAX_REQUIRED_FIELDS.toString())
            ),
            errors["requiredFields"]
        )
        assertFalse(storedFile().exists())
    }

    @Test
    fun saveCollectsEveryRejectionAtOnce() {
        val store = filesStore()

        val errors = store.save(
            userPlaybook(id = "foo-bar", initialTools = listOf("not_a_real_tool"))
                .copy(intentHints = emptyList())
        )

        assertEquals(setOf("id", "intentHints", "initialTools"), errors.keys)
        // Every slot holds its stable code (OPT-ERR-01): namespace on `id`,
        // the user-layer hint rule, and the whitelist gate on `initialTools`.
        assertEquals(ScenarioValidationError(ScenarioValidationCodes.ID_PREFIX_REQUIRED), errors["id"])
        assertEquals(
            ScenarioValidationError(ScenarioValidationCodes.INTENT_HINTS_REQUIRED),
            errors["intentHints"]
        )
        assertEquals(
            ScenarioValidationError(
                ScenarioValidationCodes.TOOL_NOT_ALLOWED,
                mapOf("tool" to "not_a_real_tool")
            ),
            errors["initialTools"]
        )
        assertFalse(storedFile().exists())
    }

    @Test
    fun aRejectedSaveKeepsTheStoredContentAndTheRawFile() {
        val store = filesStore()
        store.save(userPlaybook())
        val before = storedFile().readText()

        val errors = store.save(userPlaybook(id = "user-second").copy(title = "x".repeat(81)))

        assertTrue(errors.containsKey("title"))
        assertEquals(before, storedFile().readText())
        assertEquals(listOf("user-general-capture-health"), store.load().map { it.id })
    }

    // -----------------------------------------------------------------
    // SRE-STORE-05: quarantine of an unreadable file with empty-layer
    // fallback.  Every test here injects a fixed clock and a recording
    // reason-code sink, because the default sink touches the Android log.
    // -----------------------------------------------------------------

    @Test
    fun aCorruptFileIsQuarantinedAndTheLayerContinuesEmpty() {
        val events = mutableListOf<String>()
        scenarioDirectory().mkdirs()
        val corrupt = "{ not json"
        storedFile().writeText(corrupt)
        val store = quarantiningStore(events)

        assertTrue(store.load().isEmpty())

        assertFalse(storedFile().exists())
        assertEquals(corrupt, quarantineFile().readText())
        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), events)
    }

    @Test
    fun aFileWrittenByANewerSchemaVersionIsQuarantinedToo() {
        val events = mutableListOf<String>()
        scenarioDirectory().mkdirs()
        val future = JSONObject()
            .put("schemaVersion", UserScenarioStore.USER_SCHEMA_VERSION + 1)
            .put("playbooks", JSONArray())
            .toString()
        storedFile().writeText(future)
        val store = quarantiningStore(events)

        assertTrue(store.load().isEmpty())

        assertFalse(storedFile().exists())
        assertEquals(future, quarantineFile().readText())
        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), events)
    }

    @Test
    fun aHandEditedFileWithAnUnknownPropertyIsQuarantinedToo() {
        val events = mutableListOf<String>()
        scenarioDirectory().mkdirs()
        val edited = JSONObject(userFile()).put("overlay", JSONObject()).toString()
        storedFile().writeText(edited)
        val store = quarantiningStore(events)

        assertTrue(store.load().isEmpty())

        assertFalse(storedFile().exists())
        assertEquals(edited, quarantineFile().readText())
        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), events)
    }

    @Test
    fun aRestartAfterQuarantineStaysEmptyWithoutASecondQuarantine() {
        val events = mutableListOf<String>()
        scenarioDirectory().mkdirs()
        storedFile().writeText("{ not json")
        val first = quarantiningStore(events)
        assertTrue(first.load().isEmpty())
        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), events)

        // A later start finds no user file at all: nothing to quarantine
        // again, no new event, no second quarantine copy.
        val restarted = quarantiningStore(events)
        assertTrue(restarted.load().isEmpty())

        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), events)
        assertEquals(
            listOf(quarantineFile().name),
            scenarioDirectory().listFiles()!!.map { it.name }
        )
    }

    @Test
    fun saveAfterQuarantineWritesAFreshLayerThatLoadsBack() {
        val events = mutableListOf<String>()
        scenarioDirectory().mkdirs()
        storedFile().writeText("{ not json")
        val store = quarantiningStore(events)

        assertEquals(emptyMap<String, ScenarioValidationError>(), store.save(userPlaybook(id = "user-after-quarantine")))

        val loaded = store.load()
        assertEquals(listOf("user-after-quarantine"), loaded.map { it.id })
        assertEquals(1, loaded.single().version)
        assertTrue(quarantineFile().isFile)
        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), events)
    }

    @Test
    fun deleteAfterQuarantineIsANoOpThatWritesNothing() {
        val events = mutableListOf<String>()
        scenarioDirectory().mkdirs()
        val corrupt = "{ not json"
        storedFile().writeText(corrupt)
        val store = quarantiningStore(events)

        store.delete("user-general-capture-health")

        assertFalse(storedFile().exists())
        assertEquals(corrupt, quarantineFile().readText())
        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), events)
    }

    @Test
    fun aTakenQuarantineNameFallsBackToANumberedSuffix() {
        val events = mutableListOf<String>()
        scenarioDirectory().mkdirs()
        storedFile().writeText("{ not json")
        quarantineFile().writeText("an earlier quarantine in the same millisecond")

        val store = quarantiningStore(events)
        assertTrue(store.load().isEmpty())

        assertFalse(storedFile().exists())
        assertEquals("an earlier quarantine in the same millisecond", quarantineFile().readText())
        assertEquals("{ not json", quarantineFile("-2").readText())
        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), events)
    }

    @Test
    fun aBlockedRenameLeavesTheOriginalFileInPlace() {
        val events = mutableListOf<String>()
        scenarioDirectory().mkdirs()
        val corrupt = "{ not json"
        storedFile().writeText(corrupt)
        // A directory occupying the target name blocks the rename; the
        // original file must never be dropped in that case.
        quarantineFile().mkdirs()

        val store = quarantiningStore(events)
        assertTrue(store.load().isEmpty())

        assertTrue(storedFile().isFile)
        assertEquals(corrupt, storedFile().readText())
        assertEquals(listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED), events)
    }

    private fun scenarioDirectory(): File = File(temporaryFolder.root, UserScenarioStore.DIRECTORY_NAME)

    private fun storedFile(): File = File(scenarioDirectory(), UserScenarioStore.FILE_NAME)

    /** A store whose quarantine stamp and reason-code sink are test-controlled. */
    private fun quarantiningStore(events: MutableList<String>): UserScenarioPlaybookStore =
        UserScenarioPlaybookStore(
            directory = scenarioDirectory(),
            availableTools = availableTools,
            clock = { QUARANTINE_CLOCK_MILLIS },
            onQuarantine = { reason -> events.add(reason) }
        )

    /** The quarantine copy the store writes under the fixed test clock. */
    private fun quarantineFile(suffix: String = ""): File = File(
        scenarioDirectory(),
        UserScenarioStore.FILE_NAME + ".quarantine-" + QUARANTINE_CLOCK_MILLIS + suffix
    )

    /** A fresh store whose directory does not exist yet; the store creates it. */
    private fun filesStore(): UserScenarioPlaybookStore =
        UserScenarioPlaybookStore(scenarioDirectory(), availableTools)

    /** A caller-side draft; its version and origin are ignored by the store. */
    private fun userPlaybook(
        id: String = "user-general-capture-health",
        title: String = "General capture health",
        version: Int = 42,
        initialTools: List<String> = listOf("get_capture_overview")
    ): AgentPlaybook = AgentPlaybook(
        id = id,
        version = version,
        title = title,
        intentHints = listOf("capture health"),
        protocols = listOf("any"),
        initialTools = initialTools,
        requiredFields = emptyList(),
        checks = listOf(AgentPlaybookCheck("health", "Read the overview", listOf("get_statistics"))),
        successPath = listOf("Read the overview first"),
        failureBranches = listOf(
            AgentPlaybookFailureBranch("A query fails", emptyList(), "State the incomplete coverage.")
        ),
        requiredLimitations = listOf("Conclusions require tool evidence."),
        outputSections = listOf("summary", "limitations")
    )
}
