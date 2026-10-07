package com.example.layanalyzer.ai.playbook

import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Pins the OPT-ERR-01 contract: every validation rejection the scenario save
 * boundary can report arrives as a stable reason code — snake_case
 * `[a-z0-9_]+`, never prose with periods or spaces — keyed by the field
 * path, with the formatting payload carried only through `args`.  The tests
 * walk the rejection branches reachable from [UserScenarioStore.save] (the
 * user-layer rules, the declarative-text rules and the shared
 * [PlaybookParsing] gate), plus the format branches reachable through
 * [UserScenarioStore.decode], and pin the code shape of every produced
 * [ScenarioValidationError].
 */
class ScenarioValidationCodesTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    /** The whole-code inventory: the declared set itself is code-shaped. */
    @Test
    fun everyDeclaredCodeIsSnakeCase() {
        ScenarioValidationCodes.ALL.forEach { code ->
            assertCodeIsShapeClean(code)
        }
        assertEquals(ScenarioValidationCodes.ALL.size, ScenarioValidationCodes.ALL.distinct().size)
    }

    /** Walks several save-reachable rejection branches in one save. */
    @Test
    fun everySaveRejectionReportsACodeNotProse() {
        val store = filesStore(builtInIds = setOf("general-capture-health"))

        val errors = store.save(
            AgentPlaybook(
                id = "general-capture-health", // id_builtin_conflict wins the `id` slot
                version = 1,
                title = "x".repeat(ScenarioTextRules.USER_MAX_TITLE_LENGTH + 1), // text_too_long
                intentHints = listOf(
                    "run ```py```", // text_forbidden_content
                    "y".repeat(ScenarioTextRules.USER_MAX_HINT_LENGTH + 1) // text_too_long
                ),
                protocols = emptyList(),
                initialTools = listOf("get_capture_overview"),
                requiredFields = listOf("not.a.field"), // field_not_supported
                checks = listOf(
                    AgentPlaybookCheck(
                        "health",
                        "z".repeat(ScenarioTextRules.USER_MAX_TEXT_LENGTH + 1),
                        emptyList()
                    )
                ),
                successPath = listOf("http://example.invalid"), // text_forbidden_content
                failureBranches = emptyList(),
                requiredLimitations = emptyList(),
                outputSections = emptyList()
            )
        )

        // A multi-branch rejection lands on the paths the editor highlights.
        // (The structural gate stops at its first rejection, so the tool
        // whitelist branch gets its own save below.)
        assertEquals(
            setOf(
                "id", "title", "intentHints[0]", "intentHints[1]",
                "requiredFields", "checks[0].description", "successPath[0]"
            ),
            errors.keys
        )
        errors.forEach { (path, error) ->
            assertCodeIsShapeClean(error.code)
            assertTrue("Rejection on $path carries no prose in the code", error.code == error.code.trim())
        }
        // The codes themselves, pinned for the localization contract.
        assertEquals(ScenarioValidationCodes.ID_BUILTIN_CONFLICT, errors["id"]!!.code)
        assertEquals(ScenarioValidationCodes.TEXT_TOO_LONG, errors["title"]!!.code)
        assertEquals(ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT, errors["intentHints[0]"]!!.code)
        assertEquals(ScenarioValidationCodes.TEXT_TOO_LONG, errors["intentHints[1]"]!!.code)
        assertEquals(ScenarioValidationCodes.FIELD_NOT_SUPPORTED, errors["requiredFields"]!!.code)
        assertEquals(ScenarioValidationCodes.TEXT_TOO_LONG, errors["checks[0].description"]!!.code)
        assertEquals(ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT, errors["successPath[0]"]!!.code)
        // The formatting payload rides on args, so the code stays pure.
        assertEquals(
            ScenarioTextRules.USER_MAX_TITLE_LENGTH.toString(),
            errors["title"]!!.args["max"]
        )
        assertEquals("not.a.field", errors["requiredFields"]!!.args["field"])

        val toolErrors = store.save(
            userPlaybook().copy(initialTools = listOf("not_a_real_tool"))
        )
        assertEquals(setOf("initialTools"), toolErrors.keys)
        assertCodeIsShapeClean(toolErrors["initialTools"]!!.code)
        assertEquals(ScenarioValidationCodes.TOOL_NOT_ALLOWED, toolErrors["initialTools"]!!.code)
        assertEquals("not_a_real_tool", toolErrors["initialTools"]!!.args["tool"])
    }

    /** Branches only the structural gate sees still report codes. */
    @Test
    fun structuralGateRejectionsReportCodesToo() {
        val store = filesStore()

        // A blank title passes the user text rules and is rejected by the
        // shared boundary; the path maps back onto the editor's title field.
        val blankTitle = store.save(userPlaybook(id = "foo-bar").copy(title = "   "))
        blankTitle.values.forEach { assertCodeIsShapeClean(it.code) }
        assertEquals(ScenarioValidationCodes.ID_PREFIX_REQUIRED, blankTitle["id"]!!.code)
        assertEquals(ScenarioValidationCodes.STRING_BLANK, blankTitle["title"]!!.code)

        // `user-Foo` carries the namespace prefix yet breaks the id grammar.
        val unstableId = store.save(userPlaybook(id = "user-Foo"))
        unstableId.values.forEach { assertCodeIsShapeClean(it.code) }
        assertEquals(ScenarioValidationCodes.ID_INVALID, unstableId["id"]!!.code)

        // No whitelist injection (TestScenarioPackages.availableTools omits
        // declare_analysis_plan), so an empty tool list survives to the check.
        val noTools = store.save(userPlaybook().copy(initialTools = emptyList()))
        assertEquals(ScenarioValidationCodes.INITIAL_TOOLS_EMPTY, noTools["initialTools"]!!.code)

        val tooManySteps = store.save(
            userPlaybook().copy(successPath = List(65) { "step $it" })
        )
        assertEquals(ScenarioValidationCodes.LIST_TOO_LONG, tooManySteps["successPath"]!!.code)
        assertEquals("64", tooManySteps["successPath"]!!.args["max"])
    }

    /** The file-format boundary reports codes as well, even though only the
     *  quarantine path consumes them. */
    @Test
    fun decodeRejectionsCarryCodes() {
        val futureVersion = runCatching {
            UserScenarioStore.decode(
                JSONObject()
                    .put("schemaVersion", UserScenarioStore.USER_SCHEMA_VERSION + 98)
                    .put("playbooks", JSONArray())
                    .toString(),
                TestScenarioPackages.availableTools
            )
        }.exceptionOrNull() as PlaybookValidationException
        assertCodeIsShapeClean(futureVersion.code)
        assertEquals(ScenarioValidationCodes.SCHEMA_VERSION_UNSUPPORTED, futureVersion.code)
        assertEquals("99", futureVersion.args["version"])

        val entry = JSONObject(TestScenarioPackages.MINIMAL_PLAYBOOKS)
            .getJSONArray("playbooks")
            .getJSONObject(0)
        val duplicateIds = runCatching {
            UserScenarioStore.decode(
                JSONObject()
                    .put("schemaVersion", UserScenarioStore.USER_SCHEMA_VERSION)
                    .put("playbooks", JSONArray().put(entry).put(entry))
                    .toString(),
                TestScenarioPackages.availableTools
            )
        }.exceptionOrNull() as PlaybookValidationException
        assertCodeIsShapeClean(duplicateIds.code)
        assertEquals(ScenarioValidationCodes.DUPLICATE_IDS, duplicateIds.code)
    }

    /** The acceptance rule: a code is an identifier, not a sentence. */
    private fun assertCodeIsShapeClean(code: String) {
        assertTrue(
            "Code '$code' is not [a-z0-9_]+ shaped — map values must be codes, not prose",
            ScenarioValidationCodes.SHAPE.matches(code)
        )
        assertTrue("Code '$code' must not contain a period", !code.contains('.'))
        assertTrue("Code '$code' must not contain a space", !code.contains(' '))
    }

    private fun userPlaybook(id: String = "user-general-capture-health"): AgentPlaybook =
        AgentPlaybook(
            id = id,
            version = 1,
            title = "General capture health",
            intentHints = listOf("capture health"),
            protocols = listOf("any"),
            initialTools = listOf("get_capture_overview"),
            requiredFields = emptyList(),
            checks = listOf(AgentPlaybookCheck("health", "Read the overview", listOf("get_statistics"))),
            successPath = listOf("Read the overview first"),
            failureBranches = listOf(
                AgentPlaybookFailureBranch("A query fails", emptyList(), "State the incomplete coverage.")
            ),
            requiredLimitations = listOf("Conclusions require tool evidence."),
            outputSections = listOf("summary", "limitations")
        )

    private fun filesStore(builtInIds: Set<String> = emptySet()): UserScenarioPlaybookStore =
        UserScenarioPlaybookStore(
            File(temporaryFolder.root, UserScenarioStore.DIRECTORY_NAME),
            TestScenarioPackages.availableTools
        ) { builtInIds }
}
