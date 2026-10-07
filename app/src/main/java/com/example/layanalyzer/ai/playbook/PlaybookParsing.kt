package com.example.layanalyzer.ai.playbook

import com.example.layanalyzer.ai.tools.DeclareAnalysisPlanTool

/**
 * Shared playbook parsing and validation rules, used by verified scenario
 * package decoding ([AgentPlaybookStore.decode]) and user-authored scenario
 * saves alike.
 *
 * This is the single validation boundary for one playbook object: exact JSON
 * keys, stable id and positive version rules, the host tool whitelist, the
 * audited [AgentPlaybookStore.SUPPORTED_REQUIRED_FIELDS] field table, the
 * [AgentPlaybookStore.MAX_REQUIRED_FIELDS] cap, and non-empty initial tools.
 * Every layer that wants playbook content must go through here, so the user
 * layer cannot widen what scenario packages could not.
 *
 * Every rejection throws [PlaybookValidationException] carrying the rejected
 * [context]-anchored path, a stable [ScenarioValidationCodes] reason code,
 * and any message args (OPT-ERR-01); the shared JSON key/type helpers this
 * boundary calls do the same.  The English message stays verbatim for logs
 * and message-pinning tests; the user scenario save path consumes the code
 * and path instead of parsing the message.  No rule here is relaxed — only
 * the representation of a rejection changed.
 */
internal object PlaybookParsing {

    /**
     * Parse and validate one playbook object.  [context] names the location in
     * error messages (for example `playbooks[3]`) so callers keep their own
     * path in every rejection.
     */
    fun parsePlaybook(
        value: org.json.JSONObject,
        availableTools: Set<String>,
        context: String
    ): AgentPlaybook {
        requireExactKeys(
            value,
            setOf(
                "id", "version", "title", "intentHints", "protocols", "initialTools",
                "requiredFields", "checks", "successPath", "failureBranches",
                "requiredLimitations", "outputSections"
            ),
            context
        )
        val id = value.requiredString("id", context)
        if (!ID_PATTERN.matches(id)) {
            throw PlaybookValidationException(
                path = "$context.id",
                code = ScenarioValidationCodes.ID_INVALID,
                errorMessage = "$context.id is not a stable id."
            )
        }
        val playbook = AgentPlaybook(
            id = id,
            version = value.requiredInt("version", context).also {
                if (it <= 0) {
                    throw PlaybookValidationException(
                        path = "$context.version",
                        code = ScenarioValidationCodes.VERSION_NOT_POSITIVE,
                        errorMessage = "$context.version must be positive."
                    )
                }
            },
            title = value.requiredString("title", context),
            intentHints = value.stringList("intentHints", context),
            protocols = value.stringList("protocols", context),
            initialTools = buildList {
                if (DeclareAnalysisPlanTool.NAME in availableTools) {
                    add(DeclareAnalysisPlanTool.NAME)
                }
                addAll(value.stringList("initialTools", context))
            }.distinct(),
            requiredFields = value.stringList("requiredFields", context),
            checks = value.checks(context),
            successPath = value.stringList("successPath", context),
            failureBranches = value.branches(context),
            requiredLimitations = value.stringList("requiredLimitations", context),
            outputSections = value.stringList("outputSections", context)
        )
        if (playbook.requiredFields.size > AgentPlaybookStore.MAX_REQUIRED_FIELDS) {
            throw PlaybookValidationException(
                path = "$context.requiredFields",
                code = ScenarioValidationCodes.REQUIRED_FIELDS_CAP,
                args = mapOf("max" to AgentPlaybookStore.MAX_REQUIRED_FIELDS.toString()),
                errorMessage = "$context.requiredFields exceeds ${AgentPlaybookStore.MAX_REQUIRED_FIELDS} fields."
            )
        }
        validateFields(playbook.requiredFields, "$context.requiredFields")
        if (playbook.initialTools.isEmpty()) {
            throw PlaybookValidationException(
                path = "$context.initialTools",
                code = ScenarioValidationCodes.INITIAL_TOOLS_EMPTY,
                errorMessage = "$context.initialTools must not be empty."
            )
        }
        validateTools(playbook.initialTools, availableTools, "$context.initialTools")
        playbook.checks.forEachIndexed { checkIndex, check ->
            validateTools(check.recommendedTools, availableTools, "$context.checks[$checkIndex].recommendedTools")
        }
        playbook.failureBranches.forEachIndexed { branchIndex, branch ->
            validateTools(branch.recommendedTools, availableTools, "$context.failureBranches[$branchIndex].recommendedTools")
        }
        return playbook
    }

    private fun validateTools(tools: List<String>, available: Set<String>, path: String) {
        val unknown = tools.filterNot(available::contains)
        if (unknown.isNotEmpty()) {
            throw PlaybookValidationException(
                path = path,
                code = ScenarioValidationCodes.TOOL_NOT_ALLOWED,
                // Arg names the first rejected tool; the message lists them all.
                args = mapOf("tool" to unknown.first()),
                errorMessage = "$path references unavailable tools: ${unknown.joinToString()}"
            )
        }
    }

    private fun validateFields(fields: List<String>, path: String) {
        val unknown = fields.filterNot(AgentPlaybookStore.SUPPORTED_REQUIRED_FIELDS::contains)
        if (unknown.isNotEmpty()) {
            throw PlaybookValidationException(
                path = path,
                code = ScenarioValidationCodes.FIELD_NOT_SUPPORTED,
                // Arg names the first rejected field; the message lists them all.
                args = mapOf("field" to unknown.first()),
                errorMessage = "$path references unsupported fields: ${unknown.joinToString()}"
            )
        }
    }

    private fun org.json.JSONObject.checks(context: String): List<AgentPlaybookCheck> =
        requiredArray("checks", context).objects("$context.checks") { item, itemPath ->
            requireExactKeys(item, setOf("id", "description", "recommendedTools"), itemPath)
            AgentPlaybookCheck(
                id = item.requiredString("id", itemPath),
                description = item.requiredString("description", itemPath),
                recommendedTools = item.stringList("recommendedTools", itemPath)
            )
        }

    private fun org.json.JSONObject.branches(context: String): List<AgentPlaybookFailureBranch> =
        requiredArray("failureBranches", context).objects("$context.failureBranches") { item, itemPath ->
            requireExactKeys(item, setOf("condition", "recommendedTools", "limitation"), itemPath)
            AgentPlaybookFailureBranch(
                condition = item.requiredString("condition", itemPath),
                recommendedTools = item.stringList("recommendedTools", itemPath),
                limitation = item.requiredString("limitation", itemPath)
            )
        }

    /** The shared id grammar every playbook id in every layer must match. */
    internal val ID_PATTERN = Regex("^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
}
