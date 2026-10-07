package com.example.layanalyzer.ai.playbook

import org.json.JSONObject

/**
 * The declarative content of one verified scenario package, beyond playbooks.
 *
 * Everything here is data the host *merges additively* into its own behaviour:
 * field aliases only add accepted spellings, thresholds only flag values for
 * review, evaluation expectations only pin regression scenarios.  Nothing in a
 * package can register a tool, evaluate an expression, name a class, hold a
 * network address, or widen a sensitivity level — the parsers below reject
 * anything that looks like it could.
 */

/** One accepted alternate spelling for a supported Wireshark field abbreviation. */
data class ScenarioFieldAlias(
    val alias: String,
    val field: String,
    val region: String,
    val notes: String
)

/**
 * A review threshold contributed by the operator/device layer.
 *
 * Thresholds never become conclusions: the prompt describes them as signals
 * worth a closer look, and EvidenceValidator's confidence cap is unaffected.
 */
data class ScenarioThreshold(
    val id: String,
    val playbookId: String,
    val value: Long,
    val unit: String,
    val region: String,
    val notes: String
)

/** Which golden scenarios (or synthetic checks) must pass before a playbook ships. */
data class ScenarioEvaluationExpectation(
    val playbookId: String,
    val goldenScenarioIds: List<String>,
    val syntheticOnly: Boolean,
    val notes: String
)

/** Fully parsed package content; every cross-reference is already validated. */
data class ScenarioPackageContent(
    val playbooks: List<AgentPlaybook>,
    val aliases: List<ScenarioFieldAlias>,
    val thresholds: List<ScenarioThreshold>,
    val expectations: List<ScenarioEvaluationExpectation>
) {
    fun thresholdsFor(playbookId: String): List<ScenarioThreshold> =
        thresholds.filter { it.playbookId == playbookId }

    fun aliasesFor(field: String): List<ScenarioFieldAlias> =
        aliases.filter { it.field.equals(field, ignoreCase = true) }

    fun expectationFor(playbookId: String): ScenarioEvaluationExpectation? =
        expectations.firstOrNull { it.playbookId == playbookId }
}

object ScenarioPackageContentCodec {
    const val ALIASES_SCHEMA_VERSION = 1
    const val THRESHOLDS_SCHEMA_VERSION = 1
    const val EXPECTATIONS_SCHEMA_VERSION = 1

    /**
     * Parse all package files.  [availableTools] is the host's tool whitelist —
     * a package that references anything outside it is rejected wholesale.
     */
    fun decode(
        playbooksJson: String,
        aliasesJson: String,
        thresholdsJson: String,
        expectationsJson: String,
        availableTools: Set<String>
    ): ScenarioPackageContent {
        val playbooks = AgentPlaybookStore.decode(playbooksJson, availableTools)
        val aliases = decodeAliases(aliasesJson)
        val thresholds = decodeThresholds(thresholdsJson)
        val expectations = decodeExpectations(expectationsJson)

        val playbookIds = playbooks.map { it.id }.toSet()
        thresholds.forEach { threshold ->
            require(threshold.playbookId in playbookIds) {
                "thresholds.json references unknown playbook ${threshold.playbookId}."
            }
        }
        expectations.forEach { expectation ->
            require(expectation.playbookId in playbookIds) {
                "evaluation_expectations.json references unknown playbook ${expectation.playbookId}."
            }
        }
        return ScenarioPackageContent(
            playbooks = playbooks,
            aliases = aliases,
            thresholds = thresholds,
            expectations = expectations
        )
    }

    fun decodeAliases(json: String): List<ScenarioFieldAlias> {
        val root = JSONObject(json)
        requireExactKeys(root, setOf("schemaVersion", "aliases"), "aliases.root")
        require(root.requiredInt("schemaVersion", "aliases.root") == ALIASES_SCHEMA_VERSION) {
            "Unsupported field_aliases schema version."
        }
        val aliases = root.requiredArray("aliases", "aliases.root").objects("aliases") { item, path ->
            requireExactKeys(item, setOf("alias", "field", "region", "notes"), path)
            ScenarioFieldAlias(
                alias = item.requiredString("alias", path).also { alias ->
                    require(ALIAS_PATTERN.matches(alias)) { "$path.alias is not a field alias." }
                },
                field = item.requiredString("field", path).also { field ->
                    require(FIELD_PATTERN.matches(field)) { "$path.field is not a field name." }
                },
                region = item.requiredString("region", path).also { region ->
                    require(REGION_PATTERN.matches(region)) { "$path.region is not a region token." }
                },
                notes = item.requiredString("notes", path).also { ScenarioTextRules.requireDeclarativeText(it) }
            )
        }
        require(aliases.map { it.alias.lowercase() }.distinct().size == aliases.size) {
            "aliases must be unique."
        }
        return aliases
    }

    fun decodeThresholds(json: String): List<ScenarioThreshold> {
        val root = JSONObject(json)
        requireExactKeys(root, setOf("schemaVersion", "thresholds"), "thresholds.root")
        require(root.requiredInt("schemaVersion", "thresholds.root") == THRESHOLDS_SCHEMA_VERSION) {
            "Unsupported thresholds schema version."
        }
        val thresholds = root.requiredArray("thresholds", "thresholds.root").objects("thresholds") { item, path ->
            requireExactKeys(item, setOf("id", "playbookId", "value", "unit", "region", "notes"), path)
            ScenarioThreshold(
                id = item.requiredString("id", path).also { id ->
                    require(THRESHOLD_ID_PATTERN.matches(id)) { "$path.id is not a stable id." }
                },
                playbookId = item.requiredString("playbookId", path).also { id ->
                    require(PLAYBOOK_ID_PATTERN.matches(id)) { "$path.playbookId is not a playbook id." }
                },
                value = item.requiredLong("value", path).also { value ->
                    require(value >= 0L) { "$path.value must not be negative." }
                },
                unit = item.requiredString("unit", path).also { unit ->
                    require(unit in SUPPORTED_UNITS) { "$path.unit is not a supported unit." }
                },
                region = item.requiredString("region", path).also { region ->
                    require(REGION_PATTERN.matches(region)) { "$path.region is not a region token." }
                },
                notes = item.requiredString("notes", path).also { ScenarioTextRules.requireDeclarativeText(it) }
            )
        }
        require(thresholds.map { it.id }.distinct().size == thresholds.size) {
            "threshold ids must be unique."
        }
        return thresholds
    }

    fun decodeExpectations(json: String): List<ScenarioEvaluationExpectation> {
        val root = JSONObject(json)
        requireExactKeys(root, setOf("schemaVersion", "expectations"), "expectations.root")
        require(root.requiredInt("schemaVersion", "expectations.root") == EXPECTATIONS_SCHEMA_VERSION) {
            "Unsupported evaluation_expectations schema version."
        }
        val expectations = root.requiredArray("expectations", "expectations.root")
            .objects("expectations") { item, path ->
                requireExactKeys(item, setOf("playbookId", "goldenScenarioIds", "syntheticOnly", "notes"), path)
                ScenarioEvaluationExpectation(
                    playbookId = item.requiredString("playbookId", path).also { id ->
                        require(PLAYBOOK_ID_PATTERN.matches(id)) { "$path.playbookId is not a playbook id." }
                    },
                    goldenScenarioIds = item.stringListAt("goldenScenarioIds", path),
                    syntheticOnly = item.optBoolean("syntheticOnly", false),
                    notes = item.requiredString("notes", path).also { ScenarioTextRules.requireDeclarativeText(it) }
                )
            }
        require(expectations.map { it.playbookId }.distinct().size == expectations.size) {
            "expectation playbookIds must be unique."
        }
        return expectations
    }

    private fun JSONObject.stringListAt(name: String, context: String): List<String> =
        stringList(name, context).also { list ->
            list.forEach { scenario ->
                require(SCENARIO_ID_PATTERN.matches(scenario)) {
                    "$context.$name contains an invalid scenario id $scenario."
                }
            }
        }

    private val ALIAS_PATTERN = Regex("^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
    private val FIELD_PATTERN = Regex("^[A-Za-z][A-Za-z0-9]*(?:[._-][A-Za-z0-9]+)*$")
    private val REGION_PATTERN = Regex("^[A-Za-z0-9][A-Za-z0-9_+.-]{0,63}$")
    private val THRESHOLD_ID_PATTERN = Regex("^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
    private val PLAYBOOK_ID_PATTERN = Regex("^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
    private val SCENARIO_ID_PATTERN = Regex("^[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*$")
    private val SUPPORTED_UNITS = setOf("milliseconds", "percent", "count", "bytes", "dbm")
}
