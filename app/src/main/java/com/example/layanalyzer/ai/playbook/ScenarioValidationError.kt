package com.example.layanalyzer.ai.playbook

/**
 * One machine-readable validation rejection produced by the user scenario
 * save boundary (OPT-ERR-01).
 *
 * The point of this type is that the data layer never formats user-facing
 * prose: a rejection is a stable reason [code] plus optional string [args]
 * (for example `max` for [ScenarioValidationCodes.TEXT_TOO_LONG] or `tool`
 * for [ScenarioValidationCodes.TOOL_NOT_ALLOWED]), and the UI layer maps the
 * code to a localized string resource.  Codes are lowercase snake_case
 * identifiers (matching [ScenarioValidationCodes.SHAPE]); they carry no
 * punctuation, spaces, or user content, so a rejected save can be reported,
 * asserted on, and translated without ever leaking an English sentence into
 * a localized screen.
 */
data class ScenarioValidationError(
    /** Stable reason code, e.g. [ScenarioValidationCodes.TEXT_TOO_LONG]. */
    val code: String,
    /** Formatting arguments for the localized message, e.g. `max -> "300"`. */
    val args: Map<String, String> = emptyMap()
)

/**
 * The closed set of validation reason codes the scenario save boundary can
 * produce.  Every rejection branch in [UserScenarioPlaybookStore],
 * [ScenarioTextRules], [PlaybookParsing] and the shared JSON validation
 * helpers maps to exactly one constant here, and the UI localizes each code
 * (falling back to the raw code for anything unrecognized, which stays
 * debuggable instead of crashing).  Codes never change meaning: renaming or
 * removing one is a UI-visible contract break.
 */
object ScenarioValidationCodes {

    /** The id is already used by a built-in playbook. */
    const val ID_BUILTIN_CONFLICT = "id_builtin_conflict"

    /** The id does not carry the `user-` namespace prefix. */
    const val ID_PREFIX_REQUIRED = "id_prefix_required"

    /** The scenario declares no intent hint. */
    const val INTENT_HINTS_REQUIRED = "intent_hints_required"

    /** Free text is over the limit; arg `max` carries the limit. */
    const val TEXT_TOO_LONG = "text_too_long"

    /** Free text looks like executable content (URL, code fence, script). */
    const val TEXT_FORBIDDEN_CONTENT = "text_forbidden_content"

    /** More required fields than the cap; arg `max` carries the cap. */
    const val REQUIRED_FIELDS_CAP = "required_fields_cap"

    /** A tool reference is outside the whitelist; arg `tool` names it. */
    const val TOOL_NOT_ALLOWED = "tool_not_allowed"

    /** A required-field reference is outside the field table; arg `field`. */
    const val FIELD_NOT_SUPPORTED = "field_not_supported"

    /** An id does not match the shared stable-id grammar. */
    const val ID_INVALID = "id_invalid"

    /** A stored playbook version is not positive. */
    const val VERSION_NOT_POSITIVE = "version_not_positive"

    /** No initial tool survives parsing (whitelist injection included). */
    const val INITIAL_TOOLS_EMPTY = "initial_tools_empty"

    /** An object carries a property the format does not know; arg `properties`. */
    const val UNKNOWN_PROPERTIES = "unknown_properties"

    /** An object lacks a required property; arg `properties`. */
    const val MISSING_PROPERTIES = "missing_properties"

    /** A required string is absent or blank. */
    const val STRING_BLANK = "string_blank"

    /** A value that must be a number is not. */
    const val EXPECTED_NUMBER = "expected_number"

    /** A value that must be an object is not. */
    const val EXPECTED_OBJECT = "expected_object"

    /** A value that must be an array is not. */
    const val EXPECTED_ARRAY = "expected_array"

    /** A list exceeds its item cap; arg `max` carries the cap. */
    const val LIST_TOO_LONG = "list_too_long"

    /** The stored schema version is outside the supported window; arg `version`. */
    const val SCHEMA_VERSION_UNSUPPORTED = "schema_version_unsupported"

    /** The stored file declares the same playbook id twice. */
    const val DUPLICATE_IDS = "duplicate_ids"

    /** Catch-all: a structural rejection without a specific code. */
    const val STRUCTURAL_REJECTION = "structural_rejection"

    /** Catch-all: a text rejection without a specific code. */
    const val TEXT_REJECTED = "text_rejected"

    /** The shape every code above must match: lowercase snake_case only. */
    val SHAPE = Regex("[a-z0-9_]+")

    /** Every reason code the boundary can produce, for coverage checks. */
    val ALL: List<String> = listOf(
        ID_BUILTIN_CONFLICT,
        ID_PREFIX_REQUIRED,
        INTENT_HINTS_REQUIRED,
        TEXT_TOO_LONG,
        TEXT_FORBIDDEN_CONTENT,
        REQUIRED_FIELDS_CAP,
        TOOL_NOT_ALLOWED,
        FIELD_NOT_SUPPORTED,
        ID_INVALID,
        VERSION_NOT_POSITIVE,
        INITIAL_TOOLS_EMPTY,
        UNKNOWN_PROPERTIES,
        MISSING_PROPERTIES,
        STRING_BLANK,
        EXPECTED_NUMBER,
        EXPECTED_OBJECT,
        EXPECTED_ARRAY,
        LIST_TOO_LONG,
        SCHEMA_VERSION_UNSUPPORTED,
        DUPLICATE_IDS,
        STRUCTURAL_REJECTION,
        TEXT_REJECTED
    )
}

/**
 * [IllegalArgumentException] carrying the structured rejection an error-code
 * consumer needs instead of a parsed message (OPT-ERR-01): the rejected
 * [path] (when the thrower knows one), a stable `code` from
 * [ScenarioValidationCodes], and the message [args].  The [message] stays the
 * historical English sentence so log readers and every existing
 * message-pinning test keep working; the code is the new machine-readable
 * channel.  The data layer never surfaces these to users directly —
 * [UserScenarioPlaybookStore] converts them into [ScenarioValidationError]
 * values, and package/manifest decoding keeps its throw-and-quarantine
 * behavior.
 */
internal class PlaybookValidationException(
    /** The rejected field path, or `null` for a path-less rule. */
    val path: String?,
    val code: String,
    val args: Map<String, String> = emptyMap(),
    errorMessage: String
) : IllegalArgumentException(errorMessage)

/** The [ScenarioValidationError] twin of this exception: code + args only. */
internal fun PlaybookValidationException.toValidationError(): ScenarioValidationError =
    ScenarioValidationError(code, args)
