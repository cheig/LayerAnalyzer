package com.example.layanalyzer.ai.playbook

import android.content.Context
import android.util.Log
import com.example.layanalyzer.data.writeJsonAtomically
import java.io.File
import org.json.JSONArray
import org.json.JSONObject

/**
 * Storage contract for the user scenario layer: [AgentPlaybook] data entries
 * authored on this device, stored apart from the verified scenario package.
 *
 * File format contract — one JSON document at
 * `filesDir/scenario_rules/user_playbooks.json` ([DIRECTORY_NAME] and
 * [FILE_NAME]):
 *
 *  - the envelope is exactly `{ "schemaVersion": <int>, "playbooks": [...] }`
 *    and [decode] rejects unknown or missing properties at every level;
 *  - the `playbooks` entries are isomorphic to the package `playbooks.json`
 *    entries and pass through the same [PlaybookParsing] validation boundary
 *    (exact keys, id/version rules, tool whitelist, field table, field cap);
 *  - schema versions `1..[USER_SCHEMA_VERSION]` are accepted, independently of
 *    the scenario package's own schemaVersion; anything higher was written by
 *    a newer app and must not be silently dropped — implementations quarantine
 *    the file for recovery and continue with an empty layer.
 *
 * Trust boundary: this layer can only ever *add* playbook data entries.  It
 * cannot touch the tool whitelist, the field table,
 * [com.example.layanalyzer.ai.agent.AgentPolicy] budgets, redaction or
 * evidence validation, and overlay extras (thresholds, recommended filters)
 * never persist here.  Identity is store-owned: [generateScenarioId] and
 * [generateCopyId] mint ids under the implementation's id policy and ids are
 * immutable once saved, [AgentPlaybook.version] is managed by the
 * implementation, and `origin` never travels through JSON — every playbook
 * this layer hands out carries [ScenarioOrigin.User].
 */
interface UserScenarioStore {

    /**
     * The stored user scenarios in file order, or an empty list when the layer
     * starts empty or the file was quarantined.  Never throws: user data must
     * never take the Agent down, and the built-in layers keep working.
     */
    fun load(): List<AgentPlaybook>

    /**
     * Validates one scenario against the full playbook boundary plus the
     * user-layer rules (the `user-` id namespace, no collision with a
     * built-in playbook's id, and the declarative-text limits), then persists
     * it.  Returns an empty map when the scenario was stored; otherwise each
     * entry maps a field path (for example `title` or
     * `checks[2].description`) to the machine-readable [ScenarioValidationError]
     * — a stable reason code plus optional args, never prose — that rejected
     * that field (OPT-ERR-01).  The UI layer owns localization: it maps each
     * code to a string resource and falls back to the raw code for anything
     * unrecognized.  Nothing is written while any field is rejected.  Field
     * rejections are the only soft failure: a failed write still throws,
     * while a stored file the format boundary rejects is quarantined for
     * recovery and the save proceeds onto the empty layer.
     */
    fun save(scenario: AgentPlaybook): Map<String, ScenarioValidationError>

    /**
     * Removes the stored scenario with [playbookId]; unknown ids are a no-op,
     * so deletion stays idempotent.  A stored file the format boundary
     * rejects is quarantined for recovery first, which makes every id
     * unknown and the call a no-op on the empty layer.
     */
    fun delete(playbookId: String)

    /**
     * Mints the id for a brand-new scenario titled [title].  An ASCII title
     * becomes a slug and the id is `user-<slug>`; a blank title, any
     * non-ASCII title (for example Chinese), or an unusable slug falls back
     * to a numbered `user-scenario-<n>` id.  The result is unique against the
     * ids [load] currently returns and always matches [PlaybookParsing]'s id
     * pattern, so the `user-` prefix structurally keeps user ids apart from
     * every built-in layer's id.  Saving the scenario under the returned id
     * is the caller's step; once saved the id is immutable — later edits of
     * the same scenario keep it and pass the original id back to [save].
     */
    fun generateScenarioId(title: String): String

    /**
     * Mints the id for a copy of the scenario [sourceId].  The copy id is
     * `user-<sourceId>-copy` with one leading `user-` prefix of the source
     * removed, so built-in sources (`general-capture-health`) and user
     * sources (`user-my-rtp-check`) alike land in the user namespace without
     * stacking prefixes.  A source that degenerates to an empty remainder or
     * yields an id the shared pattern rejects falls back to a numbered
     * `user-scenario-<n>` id, and the result is unique against [load] the
     * same way [generateScenarioId] is.  The id is immutable once the copy
     * is saved.
     */
    fun generateCopyId(sourceId: String): String

    companion object {
        const val DIRECTORY_NAME = "scenario_rules"
        const val FILE_NAME = "user_playbooks.json"

        /**
         * The user layer evolves its schema independently of the scenario
         * package: a package upgrade must never force a migration of
         * on-device user content.
         */
        const val USER_SCHEMA_VERSION = 1

        /**
         * The user-layer id namespace contract: every id this layer mints
         * ([generateScenarioId], [generateCopyId]) and every id [save] accepts
         * starts with this prefix, which no built-in layer id can carry, so
         * the prefix alone structurally separates the user namespace from the
         * built-in layers.  It is deliberately *not* enforced by [decode] —
         * decode stays a pure format boundary that applies only the shared
         * syntax pattern — so the merge layer re-checks it as the second of
         * the two defense lines around the hand-editable storage file.
         */
        const val USER_ID_PREFIX = "user-"

        /**
         * Strict decode of the user-layer file, kept a pure function so the
         * owning implementation stays in full control of failure handling
         * (quarantine and degrade) and tests can pin every rejection
         * directly.
         *
         * Unlike package decoding, an empty `playbooks` array is valid: the
         * layer starts empty and deleting the last scenario must not need a
         * special case.
         *
         * Every rejection throws [PlaybookValidationException] with a stable
         * [ScenarioValidationCodes] reason code and the unchanged English
         * message.  None of these codes reaches the editor's error map — a
         * rejected stored file goes through the quarantine path, which
         * reports its own reason code only — but code-ifying them keeps the
         * whole file boundary machine-readable.  The pure-function contract
         * and the file format are untouched.
         */
        fun decode(json: String, availableTools: Set<String>): List<AgentPlaybook> {
            val root = org.json.JSONObject(json)
            requireExactKeys(root, setOf("schemaVersion", "playbooks"), "root")
            val schemaVersion = root.requiredInt("schemaVersion", "root")
            if (schemaVersion !in 1..USER_SCHEMA_VERSION) {
                throw PlaybookValidationException(
                    path = "root.schemaVersion",
                    code = ScenarioValidationCodes.SCHEMA_VERSION_UNSUPPORTED,
                    args = mapOf("version" to schemaVersion.toString()),
                    errorMessage = "Unsupported user scenario schema version $schemaVersion."
                )
            }
            val items = root.requiredArray("playbooks", "root")
            val decoded = (0 until items.length()).map { index ->
                val value = items.optJSONObject(index)
                    ?: throw PlaybookValidationException(
                        path = "playbooks[$index]",
                        code = ScenarioValidationCodes.EXPECTED_OBJECT,
                        errorMessage = "playbooks[$index] must be an object."
                    )
                PlaybookParsing.parsePlaybook(value, availableTools, "playbooks[$index]")
            }
            if (decoded.map { it.id }.distinct().size != decoded.size) {
                throw PlaybookValidationException(
                    path = "playbooks",
                    code = ScenarioValidationCodes.DUPLICATE_IDS,
                    errorMessage = "Playbook ids must be unique."
                )
            }
            return decoded.map { it.copy(origin = ScenarioOrigin.User) }
        }
    }
}

/**
 * filesDir-backed [UserScenarioStore]: one JSON document at
 * `filesDir/scenario_rules/user_playbooks.json`, rewritten whole on every
 * change through [writeJsonAtomically], so a process death mid-write leaves
 * either the previous file or the new one — never a half-written document.
 *
 * What this implementation owns:
 *  - the id policy: [generateScenarioId] and [generateCopyId] mint `user-`-
 *    prefixed ids that are unique against the ids [load] currently returns;
 *    an id is immutable once saved — edits keep it and only
 *    [AgentPlaybook.version] moves;
 *  - [AgentPlaybook.version]: the first save of an id stores version 1 and
 *    every later save of the same id bumps it by exactly one, whatever the
 *    draft carried, so `id@version` provenance stays meaningful across edits;
 *  - the save gate: [save] validates the draft in memory first — an id in the
 *    `user-` namespace that does not collide with [builtInPlaybookIds], at
 *    least one intent hint, the per-field declarative-text limits, and the
 *    shared [PlaybookParsing] boundary — and reports every rejection as a
 *    field path → [ScenarioValidationError] map (stable reason code + args,
 *    no prose — the UI localizes codes, OPT-ERR-01) without touching the
 *    disk; the overlay extras are stripped silently by serialization, never
 *    reported as errors;
 *  - the serialization surface: `origin` and the overlay extras (thresholds,
 *    recommended filters) are never written, and every document is decoded
 *    back before the write, so content the stored-format boundary rejects can
 *    never replace a readable file;
 *  - file order: [save] replaces an existing id in place and appends new ids
 *    at the end; [delete] of an unknown id writes nothing.
 *
 * Failure handling is asymmetric on purpose. [load] never throws: an
 * unreadable file is renamed aside to `user_playbooks.json.quarantine-<epoch
 * millis>` (`-2`, `-3`, ... while that name is taken) so the data stays
 * recoverable by hand, and the layer degrades to empty — a rename blocked by
 * a directory or a platform lock leaves the original in place, user data is
 * never deleted, and [onQuarantine] receives a stable reason code once,
 * never file or playbook content. A field rejection in [save] is soft: the
 * error map comes back and no file is read for the write path, let alone
 * written. [save] and [delete] read through the same quarantine path, so a
 * corrupt document no longer blocks a write: [save] continues onto the empty
 * layer and writes a fresh document, [delete] of an id the corrupt file hid
 * becomes an unknown-id no-op, and only failed writes still throw.
 *
 * Every method blocks on disk I/O: callers must invoke them from
 * Dispatchers.IO, never the main thread.
 */
class UserScenarioPlaybookStore(
    private val directory: File,
    private val availableTools: Set<String>,
    /**
     * Millisecond clock for quarantine file names.  A supplier like
     * [builtInPlaybookIds]; defaults to the wall clock and is injected by
     * tests to pin the exact `...quarantine-<millis>` name.  Placed before
     * [builtInPlaybookIds] so a trailing-lambda call keeps binding the
     * built-in id supplier.
     */
    private val clock: () -> Long = { System.currentTimeMillis() },
    /**
     * Stable sink for quarantine events, called once per unreadable file with
     * a reason code such as [QUARANTINE_DECODE_FAILED] — never playbook or
     * file content.  Defaults to a warning under [LOG_TAG]; tests inject a
     * recorder instead of touching the Android log.  The app assembly passes a
     * sink that warns under the same tag *and* forwards the code to the
     * UI-side [ScenarioQuarantineEventChannel] (OPT-QNT-01), so the quarantine
     * stays visible to the user without changing the log contract.
     */
    private val onQuarantine: (String) -> Unit = { reason -> Log.w(LOG_TAG, reason) },
    /**
     * The built-in layers' playbook ids, re-consulted on every [save] so a
     * user scenario can never take over a built-in id.  A supplier because
     * the built-in set can change (scenario package updates) while this store
     * lives; defaults to an empty set for callers that have no built-in
     * layer.  Stays the last parameter so existing trailing-lambda call sites
     * keep working unchanged.
     */
    private val builtInPlaybookIds: () -> Set<String> = { emptySet() }
) : UserScenarioStore {

    constructor(
        context: Context,
        availableTools: Set<String>,
        clock: () -> Long = { System.currentTimeMillis() },
        onQuarantine: (String) -> Unit = { reason -> Log.w(LOG_TAG, reason) },
        builtInPlaybookIds: () -> Set<String> = { emptySet() }
    ) : this(
        File(context.applicationContext.filesDir, UserScenarioStore.DIRECTORY_NAME),
        availableTools,
        clock,
        onQuarantine,
        builtInPlaybookIds
    )

    private val file = File(directory, UserScenarioStore.FILE_NAME)

    /** Serializes the read-modify-write cycle behind [save] and [delete]. */
    private val guard = Any()

    override fun load(): List<AgentPlaybook> = synchronized(guard) {
        readExisting()
    }

    override fun save(scenario: AgentPlaybook): Map<String, ScenarioValidationError> = synchronized(guard) {
        // Validate in memory first: with any rejection the file is not even
        // read, so rejected content can never reach the disk.
        val errors = validateForSave(scenario)
        if (errors.isNotEmpty()) return@synchronized errors
        val current = readExisting()
        val nextVersion = (current.firstOrNull { it.id == scenario.id }?.version ?: 0) + 1
        val stored = scenario.copy(version = nextVersion, origin = ScenarioOrigin.User)
        val updated = if (current.any { it.id == stored.id }) {
            current.map { if (it.id == stored.id) stored else it }
        } else {
            current + stored
        }
        // Everything persisted must load back: decode the document before
        // writing so rejected content can never replace a readable file.
        val encoded = encode(updated)
        UserScenarioStore.decode(encoded, availableTools)
        ensureDirectory()
        writeJsonAtomically(file, encoded, TEMP_SUFFIX)
        emptyMap()
    }

    /**
     * Runs every user-layer rule against [scenario] purely in memory and
     * collects all rejections instead of stopping at the first: the returned
     * map's key is a field path an editor can highlight and its value is the
     * machine-readable [ScenarioValidationError] — a stable
     * [ScenarioValidationCodes] reason code plus args, never prose
     * (OPT-ERR-01); the UI maps codes to localized strings.  An empty map
     * means the draft may be persisted.
     *
     * The rules claim their map slot in evaluation order, and the first
     * rejection on a path wins — a single `id` slot serves both the namespace
     * and the built-in conflict, where the conflict is the more specific
     * rejection.  After the user-layer rules, the draft is replayed through
     * the shared [PlaybookParsing] boundary exactly as a stored file would be
     * read back.
     */
    private fun validateForSave(scenario: AgentPlaybook): Map<String, ScenarioValidationError> {
        val errors = LinkedHashMap<String, ScenarioValidationError>()
        if (scenario.id in builtInPlaybookIds()) {
            errors["id"] = ScenarioValidationError(ScenarioValidationCodes.ID_BUILTIN_CONFLICT)
        }
        if (!scenario.id.startsWith(USER_ID_PREFIX)) {
            errors.putIfAbsent("id", ScenarioValidationError(ScenarioValidationCodes.ID_PREFIX_REQUIRED))
        }
        if (scenario.intentHints.isEmpty()) {
            errors.putIfAbsent("intentHints", ScenarioValidationError(ScenarioValidationCodes.INTENT_HINTS_REQUIRED))
        }
        rejectText(errors, "title", scenario.title, ScenarioTextRules.USER_MAX_TITLE_LENGTH)
        scenario.intentHints.forEachIndexed { index, hint ->
            rejectText(errors, "intentHints[$index]", hint, ScenarioTextRules.USER_MAX_HINT_LENGTH)
        }
        scenario.checks.forEachIndexed { index, check ->
            rejectText(
                errors, "checks[$index].description", check.description,
                ScenarioTextRules.USER_MAX_TEXT_LENGTH
            )
        }
        scenario.successPath.forEachIndexed { index, step ->
            rejectText(errors, "successPath[$index]", step, ScenarioTextRules.USER_MAX_TEXT_LENGTH)
        }
        scenario.failureBranches.forEachIndexed { index, branch ->
            rejectText(
                errors, "failureBranches[$index].condition", branch.condition,
                ScenarioTextRules.USER_MAX_TEXT_LENGTH
            )
            rejectText(
                errors, "failureBranches[$index].limitation", branch.limitation,
                ScenarioTextRules.USER_MAX_TEXT_LENGTH
            )
        }
        scenario.requiredLimitations.forEachIndexed { index, text ->
            rejectText(errors, "requiredLimitations[$index]", text, ScenarioTextRules.USER_MAX_TEXT_LENGTH)
        }
        scenario.outputSections.forEachIndexed { index, section ->
            rejectText(errors, "outputSections[$index]", section, ScenarioTextRules.USER_MAX_TEXT_LENGTH)
        }
        rejectStructuralRejection(errors, scenario)
        return errors
    }

    /**
     * Applies the declarative-text rule to one free-text field, recording the
     * rule's reason code ([ScenarioValidationCodes.TEXT_TOO_LONG] with the
     * `max` arg, or [ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT]) on
     * [path]; the generic [ScenarioValidationCodes.TEXT_REJECTED] stands only
     * for an unexpected rejection without a code, keeping the map's values
     * codes in every case.
     */
    private fun rejectText(
        errors: MutableMap<String, ScenarioValidationError>,
        path: String,
        text: String,
        maxLength: Int
    ) {
        try {
            ScenarioTextRules.requireDeclarativeText(text, maxLength)
        } catch (failure: PlaybookValidationException) {
            errors.putIfAbsent(path, failure.toValidationError())
        } catch (failure: IllegalArgumentException) {
            errors.putIfAbsent(path, ScenarioValidationError(ScenarioValidationCodes.TEXT_REJECTED))
        }
    }

    /**
     * Last validation gate: encodes the draft with [encodePlaybook] and parses
     * it back through [PlaybookParsing], the same boundary the stored file
     * goes through on load.  The candidate carries a fixed version of 1
     * because the real version is store-assigned and a draft's own value is
     * not meaningful, and encoding silently drops the overlay extras
     * (thresholds, recommended filters, origin): they never persist on this
     * layer, so they are not validation errors here either.  The boundary now
     * throws [PlaybookValidationException] carrying the rejected path and the
     * reason code (OPT-ERR-01), so nothing parses a message any more: the
     * exception's `playbooks[0].`-anchored path has its context prefix
     * stripped so it lines up with the user-layer paths, and a path an
     * earlier rule already rejected keeps its first error.  An unexpected
     * rejection without structured info still lands under the raw context
     * path with the generic [ScenarioValidationCodes.STRUCTURAL_REJECTION]
     * code.  This gate should never fire after the rules above; reporting it
     * here still hands the editor a field path instead of an exception, and
     * [save]'s decode guard stays as the final fail-closed line.
     */
    private fun rejectStructuralRejection(
        errors: MutableMap<String, ScenarioValidationError>,
        scenario: AgentPlaybook
    ) {
        val candidate = scenario.copy(
            version = 1,
            thresholds = emptyList(),
            recommendedFilters = emptyList(),
            origin = ScenarioOrigin.User
        )
        try {
            PlaybookParsing.parsePlaybook(encodePlaybook(candidate), availableTools, STRUCTURAL_CONTEXT)
        } catch (failure: PlaybookValidationException) {
            val path = (failure.path ?: STRUCTURAL_CONTEXT).removePrefix("$STRUCTURAL_CONTEXT.")
            errors.putIfAbsent(path, failure.toValidationError())
        } catch (failure: IllegalArgumentException) {
            errors.putIfAbsent(
                STRUCTURAL_CONTEXT,
                ScenarioValidationError(ScenarioValidationCodes.STRUCTURAL_REJECTION)
            )
        }
    }

    override fun delete(playbookId: String) {
        synchronized(guard) {
            val current = readExisting()
            if (current.none { it.id == playbookId }) return
            ensureDirectory()
            writeJsonAtomically(file, encode(current.filterNot { it.id == playbookId }), TEMP_SUFFIX)
        }
    }

    override fun generateScenarioId(title: String): String {
        val taken = load().map { it.id }.toSet()
        return slugCandidate(title)?.let { uniqueId(it, taken) } ?: numberedScenarioId(taken)
    }

    override fun generateCopyId(sourceId: String): String {
        val taken = load().map { it.id }.toSet()
        // One leading `user-` prefix comes off, so copying a user scenario
        // never stacks into `user-user-...`; the bare prefix `user` itself
        // leaves no remainder and takes the numbered fallback like an empty
        // source.
        val rest = if (sourceId == BARE_USER_PREFIX) "" else sourceId.removePrefix(USER_ID_PREFIX)
        val candidate = "$USER_ID_PREFIX$rest-copy"
        if (rest.isEmpty() || !PlaybookParsing.ID_PATTERN.matches(candidate)) {
            return numberedScenarioId(taken)
        }
        return uniqueId(candidate, taken)
    }

    /**
     * Slugs [title] when it can produce a usable `user-`-prefixed id:
     * non-blank, all-ASCII, and a non-empty slug.  Runs of non-alphanumeric
     * characters collapse into single separators and the slug is capped at
     * [MAX_SLUG_CHARS] characters, re-trimming trailing separators after the
     * cut.  `null` sends the caller to [numberedScenarioId].
     */
    private fun slugCandidate(title: String): String? {
        if (title.isBlank() || title.any { it.code > 127 }) return null
        val slug = title.lowercase()
            .replace(NON_SLUG_CHARS, "-")
            .trim('-')
            .take(MAX_SLUG_CHARS)
            .trimEnd('-')
        if (slug.isEmpty()) return null
        val candidate = USER_ID_PREFIX + slug
        return candidate.takeIf { PlaybookParsing.ID_PATTERN.matches(it) }
    }

    /** The first `user-scenario-<n>` id the current layer does not use. */
    private fun numberedScenarioId(taken: Set<String>): String {
        var number = 1
        while ("$FALLBACK_ID_PREFIX$number" in taken) number++
        return "$FALLBACK_ID_PREFIX$number"
    }

    /**
     * [candidate] when the current layer does not use it, otherwise the
     * first `candidate-2`, `candidate-3`, ... it does not.
     */
    private fun uniqueId(candidate: String, taken: Set<String>): String {
        if (candidate !in taken) return candidate
        var suffix = 2
        while ("$candidate-$suffix" in taken) suffix++
        return "$candidate-$suffix"
    }

    /**
     * The one read path behind [load], [save], and [delete]: decodes the
     * stored file strictly and, when the stored boundary rejects it — corrupt
     * JSON, an unknown property, a schema version from a newer app —
     * quarantines the file and continues with an empty layer.  Never throws:
     * user data must never take the Agent down, the built-in layers keep
     * working, and the empty layer lets [save] write a fresh document and
     * turns [delete] into an unknown-id no-op.
     */
    private fun readExisting(): List<AgentPlaybook> {
        if (!file.isFile) return emptyList()
        return try {
            UserScenarioStore.decode(file.readText(), availableTools)
        } catch (_: Exception) {
            quarantineUnreadableFile()
            emptyList()
        }
    }

    /**
     * Renames the unreadable file to
     * `user_playbooks.json.quarantine-<epoch millis>` so the data stays
     * recoverable by hand, and reports [QUARANTINE_DECODE_FAILED] through
     * [onQuarantine] exactly once — the content itself is never logged.  A
     * stamp a previous quarantine already used is skipped with `-2`, `-3`,
     * ... until a name no file occupies.  The rename is best-effort: a name
     * blocked by a directory, or a platform file lock, fails the rename and
     * leaves the original file in place — user data is never deleted here.
     */
    private fun quarantineUnreadableFile() {
        onQuarantine(QUARANTINE_DECODE_FAILED)
        val baseName = UserScenarioStore.FILE_NAME + QUARANTINE_FILE_SUFFIX + clock()
        var target = File(directory, baseName)
        var suffix = 2
        while (target.isFile) {
            target = File(directory, "$baseName-$suffix")
            suffix++
        }
        file.renameTo(target)
    }

    private fun ensureDirectory() {
        if (!directory.isDirectory) {
            check(directory.mkdirs()) { "Unable to create the user scenario directory." }
        }
    }

    private fun encode(playbooks: List<AgentPlaybook>): String = JSONObject()
        .put("schemaVersion", UserScenarioStore.USER_SCHEMA_VERSION)
        .put("playbooks", JSONArray().apply { playbooks.forEach { put(encodePlaybook(it)) } })
        .toString()

    /**
     * The stored shape is exactly the package `playbooks.json` entry shape:
     * `origin` is store-assigned after decode and the overlay extras never
     * persist on this layer, so neither is written here.
     */
    private fun encodePlaybook(playbook: AgentPlaybook): JSONObject = JSONObject()
        .put("id", playbook.id)
        .put("version", playbook.version)
        .put("title", playbook.title)
        .put("intentHints", JSONArray(playbook.intentHints))
        .put("protocols", JSONArray(playbook.protocols))
        .put("initialTools", JSONArray(playbook.initialTools))
        .put("requiredFields", JSONArray(playbook.requiredFields))
        .put("checks", JSONArray().apply {
            playbook.checks.forEach { check ->
                put(
                    JSONObject()
                        .put("id", check.id)
                        .put("description", check.description)
                        .put("recommendedTools", JSONArray(check.recommendedTools))
                )
            }
        })
        .put("successPath", JSONArray(playbook.successPath))
        .put("failureBranches", JSONArray().apply {
            playbook.failureBranches.forEach { branch ->
                put(
                    JSONObject()
                        .put("condition", branch.condition)
                        .put("recommendedTools", JSONArray(branch.recommendedTools))
                        .put("limitation", branch.limitation)
                )
            }
        })
        .put("requiredLimitations", JSONArray(playbook.requiredLimitations))
        .put("outputSections", JSONArray(playbook.outputSections))

    companion object {

        /**
         * Stable reason code [onQuarantine] receives when the stored file
         * cannot be decoded; internal so tests can pin it.  Quarantine
         * reporting carries reason codes only, never playbook or file
         * content.
         */
        internal const val QUARANTINE_DECODE_FAILED = "user_scenario_decode_failed"

        /**
         * Warning tag for the default [onQuarantine] sink.  Internal so the
         * app-assembly sink (OPT-QNT-01) can keep this exact log line while
         * it additionally forwards the reason code to the UI: replacing the
         * default sink must not change what lands in logcat.
         */
        internal const val LOG_TAG = "LayAnalyzer-AgentScenario"

        /** Separates the quarantine stamp from [UserScenarioStore.FILE_NAME]. */
        private const val QUARANTINE_FILE_SUFFIX = ".quarantine-"

        private const val TEMP_SUFFIX = ".tmp"

        /** Context [PlaybookParsing] uses when re-parsing the single draft. */
        private const val STRUCTURAL_CONTEXT = "playbooks[0]"

        /** Every generated id lives in the `user-` namespace, which no
         *  built-in layer id can enter because the shared id pattern anchors
         *  on a leading `[a-z]` segment and built-in ids never carry the
         *  prefix. */
        private const val USER_ID_PREFIX = "user-"
        private const val BARE_USER_PREFIX = "user"
        private const val FALLBACK_ID_PREFIX = "user-scenario-"

        /** Slug cap before the `user-` prefix. */
        private const val MAX_SLUG_CHARS = 50

        /** Runs of characters outside the slug alphabet become one separator. */
        private val NON_SLUG_CHARS = Regex("[^a-z0-9]+")
    }
}
