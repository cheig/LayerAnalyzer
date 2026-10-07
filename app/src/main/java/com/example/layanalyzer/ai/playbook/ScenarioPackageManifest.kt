// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

import org.json.JSONArray
import org.json.JSONObject

/**
 * The manifest of one versioned scenario package.
 *
 * A manifest is the only entry point to a package: every other file is reached
 * through `files` with its pinned SHA-256.  Everything here is declarative data
 * — no scripts, no expression evaluation, no class names, no network addresses
 * — so parsing a manifest can never execute anything.
 *
 * Signature: the manifest is signed as canonical JSON (keys sorted, UTF-8,
 * no whitespace) **without** the `signature` property, using SHA256withRSA.
 * The app ships the trusted public key as an asset; model responses and capture
 * text can never replace it, so a package update can never widen what the host
 * already enforces (tool whitelist, budgets, redaction, confidence caps).
 */
data class ScenarioPackageManifest(
    val schemaVersion: Int,
    val packageId: String,
    val version: Int,
    val minimumAppVersion: String,
    val nativeBuildRange: NativeBuildRange,
    val supportedAbis: List<String>,
    val supportedProtocols: List<String>,
    /** Regions / operator scopes this package applies to; `any` means universal. */
    val regions: List<String>,
    val layers: List<ScenarioRuleLayer>,
    val changes: List<ScenarioPackageChange>,
    val parentVersion: Int?,
    val rollbackVersion: Int?,
    val publishedAt: String,
    /** ISO-8601 instant after which the package must not be activated; null = never. */
    val expiresAt: String?,
    /** File name (within the package directory) -> expected SHA-256 hex. */
    val files: Map<String, String>,
    val signature: ScenarioPackageSignature
) {
    val versionedId: String
        get() = "$packageId@$version"

    val latestChangeSummary: String
        get() = changes.maxByOrNull { it.version }?.summary.orEmpty()

    fun isCompatibleWithApp(appVersion: String): Boolean =
        compareVersions(appVersion, minimumAppVersion) >= 0

    fun isCompatibleWithNative(nativeBuildMarker: String): Boolean =
        nativeBuildRange.contains(extractVersionPrefix(nativeBuildMarker))

    fun isCompatibleWithAbi(abis: List<String>): Boolean =
        supportedAbis.isEmpty() || abis.any(supportedAbis::contains)

    fun isExpired(nowMillis: Long): Boolean {
        val expiry = expiresAt ?: return false
        val at = parseIso8601(expiry) ?: return true
        return nowMillis >= at
    }

    /**
     * The exact bytes that were signed: canonical JSON of every property except
     * `signature`.  Canonicalization must match the build-time signing script
     * exactly (sorted keys, UTF-8, `","`/`":"` separators, no ASCII escaping).
     */
    fun canonicalSignedBytes(): ByteArray =
        canonicalJson(toJsonObject(includeSignature = false)).toByteArray(Charsets.UTF_8)

    fun toJsonObject(includeSignature: Boolean = true): JSONObject {
        val root = JSONObject()
        root.put("schemaVersion", schemaVersion)
        root.put("packageId", packageId)
        root.put("version", version)
        root.put("minimumAppVersion", minimumAppVersion)
        root.put("nativeBuildRange", JSONObject()
            .put("minimum", nativeBuildRange.minimum)
            .put("maximumExclusive", nativeBuildRange.maximumExclusive))
        root.put("supportedAbis", JSONArray(supportedAbis))
        root.put("supportedProtocols", JSONArray(supportedProtocols))
        root.put("regions", JSONArray(regions))
        root.put("layers", JSONArray().apply {
            layers.forEach { layer ->
                put(JSONObject().put("id", layer.id).put("description", layer.description))
            }
        })
        root.put("changes", JSONArray().apply {
            changes.forEach { change ->
                put(JSONObject()
                    .put("version", change.version)
                    .put("summary", change.summary)
                    .put("publishedAt", change.publishedAt))
            }
        })
        root.put("parentVersion", parentVersion ?: JSONObject.NULL)
        root.put("rollbackVersion", rollbackVersion ?: JSONObject.NULL)
        root.put("publishedAt", publishedAt)
        root.put("expiresAt", expiresAt ?: JSONObject.NULL)
        root.put("files", JSONObject().apply { files.forEach { (name, hash) -> put(name, hash) } })
        if (includeSignature) {
            root.put("signature", JSONObject()
                .put("algorithm", signature.algorithm)
                .put("keyId", signature.keyId)
                .put("value", signature.value))
        }
        return root
    }

    private fun canonicalJson(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(",", "{", "}") { key ->
            "${quote(key)}:${canonicalJson(value.get(key))}"
        }
        is JSONArray -> (0 until value.length()).joinToString(",", "[", "]") { index ->
            canonicalJson(value.get(index))
        }
        is String -> quote(value)
        is Boolean, is Int, is Long -> value.toString()
        is Double, is Float -> value.toString()
        else -> throw IllegalArgumentException("Unsupported value in manifest: ${value.javaClass.name}")
    }

    private fun quote(text: String): String = buildString(text.length + 2) {
        append('"')
        text.forEach { char ->
            when (char) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                '\b' -> append("\\b")
                '' -> append("\\f")
                else -> if (char < ' ') append("\\u%04x".format(char.code)) else append(char)
            }
        }
        append('"')
    }

    companion object {
        const val SCHEMA_VERSION = 1
        const val SIGNATURE_ALGORITHM = "SHA256withRSA"

        /** Versions embedded in this build; a package newer than this is rejected. */
        const val APP_VERSION = "1.0"
        val SUPPORTED_ABIS: List<String> = listOf("arm64-v8a", "x86_64")

        fun decode(json: String): ScenarioPackageManifest {
            val root = JSONObject(json)
            requireExactKeys(
                root,
                setOf(
                    "schemaVersion", "packageId", "version", "minimumAppVersion",
                    "nativeBuildRange", "supportedAbis", "supportedProtocols", "regions",
                    "layers", "changes", "parentVersion", "rollbackVersion",
                    "publishedAt", "expiresAt", "files", "signature"
                ),
                "manifest"
            )
            val schemaVersion = root.requiredInt("schemaVersion", "manifest")
            require(schemaVersion == SCHEMA_VERSION) { "Unsupported scenario package schema $schemaVersion." }
            val packageId = root.requiredString("packageId", "manifest")
            require(ID_PATTERN.matches(packageId)) { "manifest.packageId is not a stable id." }
            val version = root.requiredInt("version", "manifest")
            require(version > 0) { "manifest.version must be positive." }
            val minimumAppVersion = root.requiredString("minimumAppVersion", "manifest")
            require(VERSION_PATTERN.matches(minimumAppVersion)) { "manifest.minimumAppVersion is not a version." }

            val range = root.requiredObject("nativeBuildRange", "manifest")
            requireExactKeys(range, setOf("minimum", "maximumExclusive"), "manifest.nativeBuildRange")
            val nativeBuildRange = NativeBuildRange(
                minimum = range.requiredString("minimum", "manifest.nativeBuildRange"),
                maximumExclusive = range.requiredString("maximumExclusive", "manifest.nativeBuildRange")
            )
            require(VERSION_PATTERN.matches(nativeBuildRange.minimum) &&
                VERSION_PATTERN.matches(nativeBuildRange.maximumExclusive)) {
                "manifest.nativeBuildRange bounds must be versions."
            }
            require(compareVersions(nativeBuildRange.minimum, nativeBuildRange.maximumExclusive) < 0) {
                "manifest.nativeBuildRange is empty."
            }

            val abis = root.stringList("supportedAbis", "manifest")
            abis.forEach { abi ->
                require(SAFE_TOKEN.matches(abi)) { "manifest.supportedAbis contains an unsafe value." }
            }
            val protocols = root.stringList("supportedProtocols", "manifest")
            protocols.forEach { protocol ->
                require(SAFE_TOKEN.matches(protocol)) { "manifest.supportedProtocols contains an unsafe value." }
            }
            val regions = root.stringList("regions", "manifest")
            require(regions.isNotEmpty()) { "manifest.regions must not be empty." }
            regions.forEach { region ->
                require(SAFE_TOKEN.matches(region)) { "manifest.regions contains an unsafe value." }
            }

            val layers = root.requiredArray("layers", "manifest").objects("manifest.layers") { item, path ->
                requireExactKeys(item, setOf("id", "description"), path)
                val id = item.requiredString("id", path)
                require(LAYER_ID_PATTERN.matches(id)) { "$path.id is not a stable id." }
                ScenarioRuleLayer(id = id, description = item.requiredString("description", path))
            }
            require(layers.map { it.id }.distinct().size == layers.size) { "manifest.layers ids must be unique." }

            val changes = root.requiredArray("changes", "manifest").objects("manifest.changes") { item, path ->
                requireExactKeys(item, setOf("version", "summary", "publishedAt"), path)
                val changeVersion = item.requiredInt("version", path)
                require(changeVersion > 0) { "$path.version must be positive." }
                ScenarioPackageChange(
                    version = changeVersion,
                    summary = item.requiredString("summary", path),
                    publishedAt = item.requiredString("publishedAt", path)
                )
            }
            require(changes.isNotEmpty()) { "manifest.changes must not be empty." }
            require(changes.map { it.version }.distinct().size == changes.size) {
                "manifest.changes versions must be unique."
            }

            val parentVersion = root.optionalPositiveInt("parentVersion", "manifest")
            val rollbackVersion = root.optionalPositiveInt("rollbackVersion", "manifest")
            require(parentVersion == null || parentVersion < version) {
                "manifest.parentVersion must be lower than manifest.version."
            }
            require(rollbackVersion == null || rollbackVersion < version) {
                "manifest.rollbackVersion must be lower than manifest.version."
            }

            val publishedAt = root.requiredString("publishedAt", "manifest")
            require(parseIso8601(publishedAt) != null) { "manifest.publishedAt is not an ISO-8601 instant." }
            val expiresAt = if (root.isNull("expiresAt")) null else root.requiredString("expiresAt", "manifest")
            require(expiresAt == null || parseIso8601(expiresAt) != null) {
                "manifest.expiresAt is not an ISO-8601 instant."
            }

            val filesObject = root.requiredObject("files", "manifest")
            val files = linkedMapOf<String, String>()
            filesObject.keys().forEach { name ->
                require(PACKAGE_FILES.contains(name)) { "manifest.files references unknown file $name." }
                val hash = filesObject.optString(name)
                require(SHA256_PATTERN.matches(hash)) { "manifest.files.$name must be a SHA-256 hex value." }
                files[name] = hash
            }
            require(files.keys == PACKAGE_FILES) { "manifest.files must pin exactly ${PACKAGE_FILES.sorted()}." }

            val signatureObject = root.requiredObject("signature", "manifest")
            requireExactKeys(signatureObject, setOf("algorithm", "keyId", "value"), "manifest.signature")
            val algorithm = signatureObject.requiredString("algorithm", "manifest.signature")
            require(algorithm == SIGNATURE_ALGORITHM) { "manifest.signature.algorithm must be $SIGNATURE_ALGORITHM." }
            val keyId = signatureObject.requiredString("keyId", "manifest.signature")
            require(SAFE_TOKEN.matches(keyId)) { "manifest.signature.keyId is not a stable id." }
            val signatureValue = signatureObject.requiredString("value", "manifest.signature")
            require(BASE64_PATTERN.matches(signatureValue)) { "manifest.signature.value must be base64." }

            return ScenarioPackageManifest(
                schemaVersion = schemaVersion,
                packageId = packageId,
                version = version,
                minimumAppVersion = minimumAppVersion,
                nativeBuildRange = nativeBuildRange,
                supportedAbis = abis,
                supportedProtocols = protocols,
                regions = regions,
                layers = layers,
                changes = changes,
                parentVersion = parentVersion,
                rollbackVersion = rollbackVersion,
                publishedAt = publishedAt,
                expiresAt = expiresAt,
                files = files,
                signature = ScenarioPackageSignature(algorithm, keyId, signatureValue)
            )
        }

        /**
         * Compare dotted numeric versions (`4.0.10` vs `4.0.9`).  Missing
         * segments count as zero; a non-numeric suffix is ignored (`4.0.10-v1`).
         */
        fun compareVersions(left: String, right: String): Int {
            val a = numericSegments(left)
            val b = numericSegments(right)
            val length = maxOf(a.size, b.size)
            for (index in 0 until length) {
                val x = a.getOrElse(index) { 0L }
                val y = b.getOrElse(index) { 0L }
                if (x != y) return x.compareTo(y)
            }
            return 0
        }

        /**
         * The native build marker is a free-form string such as
         * `Wireshark 4.0.10 (v4.0.10-0-g...)`.  The first dotted version token
         * is what a range is compared against.
         */
        fun extractVersionPrefix(nativeBuildMarker: String): String {
            val match = VERSION_TOKEN.find(nativeBuildMarker)
            return match?.value ?: nativeBuildMarker.trim()
        }

        /** Minimal ISO-8601 instant parser; returns epoch millis or null. */
        fun parseIso8601(value: String): Long? {
            val match = ISO8601.matchEntire(value.trim()) ?: return null
            val (year, month, day, hour, minute, second) = match.destructured
            val y = year.toIntOrNull() ?: return null
            val mo = month.toIntOrNull() ?: return null
            val d = day.toIntOrNull() ?: return null
            val h = hour.toIntOrNull() ?: return null
            val mi = minute.toIntOrNull() ?: return null
            val s = second.toIntOrNull() ?: return null
            if (mo !in 1..12 || d !in 1..31 || h > 23 || mi > 59 || s > 60) return null
            val epochDay = daysFromCivil(y, mo, d) ?: return null
            return epochDay * 86_400_000L + h * 3_600_000L + mi * 60_000L + s * 1_000L
        }

        /** Howard Hinnant's days-from-civil algorithm; no java.time on minSdk 26. */
        private fun daysFromCivil(year: Int, month: Int, day: Int): Long? {
            val daysInMonth = when (month) {
                1, 3, 5, 7, 8, 10, 12 -> 31
                4, 6, 9, 11 -> 30
                2 -> if (isLeap(year)) 29 else 28
                else -> return null
            }
            if (day > daysInMonth) return null
            val y = if (month <= 2) year - 1L else year.toLong()
            val era = Math.floorDiv(y, 400L)
            val yoe = y - era * 400L
            val mp = (month + 9) % 12
            val doy = (153L * mp + 2L) / 5L + day - 1L
            val doe = yoe * 365L + yoe / 4L - yoe / 100L + doy
            return era * 146_097L + doe - 719_468L
        }

        private fun isLeap(year: Int): Boolean =
            year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)

        private fun numericSegments(version: String): List<Long> =
            VERSION_TOKEN.find(version)?.value
                ?.split('.')
                ?.mapNotNull { it.toLongOrNull() }
                ?: listOf(0L)

        private val ID_PATTERN = Regex("^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
        private val LAYER_ID_PATTERN = Regex("^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
        private val VERSION_PATTERN = Regex("^[0-9]+(?:\\.[0-9]+){0,3}$")
        private val VERSION_TOKEN = Regex("[0-9]+(?:\\.[0-9]+)+")
        private val SHA256_PATTERN = Regex("^[0-9a-f]{64}$")
        private val BASE64_PATTERN = Regex("^[A-Za-z0-9+/]+={0,2}$")
        /** Conservative token rule: no URLs, paths, class names or expressions. */
        private val SAFE_TOKEN = Regex("^[A-Za-z0-9][A-Za-z0-9_+.-]{0,63}$")
        private val ISO8601 = Regex(
            "^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.[0-9]+)?Z$"
        )
        val PACKAGE_FILES: Set<String> = linkedSetOf(
            "playbooks.json",
            "field_aliases.json",
            "thresholds.json",
            "evaluation_expectations.json"
        )
    }
}

/** Half-open native build range: `minimum` inclusive, `maximumExclusive` exclusive. */
data class NativeBuildRange(
    val minimum: String,
    val maximumExclusive: String
) {
    fun contains(nativeVersion: String): Boolean =
        ScenarioPackageManifest.compareVersions(nativeVersion, minimum) >= 0 &&
            ScenarioPackageManifest.compareVersions(nativeVersion, maximumExclusive) < 0
}

data class ScenarioRuleLayer(
    val id: String,
    val description: String
)

data class ScenarioPackageChange(
    val version: Int,
    val summary: String,
    val publishedAt: String
)

data class ScenarioPackageSignature(
    val algorithm: String,
    val keyId: String,
    val value: String
)

// The shared strict-JSON helpers below back every playbook/package format
// boundary.  Rejections throw PlaybookValidationException, which stays an
// IllegalArgumentException with the identical English message, so existing
// readers (logs, quarantine paths, message-pinning tests) never notice —
// while the user scenario save boundary (OPT-ERR-01) can report the stable
// reason code and the rejected path instead of parsing the message.

internal fun requireExactKeys(value: JSONObject, allowed: Set<String>, path: String) {
    val unknown = value.keys().asSequence().filterNot(allowed::contains).toList()
    if (unknown.isNotEmpty()) {
        throw PlaybookValidationException(
            path = path,
            code = ScenarioValidationCodes.UNKNOWN_PROPERTIES,
            args = mapOf("properties" to unknown.joinToString()),
            errorMessage = "$path has unknown properties: ${unknown.joinToString()}"
        )
    }
    val missing = allowed.filterNot(value::has)
    if (missing.isNotEmpty()) {
        throw PlaybookValidationException(
            path = path,
            code = ScenarioValidationCodes.MISSING_PROPERTIES,
            args = mapOf("properties" to missing.joinToString()),
            errorMessage = "$path is missing properties: ${missing.joinToString()}"
        )
    }
}

internal fun JSONObject.requiredString(name: String, path: String): String =
    optString(name).takeIf { it.isNotBlank() }
        ?: throw PlaybookValidationException(
            path = "$path.$name",
            code = ScenarioValidationCodes.STRING_BLANK,
            errorMessage = "$path.$name must be a non-blank string."
        )

internal fun JSONObject.requiredInt(name: String, path: String): Int {
    val value = opt(name)
    if (value !is Number) {
        throw PlaybookValidationException(
            path = "$path.$name",
            code = ScenarioValidationCodes.EXPECTED_NUMBER,
            errorMessage = "$path.$name must be a number."
        )
    }
    return value.toInt()
}

internal fun JSONObject.requiredLong(name: String, path: String): Long {
    val value = opt(name)
    require(value is Number) { "$path.$name must be a number." }
    return value.toLong()
}

internal fun JSONObject.optionalPositiveInt(name: String, path: String): Int? {
    if (!has(name) || isNull(name)) return null
    val value = requiredInt(name, path)
    require(value > 0) { "$path.$name must be positive." }
    return value
}

internal fun JSONObject.requiredObject(name: String, path: String): JSONObject =
    optJSONObject(name) ?: throw IllegalArgumentException("$path.$name must be an object.")

internal fun JSONObject.requiredArray(name: String, path: String): JSONArray =
    optJSONArray(name)
        ?: throw PlaybookValidationException(
            path = "$path.$name",
            code = ScenarioValidationCodes.EXPECTED_ARRAY,
            errorMessage = "$path.$name must be an array."
        )

internal fun JSONObject.stringList(name: String, context: String, maxItems: Int = 64): List<String> {
    val array = requiredArray(name, context)
    if (array.length() > maxItems) {
        throw PlaybookValidationException(
            path = "$context.$name",
            code = ScenarioValidationCodes.LIST_TOO_LONG,
            args = mapOf("max" to maxItems.toString()),
            errorMessage = "$context.$name has too many items."
        )
    }
    return (0 until array.length()).map { index ->
        array.optString(index).takeIf { it.isNotBlank() }
            ?: throw PlaybookValidationException(
                path = "$context.$name[$index]",
                code = ScenarioValidationCodes.STRING_BLANK,
                errorMessage = "$context.$name[$index] must be a non-blank string."
            )
    }
}

internal fun <T> JSONArray.objects(path: String, maxItems: Int = 64, transform: (JSONObject, String) -> T): List<T> {
    if (length() > maxItems) {
        throw PlaybookValidationException(
            path = path,
            code = ScenarioValidationCodes.LIST_TOO_LONG,
            args = mapOf("max" to maxItems.toString()),
            errorMessage = "$path has too many items."
        )
    }
    return (0 until length()).map { index ->
        val item = optJSONObject(index)
            ?: throw PlaybookValidationException(
                path = "$path[$index]",
                code = ScenarioValidationCodes.EXPECTED_OBJECT,
                errorMessage = "$path[$index] must be an object."
            )
        transform(item, "$path[$index]")
    }
}
