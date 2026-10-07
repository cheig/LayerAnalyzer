// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

import android.content.Context
import android.os.Build
import com.example.layanalyzer.ai.tools.AgentToolRegistry
import java.io.File
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** Where the active rules came from. */
enum class ScenarioPackageSource { BuiltIn, Downloaded }

/** What the user is shown about the active rule package. */
data class ScenarioPackageDescription(
    val packageId: String,
    val version: Int,
    val source: ScenarioPackageSource,
    val changeSummary: String,
    val publishedAt: String,
    val regions: List<String>,
    val supportedProtocols: List<String>,
    /** True when a downloaded package was rejected and the built-in one is in use. */
    val fallbackApplied: Boolean,
    val fallbackReason: String?,
    val downloadedAvailable: Boolean,
    val downloadedVersion: Int?
)

/** Why a candidate package was refused. Values are stable enough to assert on. */
enum class ScenarioPackageRejection {
    Malformed,
    SignatureInvalid,
    ContentHashMismatch,
    SchemaIncompatible,
    AppVersionIncompatible,
    NativeBuildIncompatible,
    AbiIncompatible,
    Expired,
    RuleValidationFailed,
    StorageFailed
}

sealed interface ScenarioPackageInstallResult {
    data class Activated(val description: ScenarioPackageDescription) : ScenarioPackageInstallResult
    data class Rejected(
        val rejection: ScenarioPackageRejection,
        val detail: String
    ) : ScenarioPackageInstallResult
}

/** One reason a package must not be released. */
data class ScenarioReleaseIssue(
    val playbookId: String,
    val reason: String
)

/** A verified, parsed package plus where it came from. */
data class ActiveScenarioPackage(
    val manifest: ScenarioPackageManifest,
    val content: ScenarioPackageContent,
    val source: ScenarioPackageSource,
    val playbooksJson: String,
    val fallbackReason: String? = null
)

/**
 * Loads the active scenario rule package: the built-in one shipped in the APK,
 * or a verified downloaded package that replaced it.
 *
 * Trust boundary — a downloaded package is only activated after **all** of:
 *
 *  1. the manifest parses under the strict declarative schema;
 *  2. its signature verifies against the public key shipped in the APK;
 *  3. every content file's SHA-256 matches the manifest's pinned hash;
 *  4. schema version, app version, native build range and ABI all match;
 *  5. the package has not expired;
 *  6. every playbook, alias and threshold passes host rule validation.
 *
 * Any failure — at install time or on a later cold start, e.g. after an app or
 * native-engine upgrade moved the compatibility window — falls back to the last
 * package that verified, and finally to the built-in one.  The previous package
 * is kept on disk until the new one has been re-read and re-verified *from
 * disk*, so a failed activation rolls back instead of leaving nothing usable.
 *
 * Nothing here is reachable from model output or capture text: installation is
 * an application API taking already-fetched bytes.  There is deliberately no
 * URL in the manifest and no network code in this class, so a rule package can
 * never point the app at another rule package.
 */
class VersionedScenarioPackageStore(
    private val packageRoot: File?,
    private val assetLoader: (String) -> String,
    /** Trust anchors in PEM form; a package must verify against one of them. */
    private val trustedKeyPems: List<String>,
    val availableTools: Set<String>,
    private val appVersion: String = ScenarioPackageManifest.APP_VERSION,
    private val nativeBuildMarker: () -> String = { "" },
    private val supportedAbis: List<String> = ScenarioPackageManifest.SUPPORTED_ABIS,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    constructor(
        context: Context,
        registry: AgentToolRegistry,
        nativeBuildMarker: () -> String = { "" }
    ) : this(
        packageRoot = File(context.filesDir, DIRECTORY_NAME),
        assetLoader = { name ->
            context.assets.open("$ASSET_DIRECTORY/$name").bufferedReader().use { it.readText() }
        },
        trustedKeyPems = listOf(
            context.assets.open(PUBLIC_KEY_ASSET).bufferedReader().use { it.readText() }
        ),
        availableTools = registry.toolNames.toSet(),
        nativeBuildMarker = nativeBuildMarker,
        supportedAbis = Build.SUPPORTED_ABIS?.toList() ?: ScenarioPackageManifest.SUPPORTED_ABIS
    )

    @Volatile
    private var cached: ActiveScenarioPackage? = null

    /** The active package, verifying the downloaded one on first use. */
    fun active(): ActiveScenarioPackage = cached ?: synchronized(this) {
        cached ?: resolveActive().also { cached = it }
    }

    fun describe(): ScenarioPackageDescription {
        val active = active()
        val downloadedManifest = runCatching { readDownloadedManifest() }.getOrNull()
        return ScenarioPackageDescription(
            packageId = active.manifest.packageId,
            version = active.manifest.version,
            source = active.source,
            changeSummary = active.manifest.latestChangeSummary,
            publishedAt = active.manifest.publishedAt,
            regions = active.manifest.regions,
            supportedProtocols = active.manifest.supportedProtocols,
            fallbackApplied = active.fallbackReason != null,
            fallbackReason = active.fallbackReason,
            downloadedAvailable = downloadedManifest != null,
            downloadedVersion = downloadedManifest?.version
        )
    }

    /** Raw, already-verified playbook JSON of the active package. */
    fun loadActivePlaybooksJson(): String = active().playbooksJson

    /** The operator/device overlay contributed by the active package. */
    fun activeOverlay(): ScenarioRulesOverlay {
        val content = active().content
        return ScenarioRulesOverlay(
            aliases = content.aliases,
            thresholds = content.thresholds
        )
    }

    /**
     * Install an already-downloaded package.  The caller supplies verified-at-
     * rest bytes; this method decides whether they may become active.
     */
    fun installDownloadedPackage(
        manifestJson: String,
        files: Map<String, String>
    ): ScenarioPackageInstallResult {
        val root = packageRoot
            ?: return rejected(ScenarioPackageRejection.StorageFailed, "No package directory is configured.")

        when (val verified = verifyCandidate(manifestJson, files)) {
            is CandidateResult.Rejected -> return ScenarioPackageInstallResult.Rejected(
                verified.rejection,
                verified.detail
            )
            is CandidateResult.Verified -> Unit
        }

        val downloadedDir = File(root, DOWNLOADED_DIRECTORY)
        val stagingDir = File(root, STAGING_DIRECTORY)
        val previousDir = File(root, PREVIOUS_DIRECTORY)
        val previousState = readState()
        return try {
            stagingDir.deleteRecursively()
            check(stagingDir.mkdirs()) { "Unable to create the staging directory." }
            File(stagingDir, MANIFEST_FILE).writeText(manifestJson)
            files.forEach { (name, content) -> File(stagingDir, name).writeText(content) }

            // Keep the previous package until the new one has been re-read from
            // disk, so a failed swap can always be rolled back.
            previousDir.deleteRecursively()
            if (downloadedDir.isDirectory) {
                check(downloadedDir.renameTo(previousDir)) { "Unable to retain the previous package." }
            }
            if (!stagingDir.renameTo(downloadedDir)) {
                restorePrevious(previousDir, downloadedDir)
                return rejected(ScenarioPackageRejection.StorageFailed, "Unable to activate the staged package.")
            }
            writeState(ScenarioPackageSource.Downloaded)

            // Re-verify from disk: what is activated must be what was written.
            val reloaded = runCatching { loadDownloadedPackage() }.getOrNull()
            if (reloaded == null) {
                downloadedDir.deleteRecursively()
                restorePrevious(previousDir, downloadedDir)
                writeState(previousState)
                cached = null
                return rejected(
                    ScenarioPackageRejection.StorageFailed,
                    "The activated package could not be re-read; the previous package was restored."
                )
            }
            previousDir.deleteRecursively()
            cached = reloaded
            ScenarioPackageInstallResult.Activated(describe())
        } catch (error: Exception) {
            stagingDir.deleteRecursively()
            restorePrevious(previousDir, downloadedDir)
            writeState(previousState)
            cached = null
            rejected(ScenarioPackageRejection.StorageFailed, error.message ?: "Package installation failed.")
        }.also {
            stagingDir.deleteRecursively()
        }
    }

    /** Remove any downloaded package and return to the built-in rules. */
    fun clearDownloadedPackage(): ScenarioPackageDescription {
        packageRoot?.let { root ->
            File(root, DOWNLOADED_DIRECTORY).deleteRecursively()
            File(root, PREVIOUS_DIRECTORY).deleteRecursively()
            File(root, STAGING_DIRECTORY).deleteRecursively()
            File(root, STATE_FILE).delete()
        }
        cached = null
        return describe()
    }

    /**
     * Release gate input: every playbook must be pinned by a Golden scenario or
     * explicitly marked as covered by synthetic deterministic checks, and every
     * referenced Golden scenario must exist.
     */
    fun releaseIssues(availableGoldenScenarioIds: Set<String>): List<ScenarioReleaseIssue> {
        val content = active().content
        val issues = mutableListOf<ScenarioReleaseIssue>()
        content.playbooks.forEach { playbook ->
            val expectation = content.expectationFor(playbook.id)
            if (expectation == null) {
                issues += ScenarioReleaseIssue(
                    playbook.id,
                    "No evaluation expectation is declared for this scenario."
                )
                return@forEach
            }
            if (expectation.goldenScenarioIds.isEmpty() && !expectation.syntheticOnly) {
                issues += ScenarioReleaseIssue(
                    playbook.id,
                    "No Golden capture is pinned and the scenario is not marked synthetic-only."
                )
            }
            expectation.goldenScenarioIds
                .filterNot(availableGoldenScenarioIds::contains)
                .forEach { missing ->
                    issues += ScenarioReleaseIssue(
                        playbook.id,
                        "Golden scenario $missing is declared but not available."
                    )
                }
        }
        return issues
    }

    private fun resolveActive(): ActiveScenarioPackage {
        if (readState() == ScenarioPackageSource.Downloaded) {
            val downloaded = runCatching { loadDownloadedPackage() }
            downloaded.getOrNull()?.let { return it }
            val reason = downloaded.exceptionOrNull()?.message
                ?: "The downloaded rule package could not be verified."
            return loadBuiltInPackage(fallbackReason = reason)
        }
        return loadBuiltInPackage(fallbackReason = null)
    }

    private fun loadBuiltInPackage(fallbackReason: String?): ActiveScenarioPackage {
        val manifest = ScenarioPackageManifest.decode(assetLoader(MANIFEST_FILE))
        val files = ScenarioPackageManifest.PACKAGE_FILES.associateWith { assetLoader(it) }
        verifyIntegrity(manifest, files)
        // Compatibility is not enforced for the built-in package: it ships with
        // this exact APK, so refusing it would leave the Agent with no rules at
        // all.  Its ranges still document what the package targets.
        return ActiveScenarioPackage(
            manifest = manifest,
            content = decodeContent(files),
            source = ScenarioPackageSource.BuiltIn,
            playbooksJson = files.getValue(PLAYBOOKS_FILE),
            fallbackReason = fallbackReason
        )
    }

    private fun loadDownloadedPackage(): ActiveScenarioPackage {
        val root = packageRoot ?: error("No package directory is configured.")
        val directory = File(root, DOWNLOADED_DIRECTORY)
        require(directory.isDirectory) { "No downloaded rule package is installed." }
        val manifest = ScenarioPackageManifest.decode(File(directory, MANIFEST_FILE).readText())
        val files = ScenarioPackageManifest.PACKAGE_FILES.associateWith { name ->
            File(directory, name).readText()
        }
        verifyIntegrity(manifest, files)
        requireCompatible(manifest)
        return ActiveScenarioPackage(
            manifest = manifest,
            content = decodeContent(files),
            source = ScenarioPackageSource.Downloaded,
            playbooksJson = files.getValue(PLAYBOOKS_FILE)
        )
    }

    private fun readDownloadedManifest(): ScenarioPackageManifest? {
        val root = packageRoot ?: return null
        val manifestFile = File(File(root, DOWNLOADED_DIRECTORY), MANIFEST_FILE)
        if (!manifestFile.isFile) return null
        return ScenarioPackageManifest.decode(manifestFile.readText())
    }

    private fun decodeContent(files: Map<String, String>): ScenarioPackageContent =
        ScenarioPackageContentCodec.decode(
            playbooksJson = files.getValue(PLAYBOOKS_FILE),
            aliasesJson = files.getValue(ALIASES_FILE),
            thresholdsJson = files.getValue(THRESHOLDS_FILE),
            expectationsJson = files.getValue(EXPECTATIONS_FILE),
            availableTools = availableTools
        )

    private fun verifyIntegrity(manifest: ScenarioPackageManifest, files: Map<String, String>) {
        require(verifySignature(manifest)) { "The rule package signature is not valid." }
        manifest.files.forEach { (name, expectedHash) ->
            val content = files[name] ?: throw IllegalArgumentException("Package file $name is missing.")
            require(sha256(content) == expectedHash) { "Package file $name does not match its pinned hash." }
        }
    }

    private fun requireCompatible(manifest: ScenarioPackageManifest) {
        require(!manifest.isExpired(clock())) { "The rule package has expired." }
        require(manifest.isCompatibleWithApp(appVersion)) {
            "The rule package requires app version ${manifest.minimumAppVersion}."
        }
        val marker = nativeBuildMarker()
        require(marker.isBlank() || manifest.isCompatibleWithNative(marker)) {
            "The rule package does not support this native engine build."
        }
        require(manifest.isCompatibleWithAbi(supportedAbis)) {
            "The rule package does not support this device ABI."
        }
    }

    private fun verifyCandidate(
        manifestJson: String,
        files: Map<String, String>
    ): CandidateResult {
        val manifest = try {
            ScenarioPackageManifest.decode(manifestJson)
        } catch (error: Exception) {
            return CandidateResult.Rejected(
                ScenarioPackageRejection.Malformed,
                error.message ?: "The rule package manifest is malformed."
            )
        }
        if (!verifySignature(manifest)) {
            return CandidateResult.Rejected(
                ScenarioPackageRejection.SignatureInvalid,
                "The rule package signature is not valid."
            )
        }
        manifest.files.forEach { (name, expectedHash) ->
            val content = files[name]
                ?: return CandidateResult.Rejected(
                    ScenarioPackageRejection.ContentHashMismatch,
                    "Package file $name is missing."
                )
            if (sha256(content) != expectedHash) {
                return CandidateResult.Rejected(
                    ScenarioPackageRejection.ContentHashMismatch,
                    "Package file $name does not match its pinned hash."
                )
            }
        }
        if (manifest.isExpired(clock())) {
            return CandidateResult.Rejected(ScenarioPackageRejection.Expired, "The rule package has expired.")
        }
        if (!manifest.isCompatibleWithApp(appVersion)) {
            return CandidateResult.Rejected(
                ScenarioPackageRejection.AppVersionIncompatible,
                "The rule package requires app version ${manifest.minimumAppVersion}."
            )
        }
        val marker = nativeBuildMarker()
        if (marker.isNotBlank() && !manifest.isCompatibleWithNative(marker)) {
            return CandidateResult.Rejected(
                ScenarioPackageRejection.NativeBuildIncompatible,
                "The rule package does not support this native engine build."
            )
        }
        if (!manifest.isCompatibleWithAbi(supportedAbis)) {
            return CandidateResult.Rejected(
                ScenarioPackageRejection.AbiIncompatible,
                "The rule package does not support this device ABI."
            )
        }
        val content = try {
            decodeContent(files)
        } catch (error: Exception) {
            return CandidateResult.Rejected(
                ScenarioPackageRejection.RuleValidationFailed,
                error.message ?: "The rule package content is not valid."
            )
        }
        return CandidateResult.Verified(manifest, content)
    }

    private fun verifySignature(manifest: ScenarioPackageManifest): Boolean {
        val payload = manifest.canonicalSignedBytes()
        val signatureBytes = runCatching {
            Base64.getDecoder().decode(manifest.signature.value)
        }.getOrNull() ?: return false
        return publicKeys().any { key ->
            runCatching {
                val signature = Signature.getInstance(ScenarioPackageManifest.SIGNATURE_ALGORITHM)
                signature.initVerify(key)
                signature.update(payload)
                signature.verify(signatureBytes)
            }.getOrDefault(false)
        }
    }

    private fun publicKeys(): List<PublicKey> = cachedPublicKeys ?: synchronized(this) {
        cachedPublicKeys ?: trustedKeyPems.mapNotNull { pem ->
            runCatching { parsePublicKey(pem) }.getOrNull()
        }.also { cachedPublicKeys = it }
    }

    @Volatile
    private var cachedPublicKeys: List<PublicKey>? = null

    /**
     * The trust anchor is shipped as PEM: either the signing certificate or a
     * bare SubjectPublicKeyInfo.  Both carry the same key; accepting both means
     * a release can rotate to a certificate-less key without a code change.
     */
    private fun parsePublicKey(pem: String): PublicKey =
        if (pem.contains(PUBLIC_KEY_HEADER)) {
            val base64 = pem.substringAfter(PUBLIC_KEY_HEADER)
                .substringBefore(PUBLIC_KEY_FOOTER)
                .filterNot { it.isWhitespace() }
            KeyFactory.getInstance("RSA")
                .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(base64)))
        } else {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(pem.byteInputStream())
                .publicKey
        }

    private fun sha256(content: String): String = MessageDigest.getInstance("SHA-256")
        .digest(content.toByteArray())
        .joinToString("") { byte -> "%02x".format(byte) }

    private fun readState(): ScenarioPackageSource {
        val root = packageRoot ?: return ScenarioPackageSource.BuiltIn
        val stateFile = File(root, STATE_FILE)
        if (!stateFile.isFile) return ScenarioPackageSource.BuiltIn
        return runCatching {
            if (stateFile.readText().trim() == DOWNLOADED_STATE) {
                ScenarioPackageSource.Downloaded
            } else {
                ScenarioPackageSource.BuiltIn
            }
        }.getOrDefault(ScenarioPackageSource.BuiltIn)
    }

    private fun writeState(source: ScenarioPackageSource) {
        val root = packageRoot ?: return
        root.mkdirs()
        File(root, STATE_FILE).writeText(
            if (source == ScenarioPackageSource.Downloaded) DOWNLOADED_STATE else BUILT_IN_STATE
        )
    }

    private fun restorePrevious(previousDir: File, downloadedDir: File) {
        if (!previousDir.isDirectory) return
        downloadedDir.deleteRecursively()
        previousDir.renameTo(downloadedDir)
    }

    private fun rejected(rejection: ScenarioPackageRejection, detail: String) =
        ScenarioPackageInstallResult.Rejected(rejection, detail)

    private sealed interface CandidateResult {
        data class Verified(
            val manifest: ScenarioPackageManifest,
            val content: ScenarioPackageContent
        ) : CandidateResult

        data class Rejected(
            val rejection: ScenarioPackageRejection,
            val detail: String
        ) : CandidateResult
    }

    companion object {
        const val ASSET_DIRECTORY = "scenario_package"
        const val PUBLIC_KEY_ASSET = "scenario_package_public_key.pem"
        const val DIRECTORY_NAME = "scenario_packages"
        const val MANIFEST_FILE = "manifest.json"
        const val PLAYBOOKS_FILE = "playbooks.json"
        const val ALIASES_FILE = "field_aliases.json"
        const val THRESHOLDS_FILE = "thresholds.json"
        const val EXPECTATIONS_FILE = "evaluation_expectations.json"

        private const val DOWNLOADED_DIRECTORY = "downloaded"
        private const val PREVIOUS_DIRECTORY = "previous"
        private const val STAGING_DIRECTORY = "staging"
        private const val STATE_FILE = "active-source"
        private const val DOWNLOADED_STATE = "downloaded"
        private const val BUILT_IN_STATE = "builtin"
        private const val PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----"
        private const val PUBLIC_KEY_FOOTER = "-----END PUBLIC KEY-----"
    }
}
