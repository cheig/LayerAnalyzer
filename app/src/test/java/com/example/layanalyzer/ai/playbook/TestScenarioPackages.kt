// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64
import org.json.JSONObject

/**
 * Builds signed scenario packages for tests.
 *
 * Tests generate their own key pair and self-signed certificate, so a signature
 * that must verify and a signature that must fail are both producible without
 * any committed private key.
 */
internal object TestScenarioPackages {
    val ASSET_DIR = File("src/main/assets/${VersionedScenarioPackageStore.ASSET_DIRECTORY}")
    private val PUBLIC_KEY_PEM = File("src/main/assets/${VersionedScenarioPackageStore.PUBLIC_KEY_ASSET}")

    val availableTools: Set<String> = setOf(
        "get_capture_overview", "validate_display_filter", "get_expert_info",
        "query_packet_summaries", "search_packets", "get_packet_fields",
        "get_statistics", "get_communication_analysis", "get_follow_stream_metadata",
        "get_radio_events", "get_unified_network_timeline"
    )

    fun builtInAsset(name: String): String = File(ASSET_DIR, name).readText()

    /** A store that only knows the built-in package (no download directory). */
    fun builtInStore(
        packageRoot: File? = null,
        nativeBuildMarker: () -> String = { "" },
        appVersion: String = ScenarioPackageManifest.APP_VERSION,
        supportedAbis: List<String> = ScenarioPackageManifest.SUPPORTED_ABIS,
        clock: () -> Long = { System.currentTimeMillis() },
        trustedKeyPems: List<String> = listOf(PUBLIC_KEY_PEM.readText())
    ): VersionedScenarioPackageStore = VersionedScenarioPackageStore(
        packageRoot = packageRoot,
        assetLoader = ::builtInAsset,
        trustedKeyPems = trustedKeyPems,
        availableTools = availableTools,
        appVersion = appVersion,
        nativeBuildMarker = nativeBuildMarker,
        supportedAbis = supportedAbis,
        clock = clock
    )

    /** The shipped trust anchor plus the per-run test key. */
    fun trustAnchors(): List<String> = listOf(PUBLIC_KEY_PEM.readText(), testPublicKeyPem)

    fun sha256(content: String): String = MessageDigest.getInstance("SHA-256")
        .digest(content.toByteArray())
        .joinToString("") { byte -> "%02x".format(byte) }

    /** A minimal but valid content set, so tests can mutate one part at a time. */
    fun contentFiles(
        playbooks: String = MINIMAL_PLAYBOOKS,
        aliases: String = MINIMAL_ALIASES,
        thresholds: String = MINIMAL_THRESHOLDS,
        expectations: String = MINIMAL_EXPECTATIONS
    ): Map<String, String> = linkedMapOf(
        VersionedScenarioPackageStore.PLAYBOOKS_FILE to playbooks,
        VersionedScenarioPackageStore.ALIASES_FILE to aliases,
        VersionedScenarioPackageStore.THRESHOLDS_FILE to thresholds,
        VersionedScenarioPackageStore.EXPECTATIONS_FILE to expectations
    )

    fun manifestJson(
        files: Map<String, String>,
        keyPair: KeyPair = testKeyPair,
        packageId: String = "com.layanalyzer.scenarios.test",
        version: Int = 2,
        minimumAppVersion: String = "1.0",
        nativeMinimum: String = "4.0.0",
        nativeMaximumExclusive: String = "5.0.0",
        supportedAbis: List<String> = listOf("arm64-v8a", "x86_64"),
        expiresAt: String? = null,
        signValue: String? = null,
        hashOverrides: Map<String, String> = emptyMap()
    ): String {
        val root = JSONObject()
        root.put("schemaVersion", ScenarioPackageManifest.SCHEMA_VERSION)
        root.put("packageId", packageId)
        root.put("version", version)
        root.put("minimumAppVersion", minimumAppVersion)
        root.put("nativeBuildRange", JSONObject()
            .put("minimum", nativeMinimum)
            .put("maximumExclusive", nativeMaximumExclusive))
        root.put("supportedAbis", org.json.JSONArray(supportedAbis))
        root.put("supportedProtocols", org.json.JSONArray(listOf("sip", "tcp")))
        root.put("regions", org.json.JSONArray(listOf("any")))
        root.put("layers", org.json.JSONArray().apply {
            put(JSONObject().put("id", "general-facts").put("description", "General protocol facts."))
        })
        root.put("changes", org.json.JSONArray().apply {
            put(JSONObject()
                .put("version", version)
                .put("summary", "Test package.")
                .put("publishedAt", "2026-08-01T00:00:00Z"))
        })
        root.put("parentVersion", JSONObject.NULL)
        root.put("rollbackVersion", JSONObject.NULL)
        root.put("publishedAt", "2026-08-01T00:00:00Z")
        root.put("expiresAt", expiresAt ?: JSONObject.NULL)
        root.put("files", JSONObject().apply {
            files.forEach { (name, content) -> put(name, hashOverrides[name] ?: sha256(content)) }
        })

        val unsigned = ScenarioPackageManifest.decode(
            JSONObject(root.toString()).put(
                "signature",
                JSONObject()
                    .put("algorithm", ScenarioPackageManifest.SIGNATURE_ALGORITHM)
                    .put("keyId", "test")
                    .put("value", "AA==")
            ).toString()
        )
        val signature = signValue ?: sign(unsigned.canonicalSignedBytes(), keyPair)
        return root.put(
            "signature",
            JSONObject()
                .put("algorithm", ScenarioPackageManifest.SIGNATURE_ALGORITHM)
                .put("keyId", "test")
                .put("value", signature)
        ).toString()
    }

    fun manifest(expiresAt: String? = null): ScenarioPackageManifest {
        val files = contentFiles()
        return ScenarioPackageManifest.decode(manifestJson(files, expiresAt = expiresAt))
    }

    private fun sign(payload: ByteArray, keyPair: KeyPair): String {
        val signature = Signature.getInstance(ScenarioPackageManifest.SIGNATURE_ALGORITHM)
        signature.initSign(keyPair.private)
        signature.update(payload)
        return Base64.getEncoder().encodeToString(signature.sign())
    }

    val testKeyPair: KeyPair by lazy {
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    }

    /** SubjectPublicKeyInfo PEM for [testKeyPair]; the store accepts it directly. */
    val testPublicKeyPem: String by lazy {
        val encoded = Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(testKeyPair.public.encoded)
        "-----BEGIN PUBLIC KEY-----\n$encoded\n-----END PUBLIC KEY-----\n"
    }

    val MINIMAL_PLAYBOOKS: String = """
        {"schemaVersion":2,"playbooks":[{
          "id":"general-capture-health","version":1,"title":"General capture health",
          "intentHints":["capture health"],"protocols":["any"],
          "initialTools":["get_capture_overview"],"requiredFields":[],
          "checks":[{"id":"health","description":"Read the overview","recommendedTools":["get_statistics"]}],
          "successPath":["Read the overview first"],"failureBranches":[],
          "requiredLimitations":["Conclusions require tool evidence."],
          "outputSections":["summary","limitations"]
        }]}
    """.trimIndent()

    val MINIMAL_ALIASES: String = """
        {"schemaVersion":1,"aliases":[
          {"alias":"sip.call_id","field":"sip.Call-ID","region":"any","notes":"Lowercase spelling."}
        ]}
    """.trimIndent()

    val MINIMAL_THRESHOLDS: String = """
        {"schemaVersion":1,"thresholds":[
          {"id":"capture.health.attentionpercent","playbookId":"general-capture-health","value":5,
           "unit":"percent","region":"any","notes":"Review signal only."}
        ]}
    """.trimIndent()

    val MINIMAL_EXPECTATIONS: String = """
        {"schemaVersion":1,"expectations":[
          {"playbookId":"general-capture-health","goldenScenarioIds":["capture_truncated_start"],
           "syntheticOnly":false,"notes":"Pins the no-evidence boundary."}
        ]}
    """.trimIndent()
}
