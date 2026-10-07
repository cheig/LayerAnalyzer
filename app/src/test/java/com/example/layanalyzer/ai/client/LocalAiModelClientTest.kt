package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class LocalAiModelClientTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    /** AI-25 §2: a model outside the app's own directories is refused. */
    @Test
    fun modelOutsideAllowedRootIsRefused() = runBlocking {
        val appRoot = temporaryFolder.newFolder("files")
        val elsewhere = temporaryFolder.newFolder("sdcard")
        val strayModel = File(elsewhere, "model.bin").apply { writeText("weights") }

        val error = clientFor(
            modelPath = strayModel.absolutePath,
            allowedRoots = listOf(appRoot.absolutePath)
        ).negotiateCapabilities()

        assertEquals(AgentErrorCode.MODEL_UNAVAILABLE, error?.code)
        assertEquals("model_path_outside_app_directory", error?.details?.get("reason"))
    }

    /**
     * A sibling directory that merely shares a prefix ("files2" vs "files") is
     * not inside the root, so prefix matching alone would wrongly accept it.
     */
    @Test
    fun siblingDirectoryWithSharedPrefixIsRefused() = runBlocking {
        val appRoot = temporaryFolder.newFolder("files")
        val lookalike = temporaryFolder.newFolder("files2")
        val strayModel = File(lookalike, "model.bin").apply { writeText("weights") }

        val error = clientFor(
            modelPath = strayModel.absolutePath,
            allowedRoots = listOf(appRoot.absolutePath)
        ).negotiateCapabilities()

        assertEquals("model_path_outside_app_directory", error?.details?.get("reason"))
    }

    @Test
    fun missingModelFileIsReportedSeparately() = runBlocking {
        val appRoot = temporaryFolder.newFolder("files")

        val error = clientFor(
            modelPath = File(appRoot, "absent.bin").absolutePath,
            allowedRoots = listOf(appRoot.absolutePath)
        ).negotiateCapabilities()

        assertEquals("model_file_not_found", error?.details?.get("reason"))
    }

    /** AI-25 §2: refuse before loading rather than risk an OOM mid-inference. */
    @Test
    fun insufficientRamRefusesBeforeLoadingModel() = runBlocking {
        val backend = RecordingBackend()
        val error = clientFor(
            backend = backend,
            probe = FakeResourceProbe(availableRamMb = 128L),
            minimumRamMb = 2048L
        ).negotiateCapabilities()

        assertEquals(AgentErrorCode.MODEL_UNAVAILABLE, error?.code)
        assertEquals("insufficient_ram", error?.details?.get("reason"))
        assertEquals(128L, error?.details?.get("availableRamMb"))
        assertEquals(2048L, error?.details?.get("requiredRamMb"))
        // The decisive part: the backend was never asked to touch the model.
        assertEquals(0, backend.detectCount)
    }

    @Test
    fun severeThermalThrottlingRefusesStartup() = runBlocking {
        val backend = RecordingBackend()
        val error = clientFor(
            backend = backend,
            probe = FakeResourceProbe(availableRamMb = 8192L, thermalStatus = 4)
        ).negotiateCapabilities()

        assertEquals("device_thermal_throttling", error?.details?.get("reason"))
        assertEquals(0, backend.detectCount)
    }

    @Test
    fun moderateThermalStatusStillStarts() = runBlocking {
        val error = clientFor(
            backend = RecordingBackend(),
            probe = FakeResourceProbe(availableRamMb = 8192L, thermalStatus = 2)
        ).negotiateCapabilities()

        assertNull(error)
    }

    /** AI-25 §4: no tool calling degrades to the AI-13 single-shot snapshot. */
    @Test
    fun textOnlyModelSelectsOneShotFallback() = runBlocking {
        val client = clientFor(backend = RecordingBackend(AiModelCapabilities.TEXT_ONLY))

        client.negotiateCapabilities()

        assertFalse(client.capabilities.toolCalling)
        assertTrue(client.oneShotFallback)
    }

    @Test
    fun toolCallingModelKeepsFullAgentLoop() = runBlocking {
        val detected = AiModelCapabilities(
            toolCalling = true,
            structuredOutput = true,
            maxContextTokens = 8_192,
            maxOutputTokens = 2_048
        )
        val client = clientFor(backend = RecordingBackend(detected))

        client.negotiateCapabilities()

        assertEquals(detected, client.capabilities)
        assertFalse(client.oneShotFallback)
    }

    /**
     * An on-device model is allowed in every privacy mode: LocalOnly is
     * satisfied by construction, and the stricter modes only add redaction that
     * the tool runner already applied upstream.
     */
    @Test
    fun everyPrivacyModeIsAccepted() = runBlocking {
        val client = clientFor(backend = RecordingBackend()).apply { negotiateCapabilities() }

        listOf(
            AgentPrivacyMode.LocalOnly,
            AgentPrivacyMode.RedactedMetadata,
            AgentPrivacyMode.SelectedPayload
        ).forEach { mode ->
            val response = client.respond(request(requestId = "req-${mode.name}", privacyMode = mode))
            assertTrue("$mode should reach the backend", response is AgentModelResponse.Final)
        }
    }

    @Test
    fun respondBeforeNegotiationIsRefused() = runBlocking {
        val response = clientFor(backend = RecordingBackend()).respond(request())

        assertEquals(
            "local_model_not_initialized",
            ((response as AgentModelResponse.Failure).error.details["reason"])
        )
    }

    @Test
    fun missingBackendIsReportedRatherThanAssumed() = runBlocking {
        val error = clientFor(backend = null).negotiateCapabilities()

        assertEquals("local_inference_backend_unavailable", error?.details?.get("reason"))
    }

    /**
     * AI-25 §2: a model OOM must not take down the process, because the shared
     * native Wireshark session lives in it and the user's capture is open.
     */
    @Test
    fun inferenceOutOfMemoryBecomesAnErrorNotACrash() = runBlocking {
        val client = clientFor(
            backend = RecordingBackend(failure = OutOfMemoryError("model arena"))
        ).apply { negotiateCapabilities() }

        val response = client.respond(request())

        val error = (response as AgentModelResponse.Failure).error
        assertEquals(AgentErrorCode.MODEL_UNAVAILABLE, error.code)
        assertEquals("local_model_out_of_memory", error.details["reason"])
    }

    @Test
    fun backendFailureDuringDetectionIsReported() = runBlocking {
        val error = clientFor(
            backend = RecordingBackend(detectFailure = IllegalStateException("bad header"))
        ).negotiateCapabilities()

        assertEquals("capability_detection_failed", error?.details?.get("reason"))
    }

    @Test
    fun cancelIsForwardedToBackend() = runBlocking {
        val backend = RecordingBackend()
        val client = clientFor(backend = backend).apply { negotiateCapabilities() }

        client.cancel("req-1")

        assertEquals(listOf("req-1"), backend.cancelledIds)
    }

    private fun clientFor(
        modelPath: String? = null,
        allowedRoots: List<String>? = null,
        backend: LocalInferenceBackend? = RecordingBackend(),
        probe: DeviceResourceProbe = FakeResourceProbe(),
        minimumRamMb: Long = 512L
    ): LocalAiModelClient {
        val root = temporaryFolder.root
        val resolvedPath = modelPath ?: File(root, "model.bin")
            .apply { if (!exists()) writeText("weights") }
            .absolutePath
        return LocalAiModelClient(
            configuration = LocalModelConfiguration(
                modelId = "test-model",
                modelPath = resolvedPath,
                minimumRamMb = minimumRamMb
            ),
            allowedRootPaths = allowedRoots ?: listOf(root.absolutePath),
            resourceProbe = probe,
            inferenceBackend = backend
        )
    }

    private fun request(
        requestId: String = "req-1",
        privacyMode: AgentPrivacyMode = AgentPrivacyMode.LocalOnly
    ) = AgentModelRequest(
        requestId = requestId,
        messages = listOf(AgentModelMessage.user("why did registration fail?")),
        privacyMode = privacyMode
    )
}

private class FakeResourceProbe(
    private val availableRamMb: Long = 4_096L,
    private val thermalStatus: Int = 0
) : DeviceResourceProbe {
    override fun availableRamMb(): Long = availableRamMb
    override fun thermalStatus(): Int = thermalStatus
}

private class RecordingBackend(
    private val capabilities: AiModelCapabilities = AiModelCapabilities.PHASE0,
    private val failure: Throwable? = null,
    private val detectFailure: Throwable? = null
) : LocalInferenceBackend {
    var detectCount: Int = 0
        private set
    val cancelledIds = mutableListOf<String>()

    override suspend fun detectCapabilities(modelFile: File): AiModelCapabilities {
        detectCount++
        detectFailure?.let { throw it }
        return capabilities
    }

    override suspend fun infer(request: AgentModelRequest): AgentModelResponse {
        failure?.let { throw it }
        return AgentModelResponse.Final(AgentReport(summary = "on-device summary"))
    }

    override fun cancel(requestId: String) {
        cancelledIds += requestId
    }
}
