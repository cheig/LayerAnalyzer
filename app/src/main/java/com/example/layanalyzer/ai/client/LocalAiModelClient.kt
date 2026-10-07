package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import java.io.File

/**
 * Configuration for one on-device model.
 *
 * [modelPath] is expected to point at a file the host already downloaded and
 * verified. AI-25 requires integrity, licence and rollback handling around that
 * download; this client's job is to refuse anything that is not inside a
 * directory the app owns.
 */
data class LocalModelConfiguration(
    val modelId: String,
    val modelPath: String,
    val requiresGpu: Boolean = false,
    val minimumRamMb: Long = 512L,
    /** Published first-token latency used for release records (AI-25 §5). */
    val estimatedFirstTokenMillis: Long = 0L,
    /** Models below the AI-19 evaluation gate may only run as experimental. */
    val experimental: Boolean = true
) {
    init {
        require(modelId.isNotBlank()) { "modelId must not be blank." }
        require(modelPath.isNotBlank()) { "modelPath must not be blank." }
        require(minimumRamMb > 0L) { "minimumRamMb must be positive." }
    }
}

/** Device resources read before a local model is loaded. */
interface DeviceResourceProbe {
    /** Currently available RAM in MiB. */
    fun availableRamMb(): Long

    /**
     * Android thermal status, using `PowerManager.THERMAL_STATUS_*` values.
     * Return 0 (`THERMAL_STATUS_NONE`) when the platform does not report one.
     */
    fun thermalStatus(): Int
}

/**
 * Outcome of the AI-25 pre-flight check.
 *
 * A local model must never be allowed to OOM the process, because the native
 * Wireshark session lives in it: losing that costs the user their open capture.
 */
sealed interface DeviceCapabilityCheck {
    data object Sufficient : DeviceCapabilityCheck

    data class Insufficient(
        val reason: String,
        val availableRamMb: Long? = null,
        val requiredRamMb: Long? = null,
        val thermalStatus: Int? = null
    ) : DeviceCapabilityCheck
}

/**
 * On-device [AiModelClient] with capability detection and a resource pre-flight.
 *
 * AI-25 keeps this behind the same narrow boundary as every other client, so the
 * tool whitelist and evidence validation are untouched: a local model can only
 * *ask* for a tool, exactly like a cloud model.
 *
 * Three properties are enforced here rather than left to the caller:
 *
 * 1. The model file must resolve inside one of [allowedRootPaths]. Symlinks are
 *    resolved first, so a link planted inside the app directory cannot reach
 *    `/sdcard` or another app's data.
 * 2. RAM and thermal state are checked *before* the model is loaded, and a
 *    failure is a refusal rather than a load attempt.
 * 3. Capabilities are whatever the backend reports, so a model that cannot call
 *    tools degrades to the AI-13 single-shot path via [oneShotFallback] instead
 *    of being sent tool definitions it would ignore.
 *
 * There is deliberately no privacy-mode gate. `LocalOnly` means nothing leaves
 * the device, which this client satisfies by construction — it has no transport
 * and no URL. The stricter cloud modes only add redaction the tool runner has
 * already applied upstream, so refusing them would break the default
 * configuration (`RedactedMetadata`) without improving privacy.
 */
class LocalAiModelClient(
    private val configuration: LocalModelConfiguration,
    /** Absolute directories the model file may live under. */
    private val allowedRootPaths: List<String>,
    private val resourceProbe: DeviceResourceProbe,
    private val inferenceBackend: LocalInferenceBackend? = null,
    initialCapabilities: AiModelCapabilities = AiModelCapabilities.TEXT_ONLY
) : AiModelClient, AgentCapabilityNegotiator {

    override val id: String = "local:${configuration.modelId}"

    @Volatile
    private var detectedCapabilities: AiModelCapabilities = initialCapabilities

    @Volatile
    private var initialized: Boolean = false

    override val capabilities: AiModelCapabilities
        get() = detectedCapabilities

    override val negotiateBeforeRun: Boolean
        get() = true

    /** A model without tool calling still gets one restricted summary turn. */
    override val oneShotFallback: Boolean
        get() = !detectedCapabilities.toolCalling

    /** True once the pre-flight passed and capabilities were detected. */
    val isInitialized: Boolean
        get() = initialized

    override suspend fun negotiateCapabilities(): AgentError? {
        if (initialized) return null

        val modelFile = File(configuration.modelPath)
        if (!isWithinAllowedRoot(modelFile)) {
            return unavailable("model_path_outside_app_directory")
        }
        if (!modelFile.isFile) {
            return unavailable("model_file_not_found")
        }

        when (val check = checkDeviceCapability()) {
            is DeviceCapabilityCheck.Insufficient -> return AgentError(
                code = AgentErrorCode.MODEL_UNAVAILABLE,
                userMessage = "This device does not have enough free resources to run " +
                    "the on-device model. Packet browsing is unaffected.",
                retryable = true,
                details = buildMap {
                    put("reason", check.reason)
                    check.availableRamMb?.let { put("availableRamMb", it) }
                    check.requiredRamMb?.let { put("requiredRamMb", it) }
                    check.thermalStatus?.let { put("thermalStatus", it) }
                }
            )
            DeviceCapabilityCheck.Sufficient -> Unit
        }

        val backend = inferenceBackend ?: return unavailable("local_inference_backend_unavailable")

        return try {
            detectedCapabilities = backend.detectCapabilities(modelFile)
            initialized = true
            null
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            unavailable("capability_detection_failed")
        }
    }

    override suspend fun respond(request: AgentModelRequest): AgentModelResponse {
        if (request.requestId.isBlank()) {
            return AgentModelResponse.Failure(AiModelErrors.contract("blank_request_id"))
        }
        if (!initialized) {
            return AgentModelResponse.Failure(unavailable("local_model_not_initialized"))
        }
        val backend = inferenceBackend
            ?: return AgentModelResponse.Failure(unavailable("local_inference_backend_unavailable"))

        return try {
            backend.infer(request)
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (_: OutOfMemoryError) {
            // Reported rather than rethrown: the shared native Wireshark session
            // lives in this process and must survive a failed inference.
            AgentModelResponse.Failure(
                AgentError(
                    code = AgentErrorCode.MODEL_UNAVAILABLE,
                    userMessage = "The on-device model ran out of memory. " +
                        "The capture is still open.",
                    retryable = false,
                    details = mapOf("reason" to "local_model_out_of_memory")
                )
            )
        } catch (_: Throwable) {
            AgentModelResponse.Failure(unavailable("local_inference_error"))
        }
    }

    override fun cancel(requestId: String) {
        if (requestId.isBlank()) return
        inferenceBackend?.cancel(requestId)
    }

    /** AI-25: refuse to load when RAM is short or the device is throttling. */
    fun checkDeviceCapability(): DeviceCapabilityCheck {
        val availableMb = runCatching { resourceProbe.availableRamMb() }.getOrNull()
            ?: return DeviceCapabilityCheck.Insufficient("resource_probe_unavailable")
        if (availableMb < configuration.minimumRamMb) {
            return DeviceCapabilityCheck.Insufficient(
                reason = "insufficient_ram",
                availableRamMb = availableMb,
                requiredRamMb = configuration.minimumRamMb
            )
        }

        val thermal = runCatching { resourceProbe.thermalStatus() }.getOrDefault(THERMAL_STATUS_NONE)
        if (thermal >= THERMAL_STATUS_SEVERE) {
            return DeviceCapabilityCheck.Insufficient(
                reason = "device_thermal_throttling",
                availableRamMb = availableMb,
                thermalStatus = thermal
            )
        }

        return DeviceCapabilityCheck.Sufficient
    }

    /**
     * AI-25: the model may only be read from a directory the app owns.
     *
     * Both sides are canonicalized so a symlink cannot escape the sandbox, and a
     * root is matched on a path-separator boundary so `/data/user/0/app/files2`
     * does not satisfy a `/data/user/0/app/files` root.
     */
    private fun isWithinAllowedRoot(file: File): Boolean {
        val canonical = runCatching { file.canonicalPath }.getOrNull() ?: return false
        return allowedRootPaths.any { root ->
            val canonicalRoot = runCatching { File(root).canonicalPath }.getOrNull()
                ?: return@any false
            canonical == canonicalRoot ||
                canonical.startsWith(canonicalRoot.removeSuffix(File.separator) + File.separator)
        }
    }

    private fun unavailable(reason: String) = AgentError(
        code = AgentErrorCode.MODEL_UNAVAILABLE,
        userMessage = "The on-device model is unavailable.",
        retryable = false,
        details = mapOf("reason" to reason, "modelId" to configuration.modelId)
    )

    private companion object {
        /** `PowerManager.THERMAL_STATUS_NONE`. */
        const val THERMAL_STATUS_NONE = 0

        /**
         * `PowerManager.THERMAL_STATUS_SEVERE`. At this point the platform is
         * already throttling the CPU/GPU hard, so a multi-second inference would
         * both be slow and compete with the dissection engine.
         */
        const val THERMAL_STATUS_SEVERE = 4
    }
}

/**
 * The inference boundary an on-device runtime implements.
 *
 * Keeping this separate from [LocalAiModelClient] is what lets the AI-25 policy
 * (path containment, resource pre-flight, capability degradation) be tested on
 * the JVM with no model file and no device.
 */
interface LocalInferenceBackend {
    suspend fun detectCapabilities(modelFile: File): AiModelCapabilities

    suspend fun infer(request: AgentModelRequest): AgentModelResponse

    fun cancel(requestId: String)
}
