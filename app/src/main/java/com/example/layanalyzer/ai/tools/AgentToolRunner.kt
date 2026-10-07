// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentBudgetTracker
import com.example.layanalyzer.ai.agent.AgentAliasEntry
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.ai.agent.AgentSensitivityPolicy
import com.example.layanalyzer.ai.audit.isAgentFatal
import com.example.layanalyzer.ai.cache.AgentToolCache
import com.example.layanalyzer.ai.privacy.AgentPayloadRedactor
import com.example.layanalyzer.ai.privacy.AgentPrivacyPolicy
import com.example.layanalyzer.data.AgentAnalysisRepository
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentProvenance
import com.example.layanalyzer.model.AgentToolCacheKey
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withTimeout
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/** Redacted record of one tool execution, safe for logcat and audit export. */
data class AgentToolAuditEntry(
    val toolCallId: String,
    val toolName: String,
    val toolVersion: String,
    val stepIndex: Int,
    val success: Boolean,
    val errorCode: AgentErrorCode? = null,
    val normalizedArgumentsHash: String,
    val sensitivity: AgentDataSensitivity,
    val returnedCount: Long,
    val totalCount: Long,
    val truncated: Boolean,
    val resultBytes: Int,
    val durationMillis: Long,
    /** True when the payload came from the AI-24 deterministic cache. */
    val cacheHit: Boolean = false,
    val queryMode: String? = null,
    val sampled: Boolean = false,
    val normalizationCount: Int = 0,
    val normalizationPaths: List<String> = emptyList()
)

/** Sink for audit entries.  Implementations must not log raw arguments. */
fun interface AgentToolAuditLog {
    fun record(entry: AgentToolAuditEntry)
}

/**
 * The single entry point through which every model tool call must pass.
 *
 * Order of operations, per AI-03:
 *  1. resolve the tool from the fixed registry
 *  2. validate arguments against the tool's schema subset
 *  3. check sensitivity against the current privacy mode
 *  4. reserve step and detail-frame budget
 *  5. execute under withTimeout
 *  6. redact the result, then trim it and measure UTF-8 size
 *  7. attach truncated/returned/total plus provenance
 *  8. re-check the session snapshot
 *  9. record redacted audit metadata
 *
 * The owning loop may overlap different tool names. Budget, redaction and
 * per-call diagnostic state are safe for concurrent access; native access is
 * still serialized by CaptureSessionCoordinator.
 */
class AgentToolRunner(
    private val registry: AgentToolRegistry,
    private val repository: AgentAnalysisRepository,
    private val policy: AgentPolicy = AgentPolicy(),
    private val budget: AgentBudgetTracker = AgentBudgetTracker(policy),
    private val auditLog: AgentToolAuditLog? = null,
    private val clock: () -> Long = { System.currentTimeMillis() },
    /**
     * AI-24 deterministic result cache.  Null keeps the pre-AI-24 behaviour of
     * always executing, which is what the JVM tool tests want.
     */
    private val cache: AgentToolCache? = null,
    /**
     * Identity of the loaded native engine.  It takes part in the cache key so
     * a rebuilt dissector cannot serve results produced by the previous one.
     */
    private val nativeBuildMarker: String = ""
) {
    /**
     * The run's alias map, created on the first result and reused after that.
     *
     * It must be one instance for the whole run: a fresh redactor starts with an
     * empty map and would give the same host a different alias in every tool
     * result, which is exactly the correlation a model needs in order to say
     * "these two observations are the same endpoint".  It is keyed by capture
     * and run generation so a second run over the same file still produces
     * different aliases.
     *
     * Access is synchronized because different tool names may execute in
     * parallel while sharing one run-wide alias map.
     */
    private val redactorGuard = Any()
    private var redactorKey: String? = null
    private var redactor: AgentPayloadRedactor? = null
    private val unexpectedFailures = ConcurrentHashMap<String, Throwable>()
    private val executionStepIndices = ConcurrentHashMap<String, Int>()
    @Volatile
    private var investigationDelegate: AgentInvestigationDelegate? = null

    private fun redactorFor(
        privacyMode: AgentPrivacyMode,
        snapshot: AgentCaptureSnapshot
    ): AgentPayloadRedactor = synchronized(redactorGuard) {
        val key = "${privacyMode.name}|${snapshot.captureFingerprint}|${snapshot.agentRunGeneration}"
        val existing = redactor
        if (existing != null && redactorKey == key) {
            existing
        } else {
            AgentPayloadRedactor.of(privacyMode, snapshot).also {
                redactorKey = key
                redactor = it
            }
        }
    }

    /** Definitions exported to a model; never includes implementation details. */
    fun toolDefinitions() = registry.definitions()

    val budgetTracker: AgentBudgetTracker
        get() = budget

    /** Bind the one run-scoped delegate after the loop and runner are constructed. */
    fun bindInvestigationDelegate(delegate: AgentInvestigationDelegate?) {
        investigationDelegate = delegate
    }

    /**
     * Take the raw exception from the last unexpected tool failure.
     *
     * It never enters an AgentError or model message.  The Agent loop consumes
     * it immediately and turns it into the redacted diagnostics event.
     */
    fun takeUnexpectedFailure(toolCallId: String): Throwable? =
        unexpectedFailures.remove(toolCallId)

    fun takeStepIndex(toolCallId: String): Int? = executionStepIndices.remove(toolCallId)

    /** Resolve a model-visible alias while this run's local mapping is alive. */
    fun resolveAlias(alias: String): AgentAliasEntry? = synchronized(redactorGuard) {
        redactor?.resolveAlias(alias)
    }

    /**
     * Execute one call.  Every failure path returns a structured
     * [AgentToolResult]; only cancellation propagates as an exception.
     */
    suspend fun execute(
        call: AgentToolCall,
        snapshot: AgentCaptureSnapshot,
        privacyMode: AgentPrivacyMode
    ): AgentToolResult {
        val startedAt = clock()

        // 1. Registry lookup: exact match only.
        val tool = registry.find(call.toolName)
            ?: return rejected(
                call = call,
                error = AgentError(
                    code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                    userMessage = "That analysis tool is not available.",
                    retryable = false,
                    details = mapOf(
                        "reason" to "unknown_tool",
                        "availableTools" to registry.toolNames.sorted()
                    )
                ),
                snapshot = snapshot,
                startedAt = startedAt
            )

        val definition = tool.definition

        // 2. Schema validation of model-supplied arguments.
        val validation = AgentArgumentValidator.validate(
            schema = definition.inputSchema,
            arguments = call.arguments,
            policy = policy
        )
        val normalizationMetadata = when (validation) {
            is AgentArgumentValidation.Invalid -> return rejected(
                call = call,
                error = validation.error,
                snapshot = snapshot,
                startedAt = startedAt,
                definitionVersion = definition.version,
                sensitivity = definition.sensitivity
            )
            is AgentArgumentValidation.Valid -> validation
        }
        val validatedArguments = normalizationMetadata.arguments
        val argumentsHash = AgentArgumentValidator.normalizedArgumentsHash(validatedArguments)

        // 3. Privacy gate before any capture data is touched.
        AgentSensitivityPolicy.check(definition.sensitivity, privacyMode, policy)?.let { blocked ->
            return rejected(
                call = call,
                error = blocked,
                snapshot = snapshot,
                startedAt = startedAt,
                definitionVersion = definition.version,
                sensitivity = definition.sensitivity,
                argumentsHash = argumentsHash
            )
        }

        // Snapshot must already be valid before spending any budget.
        repository.assertSnapshotValid(snapshot)?.let { stale ->
            return rejected(
                call = call,
                error = stale,
                snapshot = snapshot,
                startedAt = startedAt,
                definitionVersion = definition.version,
                sensitivity = definition.sensitivity,
                argumentsHash = argumentsHash
            )
        }

        // 4. Budget reservation, including detail frames declared by the tool.
        val requestedFrames = runCatching { tool.detailFrames(validatedArguments) }
            .getOrDefault(emptyList())
        val detailRequest = runCatching { tool.detailRequest(validatedArguments) }
            .getOrNull()
        val detailRead = requestedFrames.isNotEmpty()

        // Compile filters before spending a step or entering a native query. A
        // rejected filter is an input error, not an analysis attempt.
        filterRejection(tool, validatedArguments, snapshot)?.let { invalid ->
            return rejected(
                call = call,
                error = invalid,
                snapshot = snapshot,
                startedAt = startedAt,
                definitionVersion = definition.version,
                sensitivity = definition.sensitivity,
                argumentsHash = argumentsHash
            )
        }

        val reservationResult = if (tool.consumesEvidenceStep) {
            budget.reserve(requestedFrames, detailRequest)
        } else {
            budget.reserveOrchestration()
        }
        val reservation = reservationResult.getOrElse { failure ->
            val error = (failure as? AgentBudgetTracker.BudgetExceededException)?.agentError
                ?: internalError("budget")
            return rejected(
                call = call,
                error = error,
                snapshot = snapshot,
                startedAt = startedAt,
                definitionVersion = definition.version,
                sensitivity = definition.sensitivity,
                argumentsHash = argumentsHash
            )
        }
        executionStepIndices[call.toolCallId] = reservation.stepIndex

        val context = AgentToolContext(
            toolCallId = call.toolCallId,
            toolName = definition.name,
            snapshot = snapshot,
            policy = policy,
            privacyMode = privacyMode,
            repository = repository,
            resultByteAllowance = if (requestedFrames.isEmpty()) {
                budget.resultByteAllowance()
            } else {
                budget.detailResultByteAllowance()
            },
            stepIndex = reservation.stepIndex,
            sensitivity = definition.sensitivity,
            grantedDetailFrames = if (requestedFrames.isEmpty()) null else reservation.grantedFrames,
            omittedDetailFrames = reservation.omittedFrames.sorted(),
            omittedBySessionQuota = reservation.omittedBySessionQuota,
            omittedByPerCallLimit = reservation.omittedByPerCallLimit,
            omittedByResultByteQuota = reservation.omittedByResultByteQuota,
            remainingDetailFrameQuota = reservation.remainingSessionDetailFrames,
            detailGrantLimit = reservation.detailGrantLimit,
            detailGrantReason = reservation.detailGrantReason,
            remainingDetailResultBytes = reservation.remainingDetailResultBytes,
            argumentNormalizations = normalizationMetadata.normalizations,
            clock = clock,
            investigationDelegate = investigationDelegate
        )

        // The session detail quota is exhausted and nothing requested is free:
        // answer with an explicit empty account instead of dissecting nothing
        // silently or failing the call.  The model can see the omission, the
        // zero quota and the truncated flag, and can still conclude from what
        // earlier steps already gathered.
        //
        // The tool is never invoked here, so the payload is deliberately shaped
        // from budget facts alone — no tool-specific keys — because any tool that
        // declares detail frames can land in this branch.  The step is still
        // charged: the reservation succeeded, and refunding it would let a model
        // probe frame numbers for free once the quota ran out.
        if (requestedFrames.isNotEmpty() && reservation.grantedFrames.isEmpty()) {
            val distinctRequested = requestedFrames.toSet().sorted()
            return finish(
                call = call,
                snapshot = snapshot,
                startedAt = startedAt,
                definition = definition,
                argumentsHash = argumentsHash,
                stepIndex = reservation.stepIndex,
                privacyMode = privacyMode,
                // No packet was dissected; this is a budget-accounting response.
                // It must remain available even when the detail-result quota is
                // already exhausted, so it is charged only to the global result
                // budget.
                detailRead = false,
                result = AgentToolResult(
                    toolCallId = call.toolCallId,
                    toolName = definition.name,
                    success = true,
                    data = mapOf(
                        "detailBudgetExhausted" to true,
                        "requestedFrames" to distinctRequested,
                        "requested" to distinctRequested.size,
                        "granted" to 0,
                        "omittedFrames" to reservation.omittedFrames.sorted(),
                        "omittedByBudget" to true,
                        "omittedBySessionQuota" to reservation.omittedBySessionQuota,
                        "omittedByPerCallLimit" to reservation.omittedByPerCallLimit,
                        "omittedByResultByteQuota" to reservation.omittedByResultByteQuota,
                        "remainingFrameQuota" to reservation.remainingSessionDetailFrames,
                        "detailGrantLimit" to reservation.detailGrantLimit,
                        "detailGrantReason" to reservation.detailGrantReason,
                        "remainingDetailResultBytes" to reservation.remainingDetailResultBytes,
                        "returned" to 0,
                        "total" to distinctRequested.size,
                        "truncated" to true
                    ),
                    truncated = true,
                    sensitivity = definition.sensitivity,
                    returnedCount = 0L,
                    totalCount = distinctRequested.size.toLong()
                )
            )
        }

        // 4c. Deterministic cache lookup (AI-24).
        //
        // The cache holds the tool's own raw payload, so a hit rejoins the
        // normal path at `finish` and is redacted, truncated, counted and
        // stamped with provenance derived from *this* run's snapshot.  That is
        // what keeps a hit indistinguishable from a fresh execution: nothing
        // downstream of here can tell the difference, and a result cached under
        // one privacy mode is re-redacted for the mode in force now.
        val cacheKey = cacheKeyFor(definition, snapshot, argumentsHash)
        if (cacheKey != null) {
            cache?.get(cacheKey, definition.sensitivity)?.let { cached ->
                return finish(
                    call = call,
                    snapshot = snapshot,
                    startedAt = startedAt,
                    definition = definition,
                    argumentsHash = argumentsHash,
                    stepIndex = reservation.stepIndex,
                    privacyMode = privacyMode,
                    detailRead = detailRead,
                    result = AgentToolResult(
                        toolCallId = call.toolCallId,
                        toolName = definition.name,
                        success = true,
                        data = cached.data,
                        truncated = cached.truncated,
                        sensitivity = cached.sensitivity,
                        returnedCount = cached.returnedCount,
                        totalCount = cached.totalCount,
                        queryMode = cached.queryMode
                    ),
                    cacheHit = true
                )
            }
        }

        // 5. Bounded execution. The timeout is the smaller of the tool's own
        // default, the capture-size floor and the per-step host ceiling.
        val delegated = definition.name == DelegateInvestigationTool.NAME
        val timeoutMillis = if (delegated) {
            policy.maxDelegatedInvestigationTimeoutMillis
        } else {
            calculateAgentToolTimeoutMillis(
                toolName = definition.name,
                frameCount = snapshot.frameCount,
                defaultTimeoutMillis = definition.defaultTimeoutMillis,
                maxToolTimeoutMillis = policy.maxToolTimeoutMillis
            )
        }

        val cancellationHandle = currentCoroutineContext()[Job]?.invokeOnCompletion { cause ->
            if (cause is CancellationException) {
                // JNI is synchronous and cannot observe coroutine cancellation
                // until its native loop is told to stop explicitly.
                    if (!delegated) repository.cancelLongRunningOperations()
            }
        }
        val rawResult = try {
            if (delegated) {
                // The owning AgentLoop enforces the delegate deadline and can
                // return its last immutable child snapshot. An outer generic
                // timeout would cancel that recovery path before it can return.
                tool.execute(validatedArguments, context)
            } else withTimeout(timeoutMillis) {
                val timeoutCancellationHandle = currentCoroutineContext()[Job]?.invokeOnCompletion { cause ->
                    if (cause is TimeoutCancellationException && !delegated) {
                        repository.cancelLongRunningOperations()
                    }
                }
                try {
                    tool.execute(validatedArguments, context)
                } finally {
                    timeoutCancellationHandle?.dispose()
                }
            }
        } catch (timeout: TimeoutCancellationException) {
            // withTimeout signals via CancellationException; this is a tool
            // timeout, not a run cancellation, so it maps to TOOL_TIMEOUT.
            return finish(
                call = call,
                snapshot = snapshot,
                startedAt = startedAt,
                definition = definition,
                argumentsHash = argumentsHash,
                stepIndex = reservation.stepIndex,
                privacyMode = privacyMode,
                detailRead = detailRead,
                result = AgentToolResult(
                    toolCallId = call.toolCallId,
                    toolName = definition.name,
                    success = false,
                    error = AgentError(
                        code = AgentErrorCode.TOOL_TIMEOUT,
                        userMessage = "The analysis step timed out.",
                        retryable = true,
                        details = mapOf("timeoutMillis" to timeoutMillis)
                    ),
                    sensitivity = definition.sensitivity
                )
            )
        } catch (cancelled: CancellationException) {
            // The run itself was cancelled: never swallow or wrap this.
            throw cancelled
        } catch (toolFailure: AgentToolException) {
            return finish(
                call = call,
                snapshot = snapshot,
                startedAt = startedAt,
                definition = definition,
                argumentsHash = argumentsHash,
                stepIndex = reservation.stepIndex,
                privacyMode = privacyMode,
                detailRead = detailRead,
                result = AgentToolResult(
                    toolCallId = call.toolCallId,
                    toolName = definition.name,
                    success = false,
                    error = toolFailure.agentError,
                    sensitivity = definition.sensitivity
                )
            )
        } catch (failure: Throwable) {
            if (failure.isAgentFatal()) throw failure
            // Exception text may contain paths or capture data, so only a
            // generic, structured error is surfaced.
            unexpectedFailures[call.toolCallId] = failure
            return finish(
                call = call,
                snapshot = snapshot,
                startedAt = startedAt,
                definition = definition,
                argumentsHash = argumentsHash,
                stepIndex = reservation.stepIndex,
                privacyMode = privacyMode,
                detailRead = detailRead,
                result = AgentToolResult(
                    toolCallId = call.toolCallId,
                    toolName = definition.name,
                    success = false,
                    error = internalError("tool_execution"),
                    sensitivity = definition.sensitivity
                )
            )
        } finally {
            cancellationHandle?.dispose()
        }

        return finish(
            call = call,
            snapshot = snapshot,
            startedAt = startedAt,
            definition = definition,
            argumentsHash = argumentsHash,
            stepIndex = reservation.stepIndex,
            privacyMode = privacyMode,
            detailRead = detailRead,
            result = rawResult,
            cacheKey = cacheKey
        )
    }

    /** Steps 6 to 9 for both successful and failed executions. */
    private suspend fun finish(
        call: AgentToolCall,
        snapshot: AgentCaptureSnapshot,
        startedAt: Long,
        definition: AgentToolDefinition,
        argumentsHash: String,
        stepIndex: Int,
        privacyMode: AgentPrivacyMode,
        result: AgentToolResult,
        detailRead: Boolean = false,
        /** Non-null when a successful fresh result may be stored. */
        cacheKey: AgentToolCacheKey? = null,
        cacheHit: Boolean = false
    ): AgentToolResult {
        // 8. Re-check the session; a capture swap mid-read invalidates the data.
        repository.assertSnapshotValid(snapshot)?.let { stale ->
            return rejected(
                call = call,
                error = stale,
                snapshot = snapshot,
                startedAt = startedAt,
                definitionVersion = definition.version,
                sensitivity = definition.sensitivity,
                argumentsHash = argumentsHash,
                stepIndex = stepIndex
            )
        }

        if (!result.success || result.data == null) {
            val error = result.error ?: internalError("missing_result")
            return rejected(
                call = call,
                error = error,
                snapshot = snapshot,
                startedAt = startedAt,
                definitionVersion = definition.version,
                sensitivity = definition.sensitivity,
                argumentsHash = argumentsHash,
                stepIndex = stepIndex
            )
        }

        // 6a. Privacy enforcement.  This is the whole point of doing it here
        // rather than in each tool: a tool returns real values and stays simple,
        // and a new tool cannot forget to opt in.  It also runs *before*
        // truncation, so the byte budget measures the bytes that will actually
        // be sent, and a trim can never cut an alias in half and leave the
        // fragment of a real value behind.
        val redactedData = AgentPrivacyPolicy.redactIfNeeded(
            data = result.data,
            sensitivity = definition.sensitivity,
            privacyMode = privacyMode,
            snapshot = snapshot,
            redactor = redactorFor(privacyMode, snapshot)
        )

        // 6b. Structure-first trim, then a real UTF-8 byte measurement.
        val allowance = minOf(
            policy.maxToolResultBytes,
            if (detailRead) budget.detailResultByteAllowance() else budget.resultByteAllowance()
        ).coerceAtLeast(1)
        val outcome = AgentResultTruncator.truncate(redactedData, allowance)

        if (outcome.overflowed) {
            return rejected(
                call = call,
                error = AgentError(
                    code = AgentErrorCode.TOOL_RESULT_TOO_LARGE,
                    userMessage = "The analysis result was too large to return.",
                    retryable = false,
                    details = mapOf("maxBytes" to allowance)
                ),
                snapshot = snapshot,
                startedAt = startedAt,
                definitionVersion = definition.version,
                sensitivity = definition.sensitivity,
                argumentsHash = argumentsHash,
                stepIndex = stepIndex
            )
        }

        // Only bytes actually handed to the model consume the result budget.
        // An overflow marker is an internal failure path and never leaves this
        // method, so it must not overspend a nearly exhausted allowance.
        budget.recordResultBytes(outcome.byteSize, detailRead = detailRead)

        val returnedCount = (outcome.data["returned"] as? Number)?.toLong()
            ?: result.returnedCount
        val dataTotal = (outcome.data["total"] as? Number)?.toLong()
        val totalCount = maxOf(
            result.totalCount,
            dataTotal ?: 0L,
            returnedCount
        )
        val truncation = AgentTruncation.fromData(
            data = outcome.data,
            returned = returnedCount,
            total = totalCount,
            fallbackTruncated = result.truncated || outcome.truncated
        )
        val truncated = result.truncated || outcome.truncated || truncation.truncated
        val durationMillis = (clock() - startedAt).coerceAtLeast(0L)

        // 6c. Store the *raw* payload, not the redacted and trimmed one.
        //
        // Redaction aliases are per-run and privacy-mode specific, and the trim
        // depends on how much byte budget was left at this step; caching either
        // would make a later hit return something subtly different from a fresh
        // read.  Caching the tool's own output instead means a hit re-enters
        // redaction and truncation above with the current run's parameters.
        // The tier rules in AgentCacheTier decide whether this may touch disk.
        if (cacheKey != null && !cacheHit) {
            cache?.put(
                key = cacheKey,
                data = result.data,
                sensitivity = definition.sensitivity,
                returnedCount = returnedCount,
                totalCount = result.totalCount,
                truncated = result.truncated,
                queryMode = result.queryMode,
                durationMillis = durationMillis
            )
        }

        // 7. Attach counts and provenance.
        val provenance = AgentProvenance(
            captureFingerprint = snapshot.captureFingerprint,
            localSessionReference = localSessionReference(snapshot),
            scope = snapshot.scope,
            displayFilter = snapshot.displayFilter,
            toolName = definition.name,
            toolVersion = definition.version,
            normalizedArgumentsHash = argumentsHash,
            generatedAtMillis = clock(),
            returnedCount = returnedCount,
            totalCount = totalCount,
            truncated = truncated,
            durationMillis = durationMillis,
            queryMode = result.queryMode,
            truncation = truncation
        )

        val finalResult = result.copy(
            toolCallId = call.toolCallId,
            toolName = definition.name,
            data = outcome.data,
            truncated = truncated,
            provenance = provenance,
            durationMillis = durationMillis,
            returnedCount = returnedCount,
            totalCount = totalCount,
            resultBytes = outcome.byteSize,
            truncation = truncation
        )

        // 9. Redacted audit metadata only.
        auditLog?.record(
            AgentToolAuditEntry(
                toolCallId = call.toolCallId,
                toolName = definition.name,
                toolVersion = definition.version,
                stepIndex = stepIndex,
                success = true,
                normalizedArgumentsHash = argumentsHash,
                sensitivity = finalResult.sensitivity,
                returnedCount = returnedCount,
                totalCount = totalCount,
                truncated = truncated,
                resultBytes = finalResult.resultBytes,
                durationMillis = durationMillis,
                cacheHit = cacheHit,
                queryMode = result.queryMode,
                sampled = outcome.data["sampled"] as? Boolean ?: false,
                normalizationCount = result.data.orEmpty().keys.count { it.endsWith("Normalization") },
                normalizationPaths = result.data.orEmpty().keys
                    .filter { it.endsWith("Normalization") }
                    .map { "arguments.${it.removeSuffix("Normalization")}" }
            )
        )
        return finalResult
    }

    /**
     * Compile each filter argument the call carries, in declaration order.
     * A blank filter means "no filter" and is never sent to the engine.
     * Only a genuine syntax rejection is reported here; a stale session or a
     * cancelled run is returned as its own error so the caller does not blame
     * the filter for it.
     */
    private suspend fun filterRejection(
        tool: AgentTool,
        arguments: AgentJsonObject,
        snapshot: AgentCaptureSnapshot
    ): AgentError? {
        tool.filterArgumentNames.forEach { name ->
            val candidate = (arguments[name] as? String)?.trim().orEmpty()
            if (candidate.isEmpty()) return@forEach
            val validation = repository.validateDisplayFilter(snapshot, candidate)
            if (validation is AgentAnalysisResult.Failure) {
                return validation.error
            }
        }
        return null
    }

    /**
     * Build the complete AI-24 cache key, or null when this call must not be
     * cached at all.
     *
     * A blank fingerprint means the capture identity is not established, and a
     * blank argument hash means the arguments were never normalized — in either
     * case there is no key that could be safely matched later, so the call
     * simply executes.  Sensitivity is *not* checked here; [AgentToolCache]
     * owns that decision so there is exactly one place it can be got wrong.
     */
    private fun cacheKeyFor(
        definition: AgentToolDefinition,
        snapshot: AgentCaptureSnapshot,
        argumentsHash: String
    ): AgentToolCacheKey? {
        if (cache == null) return null
        if (snapshot.captureFingerprint.isBlank() || argumentsHash.isBlank()) return null
        return AgentToolCacheKey(
            captureFingerprint = snapshot.captureFingerprint,
            analysisConfigVersion = snapshot.analysisConfigVersion,
            toolName = definition.name,
            normalizedArgumentsHash = argumentsHash,
            nativeBuildMarker = nativeBuildMarker,
            toolVersion = definition.version,
            scopeKey = "${snapshot.scope.name}|${snapshot.displayFilter}"
        )
    }

    private fun rejected(
        call: AgentToolCall,
        error: AgentError,
        snapshot: AgentCaptureSnapshot,
        startedAt: Long,
        definitionVersion: String = "1",
        sensitivity: AgentDataSensitivity = AgentDataSensitivity.Aggregate,
        argumentsHash: String = "",
        stepIndex: Int = 0
    ): AgentToolResult {
        val durationMillis = (clock() - startedAt).coerceAtLeast(0L)
        val provenance = AgentProvenance(
            captureFingerprint = snapshot.captureFingerprint,
            localSessionReference = localSessionReference(snapshot),
            scope = snapshot.scope,
            displayFilter = snapshot.displayFilter,
            toolName = call.toolName.takeIf { registry.contains(it) } ?: "",
            toolVersion = definitionVersion,
            normalizedArgumentsHash = argumentsHash,
            generatedAtMillis = clock(),
            returnedCount = 0L,
            totalCount = 0L,
            truncated = false,
            durationMillis = durationMillis
        )
        auditLog?.record(
            AgentToolAuditEntry(
                toolCallId = call.toolCallId,
                toolName = provenance.toolName,
                toolVersion = definitionVersion,
                stepIndex = stepIndex,
                success = false,
                errorCode = error.code,
                normalizedArgumentsHash = argumentsHash,
                sensitivity = sensitivity,
                returnedCount = 0L,
                totalCount = 0L,
                truncated = false,
                resultBytes = 0,
                durationMillis = durationMillis
            )
        )
        return AgentToolResult(
            toolCallId = call.toolCallId,
            toolName = provenance.toolName,
            success = false,
            data = null,
            error = error,
            truncated = false,
            sensitivity = sensitivity,
            provenance = provenance,
            durationMillis = durationMillis,
            returnedCount = 0L,
            totalCount = 0L
        )
    }

    /**
     * Host-only session reference.  It is a salted hash of the handle and
     * generation, so it is useful for correlating local audit entries but
     * carries no pointer value.  AgentModelMessage.fromToolResult strips it
     * before anything reaches a model.
     */
    private fun localSessionReference(snapshot: AgentCaptureSnapshot): String {
        val material = buildString {
            append(SESSION_REFERENCE_SALT)
            append('|')
            append(snapshot.sessionHandle)
            append('|')
            append(snapshot.sessionGeneration)
            append('|')
            append(snapshot.captureFingerprint)
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(material.toByteArray(Charsets.UTF_8))
        return digest.take(SESSION_REFERENCE_BYTES).joinToString(separator = "") { byte ->
            "%02x".format(Locale.ROOT, byte)
        }
    }

    private fun internalError(stage: String) = AgentError(
        code = AgentErrorCode.INTERNAL_ERROR,
        userMessage = "The analysis step failed.",
        retryable = true,
        details = mapOf("stage" to stage)
    )

    private companion object {
        const val SESSION_REFERENCE_SALT = "layanalyzer.agent.session"
        const val SESSION_REFERENCE_BYTES = 12
    }
}

/**
 * Full-capture Wireshark traversals have a cost proportional to frame count.
 * A fixed 30-second ceiling turns a healthy large read into a retry storm,
 * while an unbounded timeout would make cancellation unsafe. Keep a hard host
 * ceiling and scale only the heavy deterministic tools.
 *
 * This is a pure seam so the frame-size policy can be regression-tested without
 * waiting for a real native traversal.
 */
internal fun calculateAgentToolTimeoutMillis(
    toolName: String,
    frameCount: Int,
    defaultTimeoutMillis: Long,
    maxToolTimeoutMillis: Long
): Long {
    val frameFloor = if (toolName !in HEAVY_NATIVE_TOOLS) {
        defaultTimeoutMillis
    } else {
        when {
            frameCount >= 10_000 -> 180_000L
            frameCount >= 5_000 -> 90_000L
            frameCount >= 2_000 -> 60_000L
            else -> defaultTimeoutMillis
        }
    }
    return minOf(
        maxOf(defaultTimeoutMillis, frameFloor),
        maxToolTimeoutMillis
    ).coerceAtLeast(1L)
}

private val HEAVY_NATIVE_TOOLS = setOf(
    "get_capture_overview",
    "get_statistics",
    "get_communication_analysis",
    "get_expert_info",
    "get_follow_stream_metadata"
)

/** Convenience for callers that already hold a validated payload. */
internal fun AgentJsonObject.byteSize(): Int =
    AgentResultTruncator.encode(this).toByteArray(Charsets.UTF_8).size
