package com.example.layanalyzer.data

import com.example.layanalyzer.ai.agent.AgentRunIdentity
import com.example.layanalyzer.ai.audit.AgentRunRecord
import com.example.layanalyzer.ai.audit.AgentToolRunRecord
import com.example.layanalyzer.model.AGENT_SESSION_SCHEMA_VERSION
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentConversationRound
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportProvenance
import com.example.layanalyzer.model.AgentSavedSession
import com.example.layanalyzer.model.AgentToolActivity
import com.example.layanalyzer.model.AgentToolActivityStatus
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.AnalysisScope
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** AI-24 section 8: atomic writes, migration, malformed isolation, cleanup. */
class AgentSessionStoreTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private fun store(now: Long = 1_000L): AgentSessionStore =
        AgentSessionStore(temporaryFolder.root, clock = { now })

    @Test
    fun `a saved report round-trips with its question, provenance and tool trace`() {
        val saved = store().save(session()).getOrThrow()

        val loaded = store().load(saved.conversationId)

        assertNotNull(loaded)
        assertEquals("Why did registration fail?", loaded!!.userQuestion)
        assertEquals("fingerprint-a", loaded.captureFingerprint)
        assertEquals("model-x", loaded.modelId)
        assertEquals(AnalysisScope.CurrentFilter, loaded.analysisScope)
        assertEquals("sip", loaded.displayFilter)
        assertEquals(1, loaded.report.findings.size)
        assertEquals(42L, loaded.report.findings.single().evidence.single().frameNumber)
        assertEquals("get_expert_info", loaded.toolSteps.single().toolName)
        assertEquals("abc123", loaded.toolSteps.single().normalizedArgumentsHash)
        assertEquals(AGENT_SESSION_SCHEMA_VERSION, loaded.schemaVersion)
    }

    @Test
    fun `an automatic recovery copy round-trips and is visible in the summary`() {
        val subject = store()
        subject.save(session().copy(autoSaved = true)).getOrThrow()

        assertTrue(subject.load("conv-1")!!.autoSaved)
        assertTrue(subject.listAll().single().autoSaved)
    }

    @Test
    fun `nothing is written until save is called`() {
        // Constructing the store must not create files: a run that completes
        // without an explicit save leaves no trace on disk.
        store()

        assertEquals(0, store().count())
        assertEquals(0L, store().totalBytes())
        assertTrue(store().listAll().isEmpty())
    }

    @Test
    fun `a half-written temporary file is not loaded and does not break the store`() {
        val subject = store()
        val saved = subject.save(session()).getOrThrow()

        // Simulate a process death during a later save: the temporary file the
        // atomic write uses is left behind, truncated.
        File(temporaryFolder.root, "partial.json.tmp").writeText("{\"conversationId\":\"broken")

        val listed = subject.listAll()

        assertEquals(1, listed.size)
        assertEquals(saved.conversationId, listed.single().conversationId)
    }

    @Test
    fun `a save that replaces an earlier one leaves exactly one file`() {
        val subject = store()
        subject.save(session(summary = "first")).getOrThrow()
        subject.save(session(summary = "second")).getOrThrow()

        assertEquals(1, subject.count())
        assertEquals("second", subject.load("conv-1")!!.report.summary)
    }

    @Test
    fun `a malformed file is skipped without hiding the readable ones`() {
        val subject = store()
        subject.save(session()).getOrThrow()
        File(temporaryFolder.root, "corrupt.json").writeText("this is not json")
        File(temporaryFolder.root, "truncated.json").writeText("{\"conversationId\":\"x\"")

        val listed = subject.listAll()

        assertEquals(1, listed.size)
        assertEquals("conv-1", listed.single().conversationId)
    }

    @Test
    fun `a future schema version is rejected rather than read with old semantics`() {
        val subject = store()
        val saved = subject.save(session()).getOrThrow()
        val file = temporaryFolder.root.listFiles()!!.single { it.name.endsWith(".json") }
        val bumped = JSONObject(file.readText())
            .put("schemaVersion", AGENT_SESSION_SCHEMA_VERSION + 1)
        file.writeText(bumped.toString())

        assertNull(subject.load(saved.conversationId))
        assertTrue(subject.listAll().isEmpty())
    }

    @Test
    fun `a missing schema version is read as version one and migrated`() {
        val subject = store()
        subject.save(session()).getOrThrow()
        val file = temporaryFolder.root.listFiles()!!.single { it.name.endsWith(".json") }
        // Shape the file as a genuine pre-schema-4 record: no version, and the
        // id lives under the legacy sessionId key.
        val legacy = JSONObject(file.readText()).apply {
            remove("schemaVersion")
            remove("autoSaved")
            put("sessionId", "agent-1")
            remove("conversationId")
        }
        file.writeText(legacy.toString())

        val loaded = subject.listAll().single()

        assertEquals("agent-1", subject.load(loaded.conversationId)!!.legacySessionId)
        assertEquals(AGENT_SESSION_SCHEMA_VERSION, subject.load(loaded.conversationId)!!.schemaVersion)
    }

    @Test
    fun `an unknown field from a newer build is ignored rather than failing the load`() {
        val subject = store()
        subject.save(session()).getOrThrow()
        val file = temporaryFolder.root.listFiles()!!.single { it.name.endsWith(".json") }
        val extended = JSONObject(file.readText())
            .put("someFutureField", "value")
            .put("anotherOne", 7)
        file.writeText(extended.toString())

        assertNotNull(subject.load("conv-1"))
    }

    @Test
    fun `listForCapture returns only the open capture's conversations`() {
        val subject = store()
        subject.save(session(id = "conv-a")).getOrThrow()
        subject.save(session(id = "conv-b").copy(captureFingerprint = "fingerprint-b")).getOrThrow()

        val forA = subject.listForCapture("fingerprint-a")
        val forB = subject.listForCapture("fingerprint-b")

        assertEquals(listOf("conv-a"), forA.map { it.conversationId })
        assertEquals(listOf("conv-b"), forB.map { it.conversationId })
        assertTrue(subject.listForCapture("").isEmpty())
    }

    @Test
    fun `matchesCapture refuses a blank fingerprint`() {
        val saved = session()

        assertTrue(saved.matchesCapture("fingerprint-a"))
        assertFalse(saved.matchesCapture(""))
        assertFalse(saved.matchesCapture("fingerprint-b"))
    }

    @Test
    fun `a session without a fingerprint is refused rather than saved unusable`() {
        val result = store().save(session().copy(captureFingerprint = ""))

        assertTrue(result.isFailure)
        assertEquals(0, store().count())
    }

    @Test
    fun `a session larger than the per-session ceiling is rejected before writing`() {
        val subject = store()

        val result = subject.save(session(summary = "x".repeat(33 * 1024 * 1024)))

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()?.message?.contains("Session too large") == true)
        assertEquals(0, subject.count())
        assertEquals(0L, subject.totalBytes())
    }

    @Test
    fun `an oversized replacement does not remove the existing session`() {
        val subject = store()
        subject.save(session(summary = "keep this report")).getOrThrow()

        val result = subject.save(session(summary = "x".repeat(33 * 1024 * 1024)))

        assertTrue(result.isFailure)
        assertEquals("keep this report", subject.load("conv-1")?.report?.summary)
    }

    @Test
    fun `clear removes only this store's files and leaves foreign ones alone`() {
        val subject = store()
        subject.save(session()).getOrThrow()
        val foreign = File(temporaryFolder.root, "not-ours.txt")
        foreign.writeText("keep me")

        subject.clear()

        assertEquals(0, subject.count())
        assertTrue(foreign.isFile)
    }

    @Test
    fun `deleting one session keeps the others`() {
        val subject = store()
        subject.save(session()).getOrThrow()
        subject.save(session(id = "conv-2")).getOrThrow()

        subject.delete("conv-1")

        assertEquals(listOf("conv-2"), subject.listAll().map { it.conversationId })
    }

    @Test
    fun `the newest sessions are kept when the cap is exceeded`() {
        val subject = AgentSessionStore(temporaryFolder.root, clock = { 1_000L }, maxSessions = 2)
        subject.save(session(id = "conv-1")).getOrThrow()
        Thread.sleep(5)
        subject.save(session(id = "conv-2")).getOrThrow()
        Thread.sleep(5)
        subject.save(session(id = "conv-3")).getOrThrow()

        assertEquals(2, subject.count())
        assertNull(subject.load("conv-1"))
        assertNotNull(subject.load("conv-3"))
    }

    @Test
    fun `the convenience overload copies provenance and the hash-only tool trace`() {
        val runRecord = AgentRunRecord(
            sessionId = "agent-7",
            captureFingerprint = "fingerprint-a",
            modelId = "model-x",
            promptVersion = "prompt-1",
            playbookVersion = "playbook-2",
            analysisScope = AnalysisScope.CurrentFilter.name,
            displayFilterApplied = true,
            startedAtMillis = 100L,
            completedAtMillis = 400L,
            toolCalls = listOf(
                AgentToolRunRecord(
                    toolName = "get_statistics",
                    normalizedArgumentsHash = "hash-1",
                    durationMillis = 12L,
                    returned = 4L,
                    total = 9L,
                    truncated = true
                )
            )
        )

        val saved = store().save(
            report = report(),
            userQuestion = "What broke?",
            runRecord = runRecord,
            captureFingerprint = "fingerprint-a",
            conversationId = "conv-explicit",
            captureDisplayName = "call.pcap",
            analysisConfigVersion = 3,
            cacheHits = setOf("hash-1"),
            latestRunId = "run-1",
            runIds = listOf("run-1"),
            createdAtMillis = 100L
        ).getOrThrow()

        assertEquals("conv-explicit", saved.conversationId)
        assertEquals("run-1", saved.latestRunId)
        assertEquals(listOf("run-1"), saved.runIds)
        assertEquals(100L, saved.createdAtMillis)
        assertTrue(saved.updatedAtMillis > 0L)
        assertEquals(3, saved.analysisConfigVersion)
        assertEquals("call.pcap", saved.captureDisplayName)
        val step = saved.toolSteps.single()
        assertEquals("get_statistics", step.toolName)
        assertTrue(step.truncated)
        assertTrue(step.cacheHit)
    }

    @Test
    fun `the stored file holds the conversation but never credentials`() {
        val subject = store()
        subject.save(session()).getOrThrow()
        val raw = temporaryFolder.root.listFiles()!!
            .single { it.name.endsWith(".json") }
            .readText()

        // A saved session is deliberately a full record of the analysis: the
        // transcript, the model exchanges and their tool payloads all persist so
        // that reopening it resumes the conversation.  The one thing that must
        // never appear is credential material, which lives in the keystore.
        val json = JSONObject(raw)
        val known = setOf(
            "schema", "schemaVersion", "conversationId", "legacySessionId",
            "latestRunId", "runIds", "createdAtMillis", "updatedAtMillis",
            "captureFingerprint", "captureDisplayName", "userQuestion", "report",
            "modelId", "promptVersion", "playbookVersion", "analysisConfigVersion",
            "analysisScope", "displayFilter", "savedAtMillis", "autoSaved", "toolSteps",
            "messages", "modelInteractions", "toolActivities", "completedSteps",
            "completedPlanSteps", "privacyMode", "sessionGeneration", "analysisPlan",
            "tokenUsage", "conversationTranscript", "rounds"
        )
        val unexpected = json.keys().asSequence().filterNot(known::contains).toList()
        assertTrue("Unexpected persisted fields: $unexpected", unexpected.isEmpty())

        val lowered = raw.lowercase()
        listOf("apikey", "api_key", "bearer", "authorization", "accesstoken", "access_token")
            .forEach { secret ->
                assertFalse("Credential-shaped key persisted: $secret", lowered.contains(secret))
            }
    }

    // ------------------------------------------------------- legacy migration

    @Test
    fun `a legacy record migrates to one independent conversation keeping its legacySessionId`() {
        writeLegacyFile(legacySessionId = "agent-3", fingerprint = "fingerprint-a", savedAt = 500L)

        val subject = store()
        val listed = subject.listAll()

        assertEquals(1, listed.size)
        val summary = listed.single()
        assertTrue(summary.conversationId.startsWith("conv_"))
        val loaded = subject.load(summary.conversationId)!!
        assertEquals("agent-3", loaded.legacySessionId)
        assertEquals("fingerprint-a", loaded.captureFingerprint)
        assertEquals(500L, loaded.createdAtMillis)
        assertEquals(AGENT_SESSION_SCHEMA_VERSION, loaded.schemaVersion)
        // The legacy file is replaced by the migrated one.
        assertEquals(1, temporaryFolder.root.listFiles()!!.count { it.name.endsWith(".json") })
    }

    @Test
    fun `migration is idempotent across repeated reads`() {
        writeLegacyFile(legacySessionId = "agent-5", fingerprint = "fingerprint-a", savedAt = 700L)
        val subject = store()

        val first = subject.listAll().single().conversationId
        val second = subject.listAll().single().conversationId

        assertEquals(first, second)
        assertEquals(1, subject.count())
    }

    @Test
    fun `two legacy records that once shared a session id migrate to distinct conversations`() {
        // The pre-schema-4 overwrite bug produced exactly this: survivors that
        // were all called agent-1.  They must not collapse into one record.
        writeLegacyFile("agent-1", "fingerprint-a", 100L, name = "one.json")
        writeLegacyFile("agent-1", "fingerprint-b", 200L, name = "two.json")

        val listed = store().listAll()

        assertEquals(2, listed.size)
        assertNotEquals(listed[0].conversationId, listed[1].conversationId)
    }

    @Test
    fun `a crash after the migration write leaves exactly one readable record`() {
        // First read migrates and removes the legacy file.  Simulate the crash
        // window by migrating, then restoring a legacy copy next to the result.
        writeLegacyFile("agent-9", "fingerprint-a", 300L, name = "legacy.json")
        val subject = store()
        val migratedId = subject.listAll().single().conversationId
        writeLegacyFile("agent-9", "fingerprint-a", 300L, name = "legacy.json")

        val listed = subject.listAll()

        // Exactly one conversation survives, under the id the first migration
        // derived — the second read recognises the restored legacy file as
        // already-migrated and removes the duplicate.
        assertEquals(1, listed.size)
        assertEquals(migratedId, listed.single().conversationId)
    }

    @Test
    fun `clear removes migrated and unmigrated files alike`() {
        writeLegacyFile("agent-old", "fingerprint-a", 100L)
        val subject = store()
        subject.save(session(id = "conv-new")).getOrThrow()

        subject.clear()

        assertEquals(0, subject.count())
        assertEquals(0L, subject.totalBytes())
    }

    @Test
    fun `a read path never evicts sessions or migrates by deleting`() {
        // Even when a save already ran the cap, a later list or load must not
        // delete anything further; eviction is a property of save, not of
        // browsing history.  Use a fresh directory so the cap has not fired.
        val dir = temporaryFolder.newFolder("over-cap")
        val subject = AgentSessionStore(dir, clock = { 1_000L }, maxSessions = 10)
        subject.save(session(id = "conv-1")).getOrThrow()
        subject.save(session(id = "conv-2")).getOrThrow()
        // Hand-add far more files than the cap without going through save.
        repeat(20) { index ->
            File(dir, "extra-$index.json").writeText(
                JSONObject()
                    .put("schema", "AgentSavedSession")
                    .put("schemaVersion", AGENT_SESSION_SCHEMA_VERSION)
                    .put("conversationId", "conv-extra-$index")
                    .put("captureFingerprint", "fingerprint-a")
                    .put("userQuestion", "q$index")
                    .put("report", JSONObject(
                        com.example.layanalyzer.ai.serialization.AgentJsonCodec.encodeReport(report())
                    ))
                    .put("savedAtMillis", 2_000L + index)
                    .toString()
            )
        }
        val before = subject.count()

        subject.listAll()
        subject.listForCapture("fingerprint-a")
        subject.load("conv-1")

        assertEquals(before, subject.count())
        assertNotNull(subject.load("conv-2"))
    }

    @Test
    fun `relaunching with fresh identities never reuses or overwrites a saved conversation`() {
        val subject = AgentSessionStore(temporaryFolder.root, clock = { 1_000L }, maxSessions = 1_000)
        val ids = (1..1_000).map { AgentRunIdentity.newConversation() }

        ids.forEach { identity ->
            subject.save(session(id = identity.conversationId)).getOrThrow()
        }

        assertEquals(1_000, ids.map { it.conversationId }.toSet().size)
        assertEquals(1_000, ids.map { it.runId }.toSet().size)
        assertEquals(1_000, subject.count())
    }

    @Test
    fun `the same content reopened from another path still finds its history`() {
        // The fingerprint is a content hash, so path never enters the query.
        val subject = store()
        subject.save(session(id = "conv-path")).getOrThrow()

        assertEquals(1, subject.listForCapture("fingerprint-a").size)
    }

    /** A pre-schema-4 record on disk: version 3, id under the sessionId key. */
    private fun writeLegacyFile(
        legacySessionId: String,
        fingerprint: String,
        savedAt: Long,
        name: String? = null
    ) {
        val json = JSONObject()
            .put("schema", "AgentSavedSession")
            .put("schemaVersion", 3)
            .put("sessionId", legacySessionId)
            .put("captureFingerprint", fingerprint)
            .put("userQuestion", "legacy question")
            .put("report", JSONObject(com.example.layanalyzer.ai.serialization.AgentJsonCodec.encodeReport(report())))
            .put("savedAtMillis", savedAt)
        val fileName = name ?: "legacy-${legacySessionId}-${savedAt}.json"
        File(temporaryFolder.root, fileName).writeText(json.toString())
    }

    private fun report(summary: String = "Registration failed at the second attempt.") = AgentReport(
        summary = summary,
        findings = listOf(
            AgentFinding(
                id = "finding-1",
                title = "401 without a follow-up REGISTER",
                severity = AgentFindingSeverity.Error,
                confidence = AgentConfidence.Medium,
                conclusion = "The client never retried after the challenge.",
                evidence = listOf(
                    AgentEvidence(
                        type = AgentEvidenceType.Frame,
                        frameNumber = 42L,
                        observation = "401 Unauthorized",
                        sourceToolCallId = "call-1"
                    )
                )
            )
        ),
        provenance = AgentReportProvenance(
            captureFingerprint = "fingerprint-a",
            scope = AnalysisScope.CurrentFilter,
            displayFilter = "sip",
            modelId = "model-x",
            promptVersion = "prompt-1",
            toolCallIds = listOf("call-1")
        )
    )

    private fun session(
        id: String = "conv-1",
        summary: String = "Registration failed at the second attempt."
    ) = AgentSavedSession(
        conversationId = id,
        captureFingerprint = "fingerprint-a",
        userQuestion = "Why did registration fail?",
        report = report(summary),
        modelId = "model-x",
        promptVersion = "prompt-1",
        analysisScope = AnalysisScope.CurrentFilter,
        displayFilter = "sip",
        toolSteps = listOf(
            com.example.layanalyzer.model.AgentSavedToolStep(
                toolName = "get_expert_info",
                normalizedArgumentsHash = "abc123",
                durationMillis = 5L,
                returnedCount = 2L,
                totalCount = 2L
            )
        ),
        savedAtMillis = 1_000L
    )

    // ------------------------------------------------- conversation round-trip

    @Test
    fun `a saved conversation round-trips with its transcript and exchanges`() {
        val subject = store()
        subject.save(conversationSession()).getOrThrow()

        val loaded = subject.load("conv-1")

        assertNotNull(loaded)
        requireNotNull(loaded)
        assertTrue(loaded.isResumable)
        assertEquals(listOf("Why did registration fail?", "The client never retried."),
            loaded.messages.map { it.content })
        assertEquals(
            listOf(AgentConversationRole.User, AgentConversationRole.Assistant),
            loaded.messages.map { it.role }
        )

        // The exchange keeps what a resumed detail view renders: the request's
        // full message list, the tool arguments and the vendor reasoning.
        val interaction = loaded.modelInteractions.single()
        assertEquals("req-1", interaction.request.requestId)
        assertEquals("get_expert_info", interaction.request.messages.last().toolName)
        assertEquals(
            "thinking about it",
            interaction.request.messages.first { it.role == AgentModelMessageRole.Assistant }
                .reasoningContent
        )
        val response = interaction.response as AgentModelResponse.ToolCalls
        val call = response.calls.single()
        assertEquals("get_expert_info", call.toolName)
        assertEquals("sip", call.arguments["filter"])
        assertEquals("thinking about it", response.reasoningContent)

        assertEquals(AgentPrivacyMode.UnredactedMetadata, loaded.privacyMode)
        assertEquals(7L, loaded.sessionGeneration)
        assertEquals("get_expert_info", loaded.toolActivities.single().toolName)
    }

    @Test
    fun `a session saved before the transcript existed loads as view-only`() {
        val subject = store()
        subject.save(session()).getOrThrow()

        val loaded = subject.load("conv-1")

        // A session with no transcript still opens — as a report to read, not a
        // conversation to continue.
        assertNotNull(loaded)
        assertFalse(requireNotNull(loaded).isResumable)
        assertTrue(loaded.messages.isEmpty())
        assertFalse(subject.listAll().single().isResumable)
    }

    @Test
    fun `a malformed transcript entry does not cost the rest of the session`() {
        val subject = store()
        subject.save(conversationSession()).getOrThrow()
        val file = temporaryFolder.root.listFiles()!!.single { it.name.endsWith(".json") }
        val json = JSONObject(file.readText())
        json.getJSONArray("messages").put(1, "not an object")
        file.writeText(json.toString())

        val loaded = subject.load("conv-1")

        assertNotNull(loaded)
        assertEquals(listOf("Why did registration fail?"),
            requireNotNull(loaded).messages.map { it.content })
    }

    // -------------------------------------------------- conversation history

    /**
     * The sanitized shape a finished round exports: no System message, no
     * vendor reasoning except the empty-string host-bootstrap marker, tool
     * results marked untrusted.
     */
    private fun sampleTranscript() = listOf(
        AgentModelMessage.user("Why did registration fail?"),
        AgentModelMessage.assistant(
            content = "",
            toolCalls = listOf(
                AgentToolCall(
                    toolCallId = "host-bootstrap-overview-1",
                    toolName = "get_capture_overview",
                    arguments = mapOf("detail" to "summary")
                )
            ),
            reasoningContent = ""
        ),
        AgentModelMessage.fromToolResult(
            AgentToolResult(
                toolCallId = "host-bootstrap-overview-1",
                toolName = "get_capture_overview",
                data = mapOf("frames" to 120L)
            ),
            content = "{\"frames\":120}"
        ),
        AgentModelMessage.assistant(content = "The client never retried.")
    )

    @Test
    fun `the persisted conversation transcript round-trips field by field`() {
        val subject = store()

        val saved = subject.save(
            report = report(),
            userQuestion = "Why did registration fail?",
            runRecord = null,
            captureFingerprint = "fingerprint-a",
            conversationId = "conv-transcript",
            conversationTranscript = sampleTranscript()
        ).getOrThrow()
        assertEquals(sampleTranscript().size, saved.conversationTranscript.size)

        val loaded = requireNotNull(store().load(saved.conversationId))
        assertEquals(AGENT_SESSION_SCHEMA_VERSION, loaded.schemaVersion)
        assertEquals(sampleTranscript().size, loaded.conversationTranscript.size)
        assertEquals("Why did registration fail?", loaded.conversationTranscript.first().content)
        assertEquals(
            "The client never retried.",
            loaded.conversationTranscript.last().content
        )
    }

    @Test
    fun `a round-tripped conversation transcript keeps trust markers and strips reasoning`() {
        val subject = store()
        subject.save(conversationSession().copy(conversationTranscript = sampleTranscript()))
            .getOrThrow()

        val transcript = requireNotNull(store().load("conv-1")).conversationTranscript

        // Field-by-field: the data classes differ only in metadata the codecs
        // deliberately keep out of storage, so compare the replayed fields.
        sampleTranscript().zip(transcript).forEach { (written, read) ->
            assertEquals(written.role, read.role)
            assertEquals(written.content, read.content)
            assertEquals(written.toolCallId, read.toolCallId)
            assertEquals(written.toolName, read.toolName)
            assertEquals(written.untrustedCaptureData, read.untrustedCaptureData)
            assertTrue(
                "reasoningContent must survive as null or an empty string",
                read.reasoningContent == null || read.reasoningContent!!.isEmpty()
            )
        }
        val toolResult = transcript.first { it.role == AgentModelMessageRole.Tool }
        assertTrue(toolResult.untrustedCaptureData)
        assertEquals("host-bootstrap-overview-1", toolResult.toolCallId)
        assertEquals("get_capture_overview", toolResult.toolName)
        val assistantWithCalls = transcript.first { it.toolCalls.isNotEmpty() }
        assertEquals(
            listOf("host-bootstrap-overview-1"),
            assistantWithCalls.toolCalls.map { it.toolCallId }
        )
        assertEquals("get_capture_overview", assistantWithCalls.toolCalls.single().toolName)
    }

    @Test
    fun `a schema four file without a conversation transcript loads resumable and empty`() {        val subject = store()
        subject.save(conversationSession().copy(conversationTranscript = sampleTranscript()))
            .getOrThrow()
        val file = temporaryFolder.root.listFiles()!!.single { it.name.endsWith(".json") }
        val legacy = JSONObject(file.readText()).apply {
            remove("conversationTranscript")
            put("schemaVersion", 4)
        }
        file.writeText(legacy.toString())

        val loaded = requireNotNull(store().load("conv-1"))

        // Nothing to replay: follow-ups degrade to the summary path, but the
        // visible conversation and its resume affordance are untouched.
        assertEquals(4, loaded.schemaVersion)
        assertTrue(loaded.conversationTranscript.isEmpty())
        assertTrue(loaded.isResumable)
        assertEquals(2, loaded.messages.size)
    }

    // ------------------------------------------------------- round archives

    @Test
    fun `archived rounds round-trip with question, report and completion time`() {
        val subject = store()
        val rounds = listOf(
            AgentConversationRound(
                question = "Why did registration fail?",
                report = report("First round conclusion."),
                completedAtMillis = 500L
            ),
            AgentConversationRound(
                question = "And what about the retransmissions?",
                report = report("Second round conclusion."),
                completedAtMillis = 900L
            )
        )

        subject.save(
            report = report("Newest conclusion."),
            userQuestion = "Follow-up",
            runRecord = null,
            captureFingerprint = "fingerprint-a",
            conversationId = "conv-rounds",
            rounds = rounds
        ).getOrThrow()

        val loaded = requireNotNull(store().load("conv-rounds"))
        assertEquals(2, loaded.rounds.size)
        assertEquals(rounds, loaded.rounds)
        // The current report is not duplicated inside the archive.
        assertEquals("Newest conclusion.", loaded.report.summary)
    }

    @Test
    fun `a schema five file without a rounds field loads with an empty archive`() {
        val subject = store()
        subject.save(conversationSession()).getOrThrow()
        val file = temporaryFolder.root.listFiles()!!.single { it.name.endsWith(".json") }
        val legacy = JSONObject(file.readText()).apply {
            remove("rounds")
            put("schemaVersion", 5)
        }
        file.writeText(legacy.toString())

        val loaded = requireNotNull(store().load("conv-1"))

        assertEquals(5, loaded.schemaVersion)
        assertTrue(loaded.rounds.isEmpty())
        assertTrue(loaded.isResumable)
    }

    private fun conversationSession() = session().copy(
        messages = listOf(
            AgentConversationItem(
                id = "m1",
                role = AgentConversationRole.User,
                content = "Why did registration fail?",
                createdAtMillis = 10L
            ),
            AgentConversationItem(
                id = "m2",
                role = AgentConversationRole.Assistant,
                content = "The client never retried.",
                createdAtMillis = 20L,
                report = report()
            )
        ),
        modelInteractions = listOf(
            AgentModelInteraction(
                id = "i1",
                turn = 1,
                request = AgentModelRequest(
                    requestId = "req-1",
                    messages = listOf(
                        AgentModelMessage.system("You analyse captures."),
                        AgentModelMessage.user("Why did registration fail?"),
                        AgentModelMessage.assistant(
                            content = "Checking expert info.",
                            toolCalls = listOf(
                                AgentToolCall(
                                    toolCallId = "call-1",
                                    toolName = "get_expert_info",
                                    arguments = mapOf("filter" to "sip")
                                )
                            ),
                            reasoningContent = "thinking about it"
                        ),
                        AgentModelMessage(
                            role = AgentModelMessageRole.Tool,
                            content = "expert info",
                            toolCallId = "call-1",
                            toolName = "get_expert_info",
                            untrustedCaptureData = true,
                            structuredContent = mapOf("warnings" to listOf(1, 2))
                        )
                    ),
                    privacyMode = AgentPrivacyMode.UnredactedMetadata
                ),
                response = AgentModelResponse.ToolCalls(
                    calls = listOf(
                        AgentToolCall(
                            toolCallId = "call-1",
                            toolName = "get_expert_info",
                            arguments = mapOf("filter" to "sip")
                        )
                    ),
                    assistantContent = "Checking expert info.",
                    reasoningContent = "thinking about it"
                )
            )
        ),
        toolActivities = listOf(
            AgentToolActivity(
                toolCallId = "call-1",
                toolName = "get_expert_info",
                status = AgentToolActivityStatus.Succeeded
            )
        ),
        privacyMode = AgentPrivacyMode.UnredactedMetadata,
        sessionGeneration = 7L
    )
}
