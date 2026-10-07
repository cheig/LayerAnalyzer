package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.ai.serialization.AgentJsonDecodeResult
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import com.example.layanalyzer.model.AgentJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * OPT-VAL-04-01 contracts for the polarity field of the agent-report-2 schema.
 *
 * The codec-side degradation (missing/invalid polarity decodes to Unknown and
 * default-valued reports keep the version-1 byte layout) is pinned by
 * [com.example.layanalyzer.ai.AgentJsonCodecAcoFieldsTest]; this class pins the
 * prompt-schema side that OPT-ARCH-02 deliberately left open:
 *
 * 1. `polarity` is a required property of every finding, in both the full
 *    report schema and the targeted-revision schema (single shared item);
 * 2. its enum is exactly the three declared polarities — `Unknown` is a
 *    host-derived default, never a model-supplied value;
 * 3. the *other* agent-report-2 fields remain optional-with-default, so a
 *    later edit cannot silently widen the required list past this task;
 * 4. the model default and the codec's near-miss tolerance agree with the
 *    schema so a model that follows the design-doc casing still parses.
 */
class AgentPolaritySchemaContractTest {

    @Suppress("UNCHECKED_CAST")
    private fun findingsItemSchema(reportSchema: AgentJsonObject): AgentJsonObject =
        ((reportSchema.getValue("properties") as Map<String, Any?>)
            .getValue("findings") as Map<String, Any?>)
            .getValue("items") as AgentJsonObject

    @Suppress("UNCHECKED_CAST")
    private fun requiredKeys(findingSchema: AgentJsonObject): List<String> =
        (findingSchema.getValue("required") as List<*>).map { it as String }

    @Suppress("UNCHECKED_CAST")
    private fun polarityProperty(findingSchema: AgentJsonObject): AgentJsonObject =
        (findingSchema.getValue("properties") as Map<String, Any?>)
            .getValue("polarity") as AgentJsonObject

    @Test
    fun reportSchemaFindingRequiresPolarity() {
        val findingSchema = findingsItemSchema(AgentPrompt.REPORT_SCHEMA)
        assertEquals(
            listOf("id", "title", "severity", "confidence", "conclusion", "evidence", "polarity"),
            requiredKeys(findingSchema)
        )
    }

    @Test
    fun revisedFindingsSchemaSharesTheRequiredPolarity() {
        // Revisions carry the same finding shape; a model that dropped polarity
        // from corrected findings must hit the identical contract.
        val findingSchema = findingsItemSchema(AgentPrompt.REVISED_FINDINGS_SCHEMA)
        assertTrue(
            "polarity must stay required on the revision schema",
            "polarity" in requiredKeys(findingSchema)
        )
    }

    @Test
    fun polarityEnumIsTheDeclaredVocabularyWithoutUnknown() {
        val polarity = polarityProperty(findingsItemSchema(AgentPrompt.REPORT_SCHEMA))
        assertEquals("string", polarity["type"])
        val allowed = (polarity.getValue("enum") as List<*>).map { it as String }
        assertEquals(listOf("Positive", "Negative", "Neutral"), allowed)
        // Drift guard: the wire names must keep matching the Kotlin entries the
        // codec encodes with, minus the host-only Unknown.
        assertEquals(
            AgentFindingPolarity.entries
                .filter { it != AgentFindingPolarity.Unknown }
                .map { it.name }
                .sorted(),
            allowed.sorted()
        )
    }

    @Test
    fun otherAgentReport2FieldsRemainOptional() {
        val findingSchema = findingsItemSchema(AgentPrompt.REPORT_SCHEMA)
        val required = requiredKeys(findingSchema)
        assertFalse("counterEvidenceChecked must stay optional", "counterEvidenceChecked" in required)
        assertFalse("hypothesisId must stay optional", "hypothesisId" in required)
        assertFalse("relatedSignals must stay optional", "relatedSignals" in required)
        // Report-level drift guard, handed over by OPT-VAL-03-01: this pin
        // once asserted `questionAlignment` optional (the OPT-VAL-04-01
        // anti-silent-widening guard). OPT-VAL-03-01 is the named authority
        // for this widening — design §5.3 makes the field required — so the
        // guard now pins the exact report-level required list instead: any
        // future widening still cannot land silently.
        assertEquals(
            "report-level required list is pinned exactly (OPT-VAL-03-01 handoff)",
            listOf("summary", "findings", "questionAlignment"),
            (AgentPrompt.REPORT_SCHEMA.getValue("required") as List<*>).map { it as String }
        )
    }

    @Test
    fun modelDefaultIsUnknown() {
        assertEquals(AgentFindingPolarity.Unknown, AgentFinding().polarity)
    }

    @Test
    fun codecToleratesSchemaVocabularyCaseAndNearMisses() {
        // The design document names the values lower-case; the decoder must
        // accept what the schema advertises (PascalCase) as well as the casing
        // models copy from prose, while near-miss literals stay Unknown.
        fun decodePolarity(wireValue: String): AgentFindingPolarity {
            val json = """
                {
                  "schema":"AgentReport",
                  "schemaVersion":1,
                  "summary":"s",
                  "findings":[
                    {
                      "id":"f-1",
                      "title":"t",
                      "severity":"Info",
                      "confidence":"Low",
                      "conclusion":"c",
                      "polarity":"$wireValue"
                    }
                  ]
                }
            """.trimIndent()
            val decoded = AgentJsonCodec.decodeReport(json)
            assertTrue("polarity casing must not fail decoding", decoded is AgentJsonDecodeResult.Success)
            return decoded.getOrThrow().findings.single().polarity
        }

        assertEquals(AgentFindingPolarity.Positive, decodePolarity("positive"))
        assertEquals(AgentFindingPolarity.Negative, decodePolarity("Negative"))
        assertEquals(AgentFindingPolarity.Neutral, decodePolarity("NEUTRAL"))
        assertEquals(AgentFindingPolarity.Unknown, decodePolarity("positiv"))
        assertEquals(AgentFindingPolarity.Unknown, decodePolarity("Unknown"))
    }
}
