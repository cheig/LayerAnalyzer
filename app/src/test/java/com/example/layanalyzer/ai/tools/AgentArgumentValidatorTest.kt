package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.model.AgentErrorCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentArgumentValidatorTest {
    private val schema: Map<String, Any?> = mapOf(
        "type" to "object",
        "additionalProperties" to false,
        "required" to listOf("filter"),
        "properties" to mapOf(
            "filter" to mapOf("type" to "string", "maxLength" to 200),
            "limit" to mapOf("type" to "integer", "minimum" to 1, "maximum" to 100),
            "ratio" to mapOf("type" to "number", "minimum" to 0.0, "maximum" to 1.0),
            "verbose" to mapOf("type" to "boolean"),
            "sort" to mapOf(
                "type" to "string",
                "enum" to listOf("frame_ascending", "frame_descending")
            ),
            "frames" to mapOf(
                "type" to "array",
                "maxItems" to 8,
                "items" to mapOf("type" to "integer", "minimum" to 1)
            )
        )
    )

    @Test
    fun acceptsWellFormedArguments() {
        val result = AgentArgumentValidator.validate(
            schema,
            mapOf(
                "filter" to "tcp",
                "limit" to 25,
                "sort" to "frame_ascending",
                "frames" to listOf(1, 2, 3)
            )
        )

        val arguments = result.getOrNull()
        assertNull(result.errorOrNull())
        assertEquals("tcp", arguments?.get("filter"))
        assertEquals(25L, arguments?.get("limit"))
        assertEquals(listOf(1L, 2L, 3L), arguments?.get("frames"))
    }

    @Test
    fun rejectsUnknownPropertyBecauseAdditionalPropertiesIsFalse() {
        val result = AgentArgumentValidator.validate(
            schema,
            mapOf("filter" to "tcp", "sessionPtr" to 140_733_193_388_032L)
        )

        val error = result.errorOrNull()
        assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, error?.code)
        assertEquals("arguments.sessionPtr", error?.details?.get("path"))
    }

    @Test
    fun rejectsMissingRequiredProperty() {
        val error = AgentArgumentValidator.validate(schema, mapOf("limit" to 5)).errorOrNull()

        assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, error?.code)
        assertEquals("arguments.filter", error?.details?.get("path"))
        assertEquals("is required", error?.details?.get("reason"))
    }

    @Test
    fun rejectsWrongType() {
        val error = AgentArgumentValidator.validate(
            schema,
            mapOf("filter" to 42)
        ).errorOrNull()

        assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, error?.code)
        assertEquals("must be a string", error?.details?.get("reason"))
    }

    @Test
    fun rejectsNonIntegerForIntegerField() {
        val error = AgentArgumentValidator.validate(
            schema,
            mapOf("filter" to "tcp", "limit" to 2.5)
        ).errorOrNull()

        assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, error?.code)
        assertEquals("must be an integer", error?.details?.get("reason"))
    }

    @Test
    fun reportsIndexedPathWhenArrayExceedsMaxItems() {
        val error = AgentArgumentValidator.validate(
            schema,
            mapOf("filter" to "tcp", "frames" to (1..20).toList())
        ).errorOrNull()

        assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, error?.code)
        assertEquals("arguments.frames", error?.details?.get("path"))
        assertEquals("exceeds maxItems", error?.details?.get("reason"))
        assertEquals(8, error?.details?.get("limit"))
    }

    @Test
    fun reportsElementPathForInvalidArrayItem() {
        val frames = MutableList<Any?>(6) { it + 1 }
        frames[4] = "not-a-frame"

        val error = AgentArgumentValidator.validate(
            schema,
            mapOf("filter" to "tcp", "frames" to frames)
        ).errorOrNull()

        assertEquals("arguments.frames[4]", error?.details?.get("path"))
    }

    @Test
    fun enforcesNumericBounds() {
        val tooLarge = AgentArgumentValidator.validate(
            schema,
            mapOf("filter" to "tcp", "limit" to 5_000)
        ).errorOrNull()
        assertEquals("exceeds maximum", tooLarge?.details?.get("reason"))

        val tooSmall = AgentArgumentValidator.validate(
            schema,
            mapOf("filter" to "tcp", "limit" to 0)
        ).errorOrNull()
        assertEquals("is below minimum", tooSmall?.details?.get("reason"))
    }

    @Test
    fun rejectsValueOutsideEnumWithoutEchoingIt() {
        val error = AgentArgumentValidator.validate(
            schema,
            mapOf("filter" to "tcp", "sort" to "../../etc/passwd")
        ).errorOrNull()

        assertEquals("is not an accepted value", error?.details?.get("reason"))
        assertTrue(error?.userMessage?.contains("passwd") != true)
    }

    @Test
    fun policyStringCapOverridesLargerSchemaCap() {
        val permissiveSchema: Map<String, Any?> = mapOf(
            "type" to "object",
            "properties" to mapOf(
                "filter" to mapOf("type" to "string", "maxLength" to 1_000_000)
            )
        )

        val error = AgentArgumentValidator.validate(
            permissiveSchema,
            mapOf("filter" to "a".repeat(5_000)),
            AgentPolicy(maxArgumentStringLength = 2048)
        ).errorOrNull()

        assertEquals("exceeds maxLength", error?.details?.get("reason"))
        assertEquals(2048, error?.details?.get("limit"))
    }

    @Test
    fun explicitlyDeclaredHostTruncationReturnsNormalizationMetadata() {
        val goalSchema = mapOf(
            "type" to "object",
            "required" to listOf("goal"),
            "properties" to mapOf(
                "goal" to mapOf(
                    "type" to "string",
                    "minLength" to 1,
                    "maxLength" to 8_000,
                    HOST_TRUNCATE_SCHEMA_KEY to 1_000
                )
            )
        )

        listOf(2_000, 2_049, 8_000).forEach { length ->
            val result = AgentArgumentValidator.validate(
                goalSchema,
                mapOf("goal" to "x".repeat(length))
            ) as AgentArgumentValidation.Valid
            assertEquals(1_000, (result.arguments["goal"] as String).length)
            assertEquals(length, result.normalizations.single().originalLength)
            assertEquals(1_000, result.normalizations.single().normalizedLength)
        }
    }

    @Test
    fun rejectsArgumentsNestedDeeperThanPolicyAllows() {
        var nestedSchema: Map<String, Any?> = mapOf("type" to "integer")
        var nestedValue: Any? = 1
        repeat(6) {
            nestedSchema = mapOf(
                "type" to "object",
                "properties" to mapOf("child" to nestedSchema)
            )
            nestedValue = mapOf("child" to nestedValue)
        }

        @Suppress("UNCHECKED_CAST")
        val error = AgentArgumentValidator.validate(
            nestedSchema,
            nestedValue as Map<String, Any?>,
            AgentPolicy(maxArgumentDepth = 3)
        ).errorOrNull()

        assertEquals("exceeds maxDepth", error?.details?.get("reason"))
    }

    @Test
    fun hashIgnoresKeyOrder() {
        val first = AgentArgumentValidator.normalizedArgumentsHash(
            linkedMapOf("filter" to "tcp", "limit" to 10, "frames" to listOf(1, 2))
        )
        val second = AgentArgumentValidator.normalizedArgumentsHash(
            linkedMapOf("frames" to listOf(1, 2), "limit" to 10, "filter" to "tcp")
        )

        assertEquals(first, second)
    }

    @Test
    fun hashChangesWhenAnyValueChanges() {
        val base = AgentArgumentValidator.normalizedArgumentsHash(
            mapOf("filter" to "tcp", "limit" to 10)
        )

        assertNotEquals(base, AgentArgumentValidator.normalizedArgumentsHash(mapOf("filter" to "udp", "limit" to 10)))
        assertNotEquals(base, AgentArgumentValidator.normalizedArgumentsHash(mapOf("filter" to "tcp", "limit" to 11)))
    }

    @Test
    fun hashIsSensitiveToListOrderButNotNumericRepresentation() {
        assertNotEquals(
            AgentArgumentValidator.normalizedArgumentsHash(mapOf("frames" to listOf(1, 2))),
            AgentArgumentValidator.normalizedArgumentsHash(mapOf("frames" to listOf(2, 1)))
        )
        assertEquals(
            AgentArgumentValidator.normalizedArgumentsHash(mapOf("limit" to 10)),
            AgentArgumentValidator.normalizedArgumentsHash(mapOf("limit" to 10.0))
        )
    }
}
