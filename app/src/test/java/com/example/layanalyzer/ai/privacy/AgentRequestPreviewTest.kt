// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.privacy

import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentPrivacyMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentRequestPreviewTest {
    @Test
    fun previewCountsRequestDataButNeverShowsCredentialValues() {
        val request = AgentModelRequest(
            requestId = "preview",
            messages = listOf(
                AgentModelMessage(
                    role = AgentModelMessageRole.Tool,
                    content = "{safe}",
                    toolName = "get_packet_fields",
                    untrustedCaptureData = true,
                    structuredContent = mapOf(
                        "data" to mapOf(
                            "packetCount" to 4,
                            "host" to "host-a.invalid",
                            "authorization" to mapOf("present" to true, "scheme" to "Digest", "value" to "secret")
                        )
                    )
                )
            ),
            privacyMode = AgentPrivacyMode.RedactedMetadata
        )

        val preview = AgentRequestPreviewBuilder.build(request)

        assertEquals(1, preview.categories.first { it.category == AgentDataSensitivity.Aggregate }.itemCount)
        assertTrue(preview.categories.any { it.category == AgentDataSensitivity.Identifier })
        val credential = preview.categories.first { it.category == AgentDataSensitivity.Credential }
        assertEquals(1, credential.itemCount)
        assertTrue(credential.examples.isEmpty())
        assertFalse(preview.hasCredentialExample)
        assertTrue(preview.toolNames.contains("get_packet_fields"))
    }

    @Test
    fun previewHasStableMessageCountsAndTokenEstimate() {
        val request = AgentModelRequest(
            requestId = "preview",
            messages = listOf(AgentModelMessage.user("12345678")),
            privacyMode = AgentPrivacyMode.RedactedMetadata
        )

        val preview = AgentRequestPreviewBuilder.build(request)

        assertEquals(8, preview.totalCharacters)
        assertEquals(2, preview.estimatedTokens)
        assertEquals(8, preview.messages.single().characterCount)
        assertEquals(AgentModelMessageRole.User, preview.messages.single().role)
    }

    @Test
    fun unredactedMetadataPreviewsTheSameAllowedCategoriesAsRedactedMetadata() {
        val preview = AgentRequestPreviewBuilder.build(
            AgentModelRequest(
                requestId = "preview",
                messages = listOf(AgentModelMessage.user("question")),
                privacyMode = AgentPrivacyMode.UnredactedMetadata
            )
        )

        assertTrue(preview.categories.any { it.category == AgentDataSensitivity.Aggregate })
        assertTrue(preview.categories.any { it.category == AgentDataSensitivity.Metadata })
        assertTrue(preview.categories.any { it.category == AgentDataSensitivity.Identifier })
        assertFalse(preview.categories.any { it.category == AgentDataSensitivity.Payload })
    }
}
