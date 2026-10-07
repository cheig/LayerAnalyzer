// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.agent.AgentApiType
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Contract tests for the `/models` catalog fetch used by the provider editor. */
class ProviderModelFetcherTest {

    @Test
    fun parsesOpenAiModelListAndUsesBearerAuth() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody(
                    """
                    {"object":"list","data":[
                        {"id":"model-a","object":"model","owned_by":"test"},
                        {"id":"model-b","object":"model","owned_by":"test"},
                        {"id":"model-a","object":"model","owned_by":"test"}
                    ]}
                    """.trimIndent()
                )
        )
        server.start()
        try {
            val result = fetcher().fetchModels(
                baseUrl = server.url("/v1").toString(),
                apiType = AgentApiType.OPENAI_CHAT_COMPLETIONS,
                apiKey = "secret-key"
            )

            assertEquals(
                ProviderModelFetchResult.Success(listOf("model-a", "model-b")),
                result
            )
            val recorded = server.takeRequest()
            assertEquals("/v1/models", recorded.path)
            assertEquals("Bearer secret-key", recorded.getHeader("Authorization"))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun anthropicEndpointUsesXApiKeyHeader() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody("""{"data":[{"type":"model","id":"claude-3"}]}"""))
        server.start()
        try {
            val result = fetcher().fetchModels(
                baseUrl = server.url("/v1").toString(),
                apiType = AgentApiType.ANTHROPIC_API,
                apiKey = "sk-ant"
            )

            assertTrue(result is ProviderModelFetchResult.Success)
            val recorded = server.takeRequest()
            assertEquals("/v1/models", recorded.path)
            assertEquals("sk-ant", recorded.getHeader("x-api-key"))
            assertEquals("2023-06-01", recorded.getHeader("anthropic-version"))
            assertEquals(null, recorded.getHeader("Authorization"))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun baseUrlAlreadyEndingWithModelsIsUsedAsIs() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setBody("""{"data":[{"id":"m1"}]}"""))
        server.start()
        try {
            fetcher().fetchModels(
                baseUrl = server.url("/v1/models").toString(),
                apiType = AgentApiType.OPENAI_CHAT_COMPLETIONS,
                apiKey = "k"
            )

            assertEquals("/v1/models", server.takeRequest().path)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun missingKeyIsReportedBeforeAnyNetworkCall() = runBlocking {
        val result = fetcher().fetchModels(
            baseUrl = "https://example.com/v1",
            apiType = AgentApiType.OPENAI_CHAT_COMPLETIONS,
            apiKey = "   "
        )

        assertEquals(
            ProviderModelFetchResult.Failure(ProviderModelFetchFailure.MissingApiKey),
            result
        )
    }

    @Test
    fun blankBaseUrlIsReportedAsMissing() = runBlocking {
        val result = fetcher().fetchModels(
            baseUrl = "",
            apiType = AgentApiType.OPENAI_CHAT_COMPLETIONS,
            apiKey = "k"
        )

        assertEquals(
            ProviderModelFetchResult.Failure(ProviderModelFetchFailure.MissingBaseUrl),
            result
        )
    }

    @Test
    fun http401IsMappedToAuthentication() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"bad key"}"""))
        server.start()
        try {
            val result = fetcher().fetchModels(
                baseUrl = server.url("/v1").toString(),
                apiType = AgentApiType.OPENAI_CHAT_COMPLETIONS,
                apiKey = "wrong"
            )

            assertEquals(
                ProviderModelFetchResult.Failure(ProviderModelFetchFailure.Authentication),
                result
            )
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun serverErrorAndMalformedAndEmptyResponsesAreClassified() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setResponseCode(500))
        server.enqueue(MockResponse().setBody("not json at all"))
        server.enqueue(MockResponse().setBody("""{"data":[]}"""))
        server.start()
        try {
            val fetcher = fetcher()
            assertEquals(
                ProviderModelFetchResult.Failure(ProviderModelFetchFailure.Server),
                fetcher.fetchModels(
                    server.url("/v1").toString(),
                    AgentApiType.OPENAI_CHAT_COMPLETIONS,
                    "k"
                )
            )
            assertEquals(
                ProviderModelFetchResult.Failure(ProviderModelFetchFailure.MalformedResponse),
                fetcher.fetchModels(
                    server.url("/v1").toString(),
                    AgentApiType.OPENAI_CHAT_COMPLETIONS,
                    "k"
                )
            )
            assertEquals(
                ProviderModelFetchResult.Failure(ProviderModelFetchFailure.Empty),
                fetcher.fetchModels(
                    server.url("/v1").toString(),
                    AgentApiType.OPENAI_CHAT_COMPLETIONS,
                    "k"
                )
            )
        } finally {
            server.shutdown()
        }
    }

    private fun fetcher(): ProviderModelFetcher = ProviderModelFetcher(
        transport = OkHttpAgentHttpTransport(allowInsecureHttpForTests = true)
    )
}
