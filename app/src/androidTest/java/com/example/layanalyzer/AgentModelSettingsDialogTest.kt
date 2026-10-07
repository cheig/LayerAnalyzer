package com.example.layanalyzer

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.ai.agent.AgentModelConfig
import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.ai.agent.AgentProviderConfig
import com.example.layanalyzer.ai.agent.AgentSettings
import com.example.layanalyzer.ui.components.AgentModelSettingsDialog
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The settings dialog used to pin the provider list in its own 360dp scroller
 * and leave analysis options clipped outside it. These checks keep the retry
 * field and dump-clear action reachable after that layout is filled.
 */
@RunWith(AndroidJUnit4::class)
class AgentModelSettingsDialogTest {

    @get:Rule
    val composeRule = createAndroidComposeRule<ComponentActivity>()

    private fun string(id: Int): String = composeRule.activity.getString(id)

    private fun string(id: Int, vararg args: Any): String =
        composeRule.activity.getString(id, *args)

    @Test
    fun analysisOptionsRemainReachableWhenProvidersFillTheDialog() {
        composeRule.setContent {
            LayerAnalyzerTheme {
                AgentModelSettingsDialog(
                    settings = AgentSettings(
                        providers = listOf(
                            AgentProviderConfig(
                                id = AgentSettings.LOCAL_PROVIDER_ID,
                                name = "Local mock",
                                models = listOf(AgentModelConfig(id = "mock", name = "Mock"))
                            ),
                            AgentProviderConfig(
                                id = "cloud-a",
                                name = "Cloud A",
                                baseUrl = "https://api.example.com/v1",
                                models = listOf(AgentModelConfig(id = "gpt", name = "GPT"))
                            ),
                            AgentProviderConfig(
                                id = "cloud-b",
                                name = "Cloud B",
                                baseUrl = "https://api.other.example.com/v1",
                                models = listOf(AgentModelConfig(id = "claude", name = "Claude"))
                            )
                        )
                    ),
                    byokEnabled = true,
                    onSettingsChange = {},
                    onSaveProviderKey = { _, _ -> },
                    onClearProviderKey = {},
                    onDismiss = {},
                    debugResponseCaptureAvailable = true
                )
            }
        }

        composeRule
            .onNodeWithText(string(R.string.agent_model_retry_count))
            .performScrollTo()
            .assertIsDisplayed()
        composeRule
            .onNodeWithText(
                string(
                    R.string.agent_model_retry_count_supporting,
                    AgentPolicy.MAX_MODEL_RETRIES
                )
            )
            .performScrollTo()
            .assertIsDisplayed()
        composeRule
            .onNodeWithText(string(R.string.agent_response_dumps_clear))
            .performScrollTo()
            .assertIsDisplayed()
    }
}
