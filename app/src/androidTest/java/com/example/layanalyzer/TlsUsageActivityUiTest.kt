// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.pm.ActivityInfo
import android.content.res.Configuration
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import org.junit.Rule
import org.junit.Test
import org.junit.Before
import org.junit.Assume.assumeTrue

/** Regression for the VPN page disappearing with its help on Activity recreation. */
class TlsUsageActivityUiTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()
    @Before fun requireIsolatedTarget() {
        assumeTrue("Manual TLS-407 workflow requires its isolated installation", compose.activity.packageName == "com.layeranalyzer.android.tls407")
    }

    @Test fun activeHelpSurvivesActivityRecreation() {
        check(compose.activity.packageName == "com.layeranalyzer.android.tls407")
        NativeTestSupport.awaitApplicationEngine()
        fun text(id: Int) = compose.activity.getString(id)
        val home = compose.onAllNodesWithText(text(R.string.vpn_snapshot_experimental))
        if (home.fetchSemanticsNodes().isNotEmpty()) home.onFirst().performClick()
        else {
            compose.onNodeWithContentDescription(text(R.string.more_file_actions)).performClick()
            compose.onNodeWithText(text(R.string.vpn_snapshot_title)).performClick()
        }
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(text(R.string.tls_usage_help_title)))
        compose.onNodeWithText(text(R.string.tls_usage_help_title)).performClick()
        compose.onNodeWithText(text(R.string.tls_usage_help_status)).assertIsDisplayed()
        compose.activityRule.scenario.recreate()
        compose.onNodeWithText(text(R.string.tls_usage_help_status)).assertIsDisplayed()
        val initialOrientation = compose.activity.resources.configuration.orientation
        fun rotate(orientation: Int) {
            compose.activityRule.scenario.onActivity {
                it.requestedOrientation = if (orientation == Configuration.ORIENTATION_LANDSCAPE)
                    ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE else ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
            }
            compose.waitUntil(10000) {
                compose.activity.resources.configuration.orientation == orientation &&
                    compose.onAllNodesWithText(text(R.string.tls_usage_help_status)).fetchSemanticsNodes().isNotEmpty()
            }
            compose.onNodeWithText(text(R.string.tls_usage_help_status)).assertIsDisplayed()
        }
        try {
            rotate(if (initialOrientation == Configuration.ORIENTATION_PORTRAIT)
                Configuration.ORIENTATION_LANDSCAPE else Configuration.ORIENTATION_PORTRAIT)
            rotate(initialOrientation)
        } finally {
            compose.activityRule.scenario.onActivity { it.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED }
        }
        compose.onNodeWithText(text(R.string.close)).performClick()
        compose.onNodeWithText(text(R.string.vpn_snapshot_title)).assertIsDisplayed()
        compose.onNodeWithContentDescription(text(R.string.back)).performClick()
        compose.onNodeWithText(text(R.string.tls_usage_help_status)).assertDoesNotExist()
    }
}
