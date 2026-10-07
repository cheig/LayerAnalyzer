// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Verifies that the actual long license document and appended assets remain reachable. */
@RunWith(AndroidJUnit4::class)
class ThirdPartyNoticesTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun fullLicensesAndUtf8AttributionsRemainReadable() {
        compose.onNodeWithContentDescription(compose.activity.getString(R.string.preferences))
            .performClick()
        compose.onNodeWithText(compose.activity.getString(R.string.third_party_notices))
            .performClick()

        val list = compose.onNode(hasScrollToIndexAction() and hasAnyAncestor(isDialog()))
        for (text in listOf(
            "# LayerAnalyzer Third-Party Notices",
            "kotlinx.coroutines library.",
            "Version 2.0, January 2004",
            "9. Accepting Warranty or Additional Liability.",
            "APPENDIX: How to apply the Apache License to your work.",
            "Copyright (c) 2017-2020 Ingy döt Net",
            "3. This notice may not be removed or altered from any source distribution."
        )) {
            list.performScrollToNode(hasText(text, substring = true))
            compose.onAllNodesWithText(text, substring = true)[0].assertIsDisplayed()
        }
    }
}
