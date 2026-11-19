// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.text.TextLayoutResult
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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
        NativeTestSupport.awaitApplicationEngine()
        compose.waitUntil(10000) {
            compose.onAllNodesWithContentDescription(compose.activity.getString(R.string.preferences))
                .fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithContentDescription(compose.activity.getString(R.string.preferences))
            .performClick()
        compose.onNodeWithText(compose.activity.getString(R.string.third_party_notices))
            .performClick()

        val list = compose.onNode(hasScrollToIndexAction() and hasAnyAncestor(isDialog()))
        val pending = mutableSetOf(
            "# LayerAnalyzer Third-Party Notices",
            "kotlinx.coroutines library.",
            "Version 2.0, January 2004",
            "9. Accepting Warranty or Additional Liability.",
            "APPENDIX: How to apply the Apache License to your work.",
            "Copyright (c) 2017-2020 Ingy döt Net",
            "3. This notice may not be removed or altered from any source distribution."
        )
        // Walk forward once. Repeated performScrollToNode searches can race lazy
        // semantics traversal on the instrumentation thread in this Compose version.
        var reachedEnd = false
        var maxWidthOverrun = 0f
        var position = -1f
        var maximum = 0f
        var stalledSteps = 0
        // The shipped bundle has over 2,000 paragraphs / 8,000 source lines;
        // large fonts wrap these across more than 1,000 viewports.
        for (step in 0 until 6000) {
            if (reachedEnd) break
            val node = list.fetchSemanticsNode()
            var scrollBy = 0f
            compose.runOnIdle {
                fun visit(current: SemanticsNode) {
                    val text = current.config.getOrNull(SemanticsProperties.Text)
                        .orEmpty().joinToString("\n") { it.text }
                    val found = pending.filter { text.contains(it) }
                    if (found.isNotEmpty()) {
                        val layouts = mutableListOf<TextLayoutResult>()
                        current.config.getOrNull(SemanticsActions.GetTextLayoutResult)?.action?.invoke(layouts)
                        assertTrue("License text has a layout", layouts.isNotEmpty())
                        layouts.forEach {
                            assertFalse("License paragraph height clipped: $found", it.didOverflowHeight)
                            // Natural paragraph width is fractional; IntSize rounds it.
                            // Check actual line bounds with one physical pixel tolerance.
                            for (line in 0 until it.lineCount) {
                                val overrun = it.getLineRight(line) - it.size.width
                                maxWidthOverrun = maxOf(maxWidthOverrun, overrun)
                                assertTrue("License line width clipped: $found overrun=$overrun", overrun <= 1f)
                                assertTrue(it.getLineLeft(line) >= -1f)
                                assertFalse(it.isLineEllipsized(line))
                            }
                        }
                        pending.removeAll(found.toSet())
                    }
                    current.children.forEach(::visit)
                }
                visit(node)
                val range = node.config[SemanticsProperties.VerticalScrollAxisRange]
                val next = range.value()
                maximum = range.maxValue()
                reachedEnd = next >= maximum
                stalledSteps = if (next == position) stalledSteps + 1 else 0
                position = next
                assertTrue("License scrolling stalled at $position/$maximum", reachedEnd || stalledSteps < 8)
                scrollBy = node.size.height * 0.8f
            }
            if (!reachedEnd) list.performSemanticsAction(SemanticsActions.ScrollBy) { it(0f, scrollBy) }
        }
        assertTrue("License list must reach its end: $position/$maximum, missing=$pending", reachedEnd)
        assertTrue("Missing visible license markers: $pending", pending.isEmpty())
        android.util.Log.i("R08-Notices", "markers=7 reachedEnd=true maxWidthOverrunPx=$maxWidthOverrun")
    }
}
