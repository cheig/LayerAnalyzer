// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.model.PacketReassembly
import com.example.layanalyzer.model.ProtocolNode
import com.example.layanalyzer.ui.components.ProtocolTreeView
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProtocolTreeNavigationTest {
    @get:Rule
    val composeRule = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun frameButtonNavigatesAndLongPressMarksOrClearsTheWholePdu() {
        var navigated: Long? = null
        var marked: Pair<Set<Long>, Boolean>? = null
        val group = ProtocolNode(
            "Reassembled TCP Segments", filter = "tcp.segments",
            children = listOf(4L, 7L).map {
                ProtocolNode("TCP Segment: $it", filter = "tcp.segment", filterValue = "$it", fieldType = "FT_FRAMENUM")
            }
        )
        composeRule.setContent {
            LayerAnalyzerTheme {
                ProtocolTreeView(
                    root = ProtocolNode("Packet 7", children = listOf(group)),
                    selectedNode = null,
                    defaultExpansionDepth = 3,
                    onFieldSelected = {},
                    onApplyFieldAsFilter = {},
                    onGoToFrame = { navigated = it },
                    onSetReassemblyHighlighted = { selection: PacketReassembly, enabled ->
                        marked = selection.frames to enabled
                    }
                )
            }
        }
        composeRule.onNodeWithContentDescription(composeRule.activity.getString(R.string.go_to_referenced_frame, 4))
            .performClick()
        composeRule.runOnIdle { assertEquals(4L, navigated) }

        composeRule.onNodeWithText("TCP Segment: 4").performTouchInput { longClick() }
        composeRule.onNodeWithText(composeRule.activity.getString(R.string.highlight_reassembly)).performClick()
        composeRule.runOnIdle { assertEquals(setOf(4L, 7L) to true, marked) }

        composeRule.onNodeWithText("TCP Segment: 7").performTouchInput { longClick() }
        composeRule.onNodeWithText(composeRule.activity.getString(R.string.clear_reassembly_highlights)).performClick()
        composeRule.runOnIdle { assertEquals(setOf(4L, 7L) to false, marked) }
    }
}
