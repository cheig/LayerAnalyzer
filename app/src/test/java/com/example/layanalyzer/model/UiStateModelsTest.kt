package com.example.layanalyzer.model

import com.example.layanalyzer.viewmodel.PacketNavigationState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UiStateModelsTest {
    @Test
    fun draftFilterIsTrackedSeparatelyFromAppliedFilter() {
        val state = DisplayFilterUiState(
            draftExpression = "tcp.stream == 4",
            appliedExpression = "dns",
            syntaxStatus = FilterSyntaxStatus.Valid,
            visibleCount = 12,
            totalCount = 120
        )

        assertTrue(state.hasUnappliedChanges)
        assertTrue(state.appliedExpression == "dns")
        assertTrue(state.visibleCount == 12)
    }

    @Test
    fun surroundingDraftWhitespaceDoesNotCreateFalseUnappliedState() {
        val state = DisplayFilterUiState(
            draftExpression = "  dns  ",
            appliedExpression = "dns"
        )

        assertFalse(state.hasUnappliedChanges)
    }

    @Test
    fun packetNavigationBoundsUseVisibleSetPosition() {
        val first = PacketNavigationState(position = 0, total = 3)
        val middle = PacketNavigationState(position = 1, total = 3)
        val last = PacketNavigationState(position = 2, total = 3)

        assertFalse(first.hasPrevious)
        assertTrue(first.hasNext)
        assertTrue(middle.hasPrevious && middle.hasNext)
        assertTrue(last.hasPrevious)
        assertFalse(last.hasNext)
    }

    @Test
    fun relativeTimeIsTheDefaultPreference() {
        assertTrue(AnalyzerPreferences().timeDisplayFormat == TimeDisplayFormat.Relative)
    }
}
