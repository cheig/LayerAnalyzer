package com.example.layanalyzer.ui.components

import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * agent-report-2 display contract (OPT-ARCH-04): defaults stay invisible so
 * legacy findings render exactly as before, declared values appear in a fixed
 * header order, and the related-signals section exists only when non-empty.
 */
class AgentFindingCardAcoFieldsTest {

    // ------------------------------- ① polarity: Unknown hides the badge

    @Test
    fun `unknown polarity does not render a badge`() {
        assertFalse(AgentFindingPolarity.Unknown.shouldRenderBadge())
        val badges = agentFindingHeaderBadges(AgentFinding(polarity = AgentFindingPolarity.Unknown))

        assertFalse(badges.any { it is AgentFindingHeaderBadge.Polarity })
        // Severity is the only header badge for an undeclared polarity.
        assertEquals(listOf(AgentFindingHeaderBadge.Severity), badges)
    }

    @Test
    fun `declared polarities render the badge`() {
        assertTrue(AgentFindingPolarity.Positive.shouldRenderBadge())
        assertTrue(AgentFindingPolarity.Negative.shouldRenderBadge())
        assertTrue(AgentFindingPolarity.Neutral.shouldRenderBadge())
    }

    // ------------------------------ ② hypothesis: null id hides the chip

    @Test
    fun `missing hypothesis id does not render a chip`() {
        val badges = agentFindingHeaderBadges(AgentFinding(hypothesisId = null))

        assertFalse(badges.any { it is AgentFindingHeaderBadge.Hypothesis })
    }

    @Test
    fun `hypothesis chip carries the id and follows the badges`() {
        val badges = agentFindingHeaderBadges(
            AgentFinding(polarity = AgentFindingPolarity.Negative, hypothesisId = "h-1")
        )

        assertEquals(
            listOf(
                AgentFindingHeaderBadge.Severity,
                AgentFindingHeaderBadge.Polarity(AgentFindingPolarity.Negative),
                AgentFindingHeaderBadge.Hypothesis("h-1")
            ),
            badges
        )
    }

    @Test
    fun `severity badge is always the first header item`() {
        val badges = agentFindingHeaderBadges(
            AgentFinding(polarity = AgentFindingPolarity.Neutral, hypothesisId = "h-2")
        )

        assertEquals(AgentFindingHeaderBadge.Severity, badges.first())
        assertEquals(3, badges.size)
    }

    // -------------------------- ③ related signals: empty list hides the row

    @Test
    fun `empty related signals hide the section`() {
        assertTrue(agentFindingRelatedSignals(AgentFinding()).isEmpty())
    }

    @Test
    fun `related signals keep their order and content`() {
        val signals = agentFindingRelatedSignals(
            AgentFinding(relatedSignals = listOf("sig-2", "sig-1"))
        )

        assertEquals(listOf("sig-2", "sig-1"), signals)
    }
}
