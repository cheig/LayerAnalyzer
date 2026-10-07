package com.example.layanalyzer.ai.playbook

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScenarioTextRulesTest {

    @Test
    fun acceptsPlainDeclarativeProse() {
        ScenarioTextRules.requireDeclarativeText("SIP REGISTER retransmissions exceed the carrier threshold.")
        ScenarioTextRules.requireDeclarativeText("a".repeat(ScenarioTextRules.PACKAGE_MAX_TEXT_LENGTH))
    }

    @Test
    fun rejectsTextBeyondPackageLimit() {
        val text = "a".repeat(ScenarioTextRules.PACKAGE_MAX_TEXT_LENGTH + 1)

        val error = runCatching {
            ScenarioTextRules.requireDeclarativeText(text)
        }.exceptionOrNull() as PlaybookValidationException

        assertEquals(
            "Declarative text exceeds ${ScenarioTextRules.PACKAGE_MAX_TEXT_LENGTH} characters.",
            error.message
        )
        // OPT-ERR-01: the rejection carries a stable code with the limit as
        // an arg, so callers localize without parsing the English message.
        assertEquals(ScenarioValidationCodes.TEXT_TOO_LONG, error.code)
        assertEquals(
            mapOf("max" to ScenarioTextRules.PACKAGE_MAX_TEXT_LENGTH.toString()),
            error.args
        )
    }

    @Test
    fun rejectsTextBeyondUserLayerLimit() {
        val error = runCatching {
            ScenarioTextRules.requireDeclarativeText("a".repeat(ScenarioTextRules.USER_MAX_TEXT_LENGTH + 1), ScenarioTextRules.USER_MAX_TEXT_LENGTH)
        }.exceptionOrNull() as PlaybookValidationException

        assertEquals(
            "Declarative text exceeds ${ScenarioTextRules.USER_MAX_TEXT_LENGTH} characters.",
            error.message
        )
        assertEquals(ScenarioValidationCodes.TEXT_TOO_LONG, error.code)
        assertEquals(
            mapOf("max" to ScenarioTextRules.USER_MAX_TEXT_LENGTH.toString()),
            error.args
        )
    }

    @Test
    fun rejectsUrls() {
        assertForbidden("See https://example.com/capture for details.")
        assertForbidden("See http://example.com/capture for details.")
        assertForbidden("See HTTPS://EXAMPLE.COM for details.")
    }

    @Test
    fun rejectsCodeFences() {
        assertForbidden("Run this:\n```\neval(x)\n```")
    }

    @Test
    fun rejectsScriptTags() {
        assertForbidden("<script>alert(1)</script>")
        assertForbidden("<SCRIPT>alert(1)</SCRIPT>")
    }

    @Test
    fun rejectsEvalAndExecCalls() {
        assertForbidden("call eval(payload) first")
        assertForbidden("call EVAL(payload) first")
        assertForbidden("then exec(cmd) follows")
        assertForbidden("then EXEC(cmd) follows")
    }

    @Test
    fun declarativeWordsThatMerelyLookSimilarAreAccepted() {
        ScenarioTextRules.requireDeclarativeText("The evaluator script flagged retransmissions.")
        ScenarioTextRules.requireDeclarativeText("Execution of the handshake completes normally.")
    }

    @Test
    fun userLayerLengthLimitsMatchDesignBaseline() {
        assertEquals(80, ScenarioTextRules.USER_MAX_TITLE_LENGTH)
        assertEquals(80, ScenarioTextRules.USER_MAX_HINT_LENGTH)
        assertEquals(300, ScenarioTextRules.USER_MAX_TEXT_LENGTH)
        assertEquals(500, ScenarioTextRules.PACKAGE_MAX_TEXT_LENGTH)
    }

    private fun assertForbidden(text: String) {
        val error = runCatching {
            ScenarioTextRules.requireDeclarativeText(text)
        }.exceptionOrNull() as PlaybookValidationException

        assertEquals("Declarative text contains forbidden content.", error.message)
        assertEquals(ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT, error.code)
        assertTrue(error.args.isEmpty())
    }
}
