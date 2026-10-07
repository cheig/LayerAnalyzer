// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * IMS and telecom coverage for [MetadataRedactor], per AI-11 section 3.1.
 *
 * Every test asserts two things: the real value is gone, and the alias is
 * stable.  Checking only the first would pass for an implementation that
 * randomises each occurrence, which would destroy a model's ability to tell
 * "the same subscriber twice" from "two subscribers".
 */
class MetadataRedactorImsTest {

    private fun redactor(salt: String = "capture-sha|run-1") = MetadataRedactor(salt)

    @Test
    fun `sip uri loses both the user part and the host`() {
        val out = redactor().redact("INVITE sip:alice@ims.example.com SIP/2.0")

        assertFalse(out.contains("alice"))
        assertFalse(out.contains("ims.example.com"))
        assertTrue("expected a sip: alias, got: $out", out.contains("sip:user-"))
        assertTrue(out.contains(".invalid"))
    }

    @Test
    fun `sips scheme survives while the identity does not`() {
        val out = redactor().redact("Contact: <sips:bob@secure.example.org>")

        assertTrue(out.contains("sips:"))
        assertFalse(out.contains("bob"))
        assertFalse(out.contains("secure.example.org"))
    }

    @Test
    fun `the same sip user is stable across calls and different users differ`() {
        val active = redactor()
        val first = active.redact("From: <sip:alice@example.com>")
        val second = active.redact("To: <sip:alice@example.com>")
        val other = active.redact("To: <sip:carol@example.com>")

        val aliceAlias = Regex("user-[0-9a-f]+").find(first)?.value
        assertNotEquals(null, aliceAlias)
        assertTrue("alias should repeat, got: $second", second.contains(aliceAlias!!))
        assertFalse("a different user must not reuse the alias", other.contains(aliceAlias))
    }

    @Test
    fun `a display name beside a redacted uri is redacted too`() {
        // The whole point: aliasing the URI but leaving "Alice Smith" in place
        // would hand the model the identity the alias was meant to hide.
        val out = redactor().redact("From: \"Alice Smith\" <sip:a1b2@example.com>;tag=xyz789")

        assertFalse("display name leaked: $out", out.contains("Alice Smith"))
        assertFalse(out.contains("a1b2"))
        assertFalse("dialog tag leaked: $out", out.contains("xyz789"))
    }

    @Test
    fun `tel uri keeps its shape but not its digits`() {
        val out = redactor().redact("P-Asserted-Identity: <tel:+8613800138000>")

        assertFalse(out.contains("8613800138000"))
        assertTrue("expected a tel: alias, got: $out", out.contains("tel:+1555"))
    }

    @Test
    fun `imsi imei and msisdn are replaced`() {
        val out = redactor().redact("imsi=460001234567890 imei=490154203237518 msisdn=+8613900139000")

        assertFalse(out.contains("460001234567890"))
        assertFalse(out.contains("490154203237518"))
        assertFalse(out.contains("8613900139000"))
        assertTrue(out.contains("subscriber-"))
    }

    @Test
    fun `the same imsi maps to one alias regardless of label spelling`() {
        val active = redactor()
        val a = active.redact("imsi=460001234567890")
        val b = active.redact("IMSI: 460001234567890")

        val alias = Regex("subscriber-[0-9a-f]+").find(a)?.value
        assertNotEquals(null, alias)
        assertTrue("case and separator must not fork the alias: $b", b.contains(alias!!))
    }

    @Test
    fun `call id is replaced and stays stable`() {
        val active = redactor()
        val first = active.redact("Call-ID: 3848276298220188511@atlanta.example.com")
        val second = active.redact("Call-ID: 3848276298220188511@atlanta.example.com")

        assertFalse(first.contains("3848276298220188511"))
        assertFalse(first.contains("atlanta.example.com"))
        assertEquals(first, second)
    }

    @Test
    fun `diameter session id is replaced including the entropy after the semicolons`() {
        // host;high;low — the tail is the part that identifies the session, so a
        // rule that stopped at the first semicolon would leak the useful half.
        val out = redactor().redact("Session-Id: pcscf.example.com;1876543;12345")

        assertFalse(out.contains("1876543"))
        assertFalse(out.contains("12345"))
        assertTrue("expected a session alias, got: $out", out.contains("session-"))
    }

    @Test
    fun `core network correlators are replaced`() {
        val out = redactor().redact("teid=0x1a2b3c4d amf-ue-ngap-id=42424242 guti=460001234567890")

        assertFalse(out.contains("0x1a2b3c4d"))
        assertFalse(out.contains("42424242"))
        assertTrue(out.contains("session-"))
    }

    @Test
    fun `authorization keeps the scheme and drops every parameter`() {
        val out = redactor().redact(
            "Authorization: Digest username=\"alice\", realm=\"ims.example.com\", " +
                "nonce=\"9f8e7d\", response=\"cafebabe\", cnonce=\"1234\""
        )

        assertTrue("scheme is diagnostic and should survive: $out", out.contains("Digest"))
        assertFalse(out.contains("alice"))
        assertFalse(out.contains("cafebabe"))
        assertFalse(out.contains("9f8e7d"))
        assertFalse(out.contains("1234"))
        assertFalse("realm can identify the operator: $out", out.contains("ims.example.com"))
    }

    @Test
    fun `an unknown credential scheme is dropped whole rather than echoed`() {
        val out = redactor().redact("Authorization: SomeVendorScheme secret-material-here")

        assertFalse(out.contains("secret-material-here"))
        assertFalse("an unknown scheme name is capture text: $out", out.contains("SomeVendorScheme"))
    }

    @Test
    fun `cookies are dropped`() {
        val out = redactor().redact("Cookie: session=abc123; user=alice")

        assertFalse(out.contains("abc123"))
        assertFalse(out.contains("alice"))
    }

    @Test
    fun `an ip literal inside a sip uri shares the alias of the bare address`() {
        // One endpoint must not appear as two identities just because it was
        // written once as a URI host and once as a bare address.
        val active = redactor()
        val bare = active.redact("src=192.0.2.10")
        val inUri = active.redact("Contact: <sip:alice@192.0.2.10>")

        val alias = Regex("10\\.\\d+\\.\\d+\\.\\d+").find(bare)?.value
        assertNotEquals(null, alias)
        assertTrue("uri host should reuse the address alias, got: $inUri", inUri.contains(alias!!))
    }

    @Test
    fun `redacting an already redacted string does not fork the alias`() {
        // The centralized privacy layer may run over text a tool already
        // touched; a second pass must be a no-op for values it produced.
        val active = redactor()
        val once = active.redact("From: <sip:alice@example.com> imsi=460001234567890")
        val twice = active.redact(once)

        assertEquals("second pass changed the aliases: $once -> $twice", once, twice)
    }

    @Test
    fun `a credential header survives a second pass with its scheme intact`() {
        val active = redactor()
        val once = active.redact("Authorization: Digest username=\"alice\", response=\"cafebabe\"")
        val twice = active.redact(once)

        assertEquals(once, twice)
        assertTrue("scheme lost on re-run: $twice", twice.contains("Digest"))
    }

    @Test
    fun `an ip alias produced by the ims rules is not aliased again`() {
        // An aliased IPv4 still matches the IPv4 rule, so without an
        // already-emitted guard the generic pass would rewrite the IMS pass's
        // output and one endpoint would surface as two identities.
        val active = redactor()
        val once = active.redact("Contact: <sip:alice@192.0.2.10>")
        val twice = active.redact(once)

        assertEquals("alias was re-aliased: $once -> $twice", once, twice)
    }

    @Test
    fun `different runs produce different aliases for the same subscriber`() {
        val runOne = MetadataRedactor("capture-sha|run-1").redact("imsi=460001234567890")
        val runTwo = MetadataRedactor("capture-sha|run-2").redact("imsi=460001234567890")

        assertNotEquals(runOne, runTwo)
    }

    @Test
    fun `bare digit runs that are not labelled are left alone`() {
        // A 15-digit number is far more often a byte count or a timestamp than
        // an IMSI.  Aliasing those would corrupt ordinary metrics for no gain.
        val out = redactor().redact("bytes=460001234567890 duration=1234567890123")

        assertTrue("unlabelled numbers must survive: $out", out.contains("460001234567890"))
        assertTrue(out.contains("1234567890123"))
    }

    @Test
    fun `redactValue aliases a bare identifier by family`() {
        val active = redactor()
        val callId = active.redactValue(MetadataRedactor.IdentifierKind.CallId, "abc123@host.example")
        val subscriber = active.redactValue(MetadataRedactor.IdentifierKind.Subscriber, "460001234567890")

        assertFalse(callId.contains("abc123"))
        assertFalse(subscriber.contains("460001234567890"))
        assertEquals(
            "a bare value must alias stably",
            callId,
            active.redactValue(MetadataRedactor.IdentifierKind.CallId, "abc123@host.example")
        )
    }

    @Test
    fun `redactValue keeps families apart for identical digits`() {
        val active = redactor()
        val asSubscriber = active.redactValue(MetadataRedactor.IdentifierKind.Subscriber, "12345678901234")
        val asSession = active.redactValue(MetadataRedactor.IdentifierKind.SessionId, "12345678901234")

        assertNotEquals("an IMSI and a session id must not collide", asSubscriber, asSession)
    }

    @Test
    fun `display filter syntax survives while address literals are still aliased`() {
        // The bare-hostname rule must not rewrite a Wireshark field path or a
        // protocol token: doing so would corrupt the one string the UI is
        // allowed to make clickable.  An address *literal* inside a filter is a
        // different matter — it is still an identifier and must be aliased, which
        // is why a redacted filter is documentation rather than something the
        // local engine can re-run (AI-11 section 9).
        val active = redactor()
        val filter = "tcp.analysis.retransmission || sip.Method == \"INVITE\" && ip.src == 192.0.2.1"
        val out = active.redact(filter)

        assertTrue("field path was aliased: $out", out.contains("tcp.analysis.retransmission"))
        assertTrue("field path was aliased: $out", out.contains("sip.Method"))
        assertTrue("field path was aliased: $out", out.contains("ip.src"))
        assertTrue("method literal was aliased: $out", out.contains("\"INVITE\""))
        assertFalse("address literal survived: $out", out.contains("192.0.2.1"))

        for (token in listOf("SIP/2.0", "HTTP/1.1", "RTP/AVP", "v1.0.0", "seq=1.5")) {
            assertEquals(token, active.redact(token))
        }
    }

    @Test
    fun `host names written as prose are aliased`() {
        // Info columns and Expert labels write hosts in prose — "to host
        // api.example.com" — where the labelled rules do not reach.
        val out = redactor().redact("Retransmission to host api.example.com from 192.0.2.10")

        assertFalse(out.contains("api.example.com"))
        assertFalse(out.contains("192.0.2.10"))
        assertTrue(out.contains("host-"))
    }

    @Test
    fun `blank input is returned untouched`() {
        assertEquals("", redactor().redactValue(MetadataRedactor.IdentifierKind.CallId, ""))
        assertEquals("", redactor().redact(""))
    }
}
