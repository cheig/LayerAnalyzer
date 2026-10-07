package com.example.layanalyzer.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MetadataRedactorTest {
    @Test
    fun `same values map consistently and sensitive values disappear`() {
        val redactor = MetadataRedactor("golden-file-sha")
        val first = redactor.redact("src=192.0.2.10 dst=192.0.2.10 host=api.example.com mac=aa:bb:cc:dd:ee:ff")
        val second = redactor.redact("https://api.example.com path user=alice")

        assertNotEquals(first, "src=192.0.2.10 dst=192.0.2.10 host=api.example.com mac=aa:bb:cc:dd:ee:ff")
        assertTrue(first.contains("10."))
        assertTrue(first.contains("host-"))
        assertTrue(second.contains("host-"))
        assertTrue(!second.contains("api.example.com"))
        assertTrue(!second.contains("alice"))
    }

    @Test
    fun `different salts produce different pseudonyms`() {
        val a = MetadataRedactor("a").redact("10.0.0.1")
        val b = MetadataRedactor("b").redact("10.0.0.1")
        assertNotEquals(a, b)
    }
}
