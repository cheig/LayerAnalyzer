package com.example.layanalyzer.data

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class SearchQueryValidatorTest {
    @Test
    fun acceptsBytePairsWithDocumentedSeparators() {
        assertNull(SearchQueryValidator.validateHex("de ad be ef"))
        assertNull(SearchQueryValidator.validateHex("de:ad:BE:EF"))
        assertNull(SearchQueryValidator.validateHex("de-ad-be-ef"))
    }

    @Test
    fun rejectsOddOrMalformedInput() {
        assertNotNull(SearchQueryValidator.validateHex("abc"))
        assertNotNull(SearchQueryValidator.validateHex("0x12"))
        assertNotNull(SearchQueryValidator.validateHex("12,34"))
        assertNotNull(SearchQueryValidator.validateHex("  "))
    }
}
