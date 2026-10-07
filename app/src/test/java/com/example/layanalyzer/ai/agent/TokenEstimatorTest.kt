// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import org.junit.Assert.assertEquals
import org.junit.Test

class TokenEstimatorTest {
    private val estimator = ContentAwareTokenEstimator()

    @Test
    fun estimatesLatinTextAtFourCharactersPerToken() {
        assertEquals(4, estimator.estimate("network analysis"))
    }

    @Test
    fun estimatesHanHeavyTextAtOneAndAHalfCharactersPerToken() {
        assertEquals(4, estimator.estimate("网络分析测试"))
    }

    @Test
    fun estimatesJsonHeavyTextAtTwoAndAHalfCharactersPerToken() {
        assertEquals(6, estimator.estimate("{\"a\":1,\"b\":2}"))
    }

    @Test
    fun fixedRatioEstimatorRemainsAvailableForCompatibility() {
        assertEquals(4, ConservativeCharacterTokenEstimator(3).estimate("0123456789"))
    }
}
