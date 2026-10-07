// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.ai.agent.AndroidKeystoreSecretStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A Keystore AES key requires randomized encryption, so the GCM nonce has to
 * come from the provider. Supplying one used to make every BYOK save fail.
 */
@RunWith(AndroidJUnit4::class)
class AgentSecretStoreTest {
    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private lateinit var store: AndroidKeystoreSecretStore

    @Before
    fun setUp() {
        store = AndroidKeystoreSecretStore(context, TEST_KEY_ALIAS)
        store.clear()
    }

    @After
    fun tearDown() {
        store.clear()
    }

    @Test
    fun byokSecretRoundTripsThroughKeystore() {
        assertFalse(store.hasSecret)

        val result = store.save(SECRET)

        assertTrue(
            "save failed: ${result.exceptionOrNull()}",
            result.isSuccess
        )
        assertTrue(store.hasSecret)
        assertEquals(SECRET, store.read())
    }

    @Test
    fun savingTwiceReplacesTheSecretAndUsesAFreshNonce() {
        assertTrue(store.save(SECRET).isSuccess)
        val firstCiphertext = ciphertext()

        assertTrue(store.save(OTHER_SECRET).isSuccess)

        assertEquals(OTHER_SECRET, store.read())
        assertNotEquals(
            "GCM nonce must never repeat for the same key.",
            firstCiphertext.take(NONCE_LENGTH),
            ciphertext().take(NONCE_LENGTH)
        )
    }

    @Test
    fun blankSecretIsRejectedAndClearRemovesStoredKey() {
        assertTrue(store.save("   ").isFailure)
        assertFalse(store.hasSecret)

        assertTrue(store.save(SECRET).isSuccess)
        store.clear()

        assertFalse(store.hasSecret)
        assertNull(store.read())
    }

    /** Reads the raw file so the test can assert the nonce actually changes. */
    private fun ciphertext(): List<Byte> = context.noBackupFilesDir
        .listFiles { file -> file.name.contains(SAFE_TEST_ALIAS) }
        .orEmpty()
        .single()
        .readBytes()
        .toList()

    private companion object {
        const val TEST_KEY_ALIAS = "layeranalyzer.test.byok"
        const val SAFE_TEST_ALIAS = "layeranalyzer.test.byok"
        const val SECRET = "sk-test-0123456789abcdef"
        const val OTHER_SECRET = "sk-test-fedcba9876543210"
        const val NONCE_LENGTH = 12
    }
}
