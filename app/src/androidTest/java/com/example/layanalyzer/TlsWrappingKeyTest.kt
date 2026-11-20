// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import android.content.Context
import com.example.layanalyzer.capture.tls.AndroidTlsWrappingKeyProvider
import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.capture.tls.TlsAssetException
import com.example.layanalyzer.capture.tls.TlsAssetIdentity
import com.example.layanalyzer.capture.tls.TlsAssetPurpose
import com.example.layanalyzer.capture.tls.TlsEncryptedAsset
import java.io.File
import java.security.KeyStore
import java.util.UUID
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Uses real Android Keystore, with a unique disposable alias and synthetic memory bytes. */
@RunWith(AndroidJUnit4::class)
class TlsWrappingKeyTest {
    private val id = UUID.randomUUID().toString()
    private val alias = "layeranalyzer.tls.test.$id"
    private val identity = TlsAssetIdentity(TlsAssetPurpose.CAPTURE_SECRETS, id, captureId = id)
    private lateinit var directory: File
    private val encrypted get() = File(directory, "downstream.keys.enc")
    private val wrapped get() = File(directory, "wrapped-data-key")

    @Before fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        directory = File(context.noBackupFilesDir, "tls-wrapping-test-$id")
        check(directory.mkdir())
    }

    @After fun tearDown() {
        store().deleteEntry(alias)
        if (::directory.isInitialized) {
            // Only this test's UUID directory, never real capture/CA storage.
            directory.listFiles()?.forEach { check(it.delete()) }
            check(directory.delete())
        }
    }

    @Test fun newProviderInstanceReopensSyncedAssetWithRealKeystoreKey() {
        val plaintext = ByteArray(300) { (it % 251).toByte() }
        TlsEncryptedAsset.create(encrypted, wrapped, identity, AndroidTlsWrappingKeyProvider(alias)).use {
            it.append(plaintext)
        }
        TlsEncryptedAsset.open(encrypted, wrapped, identity, AndroidTlsWrappingKeyProvider(alias)).use {
            assertEquals(1, it.watermark.sequence)
            it.readRecords { _, bytes -> assertArrayEquals(plaintext, bytes) }
        }
        assertTrue(store().containsAlias(alias))
        assertNull(store().getKey(alias, null).encoded) // wrapping key is non-exportable
        assertTrue(directory.listFiles()!!.none { it.name.endsWith(".tmp") })
    }

    @Test fun deletedWrappingAliasReturnsKeyUnavailableAndNeverReplacesOldFiles() {
        TlsEncryptedAsset.create(encrypted, wrapped, identity, AndroidTlsWrappingKeyProvider(alias)).use {
            it.append(byteArrayOf(1, 2, 3, 4))
        }
        val original = encrypted.readBytes()
        val originalWrapped = wrapped.readBytes()
        store().deleteEntry(alias)
        try {
            TlsEncryptedAsset.open(encrypted, wrapped, identity, AndroidTlsWrappingKeyProvider(alias)).close()
            fail("Expected unavailable wrapping key")
        } catch (error: TlsAssetException) {
            assertEquals(TlsAssetErrorCode.KEY_UNAVAILABLE, error.code)
            assertNull(error.cause)
        }
        assertFalse(store().containsAlias(alias))
        assertArrayEquals(original, encrypted.readBytes())
        assertArrayEquals(originalWrapped, wrapped.readBytes())
    }

    @Test fun changedWrappedTagIsAuthenticationFailure() {
        TlsEncryptedAsset.create(encrypted, wrapped, identity, AndroidTlsWrappingKeyProvider(alias)).close()
        val original = wrapped.readBytes()
        val changed = original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        wrapped.writeBytes(changed)
        try {
            TlsEncryptedAsset.open(encrypted, wrapped, identity, AndroidTlsWrappingKeyProvider(alias)).close()
            fail("Expected authentication failure")
        } catch (error: TlsAssetException) {
            assertEquals(TlsAssetErrorCode.AUTHENTICATION_FAILED, error.code)
        }
        assertArrayEquals(changed, wrapped.readBytes())
    }

    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
}
