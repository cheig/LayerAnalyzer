// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Returns opaque wrapped bytes, never a wrapping key. Failures must be redacted. */
interface TlsWrappingKeyProvider {
    fun wrap(identity: TlsAssetIdentity, dataKey: ByteArray): ByteArray
    fun unwrap(identity: TlsAssetIdentity, wrappedKey: ByteArray): ByteArray
}

/**
 * Keystore keys are generated only while wrapping a NEW asset. Reading an old asset
 * never recreates a missing key, and a present but unusable alias is never replaced.
 */
class AndroidTlsWrappingKeyProvider(
    private val alias: String = "layeranalyzer.tls.wrapping.v1"
) : TlsWrappingKeyProvider {
    private val delegate = AesGcmTlsWrappingKeyProvider { create ->
        synchronized(keyLock) {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (store.containsAlias(alias)) {
                store.getKey(alias, null) as? SecretKey
                    ?: throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
            } else {
                if (!create) throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                    init(
                        KeyGenParameterSpec.Builder(
                            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                        )
                            .setKeySize(256)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setRandomizedEncryptionRequired(true)
                            .build()
                    )
                }.generateKey()
            }
        }
    }

    override fun wrap(identity: TlsAssetIdentity, dataKey: ByteArray): ByteArray =
        delegate.wrap(identity, dataKey)

    override fun unwrap(identity: TlsAssetIdentity, wrappedKey: ByteArray): ByteArray =
        delegate.unwrap(identity, wrappedKey)

    private companion object {
        val keyLock = Any()
    }
}

/** JCA implementation shared by Android and JVM tests; there is no default test key. */
internal class AesGcmTlsWrappingKeyProvider(
    private val key: (create: Boolean) -> SecretKey
) : TlsWrappingKeyProvider {
    override fun wrap(identity: TlsAssetIdentity, dataKey: ByteArray): ByteArray = protect {
        if (dataKey.size != 32) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // Android Keystore requires the provider to choose the encryption IV.
        cipher.init(Cipher.ENCRYPT_MODE, key(true))
        if (cipher.iv.size != 12) throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
        cipher.updateAAD(aad(identity))
        ByteBuffer.allocate(WRAPPED_SIZE).putInt(MAGIC).putShort(1)
            .put(cipher.iv).put(cipher.doFinal(dataKey)).array()
    }

    override fun unwrap(identity: TlsAssetIdentity, wrappedKey: ByteArray): ByteArray = protect {
        if (wrappedKey.size != WRAPPED_SIZE) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        val input = ByteBuffer.wrap(wrappedKey)
        if (input.int != MAGIC) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
        if (input.short.toInt() != 1) throw TlsAssetException(TlsAssetErrorCode.UNSUPPORTED_VERSION)
        val nonce = ByteArray(12).also(input::get)
        val ciphertext = ByteArray(48).also(input::get)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad(identity))
        cipher.doFinal(ciphertext)
    }

    private fun aad(identity: TlsAssetIdentity): ByteArray =
        // IDs cannot contain separators; explicit lengths still make the tuple unambiguous.
        ByteBuffer.allocate(6 + 4 + identity.purpose.wireName.length + 4 + identity.assetId.length)
            .putInt(MAGIC).putShort(1)
            .putInt(identity.purpose.wireName.length)
            .put(identity.purpose.wireName.toByteArray(Charsets.US_ASCII))
            .putInt(identity.assetId.length).put(identity.assetId.toByteArray(Charsets.US_ASCII)).array()

    private inline fun <T> protect(operation: () -> T): T = try {
        operation()
    } catch (error: TlsAssetException) {
        throw error
    } catch (_: AEADBadTagException) {
        throw TlsAssetException(TlsAssetErrorCode.AUTHENTICATION_FAILED)
    } catch (_: GeneralSecurityException) {
        throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
    } catch (_: java.io.IOException) {
        throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
    } catch (_: RuntimeException) {
        // Android provider failures may be unchecked and contain alias/provider details.
        throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
    }

    companion object {
        const val WRAPPED_SIZE = 66 // LAKW + u16 + nonce[12] + encrypted AES-256 key/tag[48].
        private const val MAGIC = 0x4c414b57
    }
}
