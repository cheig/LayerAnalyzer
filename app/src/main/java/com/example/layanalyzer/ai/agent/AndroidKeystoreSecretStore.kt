// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Small secret boundary used for debug/BYOK credentials. */
interface SecretStore {
    val hasSecret: Boolean

    fun read(): String?

    fun save(secret: String): Result<Unit>

    fun clear()

    /** Returns a provider-scoped slot; legacy test stores can keep the default slot. */
    fun forAlias(alias: String?): SecretStore = this
}

/**
 * AES-GCM encrypted secret storage backed by an Android Keystore key.
 *
 * The ciphertext is placed below [Context.noBackupFilesDir], so neither the
 * Android backup system nor an evidence export can include it. The plaintext
 * only exists in memory for the duration of [save] or [read].
 */
class AndroidKeystoreSecretStore(
    private val context: Context,
    private val keyAlias: String = DEFAULT_KEY_ALIAS
) : SecretStore {
    private val secretFile: File
        get() = File(context.noBackupFilesDir, "$SAFE_FILE_PREFIX${safeAlias(keyAlias)}.bin")

    override val hasSecret: Boolean
        get() = secretFile.isFile && secretFile.length() > IV_LENGTH

    override fun read(): String? = runCatching {
        if (!hasSecret) return null
        val encrypted = secretFile.readBytes()
        val iv = encrypted.copyOfRange(0, IV_LENGTH)
        val payload = encrypted.copyOfRange(IV_LENGTH, encrypted.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, iv))
        cipher.doFinal(payload).toString(StandardCharsets.UTF_8)
    }.getOrNull()

    override fun save(secret: String): Result<Unit> {
        if (secret.isBlank()) {
            return Result.failure(IllegalArgumentException("Secret must not be blank."))
        }
        return runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            // Keystore keys require randomized encryption, so the GCM nonce must
            // come from the provider. A caller-supplied IV is rejected outright.
            cipher.init(Cipher.ENCRYPT_MODE, key())
            val iv = cipher.iv
            check(iv != null && iv.size == IV_LENGTH) { "Unexpected GCM nonce length." }
            val encrypted = cipher.doFinal(secret.toByteArray(StandardCharsets.UTF_8))
            val output = ByteArrayOutputStream(IV_LENGTH + encrypted.size)
            output.write(iv)
            output.write(encrypted)

            val parent = secretFile.parentFile
                ?: throw IOException("Unable to resolve secret storage directory.")
            check(parent.exists() || parent.mkdirs()) { "Unable to create secret storage directory." }
            val temporary = File.createTempFile("secret-", ".tmp", parent)
            try {
                temporary.writeBytes(output.toByteArray())
                if (secretFile.exists()) secretFile.delete()
                check(temporary.renameTo(secretFile)) { "Unable to commit encrypted secret." }
            } finally {
                temporary.delete()
            }
        }
    }

    override fun clear() {
        secretFile.delete()
        runCatching {
            val store = keyStore()
            if (store.containsAlias(keyAlias)) store.deleteEntry(keyAlias)
        }
    }

    override fun forAlias(alias: String?): SecretStore = alias
        ?.trim()
        ?.takeIf { it.isNotBlank() }
        ?.let { scoped ->
            AndroidKeystoreSecretStore(context, "$keyAlias.provider.$scoped")
        }
        ?: this

    /** Compatibility names useful to callers that treat this as a key vault. */
    fun get(): String? = read()

    fun put(secret: String): Result<Unit> = save(secret)

    private fun key(): SecretKey {
        val store = keyStore()
        val existing = store.getKey(keyAlias, null) as? SecretKey
        if (existing != null) return existing

        val generator = KeyGenerator.getInstance(KEY_ALGORITHM, ANDROID_KEYSTORE)
        generator.init(
            android.security.keystore.KeyGenParameterSpec.Builder(
                keyAlias,
                android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or
                    android.security.keystore.KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        return generator.generateKey()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun safeAlias(alias: String): String = alias
        .replace(Regex("[^A-Za-z0-9_.-]"), "_")
        .take(80)
        .ifBlank { "default" }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALGORITHM = "AES"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LENGTH = 12
        const val TAG_BITS = 128
        const val DEFAULT_KEY_ALIAS = "layeranalyzer.agent.byok.v1"
        const val SAFE_FILE_PREFIX = ".agent-secret-"
    }
}

typealias KeystoreSecretStore = AndroidKeystoreSecretStore
