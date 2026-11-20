// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class TlsEncryptedAssetTest {
    @get:Rule val temporary = TemporaryFolder()
    private val identity = TlsAssetIdentity(TlsAssetPurpose.CAPTURE_SECRETS, "asset-1", captureId = "capture-1")
    private val wrappingKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private var keyAvailable = true
    private var keyRequestsCreating = 0
    private val provider = AesGcmTlsWrappingKeyProvider { create ->
        if (create) keyRequestsCreating++
        if (!keyAvailable) throw TlsAssetException(TlsAssetErrorCode.KEY_UNAVAILABLE)
        wrappingKey
    }
    private val assetFile get() = File(temporary.root, "records.enc")
    private val keyFile get() = File(temporary.root, "wrapped-data-key")
    private val line = "CLIENT_RANDOM ${"ab".repeat(32)} ${"cd".repeat(48)}".toByteArray()

    @Test fun roundTripReopenAppendAndSyncedWatermarks() {
        create().use {
            assertEquals(0, it.watermark.sequence)
            val first = it.append(line)
            assertEquals(1, first.sequence)
            assertEquals(line.size.toLong(), first.plaintextBytes)
            assertEquals(assetFile.length(), first.fileBytes)
        }
        open().use {
            assertEquals(1, it.watermark.sequence)
            it.append(byteArrayOf(1, 2, 3))
            val records = mutableListOf<ByteArray>()
            it.readRecords { sequence, bytes ->
                assertEquals(records.size + 1L, sequence)
                records += bytes.copyOf()
            }
            assertArrayEquals(line, records[0])
            assertArrayEquals(byteArrayOf(1, 2, 3), records[1])
            assertEquals(2, it.watermark.sequence)
        }
        assertEquals(1, keyRequestsCreating)
        assertFalse(assetFile.readBytes().toString(Charsets.ISO_8859_1).contains(line.toString(Charsets.US_ASCII)))
        assertEquals(66, keyFile.length())
    }

    @Test fun caPurposeUsesSameFormatAndMaximumRecord() {
        val ca = TlsAssetIdentity(TlsAssetPurpose.CA_PRIVATE_KEY, "asset-ca", caId = "ca-1")
        val block = ByteArray(TlsEncryptedAsset.MAX_PLAINTEXT_RECORD_BYTES) { (it % 251).toByte() }
        TlsEncryptedAsset.create(assetFile, keyFile, ca, provider).use { it.append(block) }
        TlsEncryptedAsset.open(assetFile, keyFile, ca, provider).use { asset ->
            asset.readRecords { _, bytes -> assertArrayEquals(block, bytes) }
        }
    }

    @Test fun fileDataKeysAreIndependentAndNoPlaintextKeyIsPersisted() {
        create().close()
        val key1 = provider.unwrap(identity, keyFile.readBytes())
        val other = identity.copy(assetId = "asset-2")
        val second = File(temporary.root, "second.enc")
        val secondKey = File(temporary.root, "second-key")
        TlsEncryptedAsset.create(second, secondKey, other, provider).close()
        val key2 = provider.unwrap(other, secondKey.readBytes())
        assertFalse(key1.contentEquals(key2))
        assertFalse(keyFile.readBytes().contentEquals(key1))
        key1.fill(0)
        key2.fill(0)
    }

    @Test fun modifiedSemanticallyEquivalentHeaderFailsAuthenticationAndPreservesFile() {
        oneRecord()
        val original = assetFile.readBytes()
        val size = headerSize(original)
        val json = original.copyOfRange(10, size).toString(Charsets.UTF_8)
        // Reorder members without changing meaning or length: AAD covers the exact header bytes.
        val start = json.indexOf('"')
        val end = json.indexOf(',')
        val changed = "{" + json.substring(end + 1, json.lastIndexOf('}')) + "," + json.substring(start, end) + "}"
        changed.toByteArray().copyInto(original, 10)
        assetFile.writeBytes(original)
        expectUnchanged(TlsAssetErrorCode.AUTHENTICATION_FAILED, original)
    }

    @Test fun changedCaptureAssetAndPurposeAreRejected() {
        oneRecord()
        expect(TlsAssetErrorCode.BINDING_MISMATCH) { open(identity.copy(captureId = "capture-2")) }
        expect(TlsAssetErrorCode.BINDING_MISMATCH) { open(identity.copy(assetId = "asset-2")) }
        expect(TlsAssetErrorCode.INVALID_FORMAT) {
            open(TlsAssetIdentity(TlsAssetPurpose.CA_PRIVATE_KEY, identity.assetId, caId = "ca-1"))
        }
    }

    @Test fun sequenceMutationIsNotAnIncompleteTail() {
        oneRecord()
        val bytes = assetFile.readBytes()
        ByteBuffer.wrap(bytes).putLong(headerSize(bytes) + 4, 2)
        assetFile.writeBytes(bytes)
        expectUnchanged(TlsAssetErrorCode.INVALID_SEQUENCE, bytes)
    }

    @Test fun completeTagFailureNeverTruncates() {
        oneRecord()
        val bytes = assetFile.readBytes().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assetFile.writeBytes(bytes)
        expectUnchanged(TlsAssetErrorCode.AUTHENTICATION_FAILED, bytes)
    }

    @Test fun replayedRecordSequenceIsRejected() {
        oneRecord()
        val bytes = assetFile.readBytes()
        val replayed = bytes + bytes.copyOfRange(headerSize(bytes), bytes.size)
        assetFile.writeBytes(replayed)
        expectUnchanged(TlsAssetErrorCode.INVALID_SEQUENCE, replayed)
    }

    @Test fun reorderedRecordsWithRenumberedSequencesStillFailAuthentication() {
        create().use { it.append(line); it.append(line) }
        val original = assetFile.readBytes()
        val start = headerSize(original)
        val recordBytes = 4 + 36 + line.size
        val first = original.copyOfRange(start, start + recordBytes)
        val second = original.copyOfRange(start + recordBytes, original.size)
        ByteBuffer.wrap(second).putLong(4, 1)
        ByteBuffer.wrap(first).putLong(4, 2)
        val changed = original.copyOf(start) + second + first
        assetFile.writeBytes(changed)
        expectUnchanged(TlsAssetErrorCode.AUTHENTICATION_FAILED, changed)
    }

    @Test fun changedNonceAndCiphertextFailAuthentication() {
        oneRecord()
        val original = assetFile.readBytes()
        val start = headerSize(original)
        for (offset in listOf(start + 12, start + 24)) {
            val changed = original.copyOf().also { it[offset] = (it[offset].toInt() xor 1).toByte() }
            assetFile.writeBytes(changed)
            expectUnchanged(TlsAssetErrorCode.AUTHENTICATION_FAILED, changed)
        }
    }

    @Test fun duplicateNonceIsRejectedBeforeDecryptingSecondRecord() {
        create().use { it.append(line); it.append(line) }
        val bytes = assetFile.readBytes()
        val first = headerSize(bytes)
        val second = first + 4 + ByteBuffer.wrap(bytes).getInt(first)
        bytes.copyOfRange(first + 12, first + 24).copyInto(bytes, second + 12)
        assetFile.writeBytes(bytes)
        expectUnchanged(TlsAssetErrorCode.NONCE_REUSED, bytes)
    }

    @Test fun entropyCollisionRejectedOnAppendAndAfterReopen() {
        val repeated = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) { bytes.fill(7) }
        }
        TlsEncryptedAsset.create(assetFile, keyFile, identity, provider, random = repeated).use {
            it.append(line)
            expect(TlsAssetErrorCode.NONCE_REUSED) { it.append(line) }
            assertEquals(1, it.watermark.sequence)
        }
        TlsEncryptedAsset.open(assetFile, keyFile, identity, provider, random = repeated).use {
            expect(TlsAssetErrorCode.NONCE_REUSED) { it.append(line) }
        }
    }

    @Test fun eachIncompleteSuffixCanBeExplicitlyRecoveredThenAppended() {
        create().use { it.append(line); it.append(byteArrayOf(1, 2, 3)) }
        val complete = assetFile.readBytes()
        val second = headerSize(complete) + 4 + 36 + line.size
        for (end in second + 1 until complete.size) {
            val incomplete = complete.copyOf(end)
            assetFile.writeBytes(incomplete)
            expect(TlsAssetErrorCode.TRUNCATED_TAIL) { open() }
            assertArrayEquals(incomplete, assetFile.readBytes())
            TlsEncryptedAsset.open(assetFile, keyFile, identity, provider, TlsTailRecovery.TRUNCATE_INCOMPLETE).use {
                assertEquals((end - second).toLong(), it.recoveredTailBytes)
                assertEquals(second.toLong(), assetFile.length())
                assertEquals(1, it.watermark.sequence)
                assertEquals(2, it.append(byteArrayOf(9)).sequence)
            }
        }
    }

    @Test fun corruptionBeforeIncompleteTailPreventsRecovery() {
        create().use { it.append(line); it.append(line) }
        val bytes = assetFile.readBytes().copyOf(assetFile.length().toInt() - 1)
        val firstTag = headerSize(bytes) + 4 + 36 + line.size - 1
        bytes[firstTag] = (bytes[firstTag].toInt() xor 1).toByte()
        assetFile.writeBytes(bytes)
        expectUnchanged(TlsAssetErrorCode.AUTHENTICATION_FAILED, bytes)
    }

    @Test fun invalidRecordLengthsIncludingUnsignedOverflowAreNotTruncation() {
        oneRecord()
        val original = assetFile.readBytes()
        for (length in listOf(0, 35, 16385, Int.MAX_VALUE, -1, Int.MIN_VALUE)) {
            val changed = original.copyOf()
            ByteBuffer.wrap(changed).putInt(headerSize(changed), length)
            assetFile.writeBytes(changed)
            expectUnchanged(TlsAssetErrorCode.INVALID_FORMAT, changed)
        }
    }

    @Test fun invalidHeaderLengthsVersionsAndTruncatedHeaderAreNotRecoverable() {
        oneRecord()
        val original = assetFile.readBytes()
        for (length in listOf(0, 4097, Int.MAX_VALUE, -1)) {
            val changed = original.copyOf()
            ByteBuffer.wrap(changed).putInt(6, length)
            assetFile.writeBytes(changed)
            expectUnchanged(TlsAssetErrorCode.INVALID_FORMAT, changed)
        }
        val newer = original.copyOf().also { ByteBuffer.wrap(it).putShort(4, 2) }
        assetFile.writeBytes(newer)
        expectUnchanged(TlsAssetErrorCode.UNSUPPORTED_VERSION, newer)
        for (length in listOf(0, 4, 9, headerSize(original) - 1)) {
            val truncated = original.copyOf(length)
            assetFile.writeBytes(truncated)
            expectUnchanged(TlsAssetErrorCode.INVALID_FORMAT, truncated)
        }
    }

    @Test fun missingWrappingKeyNeverCreatesOrOverwrites() {
        oneRecord()
        val ciphertext = assetFile.readBytes()
        val wrapped = keyFile.readBytes()
        keyAvailable = false
        expect(TlsAssetErrorCode.KEY_UNAVAILABLE) { open() }
        assertEquals(1, keyRequestsCreating)
        assertArrayEquals(ciphertext, assetFile.readBytes())
        assertArrayEquals(wrapped, keyFile.readBytes())
        expect(TlsAssetErrorCode.ALREADY_EXISTS) { create() }
        assertEquals(1, keyRequestsCreating)
    }

    @Test fun wrappedKeyAuthenticatesVersionPurposeAndAssetId() {
        val key = ByteArray(32) { it.toByte() }
        val wrapped = provider.wrap(identity, key)
        assertArrayEquals(key, provider.unwrap(identity, wrapped))
        expect(TlsAssetErrorCode.AUTHENTICATION_FAILED) { provider.unwrap(identity.copy(assetId = "other"), wrapped) }
        expect(TlsAssetErrorCode.AUTHENTICATION_FAILED) {
            provider.unwrap(TlsAssetIdentity(TlsAssetPurpose.CA_PRIVATE_KEY, identity.assetId, caId = "ca-1"), wrapped)
        }
        val changed = wrapped.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        expect(TlsAssetErrorCode.AUTHENTICATION_FAILED) { provider.unwrap(identity, changed) }
        expect(TlsAssetErrorCode.INVALID_FORMAT) { provider.unwrap(identity, wrapped.copyOf(65)) }
        expect(TlsAssetErrorCode.UNSUPPORTED_VERSION) {
            provider.unwrap(identity, wrapped.copyOf().also { ByteBuffer.wrap(it).putShort(4, 2) })
        }
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) { provider.wrap(identity, ByteArray(16)) }
    }

    @Test fun wrappedKeySwappedBetweenFilesCannotDecrypt() {
        oneRecord()
        val other = identity.copy(assetId = "asset-2")
        val otherWrapped = provider.wrap(other, ByteArray(32) { 2 })
        keyFile.writeBytes(otherWrapped)
        expect(TlsAssetErrorCode.AUTHENTICATION_FAILED) { open() }
        assertArrayEquals(otherWrapped, keyFile.readBytes())
    }

    @Test fun writerAndReaderLimitsCheckedWithoutWritingMoreData() {
        val limits = TlsAssetLimits(maxPlaintextBytes = line.size.toLong(), maxRecords = 1)
        TlsEncryptedAsset.create(assetFile, keyFile, identity, provider, limits).use { it.append(line) }
        val bytes = assetFile.readBytes()
        TlsEncryptedAsset.open(assetFile, keyFile, identity, provider, limits = limits).use {
            expect(TlsAssetErrorCode.CAPACITY_EXCEEDED) { it.append(byteArrayOf(1)) }
            expect(TlsAssetErrorCode.INVALID_ARGUMENT) { it.append(ByteArray(0)) }
            expect(TlsAssetErrorCode.INVALID_ARGUMENT) { it.append(ByteArray(16349)) }
        }
        assertArrayEquals(bytes, assetFile.readBytes())
        expect(TlsAssetErrorCode.CAPACITY_EXCEEDED) {
            TlsEncryptedAsset.open(assetFile, keyFile, identity, provider, limits = TlsAssetLimits(maxPlaintextBytes = 1))
        }
        expect(TlsAssetErrorCode.CAPACITY_EXCEEDED) {
            TlsEncryptedAsset.open(assetFile, keyFile, identity, provider, limits = TlsAssetLimits(maxFileBytes = 10))
        }
    }

    @Test fun lockPreventsConcurrentUseAndCloseIsIdempotent() {
        val asset = create()
        expect(TlsAssetErrorCode.IN_USE) { open() }
        asset.close()
        asset.close()
        expect(TlsAssetErrorCode.CLOSED) { asset.append(line) }
        open().close()
    }

    @Test fun recordBufferIsClearedOnSuccessAndConsumerCancellation() {
        oneRecord()
        var borrowed: ByteArray? = null
        open().use { asset -> asset.readRecords { _, bytes -> borrowed = bytes; assertArrayEquals(line, bytes) } }
        assertTrue(borrowed!!.all { it == 0.toByte() })
        open().use { asset ->
            try {
                asset.readRecords { _, bytes -> borrowed = bytes; throw IllegalStateException("cancel") }
                fail("Expected consumer cancellation")
            } catch (_: IllegalStateException) { }
            assertTrue(borrowed!!.all { it == 0.toByte() })
            expect(TlsAssetErrorCode.CLOSED) { asset.append(line) }
        }
    }

    @Test fun consumerCannotReenterWriterOrCloseItsBorrowedRecord() {
        oneRecord()
        open().use { asset ->
            asset.readRecords { _, bytes ->
                expect(TlsAssetErrorCode.IN_USE) { asset.append(line) }
                expect(TlsAssetErrorCode.IN_USE) { asset.close() }
                assertArrayEquals(line, bytes)
            }
            assertEquals(1, asset.watermark.sequence)
        }
    }

    @Test fun orphanedPairAndFailedCreateNeverOverwriteAnExistingMember() {
        oneRecord()
        val ciphertext = assetFile.readBytes()
        val wrapped = keyFile.readBytes()
        assertTrue(keyFile.delete())
        expect(TlsAssetErrorCode.IO_ERROR) { open() }
        expect(TlsAssetErrorCode.ALREADY_EXISTS) { create() }
        assertArrayEquals(ciphertext, assetFile.readBytes())
        assertFalse(keyFile.exists())
        assertTrue(assetFile.delete())
        keyFile.writeBytes(wrapped)
        expect(TlsAssetErrorCode.ALREADY_EXISTS) { create() }
        assertArrayEquals(wrapped, keyFile.readBytes())
        assertFalse(assetFile.exists())
    }

    @Test fun pathsAndIdsAreLocalAndExistingPairNeverOverwritten() {
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) { identity.copy(assetId = "../other") }
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) { identity.copy(captureId = "") }
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) { identity.copy(caId = "ca-1") }
        expect(TlsAssetErrorCode.INVALID_ARGUMENT) { TlsEncryptedAsset.create(assetFile, assetFile, identity, provider) }
        oneRecord()
        val before = assetFile.readBytes()
        expect(TlsAssetErrorCode.ALREADY_EXISTS) { create() }
        assertArrayEquals(before, assetFile.readBytes())
        assertTrue(temporary.root.listFiles()!!.none { it.name.endsWith(".tmp") })
    }

    @Test fun diskAndProviderErrorsAreClassifiedWithoutLeakingInputOrCause() {
        val secret = line.toString(Charsets.US_ASCII)
        for ((message, code) in listOf(
            "write failed: ENOSPC $secret" to TlsAssetErrorCode.DISK_FULL,
            "No space left on device $secret" to TlsAssetErrorCode.DISK_FULL,
            "The disk full $secret" to TlsAssetErrorCode.DISK_FULL,
            "permission denied $secret" to TlsAssetErrorCode.IO_ERROR
        )) {
            val error = TlsEncryptedAsset.sanitized(IOException(message))
            assertEquals(code, error.code)
            assertEquals(code.name, error.message)
            assertNull(error.cause)
            assertFalse(error.stackTraceToString().contains(secret))
        }
        val broken = AesGcmTlsWrappingKeyProvider { throw IllegalStateException(secret) }
        expect(TlsAssetErrorCode.KEY_UNAVAILABLE) { broken.wrap(identity, ByteArray(32)) }
    }

    private fun create() = TlsEncryptedAsset.create(assetFile, keyFile, identity, provider)
    private fun open(expected: TlsAssetIdentity = identity) = TlsEncryptedAsset.open(assetFile, keyFile, expected, provider)
    private fun oneRecord() = create().use { it.append(line) }
    private fun headerSize(bytes: ByteArray) = 10 + ByteBuffer.wrap(bytes).getInt(6)

    private fun expectUnchanged(code: TlsAssetErrorCode, bytes: ByteArray) {
        expect(code) { TlsEncryptedAsset.open(assetFile, keyFile, identity, provider, TlsTailRecovery.TRUNCATE_INCOMPLETE) }
        assertArrayEquals(bytes, assetFile.readBytes())
    }

    private fun expect(code: TlsAssetErrorCode, action: () -> Any?) {
        try {
            (action() as? AutoCloseable)?.close()
            fail("Expected $code")
        } catch (error: TlsAssetException) {
            assertEquals(code, error.code)
            assertEquals(code.name, error.message)
            assertNull(error.cause)
        }
    }
}
