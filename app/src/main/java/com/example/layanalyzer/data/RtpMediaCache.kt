// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import java.io.File

class RtpMediaCache(rootDir: File) {
    val rootDir = rootDir.canonicalFile

    /** Returns true when [file] is the cache root or one of its descendants. */
    fun contains(file: File): Boolean =
        runCatching {
            canonicalPathWithinRoot(rootDir, file)
            true
        }.getOrDefault(false)

    fun dirFor(sessionHandle: Long, requestId: Long, create: Boolean = true): File {
        val sessionDir = sessionDir(sessionHandle)
        val requestDir = requestDir(sessionHandle, requestId)
        if (create) {
            ensureDirectory(sessionDir)
            ensureDirectory(requestDir)
        }
        return contained(requestDir)
    }

    fun deleteSession(sessionHandle: Long) {
        val directory = sessionDir(sessionHandle)
        if (directory.exists()) {
            directory.deleteRecursively()
        }
    }

    fun deleteRequest(sessionHandle: Long, requestId: Long) {
        val directory = requestDir(sessionHandle, requestId)
        if (directory.exists()) {
            directory.deleteRecursively()
        }
    }

    fun clearAll() {
        val directory = validateRoot()
        if (directory.exists()) {
            directory.deleteRecursively()
        }
    }

    /**
     * Deletes the oldest request directories until their combined size is at
     * most [maxBytes], returning the number of bytes actually removed.
     */
    fun enforceMaxBytes(maxBytes: Long = 1L shl 30): Long {
        require(maxBytes >= 0L) { "maxBytes must not be negative." }
        val requests = requestDirectories()
        val entries = requests.map { directory ->
            CacheEntry(directory, directory.lastModified())
        }.sortedWith(
            compareBy<CacheEntry> { it.lastModified }
                .thenBy { it.directory.path }
        )

        var totalBytes = entries.fold(0L) { total, entry ->
            saturatedAdd(total, directorySize(entry.directory))
        }
        var deletedBytes = 0L
        for (entry in entries) {
            if (totalBytes <= maxBytes) break

            val bytesBefore = directorySize(entry.directory)
            entry.directory.deleteRecursively()
            val bytesAfter = directorySize(entry.directory)
            val removed = (bytesBefore - bytesAfter).coerceAtLeast(0L)
            deletedBytes = saturatedAdd(deletedBytes, removed)
            totalBytes = (totalBytes - removed).coerceAtLeast(0L)
        }
        return deletedBytes
    }

    private fun sessionDir(sessionHandle: Long): File =
        contained(File(rootDir, sessionHandle.toString()))

    private fun requestDir(sessionHandle: Long, requestId: Long): File =
        contained(File(sessionDir(sessionHandle), requestId.toString()))

    private fun ensureDirectory(directory: File) {
        if (!directory.isDirectory) {
            check(directory.mkdirs() || directory.isDirectory) {
                "Unable to create RTP media cache directory: ${directory.path}"
            }
        }
        contained(directory)
    }

    private fun requestDirectories(): List<File> {
        val directory = validateRoot()
        if (!directory.isDirectory) return emptyList()
        return directory.listFiles().orEmpty()
            .filter { it.isDirectory }
            .flatMap { session ->
                contained(session).listFiles().orEmpty()
                    .filter { it.isDirectory }
                    .map(::contained)
            }
    }

    private fun directorySize(directory: File): Long {
        if (!directory.exists()) return 0L
        var total = 0L
        directory.walkTopDown().forEach { entry ->
            val canonicalEntry = contained(entry)
            if (canonicalEntry.isFile) {
                total = saturatedAdd(total, canonicalEntry.length())
            }
        }
        return total
    }

    private fun validateRoot(): File {
        val canonicalRoot = contained(rootDir)
        require(canonicalRoot == rootDir) {
            "RTP media cache root changed outside its canonical path."
        }
        return canonicalRoot
    }

    private fun contained(file: File): File {
        return canonicalPathWithinRoot(rootDir, file)
    }

    private fun saturatedAdd(left: Long, right: Long): Long =
        if (right > Long.MAX_VALUE - left) Long.MAX_VALUE else left + right

    private data class CacheEntry(
        val directory: File,
        val lastModified: Long
    )
}

internal fun canonicalPathWithinRoot(rootDir: File, path: File): File {
    val canonicalRoot = rootDir.canonicalFile
    val canonicalPath = path.canonicalFile
    require(canonicalPath == canonicalRoot || canonicalPath.startsWith(canonicalRoot)) {
        "RTP media cache path escapes its root: ${canonicalPath.path}"
    }
    return canonicalPath
}
