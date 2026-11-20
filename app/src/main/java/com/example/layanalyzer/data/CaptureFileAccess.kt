// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.capture.tls.TlsAssetException
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS

/** Process-wide ownership for the app's single Android process. Never waits while holding a
 * native/secret-store lock. Parents conflict with children; siblings remain independent. */
internal object CaptureFileAccess {
    private class Use(val paths: List<File>, val exclusive: Boolean)
    private val uses = mutableSetOf<Use>()
    private val deferred = mutableSetOf<() -> Unit>()

    fun retain(vararg files: File): AutoCloseable = acquire(files.toList(), false)

    fun <T> idle(files: List<File>, block: () -> T): T = acquire(files, true).use { block() }

    @Synchronized private fun acquire(files: List<File>, exclusive: Boolean): AutoCloseable {
        val paths = files.map { it.canonicalFile }
        if (uses.any { old -> (exclusive || old.exclusive) && old.paths.any { a ->
                paths.any { b -> a.toPath().startsWith(b.toPath()) || b.toPath().startsWith(a.toPath()) }
            } }) throw TlsAssetException(TlsAssetErrorCode.IN_USE)
        val token = Use(paths, exclusive)
        uses.add(token)
        return AutoCloseable {
            val retry = synchronized(this) {
                if (uses.remove(token)) deferred.toList().also { deferred.clear() } else emptyList()
            }
            retry.forEach(::retryWhenReleased)
        }
    }

    /** A close may race a still-finishing export. The durable journal also retries on restart. */
    fun retryWhenReleased(operation: () -> Unit) {
        try { operation() } catch (_: java.io.IOException) {
            synchronized(this) { deferred.add(operation) }
        }
    }
}

/** All destructive targets are local flat children. Reject links before any mutation. */
internal object CaptureFiles {
    fun child(root: File, name: String): File {
        if (name.isBlank() || name in setOf(".", "..") || name.any { it == '/' || it == '\\' || it == ':' })
            throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        val file = File(root, name)
        if (Files.isSymbolicLink(root.toPath()) || Files.isSymbolicLink(file.toPath()) ||
            file.canonicalFile.parentFile != root.canonicalFile)
            throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        rejectRedirect(file)
        return file
    }

    fun checkTree(file: File) {
        if (Files.isSymbolicLink(file.toPath())) throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        if (!Files.exists(file.toPath(), NOFOLLOW_LINKS)) return
        rejectRedirect(file)
        if (file.isDirectory) children(file).forEach(::checkTree)
        else if (!Files.isRegularFile(file.toPath(), NOFOLLOW_LINKS))
            throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
    }

    private fun rejectRedirect(file: File) {
        // Windows directory junctions are not reported by isSymbolicLink().
        if (Files.exists(file.toPath(), NOFOLLOW_LINKS) &&
            file.toPath().toRealPath() != file.absoluteFile.parentFile!!.toPath().toRealPath().resolve(file.name))
            throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
    }

    fun children(directory: File): List<File> = if (!directory.exists()) emptyList() else
        Files.newDirectoryStream(directory.toPath()).use { entries ->
            entries.map { child(directory, it.fileName.toString()) }.toList()
        }

    /** Only called after checkTree on the entire bounded capture/operation subtree. */
    fun deleteTree(file: File) {
        checkTree(file)
        if (file.isDirectory) children(file).forEach(::deleteTree)
        Files.deleteIfExists(file.toPath())
    }
}
