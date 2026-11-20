// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import com.example.layanalyzer.capture.tls.TlsAssetException
import com.example.layanalyzer.capture.tls.TlsAssetErrorCode

/** Private, bounded operation directories; OS locks survive neither process death nor reboot. */
internal object TlsBundleWorkspaces {
    private val live = mutableSetOf<String>()

    fun <T> use(root: File, block: (File) -> T): T {
        val directory = synchronized(this) {
            CaptureFiles.checkTree(root)
            check(root.mkdirs() || root.isDirectory)
            Files.createTempDirectory(root.toPath(), "operation-").toFile().also { live.add(it.canonicalPath) }
        }
        try {
            RandomAccessFile(CaptureFiles.child(directory, ".live.lock"), "rw").use { file ->
                file.channel.lock().use { return block(directory) }
            }
        } finally {
            synchronized(this) {
                try { CaptureFiles.deleteTree(directory) } finally { live.remove(directory.canonicalPath) }
            }
        }
    }

    @Synchronized fun cleanup(root: File): Int {
        var removed = 0
        CaptureFiles.children(root).filter { it.name.startsWith("operation-") }.forEach { directory ->
            if (directory.canonicalPath in live) return@forEach
            CaptureFiles.checkTree(directory)
            if (!directory.isDirectory) throw TlsAssetException(TlsAssetErrorCode.INVALID_FORMAT)
            val lockFile = CaptureFiles.child(directory, ".live.lock")
            var owned = false
            RandomAccessFile(lockFile, "rw").use { file ->
                val lock = try { file.channel.tryLock() } catch (_: OverlappingFileLockException) { null }
                lock?.use {
                    CaptureFiles.children(directory).filter { it != lockFile }.forEach(CaptureFiles::deleteTree)
                    owned = true
                }
            }
            if (owned) { CaptureFiles.deleteTree(directory); removed++ }
        }
        return removed
    }
}
