package com.example.layanalyzer.data

import java.io.File

/**
 * Write [encoded] to [target] atomically: full contents go to a temporary file
 * in the same directory, then a rename moves it into place, so a process death
 * mid-write leaves either the previous file or the new one — never a
 * half-written JSON that would fail to decode on the next launch.
 *
 * The temporary-file suffix is chosen by the caller so a store can keep its own
 * convention for what [clear] is allowed to sweep up.
 *
 * Note: `renameTo` does not replace on every filesystem, so an existing
 * [target] is removed first.  A crash in that gap loses the old file; callers
 * that must never lose data (session migration) only ever call this with a
 * brand-new target name.
 */
internal fun writeJsonAtomically(target: File, encoded: String, tempSuffix: String = ".tmp") {
    val temporary = File(target.parentFile, "${target.name}$tempSuffix")
    try {
        temporary.writeText(encoded)
        if (target.exists() && !target.delete()) {
            throw IllegalStateException("Unable to replace the existing file.")
        }
        if (!temporary.renameTo(target)) {
            throw IllegalStateException("Unable to store the file.")
        }
    } finally {
        temporary.delete()
    }
}
