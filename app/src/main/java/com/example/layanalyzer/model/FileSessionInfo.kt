package com.example.layanalyzer.model

data class FileSessionInfo(
    val displayName: String,
    val sizeBytes: Long,
    val fileType: String,
    val frameCount: Int,
    val localPath: String,
    val encapsulation: String = "unknown"
)

data class RecentCapture(
    val displayName: String,
    val sizeBytes: Long,
    val localPath: String,
    val openedAtMillis: Long,
    val frameCount: Int = 0,
    val hasSavedWorkspace: Boolean = false
)

data class OpenProgress(
    val message: String,
    val framesIndexed: Int = 0,
    val bytesRead: Long = 0,
    val totalBytes: Long = 0
) {
    val progressFraction: Float?
        get() = if (totalBytes > 0L) (bytesRead.toFloat() / totalBytes).coerceIn(0f, 1f) else null
}
