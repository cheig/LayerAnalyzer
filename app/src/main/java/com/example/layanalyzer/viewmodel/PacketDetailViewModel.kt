// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import android.content.Context
import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.layanalyzer.R
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.model.ExportResult
import com.example.layanalyzer.model.ExportUiState
import com.example.layanalyzer.model.FollowStreamResult
import com.example.layanalyzer.model.PacketSummary
import com.example.layanalyzer.model.ProtocolNode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import org.json.JSONArray

data class PacketDetailState(
    val frameNumber: Long,
    val root: ProtocolNode,
    val bytes: ByteArray,
    val summary: PacketSummary? = null
)

data class PacketNavigationState(
    val position: Int = -1,
    val total: Int = 0,
    val scope: String = "current filtered packet set"
) {
    val hasPrevious: Boolean get() = position > 0
    val hasNext: Boolean get() = position >= 0 && position < total - 1
}

/** "显示分组字节"弹窗的瞬时状态：只存帧偏移区间，字节从 selectedPacket.bytes 现取，避免大帧二次拷贝驻留 */
data class PacketBytesViewerState(
    val frameNumber: Long,
    val nodeLabel: String,      // 协议层显示名，如 "Transmission Control Protocol"
    val start: Int,             // 帧偏移起点（含）
    val endExclusive: Int       // 帧偏移终点（不含），恒有 endExclusive >= start
)

class PacketDetailViewModel(
    private val repository: PacketRepository,
    context: Context
) : ViewModel() {
    private val appContext = context.applicationContext
    private fun text(@StringRes id: Int, vararg args: Any): String = appContext.getString(id, *args)
    private val bookmarkPrefs = appContext.getSharedPreferences("packet_bookmarks", Context.MODE_PRIVATE)

    private val _selectedPacket = MutableStateFlow<PacketDetailState?>(null)
    val selectedPacket = _selectedPacket.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading = _isLoading.asStateFlow()

    private val _selectedByteRange = MutableStateFlow<IntRange?>(null)
    val selectedByteRange = _selectedByteRange.asStateFlow()

    private val _selectedField = MutableStateFlow<ProtocolNode?>(null)
    val selectedField = _selectedField.asStateFlow()

    private val _navigationState = MutableStateFlow(PacketNavigationState())
    val navigationState = _navigationState.asStateFlow()

    private val _followStream = MutableStateFlow<FollowStreamResult?>(null)
    val followStream = _followStream.asStateFlow()

    private val _isFollowingStream = MutableStateFlow(false)
    val isFollowingStream = _isFollowingStream.asStateFlow()

    private val _packetBytesViewer = MutableStateFlow<PacketBytesViewerState?>(null)
    val packetBytesViewer = _packetBytesViewer.asStateFlow()

    private val _exportState = MutableStateFlow(ExportUiState())
    val exportState = _exportState.asStateFlow()

    private var bookmarkPath = repository.currentFile()?.localPath.orEmpty()
    private val _bookmarkedFrames = MutableStateFlow(loadBookmarks(bookmarkPath))
    val bookmarkedFrames = _bookmarkedFrames.asStateFlow()

    fun loadPacketDetail(frameNumber: Long) {
        refreshBookmarksForCurrentFile()
        viewModelScope.launch {
            _isLoading.value = true
            _selectedByteRange.value = null
            _selectedField.value = null
            _packetBytesViewer.value = null
            val detail = withContext(Dispatchers.IO) {
                val position = repository.findVisibleFramePosition(frameNumber)
                val node = repository.getPacketDetails(frameNumber)
                val bytes = repository.getPacketBytes(frameNumber)
                val summary = position?.let(repository::getVisiblePacketSummary)
                Pair(
                    if (node == null) null else PacketDetailState(frameNumber, node, bytes, summary),
                    PacketNavigationState(
                        position = position ?: -1,
                        total = repository.getVisibleFrameCount()
                    )
                )
            }
            _selectedPacket.value = detail.first
            _navigationState.value = detail.second
            _isLoading.value = false
        }
    }

    fun loadAdjacentPacket(offset: Int) {
        val navigation = _navigationState.value
        val targetPosition = navigation.position + offset
        if (targetPosition !in 0 until navigation.total) return
        val targetFrame = repository.getVisiblePacketSummary(targetPosition)?.frameNumber ?: return
        loadPacketDetail(targetFrame)
    }

    fun refreshNavigation() {
        val frameNumber = _selectedPacket.value?.frameNumber ?: return
        viewModelScope.launch {
            val navigation = withContext(Dispatchers.IO) {
                PacketNavigationState(
                    position = repository.findVisibleFramePosition(frameNumber) ?: -1,
                    total = repository.getVisibleFrameCount()
                )
            }
            if (_selectedPacket.value?.frameNumber == frameNumber) {
                _navigationState.value = navigation
            }
        }
    }

    fun toggleBookmark() {
        refreshBookmarksForCurrentFile()
        val frame = _selectedPacket.value?.frameNumber ?: return
        val next = _bookmarkedFrames.value.toMutableSet().apply {
            if (!add(frame)) remove(frame)
        }
        _bookmarkedFrames.value = next
        bookmarkPrefs.edit().putString(
            bookmarkPath,
            JSONArray(next.sorted()).toString()
        ).apply()
    }

    fun selectField(node: ProtocolNode) {
        _selectedField.value = node
        _selectedByteRange.value = if (node.length > 0) {
            node.start until (node.start + node.length)
        } else {
            null
        }
    }

    /** 打开"显示分组字节"弹窗；start/length 越界由 clamp 防御 */
    fun showPacketBytes(node: ProtocolNode) {
        val detail = _selectedPacket.value ?: return
        val start = node.start.coerceIn(0, detail.bytes.size)
        // 用 Long 求终点，避免 start+length 溢出成负数后被错误 clamp
        val requestedEnd = node.start.toLong() + node.length
        val end = when {
            requestedEnd > detail.bytes.size -> detail.bytes.size
            requestedEnd < start -> start
            else -> requestedEnd.toInt()
        }
        _packetBytesViewer.value = PacketBytesViewerState(
            frameNumber = detail.frameNumber,
            nodeLabel = node.label,
            start = start,
            endExclusive = end
        )
    }

    fun dismissPacketBytesViewer() {
        _packetBytesViewer.value = null
    }

    fun selectByte(offset: Int) {
        val bytes = _selectedPacket.value?.bytes ?: return
        if (offset !in bytes.indices) return
        _selectedField.value = null
        _selectedByteRange.value = offset..offset
    }

    fun selectByteRange(range: IntRange) {
        val bytes = _selectedPacket.value?.bytes ?: return
        if (bytes.isEmpty()) return
        val start = range.first.coerceIn(bytes.indices)
        val end = range.last.coerceIn(bytes.indices)
        _selectedField.value = null
        _selectedByteRange.value = minOf(start, end)..maxOf(start, end)
    }

    fun followStream(protocol: String) {
        val frameNumber = _selectedPacket.value?.frameNumber ?: return
        viewModelScope.launch {
            _isFollowingStream.value = true
            _followStream.value = withContext(Dispatchers.IO) {
                repository.followStream(frameNumber, protocol)
            }
            _isFollowingStream.value = false
        }
    }

    fun clearFollowStream() {
        _followStream.value = null
    }

    fun exportPacketDetailsForShare() {
        val frameNumber = _selectedPacket.value?.frameNumber ?: return
        viewModelScope.launch {
            _exportState.value = ExportUiState(isExporting = true)
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val fileName = "packet-$frameNumber-details.txt"
                    val file = createExportFile(fileName)
                    file.outputStream().use { output -> repository.exportPacketDetailsText(frameNumber, output) }
                    ExportResult(file.absolutePath, fileName, "text/plain")
                }
            }
            _exportState.value = result.fold(
                onSuccess = { ExportUiState(message = text(R.string.packet_details_exported), shareResult = it) },
                onFailure = { ExportUiState(error = it.message ?: text(R.string.error_export_packet_details)) }
            )
        }
    }

    fun exportSelectedBytesForShare() {
        val state = _selectedPacket.value ?: return
        viewModelScope.launch {
            _exportState.value = ExportUiState(isExporting = true)
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    val fileName = "packet-${state.frameNumber}-bytes.hex.txt"
                    val file = createExportFile(fileName)
                    file.outputStream().use { output ->
                        repository.exportPacketBytesHex(state.frameNumber, _selectedByteRange.value, output)
                    }
                    ExportResult(file.absolutePath, fileName, "text/plain")
                }
            }
            _exportState.value = result.fold(
                onSuccess = { ExportUiState(message = text(R.string.packet_bytes_exported), shareResult = it) },
                onFailure = { ExportUiState(error = it.message ?: text(R.string.error_export_packet_bytes)) }
            )
        }
    }

    fun clearExportState() {
        _exportState.value = ExportUiState()
    }

    fun clearSelection() {
        _selectedPacket.value = null
        _selectedByteRange.value = null
        _selectedField.value = null
        _followStream.value = null
        _packetBytesViewer.value = null
    }

    private fun createExportFile(fileName: String): File {
        val dir = File(appContext.filesDir, "exports").apply { mkdirs() }
        val sanitized = fileName.replace(Regex("[\\\\/:*?\"<>|]"), "_")
        return File(dir, sanitized)
    }

    private fun refreshBookmarksForCurrentFile() {
        val currentPath = repository.currentFile()?.localPath.orEmpty()
        if (currentPath == bookmarkPath) return
        bookmarkPath = currentPath
        _bookmarkedFrames.value = loadBookmarks(currentPath)
    }

    private fun loadBookmarks(path: String): Set<Long> {
        if (path.isBlank()) return emptySet()
        val raw = bookmarkPrefs.getString(path, null) ?: return emptySet()
        return runCatching {
            val values = JSONArray(raw)
            buildSet {
                for (index in 0 until values.length()) add(values.getLong(index))
            }
        }.getOrDefault(emptySet())
    }
}
