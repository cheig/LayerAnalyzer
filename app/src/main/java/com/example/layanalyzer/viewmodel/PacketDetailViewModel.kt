// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import android.content.Context
import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.layanalyzer.R
import com.example.layanalyzer.data.PacketReassemblyResolver
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.model.ExportResult
import com.example.layanalyzer.model.ExportUiState
import com.example.layanalyzer.model.FollowStreamResult
import com.example.layanalyzer.model.PacketReassembly
import com.example.layanalyzer.model.PacketSummary
import com.example.layanalyzer.model.ProtocolNode
import com.example.layanalyzer.model.PacketDetailSnapshot
import com.example.layanalyzer.model.PacketDataSourceException
import com.example.layanalyzer.model.PACKET_DATA_RANGE_LIMIT
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import org.json.JSONArray

data class PacketDetailState(
    val frameNumber: Long,
    val root: ProtocolNode,
    val bytes: ByteArray,
    val summary: PacketSummary? = null,
    val dataSnapshot: PacketDetailSnapshot? = null
)

data class PacketNavigationState(
    val position: Int = -1,
    val total: Int = 0,
    val scope: String = "current filtered packet set"
) {
    val hasPrevious: Boolean get() = position > 0
    val hasNext: Boolean get() = position >= 0 && position < total - 1
}

/**
 * TLS-307 byte window state. Only the frame, the clicked field label and whether that field had an
 * addressable range are captured here; the bytes, source identity, window offset and highlight live
 * in [PacketDataSourceState] so the dialog always renders the current source and never a stale copy.
 * `selectionAvailable=false` closes the selection actions for generated / missing-offset fields.
 */
data class PacketBytesViewerState(
    val frameNumber: Long,
    val nodeLabel: String,
    val selectionAvailable: Boolean,
    /** Legacy details (no native snapshot) keep browsing raw frame bytes through this source-relative slice. */
    val legacyRawRange: IntRange? = null
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

    private val _dataSourceState = MutableStateFlow(PacketDataSourceState())
    /** TLS-307 consumes these source-relative windows separately from the legacy raw-byte screen. */
    val dataSourceState = _dataSourceState.asStateFlow()
    private var dataSourceJob: Job? = null

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

    private var detailJob: Job? = null
    private var reassemblyJob: Job? = null
    private var followJob: Job? = null
    private var selectionGeneration = 0L
    private val _isResolvingReassembly = MutableStateFlow(false)
    val isResolvingReassembly = _isResolvingReassembly.asStateFlow()
    private val _actionMessage = MutableStateFlow<String?>(null)
    val actionMessage = _actionMessage.asStateFlow()

    init {
        viewModelScope.launch {
            repository.analysisRevisions.drop(1).collect {
                clearSelection()
                _navigationState.value = PacketNavigationState()
                _exportState.value = ExportUiState()
            }
        }
    }

    fun loadPacketDetail(frameNumber: Long) {
        val generation = ++selectionGeneration
        detailJob?.cancel()
        dataSourceJob?.cancel()
        _dataSourceState.value = PacketDataSourceState(serial = _dataSourceState.value.serial + 1)
        reassemblyJob?.cancel()
        _isResolvingReassembly.value = false
        _actionMessage.value = null
        refreshBookmarksForCurrentFile()
        val session = repository.currentAnalysisRevision()
        detailJob = viewModelScope.launch {
            _isLoading.value = true
            _selectedByteRange.value = null
            _selectedField.value = null
            _packetBytesViewer.value = null
            try {
                val detail = withContext(Dispatchers.IO) {
                    check(repository.isAnalysisCurrent(session))
                    check(frameNumber in 1..repository.getFrameCount().toLong())
                    val position = repository.findVisibleFramePosition(frameNumber)
                    val snapshot = repository.getPacketDetailSnapshot(frameNumber, session)
                    val bytes = repository.getPacketBytes(frameNumber)
                    val summary = position?.let(repository::getVisiblePacketSummary)
                    Pair(
                        PacketDetailState(frameNumber, snapshot.root, bytes, summary, snapshot),
                        PacketNavigationState(
                            position = position ?: -1,
                            total = repository.getVisibleFrameCount()
                        )
                    )
                }
                if (!repository.isAnalysisCurrent(session) || generation != selectionGeneration) return@launch
                _selectedPacket.value = detail.first
                _navigationState.value = detail.second
                val snapshot = detail.first.dataSnapshot!!
                _dataSourceState.value = _dataSourceState.value.open(session, snapshot)
                _dataSourceState.value.source?.let {
                    readPacketDataSourceRange(0, minOf(it.availableLength, PACKET_DATA_RANGE_LIMIT))
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (generation == selectionGeneration && repository.isAnalysisCurrent(session)) {
                    _actionMessage.value = text(R.string.error_open_referenced_frame, frameNumber)
                }
            } finally {
                if (generation == selectionGeneration) _isLoading.value = false
            }
        }
    }

    fun setReassemblyHighlighted(
        selection: PacketReassembly,
        highlighted: Boolean,
        onResolved: (Set<Long>, Boolean) -> Unit
    ) {
        val detail = _selectedPacket.value ?: return
        if (_isLoading.value || _isResolvingReassembly.value) return
        val generation = selectionGeneration
        val session = repository.currentAnalysisRevision()
        _actionMessage.value = null
        _isResolvingReassembly.value = true
        reassemblyJob = viewModelScope.launch {
            try {
                val frames = withContext(Dispatchers.IO) {
                    PacketReassemblyResolver(repository.getFrameCount()) { frame ->
                        ensureActive()
                        check(repository.isAnalysisCurrent(session))
                        repository.getPacketDetails(frame)
                    }.resolve(detail.frameNumber, detail.root, selection)
                }
                if (!repository.isAnalysisCurrent(session) || _selectedPacket.value !== detail) return@launch
                onResolved(frames, highlighted)
                _actionMessage.value = text(
                    if (highlighted) R.string.reassembly_highlighted else R.string.reassembly_highlights_cleared,
                    frames.size
                )
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (generation == selectionGeneration && repository.isAnalysisCurrent(session)) {
                    _actionMessage.value = text(R.string.error_resolve_reassembly)
                }
            } finally {
                if (generation == selectionGeneration) _isResolvingReassembly.value = false
            }
        }
    }

    fun clearActionMessage() {
        _actionMessage.value = null
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
        val expected = repository.currentAnalysisRevision()
        viewModelScope.launch {
            val navigation = withContext(Dispatchers.IO) {
                PacketNavigationState(
                    position = repository.findVisibleFramePosition(frameNumber) ?: -1,
                    total = repository.getVisibleFrameCount()
                )
            }
            if (repository.isAnalysisCurrent(expected) && _selectedPacket.value?.frameNumber == frameNumber) {
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
        // The hex tab still shows raw frame bytes, so only a raw field highlights there. A derived
        // field is selected in dataSourceState against its own source, never against this raw array.
        _selectedByteRange.value = rawNodeRange(node)
        selectDataSourceField(node)
    }

    /**
     * TLS-307: open the source-aware byte window for [node]. The bytes come from the node's own
     * data source; a generated / missing-offset field opens the window with the selection actions
     * closed instead of falling back to raw.
     */
    fun showPacketBytes(node: ProtocolNode) {
        val detail = _selectedPacket.value ?: return
        val state = _dataSourceState.value
        // Legacy details carry no native snapshot: keep the previous raw-only dialog, byte-for-byte.
        if (detail.dataSnapshot?.snapshot == null || state.sources.isEmpty()) {
            val range = rawNodeRange(node) ?: run {
                _packetBytesViewer.value = null
                return
            }
            _packetBytesViewer.value = PacketBytesViewerState(
                frameNumber = detail.frameNumber,
                nodeLabel = node.label,
                selectionAvailable = false,
                legacyRawRange = range
            )
            return
        }
        val addressable = PacketBytesSourceActions.fieldTarget(state, node) != null
        _packetBytesViewer.value = PacketBytesViewerState(
            frameNumber = detail.frameNumber,
            nodeLabel = node.label,
            selectionAvailable = addressable
        )
        if (addressable) {
            selectDataSourceField(node)
        } else {
            _dataSourceState.value = state.clearSelection()
        }
    }

    fun dismissPacketBytesViewer() {
        _packetBytesViewer.value = null
    }

    private fun rawNodeRange(node: ProtocolNode): IntRange? {
        val detail = _selectedPacket.value ?: return null
        fun contains(root: ProtocolNode): Boolean = root === node || root.children.any(::contains)
        if (!contains(detail.root)) return null
        val available = detail.dataSnapshot?.sources?.firstOrNull { it.id == "raw" }?.availableLength
            ?: detail.bytes.size
        return node.byteRange("raw", minOf(available, detail.bytes.size))
    }

    /** Switch the visible data source (dialog source chips); the open byte window stays open. */
    fun selectPacketDataSource(sourceId: String) {
        dataSourceJob?.cancel()
        _selectedByteRange.value = null
        _selectedField.value = null
        val next = _dataSourceState.value.switchSource(sourceId)
        _dataSourceState.value = next
        next.source?.let { source ->
            readPacketDataSourceRange(0, minOf(source.availableLength, PACKET_DATA_RANGE_LIMIT))
        }
    }

    /**
     * TLS-307: click a field -> switch to the field's own source by `dataSourceId`, load the bounded
     * window that covers it, then highlight its source-relative range. Fields with no addressable
     * range clear the highlight rather than guessing raw.
     */
    fun selectDataSourceField(node: ProtocolNode) {
        val state = _dataSourceState.value
        val target = PacketBytesSourceActions.fieldTarget(state, node)
        if (target == null) {
            _dataSourceState.value = state.clearSelection()
            return
        }
        val (source, range) = target
        val window = PacketBytesSourceActions.windowRead(range, source)
        if (window == null) {
            _dataSourceState.value = state.clearSelection()
            return
        }
        val switched = if (source.id == state.sourceId) state else state.switchSource(source.id)
        val alreadyLoaded = !switched.isLoading && range.first >= switched.offset &&
            range.last < switched.offset.toLong() + switched.bytes.size
        if (alreadyLoaded) {
            _dataSourceState.value = switched.selectRange(range)
        } else {
            _dataSourceState.value = switched
            val selection = PacketBytesSourceActions.loadedSelection(range, window)
            loadPacketDataSourceRange(window.first, window.count(), true) { loaded -> loaded.selectRange(selection) }
        }
    }

    fun selectDataSourceByteRange(range: IntRange?) {
        _dataSourceState.value = _dataSourceState.value.selectRange(range)
    }

    fun readPacketDataSourceRange(offset: Int, length: Int) = loadPacketDataSourceRange(offset, length, true, null)

    private fun loadPacketDataSourceRange(
        offset: Int,
        length: Int,
        recoverStale: Boolean,
        onLoaded: ((PacketDataSourceState) -> PacketDataSourceState)?
    ) {
        dataSourceJob?.cancel()
        val pending = _dataSourceState.value.beginRange(offset, length)
        _dataSourceState.value = pending
        val token = pending.request!!
        dataSourceJob = viewModelScope.launch {
            try {
                val chunk = withContext(Dispatchers.IO) {
                    repository.readPacketDataSource(token.snapshot, token.source, offset, length, token.analysis)
                }
                if (repository.isAnalysisCurrent(token.analysis)) {
                    val completed = _dataSourceState.value.complete(token, chunk)
                    _dataSourceState.value = onLoaded?.invoke(completed) ?: completed
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (!repository.isAnalysisCurrent(token.analysis) || !_dataSourceState.value.accepts(token)) return@launch
                val code = (e as? PacketDataSourceException)?.errorCode ?: "IO_ERROR"
                if (code == "STALE_GENERATION" && recoverStale) {
                    try {
                        val fresh = withContext(Dispatchers.IO) {
                            repository.getPacketDetailSnapshot(token.snapshot.frameNumber, token.analysis)
                        }
                        if (!repository.isAnalysisCurrent(token.analysis) || !_dataSourceState.value.accepts(token)) return@launch
                        _selectedPacket.value = _selectedPacket.value?.copy(root = fresh.root, dataSnapshot = fresh)
                        _selectedField.value = null
                        _selectedByteRange.value = null
                        _dataSourceState.value = _dataSourceState.value.refreshed(token, fresh)
                        // Raw is stable; derived IDs must be selected again from the new tree.
                        _dataSourceState.value.source?.let {
                            loadPacketDataSourceRange(0, minOf(it.availableLength, PACKET_DATA_RANGE_LIMIT), false, null)
                        }
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (refreshError: Exception) {
                        if (repository.isAnalysisCurrent(token.analysis)) {
                            _dataSourceState.value = _dataSourceState.value.fail(token,
                                (refreshError as? PacketDataSourceException)?.errorCode ?: "IO_ERROR")
                        }
                    }
                } else {
                    _dataSourceState.value = _dataSourceState.value.fail(token, code)
                }
            }
        }
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
        val expected = repository.currentAnalysisRevision()
        val generation = selectionGeneration
        followJob?.cancel()
        followJob = viewModelScope.launch {
            _isFollowingStream.value = true
            try {
                val result = withContext(Dispatchers.IO) {
                    repository.followStream(frameNumber, protocol)
                }
                if (repository.isAnalysisCurrent(expected) && generation == selectionGeneration) {
                    _followStream.value = result
                }
            } finally {
                if (generation == selectionGeneration) _isFollowingStream.value = false
            }
        }
    }

    fun clearFollowStream() {
        _followStream.value = null
    }

    fun exportPacketDetailsForShare() {
        val frameNumber = _selectedPacket.value?.frameNumber ?: return
        val expected = repository.currentAnalysisRevision()
        viewModelScope.launch {
            _exportState.value = ExportUiState(isExporting = true)
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    repository.withCaptureExport(expected) {
                        val fileName = "packet-$frameNumber-details.txt"
                        val file = createExportFile(fileName)
                        file.outputStream().use { output -> repository.exportPacketDetailsText(frameNumber, output) }
                        ExportResult(file.absolutePath, fileName, "text/plain")
                    }
                }
            }
            if (!repository.isAnalysisCurrent(expected)) return@launch
            _exportState.value = result.fold(
                onSuccess = { ExportUiState(message = text(R.string.packet_details_exported), shareResult = it) },
                onFailure = { ExportUiState(error = it.message ?: text(R.string.error_export_packet_details)) }
            )
        }
    }

    fun exportSelectedBytesForShare() {
        val state = _selectedPacket.value ?: return
        val expected = repository.currentAnalysisRevision()
        viewModelScope.launch {
            _exportState.value = ExportUiState(isExporting = true)
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    repository.withCaptureExport(expected) {
                        val fileName = "packet-${state.frameNumber}-bytes.hex.txt"
                        val file = createExportFile(fileName)
                        file.outputStream().use { output ->
                            repository.exportPacketBytesHex(state.frameNumber, _selectedByteRange.value, output)
                        }
                        ExportResult(file.absolutePath, fileName, "text/plain")
                    }
                }
            }
            if (!repository.isAnalysisCurrent(expected)) return@launch
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
        selectionGeneration++
        dataSourceJob?.cancel()
        _dataSourceState.value = PacketDataSourceState(serial = _dataSourceState.value.serial + 1)
        detailJob?.cancel()
        reassemblyJob?.cancel()
        followJob?.cancel()
        _isFollowingStream.value = false
        _isLoading.value = false
        _isResolvingReassembly.value = false
        _actionMessage.value = null
        _selectedPacket.value = null
        _selectedByteRange.value = null
        _selectedField.value = null
        _followStream.value = null
        _packetBytesViewer.value = null
    }

    private fun createExportFile(fileName: String): File {
        val source = repository.currentFile() ?: error("No capture is open.")
        val dir = com.example.layanalyzer.data.CaptureArtifactLifecycle(appContext)
            .exportDirectory(File(source.localPath))
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
