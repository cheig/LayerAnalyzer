// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.example.layanalyzer.model.PacketSummary
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.withContext
import kotlin.math.max

interface PacketPageReader {
    fun getVisibleFrameCount(): Int
    fun getPacketSummaries(start: Int, count: Int): List<PacketSummary>
}

@OptIn(ExperimentalCoroutinesApi::class)
private val PACKET_PAGING_DISPATCHER: CoroutineDispatcher =
    Dispatchers.IO.limitedParallelism(1)

class PacketPagingSource(
    private val repository: PacketPageReader,
    private val pagingDispatcher: CoroutineDispatcher = PACKET_PAGING_DISPATCHER
) : PagingSource<Int, PacketSummary>() {

    override fun getRefreshKey(state: PagingState<Int, PacketSummary>): Int? {
        return state.anchorPosition
    }

    override suspend fun load(params: LoadParams<Int>): LoadResult<Int, PacketSummary> {
        return withContext(pagingDispatcher) {
            val total = repository.getVisibleFrameCount()
            val offset = (params.key ?: 0).coerceIn(0, max(total - 1, 0))
            val pageSize = params.loadSize

            try {
                if (total <= 0) {
                    return@withContext LoadResult.Page(
                        data = emptyList(),
                        prevKey = null,
                        nextKey = null,
                        itemsBefore = 0,
                        itemsAfter = 0
                    )
                }

                val data = repository.getPacketSummaries(offset, pageSize)

                val nextOffset = offset + data.size
                val nextKey = if (data.isEmpty() || nextOffset >= total) null else nextOffset
                val prevKey = (offset - pageSize).takeIf { it >= 0 } ?: if (offset > 0) 0 else null

                LoadResult.Page(
                    data = data,
                    prevKey = prevKey,
                    nextKey = nextKey,
                    itemsBefore = offset,
                    itemsAfter = (total - nextOffset).coerceAtLeast(0)
                )
            } catch (e: Exception) {
                LoadResult.Error(e)
            }
        }
    }
}
