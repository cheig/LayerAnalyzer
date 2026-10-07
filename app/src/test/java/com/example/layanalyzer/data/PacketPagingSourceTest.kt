// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import androidx.paging.PagingSource
import com.example.layanalyzer.model.PacketSummary
import java.util.concurrent.Executors
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketPagingSourceTest {
    @Test
    fun pageLoadsUseTheDedicatedNativeReadDispatcher() = runBlocking {
        val executor = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "packet-paging-native-read")
        }
        val dispatcher = executor.asCoroutineDispatcher()
        try {
            var readThread = ""
            val reader = object : PacketPageReader {
                override fun getVisibleFrameCount(): Int = 1

                override fun getPacketSummaries(start: Int, count: Int): List<PacketSummary> {
                    readThread = Thread.currentThread().name
                    return listOf(
                        PacketSummary(
                            frameNumber = 1L,
                            time = "0.0",
                            source = "a",
                            destination = "b",
                            protocol = "tcp",
                            length = 64,
                            info = "test"
                        )
                    )
                }
            }

            val result = PacketPagingSource(reader, dispatcher).load(
                PagingSource.LoadParams.Refresh(
                    key = null,
                    loadSize = 50,
                    placeholdersEnabled = true
                )
            )

            assertTrue(result is PagingSource.LoadResult.Page)
            assertTrue(readThread.startsWith("packet-paging-native-read"))
        } finally {
            dispatcher.close()
            executor.shutdownNow()
        }
    }
}
