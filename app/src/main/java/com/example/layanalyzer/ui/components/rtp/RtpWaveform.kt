package com.example.layanalyzer.ui.components.rtp

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.model.RtpEvent
import com.example.layanalyzer.model.RtpGap
import kotlin.math.roundToLong

/** 把 peaks（min/max 交错）按目标宽度降采样。纯函数，可单测。 */
fun downsamplePeaks(peaks: ShortArray, targetBuckets: Int): ShortArray {
    if (peaks.isEmpty() || targetBuckets <= 0 || targetBuckets > Int.MAX_VALUE / 2) {
        return ShortArray(0)
    }

    val inputBuckets = peaks.size / 2
    if (inputBuckets == 0) return ShortArray(0)

    val output = ShortArray(targetBuckets * 2)
    val bucketsPerOutput = (inputBuckets + targetBuckets - 1) / targetBuckets
    for (outputIndex in 0 until targetBuckets) {
        val start = outputIndex * bucketsPerOutput
        if (start >= inputBuckets) break

        val end = minOf(start + bucketsPerOutput, inputBuckets)
        var minValue = Short.MAX_VALUE
        var maxValue = Short.MIN_VALUE
        for (inputIndex in start until end) {
            val inputMin = peaks[inputIndex * 2]
            val inputMax = peaks[inputIndex * 2 + 1]
            if (inputMin < minValue) minValue = inputMin
            if (inputMax > maxValue) maxValue = inputMax
        }

        output[outputIndex * 2] = minValue
        output[outputIndex * 2 + 1] = maxValue
    }
    return output
}

data class RtpWaveformTrack(
    val peaks: ShortArray,
    val samplesPerBucket: Int,
    val label: String
)

/**
 * RTP 音频波形。
 *
 * 主轨和 [extraTracks] 共用同一时间轴。绘制只使用 [MaterialTheme.colorScheme]
 * 的语义色，避免深色模式下出现不可读的固定颜色。
 */
@Composable
fun RtpWaveform(
    peaks: ShortArray,
    sampleRate: Int,
    samplesPerBucket: Int,
    durationMs: Long,
    gaps: List<RtpGap>,
    events: List<RtpEvent>,
    playheadMs: Long,
    onSeek: (Long) -> Unit,
    modifier: Modifier = Modifier,
    extraTracks: List<RtpWaveformTrack> = emptyList()
) {
    val colorScheme = MaterialTheme.colorScheme
    val waveformColor = colorScheme.primary
    val eventColor = colorScheme.secondary
    val playheadColor = colorScheme.onSurface
    val centerLineColor = colorScheme.outlineVariant
    val safeDurationMs = durationMs.coerceAtLeast(0L)

    var isDragging by remember { mutableStateOf(false) }
    var displayedPlayheadMs by remember {
        mutableStateOf(playheadMs.coerceIn(0L, safeDurationMs))
    }
    val currentOnSeek by rememberUpdatedState(onSeek)

    LaunchedEffect(playheadMs, safeDurationMs, isDragging) {
        if (!isDragging) {
            displayedPlayheadMs = playheadMs.coerceIn(0L, safeDurationMs)
        }
    }

    Canvas(
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 96.dp)
            .pointerInput(safeDurationMs) {
                detectTapGestures { position ->
                    if (size.width <= 0) return@detectTapGestures
                    val seekMs = seekMsAt(position.x, size.width, safeDurationMs)
                    displayedPlayheadMs = seekMs
                    currentOnSeek(seekMs)
                }
            }
            .pointerInput(safeDurationMs) {
                detectHorizontalDragGestures(
                    onDragStart = { position ->
                        if (size.width <= 0) return@detectHorizontalDragGestures
                        isDragging = true
                        displayedPlayheadMs = seekMsAt(
                            position.x,
                            size.width,
                            safeDurationMs
                        )
                    },
                    onHorizontalDrag = { change, _ ->
                        if (size.width > 0) {
                            displayedPlayheadMs = seekMsAt(
                                change.position.x,
                                size.width,
                                safeDurationMs
                            )
                            change.consume()
                        }
                    },
                    onDragEnd = {
                        if (isDragging) {
                            isDragging = false
                            currentOnSeek(displayedPlayheadMs)
                        }
                    },
                    onDragCancel = {
                        isDragging = false
                    }
                )
            }
    ) {
        if (size.width <= 0f || size.height <= 0f) return@Canvas

        val width = size.width
        val height = size.height
        val targetBuckets = width.toInt().coerceAtLeast(1)
        val trackCount = 1 + extraTracks.size
        val verticalPadding = minOf(6.dp.toPx(), height / (trackCount * 4f))
        val laneHeight = (height - verticalPadding * 2f) / trackCount

        drawWaveformTrack(
            peaks = peaks,
            targetBuckets = targetBuckets,
            sampleRate = sampleRate,
            samplesPerBucket = samplesPerBucket,
            durationMs = safeDurationMs,
            top = verticalPadding,
            bottom = verticalPadding + laneHeight,
            waveformColor = waveformColor,
            centerLineColor = centerLineColor
        )
        extraTracks.forEachIndexed { index, track ->
            val top = verticalPadding + (index + 1) * laneHeight
            drawWaveformTrack(
                peaks = track.peaks,
                targetBuckets = targetBuckets,
                sampleRate = sampleRate,
                samplesPerBucket = track.samplesPerBucket,
                durationMs = safeDurationMs,
                top = top,
                bottom = top + laneHeight,
                waveformColor = waveformColor,
                centerLineColor = centerLineColor
            )
        }

        drawGaps(gaps, safeDurationMs, width, height, colorScheme)
        drawEvents(events, safeDurationMs, width, height, eventColor)
        drawPlayhead(displayedPlayheadMs, safeDurationMs, width, height, playheadColor)
    }
}

private fun DrawScope.drawWaveformTrack(
    peaks: ShortArray,
    targetBuckets: Int,
    sampleRate: Int,
    samplesPerBucket: Int,
    durationMs: Long,
    top: Float,
    bottom: Float,
    waveformColor: Color,
    centerLineColor: Color
) {
    val laneHeight = (bottom - top).coerceAtLeast(0f)
    val centerY = top + laneHeight / 2f
    drawLine(
        color = centerLineColor,
        start = Offset(0f, centerY),
        end = Offset(size.width, centerY),
        strokeWidth = 1f
    )

    if (peaks.isEmpty() || laneHeight <= 0f) return

    val inputBuckets = peaks.size / 2
    val renderedPeaks = if (inputBuckets > targetBuckets) {
        downsamplePeaks(peaks, targetBuckets)
    } else {
        peaks
    }
    val renderedBuckets = renderedPeaks.size / 2
    if (renderedBuckets == 0) return

    val amplitude = (laneHeight / 2f - 1f).coerceAtLeast(0f)
    val bucketDurationMs = if (sampleRate > 0 && samplesPerBucket > 0) {
        samplesPerBucket.toDouble() * 1000.0 / sampleRate
    } else {
        0.0
    }
    val usesTimeline = durationMs > 0L && bucketDurationMs > 0.0
    val inputBucketsPerOutput = if (inputBuckets > targetBuckets) {
        (inputBuckets + targetBuckets - 1) / targetBuckets
    } else {
        1
    }
    val fallbackBucketWidth = size.width / renderedBuckets
    for (index in 0 until renderedBuckets) {
        val valueA = renderedPeaks[index * 2]
        val valueB = renderedPeaks[index * 2 + 1]
        val minValue = minOf(valueA, valueB)
        val maxValue = maxOf(valueA, valueB)
        val yA = centerY - minValue / 32768f * amplitude
        val yB = centerY - maxValue / 32768f * amplitude
        val sourceStart = index * inputBucketsPerOutput
        val sourceEnd = minOf(sourceStart + inputBucketsPerOutput, inputBuckets)
        val x = if (usesTimeline) {
            val centerMs = ((sourceStart + sourceEnd) / 2.0 * bucketDurationMs).roundToLong()
            timeToX(centerMs, durationMs, size.width)
        } else {
            ((index + 0.5f) * fallbackBucketWidth).coerceIn(0f, size.width)
        }

        drawLine(
            color = waveformColor,
            start = Offset(x, minOf(yA, yB)),
            end = Offset(x, maxOf(yA, yB)),
            strokeWidth = 1f,
            cap = StrokeCap.Round
        )
    }
}

private fun DrawScope.drawGaps(
    gaps: List<RtpGap>,
    durationMs: Long,
    width: Float,
    height: Float,
    colorScheme: ColorScheme
) {
    gaps.forEach { gap ->
        val x = timeToX(gap.atMs, durationMs, width)
        drawLine(
            color = gapColor(gap.reason, colorScheme),
            start = Offset(x, 0f),
            end = Offset(x, height),
            strokeWidth = 2f
        )
    }
}

private fun DrawScope.drawEvents(
    events: List<RtpEvent>,
    durationMs: Long,
    width: Float,
    height: Float,
    eventColor: Color
) {
    val markerHeight = minOf(7.dp.toPx(), height).coerceAtLeast(0f)
    val markerHalfWidth = minOf(4.dp.toPx(), width / 2f, markerHeight)
    events.forEach { event ->
        val x = timeToX(event.atMs, durationMs, width)
            .coerceIn(markerHalfWidth, (width - markerHalfWidth).coerceAtLeast(markerHalfWidth))
        val left = (x - markerHalfWidth).coerceIn(0f, width)
        val right = (x + markerHalfWidth).coerceIn(0f, width)
        val marker = Path().apply {
            moveTo(left, 0f)
            lineTo(right, 0f)
            lineTo(x, markerHeight)
            close()
        }
        drawPath(marker, eventColor)
    }
}

private fun DrawScope.drawPlayhead(
    playheadMs: Long,
    durationMs: Long,
    width: Float,
    height: Float,
    color: Color
) {
    val x = timeToX(playheadMs, durationMs, width)
    drawLine(
        color = color,
        start = Offset(x, 0f),
        end = Offset(x, height),
        strokeWidth = 2f
    )
}

private fun gapColor(reason: String, colorScheme: ColorScheme): Color {
    val normalized = reason.trim().lowercase()
    return when {
        normalized.contains("lost") -> colorScheme.error
        normalized.contains("late") -> colorScheme.tertiary
        normalized.contains("silence") || normalized == "cn" -> colorScheme.onSurfaceVariant
        normalized.contains("wrong") -> colorScheme.secondary
        else -> colorScheme.outline
    }
}

private fun seekMsAt(x: Float, width: Int, durationMs: Long): Long {
    if (width <= 0 || durationMs <= 0L) return 0L
    val fraction = x.coerceIn(0f, width.toFloat()) / width.toFloat()
    return (fraction * durationMs.toDouble()).roundToLong().coerceIn(0L, durationMs)
}

private fun timeToX(timeMs: Long, durationMs: Long, width: Float): Float {
    if (durationMs <= 0L) return 0f
    val fraction = timeMs.coerceIn(0L, durationMs).toDouble() / durationMs.toDouble()
    return (fraction * width.toDouble()).toFloat().coerceIn(0f, width)
}
