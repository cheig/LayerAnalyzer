// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

/**
 * M3 fades disabled chip content to 0.38 alpha; border and content fade by the
 * same amount so the whole chip reads as one dimmed control.
 */
private const val DISABLED_CONTENT_ALPHA = 0.38f

/**
 * Scenario chip for the agent screen: looks like a flat Material3 assist chip
 * (32.dp height, 8.dp corners, 1.dp outline border, surface container) but is
 * built on [androidx.compose.foundation.combinedClickable] so a long press can
 * carry extra actions without changing the tap behaviour of AssistChip.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun AgentScenarioChip(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onLongClick: (() -> Unit)? = null,
    leadingIcon: (@Composable () -> Unit)? = null,
    trailingIcon: (@Composable () -> Unit)? = null,
    label: @Composable () -> Unit
) {
    val contentColor = if (enabled) {
        MaterialTheme.colorScheme.onSurface
    } else {
        MaterialTheme.colorScheme.onSurface.copy(alpha = DISABLED_CONTENT_ALPHA)
    }
    val borderColor = if (enabled) {
        MaterialTheme.colorScheme.outline
    } else {
        MaterialTheme.colorScheme.outline.copy(alpha = DISABLED_CONTENT_ALPHA)
    }
    Surface(
        modifier = modifier.combinedClickable(
            enabled = enabled,
            role = Role.Button,
            onClick = onClick,
            onLongClick = onLongClick
        ),
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surface,
        contentColor = contentColor,
        border = BorderStroke(1.dp, borderColor)
    ) {
        Row(
            modifier = Modifier
                .heightIn(min = 32.dp)
                .padding(horizontal = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (leadingIcon != null) {
                leadingIcon()
                Spacer(Modifier.width(8.dp))
            }
            label()
            if (trailingIcon != null) {
                Spacer(Modifier.width(8.dp))
                trailingIcon()
            }
        }
    }
}
