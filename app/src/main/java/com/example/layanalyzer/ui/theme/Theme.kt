// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.sp

private val LightColors = lightColorScheme(
    primary = Color(0xFF075E54),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD2E8E3),
    onPrimaryContainer = Color(0xFF073B35),
    secondary = Color(0xFF4D5F65),
    secondaryContainer = Color(0xFFDCE4E6),
    tertiary = Color(0xFF865300),
    tertiaryContainer = Color(0xFFFFDDB1),
    error = Color(0xFFB3261E),
    errorContainer = Color(0xFFF9DEDC),
    background = Color(0xFFF9FAF8),
    surface = Color(0xFFF9FAF8),
    surfaceVariant = Color(0xFFE6E9E5),
    outline = Color(0xFF737874),
    outlineVariant = Color(0xFFC5C9C5)
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF86D3C5),
    onPrimary = Color(0xFF003731),
    primaryContainer = Color(0xFF075E54),
    onPrimaryContainer = Color(0xFFC2F1E8),
    secondary = Color(0xFFB8C9CE),
    secondaryContainer = Color(0xFF354A50),
    tertiary = Color(0xFFFFB951),
    tertiaryContainer = Color(0xFF654000),
    error = Color(0xFFFFB4AB),
    errorContainer = Color(0xFF8C1D18),
    background = Color(0xFF101412),
    surface = Color(0xFF101412),
    surfaceVariant = Color(0xFF292E2B),
    outline = Color(0xFF8E938F),
    outlineVariant = Color(0xFF414642)
)

private val AnalyzerTypography = androidx.compose.material3.Typography(
    bodySmall = TextStyle(fontSize = 12.sp, lineHeight = 16.sp),
    labelSmall = TextStyle(fontSize = 11.sp, lineHeight = 14.sp),
    labelMedium = TextStyle(fontSize = 12.sp, lineHeight = 16.sp),
    bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 19.sp),
    titleMedium = TextStyle(fontSize = 18.sp, lineHeight = 24.sp),
    titleLarge = TextStyle(fontSize = 22.sp, lineHeight = 28.sp),
    displaySmall = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 32.sp, lineHeight = 38.sp)
)

@Composable
fun LayerAnalyzerTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = AnalyzerTypography,
        content = content
    )
}
