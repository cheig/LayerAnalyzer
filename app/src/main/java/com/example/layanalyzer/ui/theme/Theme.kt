// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val LightColors = lightColorScheme(
    primary = Color(0xFF075E54),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE4F0EB),
    onPrimaryContainer = Color(0xFF073B35),
    secondary = Color(0xFF4D5F65),
    secondaryContainer = Color(0xFFEBF0EE),
    onSecondaryContainer = Color(0xFF34483F),
    tertiary = Color(0xFF865300),
    tertiaryContainer = Color(0xFFFAF0DD),
    onTertiaryContainer = Color(0xFF74470E),
    error = Color(0xFFB3261E),
    errorContainer = Color(0xFFFBECE9),
    onErrorContainer = Color(0xFF8C2921),
    background = Color(0xFFF4F6F5),
    onBackground = Color(0xFF202A26),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF202A26),
    surfaceVariant = Color(0xFFEEF2EF),
    onSurfaceVariant = Color(0xFF616E67),
    surfaceDim = Color(0xFFDDE5E0),
    surfaceBright = Color(0xFFFFFFFF),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFFFFFFF),
    surfaceContainer = Color(0xFFEEF2EF),
    surfaceContainerHigh = Color(0xFFE6ECE8),
    surfaceContainerHighest = Color(0xFFDDE5E0),
    outline = Color(0xFF748179),
    outlineVariant = Color(0xFFDDE5E0)
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF86D3C5),
    onPrimary = Color(0xFF003731),
    primaryContainer = Color(0xFF203D33),
    onPrimaryContainer = Color(0xFFC2F1E8),
    secondary = Color(0xFFB8C9CE),
    secondaryContainer = Color(0xFF293830),
    onSecondaryContainer = Color(0xFFD2E3D9),
    tertiary = Color(0xFFFFB951),
    tertiaryContainer = Color(0xFF392E1D),
    onTertiaryContainer = Color(0xFFEBBC79),
    error = Color(0xFFFFB4AB),
    errorContainer = Color(0xFF422822),
    onErrorContainer = Color(0xFFFFC8BE),
    background = Color(0xFF111715),
    onBackground = Color(0xFFE1E9E5),
    surface = Color(0xFF1A221F),
    onSurface = Color(0xFFE1E9E5),
    surfaceVariant = Color(0xFF242E28),
    onSurfaceVariant = Color(0xFFA7B5AD),
    surfaceDim = Color(0xFF111715),
    surfaceBright = Color(0xFF35423B),
    surfaceContainerLowest = Color(0xFF0D1310),
    surfaceContainerLow = Color(0xFF1A221F),
    surfaceContainer = Color(0xFF202A24),
    surfaceContainerHigh = Color(0xFF29352E),
    surfaceContainerHighest = Color(0xFF35423B),
    outline = Color(0xFF82938A),
    outlineVariant = Color(0xFF35423B)
)

private val AnalyzerShapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(20.dp),
    extraLarge = RoundedCornerShape(28.dp)
)

private val AnalyzerTypography = androidx.compose.material3.Typography(
    bodySmall = TextStyle(fontSize = 12.sp, lineHeight = 18.sp),
    labelSmall = TextStyle(fontSize = 12.sp, lineHeight = 16.sp),
    labelMedium = TextStyle(fontSize = 12.sp, lineHeight = 16.sp),
    bodyMedium = TextStyle(fontSize = 14.sp, lineHeight = 21.sp),
    titleSmall = TextStyle(fontSize = 16.sp, lineHeight = 22.sp, fontWeight = FontWeight.Medium),
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
        shapes = AnalyzerShapes,
        content = content
    )
}
