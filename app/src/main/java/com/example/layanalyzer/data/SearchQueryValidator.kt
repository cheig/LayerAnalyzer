// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

object SearchQueryValidator {
    fun validateHex(query: String): String? {
        val compact = buildString {
            query.forEach { character ->
                when {
                    character.isWhitespace() || character == ':' || character == '-' -> Unit
                    character.isDigit() || character.lowercaseChar() in 'a'..'f' -> append(character)
                    else -> return "Hex search accepts byte pairs separated by spaces, colons, or hyphens."
                }
            }
        }
        return when {
            compact.isEmpty() -> "Enter at least one hexadecimal byte."
            compact.length % 2 != 0 -> "Hex search requires complete two-digit byte pairs."
            else -> null
        }
    }
}
