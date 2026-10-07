package com.example.layanalyzer.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.ai.markdown.ReportMarkdown
import com.example.layanalyzer.ai.markdown.children
import org.commonmark.node.BlockQuote
import org.commonmark.node.BulletList
import org.commonmark.node.Code
import org.commonmark.node.Emphasis
import org.commonmark.node.FencedCodeBlock
import org.commonmark.node.HardLineBreak
import org.commonmark.node.Heading
import org.commonmark.node.HtmlBlock
import org.commonmark.node.HtmlInline
import org.commonmark.node.IndentedCodeBlock
import org.commonmark.node.Node
import org.commonmark.node.OrderedList
import org.commonmark.node.Paragraph
import org.commonmark.node.SoftLineBreak
import org.commonmark.node.StrongEmphasis
import org.commonmark.node.Text as MarkdownText
import org.commonmark.node.ThematicBreak

/** Selectable report prose. Links/images contribute labels only, never URLs or actions. */
@Composable
internal fun AgentMarkdownText(
    markdown: String,
    modifier: Modifier = Modifier,
    style: TextStyle = MaterialTheme.typography.bodyMedium,
    color: Color = LocalContentColor.current,
    listItem: Boolean = false
) {
    val document = remember(markdown) { ReportMarkdown.parse(markdown) }
    // Some providers add list markers even inside array entries. Avoid a double bullet.
    val alreadyList = document.firstChild?.let {
        it.next == null && (it is BulletList || it is OrderedList)
    } == true
    SelectionContainer(modifier) {
        if (listItem && !alreadyList) {
            MarkdownListRow("•", style, color) { MarkdownBlocks(document, style, color) }
        } else {
            MarkdownBlocks(document, style, color)
        }
    }
}

@Composable
private fun MarkdownBlocks(parent: Node, style: TextStyle, color: Color, tight: Boolean = false) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(if (tight) 4.dp else 10.dp)
    ) {
        parent.children().forEach { node ->
            when (node) {
                is Paragraph -> MarkdownInlineText(node, style, color)
                is Heading -> MarkdownInlineText(
                    node,
                    when (node.level) {
                        1 -> MaterialTheme.typography.titleLarge
                        2 -> MaterialTheme.typography.titleMedium
                        else -> MaterialTheme.typography.titleSmall
                    }.copy(fontWeight = FontWeight.SemiBold),
                    color
                )
                is BulletList -> Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    node.children().forEach { item ->
                        MarkdownListRow("•", style, color) {
                            MarkdownBlocks(item, style, color, node.isTight)
                        }
                    }
                }
                is OrderedList -> Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    node.children().forEachIndexed { index, item ->
                        MarkdownListRow("${(node.markerStartNumber ?: 1) + index}.", style, color) {
                            MarkdownBlocks(item, style, color, node.isTight)
                        }
                    }
                }
                is BlockQuote -> {
                    val border = color.copy(alpha = 0.35f)
                    Column(Modifier.drawBehind {
                        drawLine(border, Offset.Zero, Offset(0f, size.height), 3.dp.toPx())
                    }.padding(start = 12.dp)) {
                        MarkdownBlocks(node, style, color)
                    }
                }
                is ThematicBreak -> HorizontalDivider(color = color.copy(alpha = 0.2f))
                // Code blocks reaching us from old reports stay inert, selectable text.
                is FencedCodeBlock -> Text(node.literal.trimEnd(), style = style, color = color,
                    fontFamily = FontFamily.Monospace)
                is IndentedCodeBlock -> Text(node.literal.trimEnd(), style = style, color = color,
                    fontFamily = FontFamily.Monospace)
                is HtmlBlock -> Unit
                else -> MarkdownInlineText(node, style, color)
            }
        }
    }
}

@Composable
private fun MarkdownListRow(marker: String, style: TextStyle, color: Color, content: @Composable () -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(marker, style = style, color = color)
        Column(Modifier.weight(1f)) { content() }
    }
}

@Composable
private fun MarkdownInlineText(node: Node, style: TextStyle, color: Color) {
    val codeBackground = color.copy(alpha = 0.08f)
    val text = remember(node, codeBackground) { reportInlineText(node, codeBackground) }
    Text(text, style = style, color = color)
}

/** Pure inline projection so formatting and the absence of link annotations can be tested. */
internal fun reportInlineText(node: Node, codeBackground: Color): AnnotatedString = buildAnnotatedString {
    fun appendNode(current: Node) {
        when (current) {
            is MarkdownText -> append(current.literal)
            is Code -> withStyle(SpanStyle(fontFamily = FontFamily.Monospace, background = codeBackground)) {
                append(current.literal)
            }
            is StrongEmphasis -> withStyle(SpanStyle(fontWeight = FontWeight.Bold)) {
                current.children().forEach(::appendNode)
            }
            is Emphasis -> withStyle(SpanStyle(fontStyle = FontStyle.Italic)) {
                current.children().forEach(::appendNode)
            }
            is SoftLineBreak -> append(' ')
            is HardLineBreak -> append('\n')
            is HtmlInline -> Unit
            // Link and Image deliberately use children only (label/alt text).
            else -> current.children().forEach(::appendNode)
        }
    }
    appendNode(node)
}
