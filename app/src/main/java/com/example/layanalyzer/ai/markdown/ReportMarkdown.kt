package com.example.layanalyzer.ai.markdown

import org.commonmark.node.AbstractVisitor
import org.commonmark.node.BulletList
import org.commonmark.node.Code
import org.commonmark.node.FencedCodeBlock
import org.commonmark.node.HardLineBreak
import org.commonmark.node.HtmlBlock
import org.commonmark.node.HtmlInline
import org.commonmark.node.IndentedCodeBlock
import org.commonmark.node.Node
import org.commonmark.node.OrderedList
import org.commonmark.node.SoftLineBreak
import org.commonmark.node.Text
import org.commonmark.parser.Parser

/** CommonMark only: no HTML rendering, image loading, or actionable link targets. */
object ReportMarkdown {
    private val parser = Parser.builder().build()

    fun parse(markdown: String): Node = parser.parse(markdown)

    /** Compact text for collapsed report rows, preserving inline protocol identifiers. */
    fun preview(markdown: String): String = plainText(parse(markdown))
        .replace(Regex("\\s+"), " ")
        .trim()

    fun plainText(node: Node): String = buildString {
        node.accept(object : AbstractVisitor() {
            override fun visit(text: Text) { append(text.literal) }
            override fun visit(code: Code) { append(code.literal) }
            override fun visit(softLineBreak: SoftLineBreak) { append(' ') }
            override fun visit(hardLineBreak: HardLineBreak) { append('\n') }
            override fun visit(fencedCodeBlock: FencedCodeBlock) { append(fencedCodeBlock.literal) }
            override fun visit(indentedCodeBlock: IndentedCodeBlock) { append(indentedCodeBlock.literal) }
            override fun visit(htmlInline: HtmlInline) { /* Never interpret HTML. */ }
            override fun visit(htmlBlock: HtmlBlock) { /* Never interpret HTML. */ }
            override fun visitChildren(parent: Node) {
                super.visitChildren(parent)
                if (parent is org.commonmark.node.Block) append('\n')
            }
        })
    }.trim()

    /** Indent every continuation line so paragraphs stay inside their exported list item. */
    fun listItem(markdown: String, prefix: String = "- "): String {
        val text = markdown.trim()
        val first = parse(text).firstChild
        if (first != null && first.next == null && (first is BulletList || first is OrderedList)) {
            return text.prependIndent(" ".repeat((prefix.length - 2).coerceAtLeast(0)))
        }
        return text.lineSequence().mapIndexed { index, line ->
            if (index == 0) prefix + line else " ".repeat(prefix.length) + line
        }.joinToString("\n")
    }
}

internal fun Node.children(): Sequence<Node> = generateSequence(firstChild) { it.next }
