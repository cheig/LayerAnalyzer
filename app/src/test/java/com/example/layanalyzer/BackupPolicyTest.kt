// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Test
import org.w3c.dom.Element
import org.w3c.dom.Node

class BackupPolicyTest {
    @Test
    fun manifestDisablesBackupAndExtractionRulesExcludeAllPrivateData() {
        val manifest = File("src/main/AndroidManifest.xml")
        val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(manifest)
        val application = document.getElementsByTagName("application").item(0)
        val attributes = application.attributes

        assertEquals("false", attributes.getNamedItem("android:allowBackup")?.nodeValue)
        assertEquals("@xml/data_extraction_rules", attributes.getNamedItem("android:dataExtractionRules")?.nodeValue)
        assertEquals("@xml/backup_rules", attributes.getNamedItem("android:fullBackupContent")?.nodeValue)

        val extraction = parseRoot(File("src/main/res/xml/data_extraction_rules.xml"))
        assertEquals("data-extraction-rules", extraction.tagName)
        val sections = childElements(extraction)
        assertEquals(2, sections.size)
        assertEquals(setOf("cloud-backup", "device-transfer"), sections.map { it.tagName }.toSet())
        sections.forEach(::assertAllPrivateDomainsExcluded)

        val backup = parseRoot(File("src/main/res/xml/backup_rules.xml"))
        assertEquals("full-backup-content", backup.tagName)
        assertAllPrivateDomainsExcluded(backup)
    }

    private fun parseRoot(file: File): Element =
        DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file).documentElement

    private fun childElements(parent: Element): List<Element> =
        (0 until parent.childNodes.length).map { parent.childNodes.item(it) }
            .filter { it.nodeType == Node.ELEMENT_NODE }.map { it as Element }

    private fun assertAllPrivateDomainsExcluded(section: Element) {
        val domains = setOf(
            "root", "file", "database", "sharedpref", "external",
            "device_root", "device_file", "device_database", "device_sharedpref",
        )
        val exclusions = childElements(section)
        assertEquals(domains.size, exclusions.size)
        assertEquals(domains, exclusions.map { it.getAttribute("domain") }.toSet())
        exclusions.forEach { exclusion ->
            assertEquals("exclude", exclusion.tagName)
            assertEquals(".", exclusion.getAttribute("path"))
            assertEquals(0, childElements(exclusion).size)
        }
    }
}
