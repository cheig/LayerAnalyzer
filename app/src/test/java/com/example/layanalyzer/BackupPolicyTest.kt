// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Test

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

        assertRootExclusions(File("src/main/res/xml/data_extraction_rules.xml"), expected = 2)
        assertRootExclusions(File("src/main/res/xml/backup_rules.xml"), expected = 1)
    }

    private fun assertRootExclusions(file: File, expected: Int) {
        val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
        assertEquals(0, document.getElementsByTagName("include").length)
        val exclusions = document.getElementsByTagName("exclude")
        assertEquals(expected, exclusions.length)
        repeat(exclusions.length) { index ->
            val attributes = exclusions.item(index).attributes
            assertEquals("root", attributes.getNamedItem("domain")?.nodeValue)
            assertEquals(".", attributes.getNamedItem("path")?.nodeValue)
        }
    }
}
