package com.example.layanalyzer.data

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class EvidencePackageWriter {
    fun write(
        output: File,
        manifestJson: String,
        reportMarkdown: String,
        framesJson: String,
        captureFile: File? = null,
        additionalEntries: Map<String, String> = emptyMap()
    ) {
        output.parentFile?.mkdirs()
        ZipOutputStream(output.outputStream().buffered()).use { zip ->
            zip.writeText("report.json", manifestJson)
            zip.writeText("report.md", reportMarkdown)
            zip.writeText("frames.json", framesJson)
            additionalEntries.toSortedMap().forEach { (name, value) ->
                require(name.isNotBlank() && !name.startsWith("/") && !name.contains("..")) {
                    "Invalid evidence package entry name."
                }
                require(name !in REQUIRED_ENTRY_NAMES) { "Evidence package entry already exists: $name" }
                zip.writeText(name, value)
            }
            if (captureFile != null) {
                zip.putNextEntry(ZipEntry("capture/${captureFile.name}"))
                captureFile.inputStream().buffered().use { it.copyTo(zip) }
                zip.closeEntry()
            }
        }
    }

    private fun ZipOutputStream.writeText(name: String, value: String) {
        putNextEntry(ZipEntry(name))
        write(value.toByteArray(Charsets.UTF_8))
        closeEntry()
    }

    private companion object {
        val REQUIRED_ENTRY_NAMES = setOf("report.json", "report.md", "frames.json")
    }
}
