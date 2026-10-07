package com.example.layanalyzer.data

import android.content.Context
import com.example.layanalyzer.model.ScenarioStep
import com.example.layanalyzer.model.ScenarioTemplate
import org.json.JSONObject

class ScenarioTemplateStore(private val context: Context) {
    fun load(): List<ScenarioTemplate> = runCatching {
        val root = JSONObject(context.assets.open("scenario_templates.json").bufferedReader().use { it.readText() })
        val templates = root.optJSONArray("templates") ?: return emptyList()
        buildList {
            for (i in 0 until templates.length()) {
                val item = templates.getJSONObject(i)
                val steps = item.optJSONArray("steps") ?: continue
                add(ScenarioTemplate(
                    id = item.getString("id"),
                    version = item.optInt("version", 1),
                    title = item.getString("title"),
                    description = item.optString("description"),
                    steps = buildList {
                        for (stepIndex in 0 until steps.length()) {
                            val step = steps.getJSONObject(stepIndex)
                            add(ScenarioStep(step.getString("id"), step.getString("title"), step.getString("filter"), step.optString("conclusion")))
                        }
                    }
                ))
            }
        }
    }.getOrDefault(emptyList())
}
