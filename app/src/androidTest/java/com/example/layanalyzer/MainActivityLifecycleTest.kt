package com.example.layanalyzer

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertSame
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityLifecycleTest {
    @Test
    fun repositoryRemainsProcessScopedAcrossActivityRecreation() {
        val application = ApplicationProvider.getApplicationContext<LayerAnalyzerApplication>()
        val repository = application.repository
        val intent = Intent(application, MainActivity::class.java)

        ActivityScenario.launch<MainActivity>(intent).use { scenario ->
            scenario.recreate()
            scenario.onActivity { activity ->
                assertSame(application, activity.application)
                assertSame(repository, (activity.application as LayerAnalyzerApplication).repository)
            }
        }
    }
}
