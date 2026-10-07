package com.example.layanalyzer

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.media.ExternalPlayerLauncher
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ExternalPlayerLauncherTest {
    @Test
    fun grantsReadPermissionToResolvedViewers() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val file = File(context.cacheDir, "rtp/qa03/external-player-test.wav").apply {
            parentFile?.mkdirs()
            writeBytes(byteArrayOf(0x52, 0x49, 0x46, 0x46))
        }
        val uri = ExternalPlayerLauncher.uriFor(context, file)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "audio/wav")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val targets = context.packageManager.queryIntentActivities(intent, 0)
        assumeTrue("No audio/wav viewer is installed", targets.isNotEmpty())

        ExternalPlayerLauncher.grantReadPermission(context, intent, listOf(uri))

        val target = targets.first()
        val targetUid = context.packageManager
            .getApplicationInfo(target.activityInfo.packageName, 0)
            .uid
        assertEquals(
            PackageManager.PERMISSION_GRANTED,
            context.checkUriPermission(
                uri,
                -1,
                targetUid,
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        )
        assertFalse(uri.toString().isBlank())
        assertTrue(file.isFile)
    }
}
