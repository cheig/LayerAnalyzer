// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.background

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.example.layanalyzer.LayerAnalyzerApplication
import com.example.layanalyzer.MainActivity
import com.example.layanalyzer.R

/**
 * The process-priority half of background execution — and nothing more.
 *
 * The run itself is owned by [AgentRunCoordinator] on an Application-scoped
 * coroutine, so this service holds no run state and can be killed, denied or
 * restarted without losing the analysis.  It does exactly two things: raise
 * the process to foreground priority (with a notification) while a run is
 * active, and route the notification's "cancel" action back to the
 * coordinator.  Deliberately `START_NOT_STICKY`: a dead run is recovered by
 * the Phase 4 checkpoint, not by resurrecting a service with nothing to run.
 *
 * The failure policy is the inverse of the capture VPN service's: a
 * `startForeground` denial degrades priority but must not kill the run, so it
 * is logged and swallowed rather than turning into a failed analysis.
 */
class AgentAnalysisService : Service() {

    private val coordinator: AgentRunCoordinator?
        get() = (application as? LayerAnalyzerApplication)?.agentRunCoordinator

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                coordinator?.cancel()
                stopForegroundCompat()
                stopSelf()
            }
            else -> startForegroundSafely(intent)
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopForegroundCompat()
        super.onDestroy()
    }

    private fun startForegroundSafely(intent: Intent?) {
        val conversationId = intent?.getStringExtra(EXTRA_CONVERSATION_ID).orEmpty()
        val title = intent?.getStringExtra(EXTRA_TITLE)
            ?: getString(R.string.agent_analysis_notification_title)
        ensureNotificationChannel()
        try {
            startForeground(NOTIFICATION_ID, buildNotification(title, conversationId))
        } catch (denied: Exception) {
            // POST_NOTIFICATIONS denied, a background-start restriction or an
            // OEM block only lowers the run's priority; it does not stop the
            // coordinator's coroutine.  Log and continue without the service.
            android.util.Log.w(TAG, "Analysis foreground notification unavailable", denied)
            stopSelf()
        }
    }

    private fun buildNotification(title: String, conversationId: String): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, AgentAnalysisService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val text = if (conversationId.isBlank()) {
            getString(R.string.agent_analysis_notification_text)
        } else {
            getString(
                R.string.agent_analysis_notification_text_with_id,
                conversationId.removePrefix("conv_").take(8)
            )
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(openApp)
            .addAction(0, getString(R.string.cancel_analysis), stop)
            .build()
    }

    private fun ensureNotificationChannel() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                getString(R.string.agent_analysis_notification_channel),
                NotificationManager.IMPORTANCE_LOW
            )
        )
    }

    private fun stopForegroundCompat() {
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    companion object {
        private const val TAG = "AgentAnalysisService"
        private const val CHANNEL_ID = "agent_analysis"
        private const val NOTIFICATION_ID = 4202
        private const val EXTRA_CONVERSATION_ID = "conversationId"
        private const val EXTRA_TITLE = "title"

        const val ACTION_START = "com.example.layanalyzer.ai.background.START"
        const val ACTION_STOP = "com.example.layanalyzer.ai.background.STOP"

        fun startIntent(context: Context, conversationId: String, title: String? = null): Intent =
            Intent(context, AgentAnalysisService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_CONVERSATION_ID, conversationId)
                .putExtra(EXTRA_TITLE, title)

        fun stopIntent(context: Context): Intent =
            Intent(context, AgentAnalysisService::class.java).setAction(ACTION_STOP)
    }
}
