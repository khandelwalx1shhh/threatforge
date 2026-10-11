package com.threatforge.android.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.threatforge.android.MainActivity
import com.threatforge.android.model.RiskAnalysisResult
import com.threatforge.android.model.RiskLevel

object AlertNotificationHelper {

    private const val CHANNEL_ID = "threat_security_alerts"
    private const val CHANNEL_NAME = "Argus Security Warnings"
    private const val CHANNEL_DESC = "Urgent alerts for suspected phishing, scam, and fraudulent messages."

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val importance = NotificationManager.IMPORTANCE_HIGH
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, importance).apply {
                description = CHANNEL_DESC
                enableVibration(true)
                enableLights(true)
            }
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            notificationManager?.createNotificationChannel(channel)
        }
    }

    /**
     * Dispatches an immediate high-priority warning notification to the user
     * if the incoming message from an unknown sender is classified as HIGH or MEDIUM risk.
     */
    fun sendThreatWarning(context: Context, sender: String, textSnippet: String, result: RiskAnalysisResult) {
        if (result.level != RiskLevel.HIGH && result.level != RiskLevel.MEDIUM && result.level != RiskLevel.CRITICAL) {
            return
        }

        ensureChannel(context)

        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            context,
            System.currentTimeMillis().toInt(),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val riskLabel = when (result.level) {
            RiskLevel.CRITICAL -> "CRITICAL RISK"
            RiskLevel.HIGH -> "HIGH RISK"
            RiskLevel.MEDIUM -> "SUSPICIOUS"
            else -> "WARNING"
        }
        val reasons = if (result.reasons.isNotEmpty()) result.reasons.take(2).joinToString("; ") else "Potential scam or phishing attempt"

        val warningText = "Unknown sender: $sender\n⚠️ $reasons. Do not reply or click links!"

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("🚨 Argus Alert: $riskLabel Message")
            .setContentText("Suspicious message from $sender. Tap to review.")
            .setStyle(NotificationCompat.BigTextStyle().bigText(warningText))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)

        try {
            val notificationManager = NotificationManagerCompat.from(context)
            val notificationId = (System.currentTimeMillis() % 100000).toInt()
            notificationManager.notify(notificationId, builder.build())
        } catch (e: SecurityException) {
            // Permission POST_NOTIFICATIONS may not be granted yet
        }
    }
}
