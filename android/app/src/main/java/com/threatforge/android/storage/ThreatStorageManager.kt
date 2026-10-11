package com.threatforge.android.storage

import android.content.Context
import android.content.SharedPreferences
import com.threatforge.android.model.AnalysisSource
import com.threatforge.android.model.RiskAnalysisResult
import com.threatforge.android.model.RiskLevel
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class ThreatStorageManager(private val context: Context) {

    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val alertsFile: File = File(context.filesDir, ALERTS_FILE_NAME)

    companion object {
        private const val PREFS_NAME = "threatforge_persistent_prefs"
        private const val ALERTS_FILE_NAME = "threat_alerts.json"

        private const val KEY_FIRST_LAUNCH_COMPLETED = "first_launch_completed"
        private const val KEY_NOTIFICATION_CONSENT = "notification_consent_granted"
        private const val KEY_USER_CONSENT = "user_consent_granted"
        private const val KEY_CLOUD_ANALYSIS = "cloud_analysis_enabled"
        private const val KEY_LOCAL_ONLY = "local_only_mode"
        private const val KEY_RETENTION_DAYS = "retention_days"
        private const val KEY_IGNORED_COUNT = "ignored_count"
        private const val KEY_DEDUPED_COUNT = "deduped_count"
        private const val KEY_SERVER_URL = "backend_server_url"
        private const val MAX_SAVED_ALERTS = 100
    }

    // ── First-Time Launch & Consent State ──
    fun isFirstLaunch(): Boolean {
        return !prefs.getBoolean(KEY_FIRST_LAUNCH_COMPLETED, false)
    }

    fun setFirstLaunchCompleted(completed: Boolean = true) {
        prefs.edit().putBoolean(KEY_FIRST_LAUNCH_COMPLETED, completed).apply()
    }

    fun isNotificationConsentGranted(): Boolean {
        return prefs.getBoolean(KEY_NOTIFICATION_CONSENT, false)
    }

    fun setNotificationConsentGranted(granted: Boolean) {
        prefs.edit().putBoolean(KEY_NOTIFICATION_CONSENT, granted).apply()
    }

    // ── Settings State ──
    fun isUserConsentGranted(): Boolean {
        return prefs.getBoolean(KEY_USER_CONSENT, false)
    }

    fun setUserConsentGranted(granted: Boolean) {
        prefs.edit().putBoolean(KEY_USER_CONSENT, granted).apply()
    }

    fun isCloudAnalysisEnabled(): Boolean {
        return prefs.getBoolean(KEY_CLOUD_ANALYSIS, true)
    }

    fun setCloudAnalysisEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_CLOUD_ANALYSIS, enabled).apply()
    }

    fun isLocalOnlyMode(): Boolean {
        return prefs.getBoolean(KEY_LOCAL_ONLY, false)
    }

    fun setLocalOnlyMode(localOnly: Boolean) {
        prefs.edit().putBoolean(KEY_LOCAL_ONLY, localOnly).apply()
    }

    fun getRetentionDays(): Int {
        return prefs.getInt(KEY_RETENTION_DAYS, 7)
    }

    fun setRetentionDays(days: Int) {
        prefs.edit().putInt(KEY_RETENTION_DAYS, days).apply()
    }

    // ── Server URL Configuration ──
    fun getBaseUrl(): String {
        return prefs.getString(KEY_SERVER_URL, com.threatforge.android.network.ThreatForgeApiClient.DEFAULT_BASE_URL)
            ?: com.threatforge.android.network.ThreatForgeApiClient.DEFAULT_BASE_URL
    }

    fun setBaseUrl(url: String) {
        prefs.edit().putString(KEY_SERVER_URL, url).apply()
    }

    // ── Counters ──
    fun getIgnoredCount(): Int {
        return prefs.getInt(KEY_IGNORED_COUNT, 0)
    }

    fun setIgnoredCount(count: Int) {
        prefs.edit().putInt(KEY_IGNORED_COUNT, count).apply()
    }

    fun getDedupedCount(): Int {
        return prefs.getInt(KEY_DEDUPED_COUNT, 0)
    }

    fun setDedupedCount(count: Int) {
        prefs.edit().putInt(KEY_DEDUPED_COUNT, count).apply()
    }

    // ── Alerts Persistence ──
    @Synchronized
    fun loadAlerts(): List<RiskAnalysisResult> {
        if (!alertsFile.exists()) return emptyList()

        return try {
            val jsonStr = alertsFile.readText()
            if (jsonStr.isBlank()) return emptyList()

            val jsonArray = JSONArray(jsonStr)
            val list = mutableListOf<RiskAnalysisResult>()

            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)

                val reasonsArray = obj.optJSONArray("reasons") ?: JSONArray()
                val reasons = mutableListOf<String>()
                for (r in 0 until reasonsArray.length()) {
                    reasons.add(reasonsArray.getString(r))
                }

                val indicatorsArray = obj.optJSONArray("indicators") ?: JSONArray()
                val indicators = mutableListOf<String>()
                for (ind in 0 until indicatorsArray.length()) {
                    indicators.add(indicatorsArray.getString(ind))
                }

                val levelStr = obj.optString("level", "LOW")
                val level = try {
                    RiskLevel.valueOf(levelStr)
                } catch (e: Exception) {
                    RiskLevel.LOW
                }

                val sourceStr = obj.optString("analysisSource", "LOCAL_HEURISTIC")
                val source = try {
                    AnalysisSource.valueOf(sourceStr)
                } catch (e: Exception) {
                    AnalysisSource.LOCAL_HEURISTIC
                }

                list.add(
                    RiskAnalysisResult(
                        score = if (obj.has("score") && !obj.isNull("score")) obj.getInt("score") else null,
                        level = level,
                        reasons = reasons,
                        safeAction = obj.optString("safeAction", "No action needed"),
                        analysisSource = source,
                        isSynthetic = obj.optBoolean("isSynthetic", false),
                        eventKey = obj.optString("eventKey", ""),
                        timestamp = obj.optLong("timestamp", System.currentTimeMillis()),
                        packageName = if (obj.has("packageName") && !obj.isNull("packageName")) obj.getString("packageName") else null,
                        indicators = indicators,
                        modelVersion = if (obj.has("modelVersion") && !obj.isNull("modelVersion")) obj.getString("modelVersion") else null,
                        analysisMode = if (obj.has("analysisMode") && !obj.isNull("analysisMode")) obj.getString("analysisMode") else null,
                        confidenceScore = if (obj.has("confidenceScore") && !obj.isNull("confidenceScore")) obj.getDouble("confidenceScore") else null,
                        uncertaintyRange = if (obj.has("uncertaintyRange") && !obj.isNull("uncertaintyRange")) obj.getString("uncertaintyRange") else null,
                        summary = if (obj.has("summary") && !obj.isNull("summary")) obj.getString("summary") else null
                    )
                )
            }
            list
        } catch (e: Exception) {
            emptyList()
        }
    }

    @Synchronized
    fun saveAlerts(alerts: List<RiskAnalysisResult>) {
        try {
            val jsonArray = JSONArray()
            val limited = alerts.take(MAX_SAVED_ALERTS)

            for (a in limited) {
                val obj = JSONObject()
                if (a.score != null) obj.put("score", a.score) else obj.put("score", JSONObject.NULL)
                obj.put("level", a.level.name)
                
                val reasonsArr = JSONArray()
                a.reasons.forEach { reasonsArr.put(it) }
                obj.put("reasons", reasonsArr)

                obj.put("safeAction", a.safeAction)
                obj.put("analysisSource", a.analysisSource.name)
                obj.put("isSynthetic", a.isSynthetic)
                obj.put("eventKey", a.eventKey)
                obj.put("timestamp", a.timestamp)
                if (a.packageName != null) obj.put("packageName", a.packageName)
                
                val indArr = JSONArray()
                a.indicators.forEach { indArr.put(it) }
                obj.put("indicators", indArr)

                if (a.modelVersion != null) obj.put("modelVersion", a.modelVersion)
                if (a.analysisMode != null) obj.put("analysisMode", a.analysisMode)
                if (a.confidenceScore != null) obj.put("confidenceScore", a.confidenceScore)
                if (a.uncertaintyRange != null) obj.put("uncertaintyRange", a.uncertaintyRange)
                if (a.summary != null) obj.put("summary", a.summary)

                jsonArray.put(obj)
            }

            alertsFile.writeText(jsonArray.toString(2))
        } catch (e: Exception) {
            // Silently handle storage write failures
        }
    }

    @Synchronized
    fun clearAllAlerts() {
        try {
            if (alertsFile.exists()) {
                alertsFile.delete()
            }
            setIgnoredCount(0)
            setDedupedCount(0)
        } catch (e: Exception) {
            // Handled
        }
    }
}
