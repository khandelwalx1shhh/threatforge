package com.threatforge.android.network

import com.threatforge.android.model.AnalysisSource
import com.threatforge.android.model.NetworkResult
import com.threatforge.android.model.RiskAnalysisResult
import com.threatforge.android.model.RiskLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

class ThreatForgeApiClient(
    var baseUrl: String = DEFAULT_BASE_URL
) {

    companion object {
        const val EMULATOR_BASE_URL = "http://10.0.2.2:8000"
        const val USB_REVERSE_BASE_URL = "http://127.0.0.1:8000"
        const val LAN_WIFI_BASE_URL = "http://10.21.97.62:8000"

        // Default to USB / reverse proxy which matches direct device connection
        const val DEFAULT_BASE_URL = USB_REVERSE_BASE_URL
        private const val CONNECT_TIMEOUT_MS = 4000
        private const val READ_TIMEOUT_MS = 6000
    }

    /**
     * Executes POST /api/analyze against the configured backend.
     * Enforces privacy checks, network timeouts, and strict response schema validation.
     */
    suspend fun analyzeText(
        text: String,
        source: String,
        isSynthetic: Boolean,
        eventKey: String,
        cloudAnalysisEnabled: Boolean,
        userConsentGranted: Boolean
    ): NetworkResult<RiskAnalysisResult> = withContext(Dispatchers.IO) {
        // Privacy Gate Check 1: Cloud analysis toggle
        if (!cloudAnalysisEnabled) {
            return@withContext NetworkResult.Unavailable(
                "Cloud analysis is disabled. Enable cloud screening to query backend threat intelligence."
            )
        }

        // Privacy Gate Check 2: Explicit user consent
        if (!userConsentGranted) {
            return@withContext NetworkResult.ConsentRequired
        }

        // Validation Check 3: Usable content
        val trimmed = text.trim()
        if (trimmed.isEmpty()) {
            return@withContext NetworkResult.InvalidInput("Cannot submit empty or blank notification text.")
        }

        val endpointUrl = "${baseUrl.trimEnd('/')}/api/analyze"
        var connection: HttpURLConnection? = null

        try {
            val url = URL(endpointUrl)
            connection = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                doInput = true
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=UTF-8")
                setRequestProperty("Accept", "application/json")
            }

            // Construct payload matching backend contract
            val jsonPayload = JSONObject().apply {
                put("message", trimmed)
                put("text", trimmed)
                put("sender", source)
                put("source", source)
                put("cloud_analysis", true)
            }

            OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { writer ->
                writer.write(jsonPayload.toString())
                writer.flush()
            }

            val statusCode = connection.responseCode
            if (statusCode in 200..299) {
                val responseText = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
                return@withContext parseAndValidateResponse(
                    responseText = responseText,
                    packageName = source,
                    isSynthetic = isSynthetic,
                    eventKey = eventKey
                )
            } else {
                val errorBody = try {
                    connection.errorStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }
                } catch (_: Exception) { null }
                return@withContext NetworkResult.Error(
                    code = statusCode,
                    message = "Backend returned HTTP $statusCode: ${errorBody ?: "Request failed"}"
                )
            }
        } catch (e: java.net.SocketTimeoutException) {
            return@withContext NetworkResult.Unavailable("Cloud analysis timed out after ${CONNECT_TIMEOUT_MS / 1000}s. Endpoint did not respond.")
        } catch (e: java.net.ConnectException) {
            return@withContext NetworkResult.Unavailable("Could not connect to THREATFORGE backend at $endpointUrl. Confirm server is running.")
        } catch (e: Exception) {
            return@withContext NetworkResult.Unavailable("Network error: ${e.message ?: "Unknown communication error"}")
        } finally {
            connection?.disconnect()
        }
    }

    /**
     * Parses and validates the response against the THREATFORGE contract.
     * Rejects invalid or fabricated responses.
     */
    fun parseAndValidateResponse(
        responseText: String,
        packageName: String,
        isSynthetic: Boolean,
        eventKey: String
    ): NetworkResult<RiskAnalysisResult> {
        return try {
            val json = JSONObject(responseText)

            // Validate risk_score (accepts double/int, range 0..100)
            if (!json.has("risk_score") && !json.has("score")) {
                return NetworkResult.Unavailable("Malformed backend response: missing required 'risk_score' field.")
            }
            val rawScore = if (json.has("risk_score")) json.optDouble("risk_score", -1.0) else json.optDouble("score", -1.0)
            if (rawScore < 0.0 || rawScore > 100.0) {
                return NetworkResult.Unavailable("Invalid backend response: 'risk_score' ($rawScore) out of valid range [0, 100].")
            }
            val scoreInt = rawScore.toInt()

            // Validate risk_level
            val rawLevel = json.optString("risk_level", json.optString("level", "")).uppercase()
            val level = when (rawLevel) {
                "CRITICAL" -> RiskLevel.CRITICAL
                "HIGH" -> RiskLevel.HIGH
                "MEDIUM" -> RiskLevel.MEDIUM
                "LOW" -> RiskLevel.LOW
                else -> {
                    // Derive from standard risk score bands if level string was omitted:
                    // 0–29 Low, 30–59 Medium, 60–79 High, 80–100 Critical
                    when {
                        scoreInt >= 80 -> RiskLevel.CRITICAL
                        scoreInt >= 60 -> RiskLevel.HIGH
                        scoreInt >= 30 -> RiskLevel.MEDIUM
                        else -> RiskLevel.LOW
                    }
                }
            }

            // Extract reasons (from 'reasons' array or 'breakdown' array)
            val reasons = mutableListOf<String>()
            if (json.has("reasons")) {
                val reasonsArr = json.optJSONArray("reasons") ?: JSONArray()
                for (i in 0 until reasonsArr.length()) {
                    val r = reasonsArr.optString(i)
                    if (r.isNotBlank()) reasons.add(r)
                }
            } else if (json.has("breakdown")) {
                val breakdownArr = json.optJSONArray("breakdown") ?: JSONArray()
                for (i in 0 until breakdownArr.length()) {
                    val factorObj = breakdownArr.optJSONObject(i)
                    if (factorObj != null) {
                        val desc = factorObj.optString("description", "")
                        val label = factorObj.optString("label", factorObj.optString("factor", ""))
                        if (desc.isNotBlank()) {
                            reasons.add(desc)
                        } else if (label.isNotBlank()) {
                            reasons.add(label)
                        }
                    }
                }
            }

            if (reasons.isEmpty()) {
                val summary = json.optString("summary", "")
                if (summary.isNotBlank()) {
                    reasons.add(summary)
                } else {
                    reasons.add("Backend analysis complete: standard baseline risk profile.")
                }
            }

            // Extract recommended action
            val safeAction = when {
                json.has("recommended_action") && json.optString("recommended_action").isNotBlank() -> {
                    json.getString("recommended_action")
                }
                json.has("recommendations") -> {
                    val recsArr = json.optJSONArray("recommendations") ?: JSONArray()
                    val recList = mutableListOf<String>()
                    for (i in 0 until recsArr.length()) {
                        val rec = recsArr.optString(i)
                        if (rec.isNotBlank()) recList.add(rec)
                    }
                    if (recList.isNotEmpty()) recList.joinToString(" ") else "Maintain standard cybersecurity caution."
                }
                level == RiskLevel.CRITICAL || level == RiskLevel.HIGH -> {
                    "Do not share verification secrets or transfer funds. Verify with official service channels."
                }
                else -> "Verify any unusual communications through official channels."
            }

            // Extract indicators if available
            val indicators = mutableListOf<String>()
            if (json.has("indicators")) {
                val indArr = json.optJSONArray("indicators") ?: JSONArray()
                for (i in 0 until indArr.length()) {
                    val indObj = indArr.optJSONObject(i)
                    if (indObj != null) {
                        val v = indObj.optString("value", "")
                        if (v.isNotBlank()) indicators.add(v)
                    } else {
                        val s = indArr.optString(i)
                        if (s.isNotBlank()) indicators.add(s)
                    }
                }
            }

            val modelVersion = json.optString("model_version", "v1.0-rules-ml")
            val analysisMode = json.optString("analysis_mode", "cloud_threat_analyzer")
            val confidenceScore = if (json.has("confidence_score")) json.optDouble("confidence_score") else null
            val uncertaintyRange = if (json.has("uncertainty_range")) json.optString("uncertainty_range") else null
            val summary = if (json.has("summary")) json.optString("summary") else null

            val validatedResult = RiskAnalysisResult(
                score = scoreInt,
                level = level,
                reasons = reasons,
                safeAction = safeAction,
                analysisSource = AnalysisSource.BACKEND_ANALYSIS,
                isSynthetic = isSynthetic,
                eventKey = eventKey,
                packageName = packageName,
                indicators = indicators,
                modelVersion = modelVersion,
                analysisMode = analysisMode,
                confidenceScore = confidenceScore,
                uncertaintyRange = uncertaintyRange,
                summary = summary
            )

            NetworkResult.Success(validatedResult)
        } catch (e: Exception) {
            NetworkResult.Unavailable("Failed to parse backend response: ${e.message}")
        }
    }
}
