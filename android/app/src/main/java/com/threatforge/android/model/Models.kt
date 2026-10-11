package com.threatforge.android.model

enum class RiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

enum class AnalysisSource {
    LOCAL_HEURISTIC,
    BACKEND_ANALYSIS
}

data class NotificationEvent(
    val packageName: String,
    val title: String,
    val text: String,
    val timestamp: Long = System.currentTimeMillis(),
    val isSynthetic: Boolean = false
)

data class RiskAnalysisResult(
    val score: Int?,
    val level: RiskLevel,
    val reasons: List<String>,
    val safeAction: String,
    val analysisSource: AnalysisSource = AnalysisSource.LOCAL_HEURISTIC,
    val isSynthetic: Boolean = false,
    val eventKey: String,
    val timestamp: Long = System.currentTimeMillis(),
    val packageName: String? = null,
    val indicators: List<String> = emptyList(),
    val modelVersion: String? = null,
    val analysisMode: String? = null,
    val confidenceScore: Double? = null,
    val uncertaintyRange: String? = null,
    val summary: String? = null
)

sealed class NetworkResult<out T> {
    data class Success<out T>(val data: T) : NetworkResult<T>()
    data class Error(val code: Int, val message: String) : NetworkResult<Nothing>()
    data class Unavailable(val reason: String) : NetworkResult<Nothing>()
    object ConsentRequired : NetworkResult<Nothing>()
    data class InvalidInput(val message: String) : NetworkResult<Nothing>()
}
