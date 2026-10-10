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
    val indicators: List<String> = emptyList()
)
