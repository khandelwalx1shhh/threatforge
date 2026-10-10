package com.threatforge.android.pipeline

import com.threatforge.android.analyzer.LocalRiskAnalyzer
import com.threatforge.android.dedup.EventDeduplicator
import com.threatforge.android.filter.PackageFilter
import com.threatforge.android.model.NotificationEvent
import com.threatforge.android.model.RiskAnalysisResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class DetectionPipeline(
    private val localRiskAnalyzer: LocalRiskAnalyzer = LocalRiskAnalyzer(),
    private val eventDeduplicator: EventDeduplicator = EventDeduplicator()
) {

    private val _alerts = MutableStateFlow<List<RiskAnalysisResult>>(emptyList())
    val alerts: StateFlow<List<RiskAnalysisResult>> = _alerts.asStateFlow()

    private val _ignoredCount = MutableStateFlow(0)
    val ignoredCount: StateFlow<Int> = _ignoredCount.asStateFlow()

    private val _dedupedCount = MutableStateFlow(0)
    val dedupedCount: StateFlow<Int> = _dedupedCount.asStateFlow()

    /**
     * Processes an incoming event through the complete downstream pipeline:
     * 1. Package filtering (WhatsApp and Telegram only)
     * 2. Content validation (ignores empty/malformed text)
     * 3. Bounded deduplication
     * 4. Explainable local risk analysis
     */
    fun processEvent(event: NotificationEvent): RiskAnalysisResult? {
        // Step 1: Strict package filtering
        if (!PackageFilter.isPermitted(event.packageName)) {
            _ignoredCount.value += 1
            // Event discarded before notification-content analysis
            return null
        }

        // Step 2: Content validation
        if (!PackageFilter.hasUsableContent(event.title, event.text)) {
            _ignoredCount.value += 1
            return null
        }

        // Step 3: Deduplication
        val eventKey = eventDeduplicator.generateKey(event.packageName, event.title, event.text)
        if (eventDeduplicator.isDuplicateAndRecord(eventKey)) {
            _dedupedCount.value += 1
            return null
        }

        // Step 4: Local heuristic risk analysis
        val result = localRiskAnalyzer.analyze(
            title = event.title,
            text = event.text,
            packageName = event.packageName,
            isSynthetic = event.isSynthetic,
            eventKey = eventKey
        )

        // Prepend new alert to stream
        _alerts.value = listOf(result) + _alerts.value

        return result
    }

    /**
     * Clears all alerts and deduplication state for demo testing.
     */
    fun clearAlerts() {
        _alerts.value = emptyList()
        _ignoredCount.value = 0
        _dedupedCount.value = 0
        eventDeduplicator.clear()
    }
}
