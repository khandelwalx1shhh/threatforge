package com.threatforge.android.pipeline

import com.threatforge.android.analyzer.LocalRiskAnalyzer
import com.threatforge.android.dedup.EventDeduplicator
import com.threatforge.android.filter.PackageFilter
import com.threatforge.android.model.AnalysisSource
import com.threatforge.android.model.NetworkResult
import com.threatforge.android.model.NotificationEvent
import com.threatforge.android.model.RiskAnalysisResult
import com.threatforge.android.network.ThreatForgeApiClient
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class DetectionPipeline(
    val localRiskAnalyzer: LocalRiskAnalyzer = LocalRiskAnalyzer(),
    val eventDeduplicator: EventDeduplicator = EventDeduplicator(),
    val apiClient: ThreatForgeApiClient = ThreatForgeApiClient()
) {

    private val _alerts = MutableStateFlow<List<RiskAnalysisResult>>(emptyList())
    val alerts: StateFlow<List<RiskAnalysisResult>> = _alerts.asStateFlow()

    private val _ignoredCount = MutableStateFlow(0)
    val ignoredCount: StateFlow<Int> = _ignoredCount.asStateFlow()

    private val _dedupedCount = MutableStateFlow(0)
    val dedupedCount: StateFlow<Int> = _dedupedCount.asStateFlow()

    val cloudAnalysisEnabled = MutableStateFlow(true)
    val userConsentGranted = MutableStateFlow(false)

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    /**
     * Processes an incoming event through the complete downstream pipeline:
     * 1. Package filtering (WhatsApp and Telegram only)
     * 2. Content validation (ignores empty/malformed text)
     * 3. Bounded deduplication
     * 4. Privacy Gate: checks cloud toggle & user consent
     * 5. Remote API client when authorized, otherwise explainable local fallback
     */
    suspend fun processEvent(event: NotificationEvent): RiskAnalysisResult? {
        // Step 1: Strict package filtering
        if (!PackageFilter.isPermitted(event.packageName)) {
            _ignoredCount.value += 1
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

        val combinedText = "${event.title} ${event.text}".trim()

        // Step 4: Privacy-gated Analysis Path
        if (cloudAnalysisEnabled.value && userConsentGranted.value) {
            _isLoading.value = true
            _statusMessage.value = "Contacting THREATFORGE cloud backend at ${apiClient.baseUrl}..."

            val netResult = apiClient.analyzeText(
                text = combinedText,
                source = event.packageName,
                isSynthetic = event.isSynthetic,
                eventKey = eventKey,
                cloudAnalysisEnabled = true,
                userConsentGranted = true
            )

            _isLoading.value = false

            when (netResult) {
                is NetworkResult.Success -> {
                    _statusMessage.value = "Verified backend analysis result received successfully."
                    _alerts.value = listOf(netResult.data) + _alerts.value
                    return netResult.data
                }
                is NetworkResult.Unavailable -> {
                    _statusMessage.value = "Cloud analysis is currently unavailable. No verified backend result was received. Exercising local fallback."
                    // Fall back to local heuristic analysis, clearly identified
                    val fallbackResult = localRiskAnalyzer.analyze(
                        title = event.title,
                        text = event.text,
                        packageName = event.packageName,
                        isSynthetic = event.isSynthetic,
                        eventKey = eventKey
                    )
                    _alerts.value = listOf(fallbackResult) + _alerts.value
                    return fallbackResult
                }
                is NetworkResult.Error -> {
                    _statusMessage.value = "Backend returned error (${netResult.code}). Exercising local fallback."
                    val fallbackResult = localRiskAnalyzer.analyze(
                        title = event.title,
                        text = event.text,
                        packageName = event.packageName,
                        isSynthetic = event.isSynthetic,
                        eventKey = eventKey
                    )
                    _alerts.value = listOf(fallbackResult) + _alerts.value
                    return fallbackResult
                }
                is NetworkResult.ConsentRequired -> {
                    _statusMessage.value = "Cloud analysis requires explicit user consent before transmitting notification text."
                    val fallbackResult = localRiskAnalyzer.analyze(
                        title = event.title,
                        text = event.text,
                        packageName = event.packageName,
                        isSynthetic = event.isSynthetic,
                        eventKey = eventKey
                    )
                    _alerts.value = listOf(fallbackResult) + _alerts.value
                    return fallbackResult
                }
                is NetworkResult.InvalidInput -> {
                    _statusMessage.value = "Input validation failed: ${netResult.message}"
                    return null
                }
            }
        } else {
            // Cloud analysis disabled or consent not provided: NEVER transmit content!
            if (cloudAnalysisEnabled.value && !userConsentGranted.value) {
                _statusMessage.value = "Cloud analysis disabled (consent required). Processed using local heuristic engine."
            } else {
                _statusMessage.value = "Cloud analysis disabled by user. Processed using local heuristic engine."
            }

            val localResult = localRiskAnalyzer.analyze(
                title = event.title,
                text = event.text,
                packageName = event.packageName,
                isSynthetic = event.isSynthetic,
                eventKey = eventKey
            )
            _alerts.value = listOf(localResult) + _alerts.value
            return localResult
        }
    }

    /**
     * Clears all alerts, deduplication state, and status messages.
     */
    fun clearAlerts() {
        _alerts.value = emptyList()
        _ignoredCount.value = 0
        _dedupedCount.value = 0
        _statusMessage.value = null
        eventDeduplicator.clear()
    }
}
