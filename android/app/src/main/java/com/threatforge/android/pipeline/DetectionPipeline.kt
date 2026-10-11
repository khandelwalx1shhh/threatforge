package com.threatforge.android.pipeline

import com.threatforge.android.analyzer.LocalRiskAnalyzer
import com.threatforge.android.dedup.EventDeduplicator
import com.threatforge.android.filter.PackageFilter
import com.threatforge.android.model.AnalysisSource
import com.threatforge.android.model.NetworkResult
import com.threatforge.android.model.NotificationEvent
import com.threatforge.android.model.RiskAnalysisResult
import com.threatforge.android.network.ThreatForgeApiClient
import com.threatforge.android.storage.ThreatStorageManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class DetectionPipeline(
    val localRiskAnalyzer: LocalRiskAnalyzer = LocalRiskAnalyzer(),
    val eventDeduplicator: EventDeduplicator = EventDeduplicator(),
    val apiClient: ThreatForgeApiClient = ThreatForgeApiClient(),
    val storageManager: ThreatStorageManager? = try {
        if (com.threatforge.android.ThreatForgeApplication.isInitialized) {
            ThreatStorageManager(com.threatforge.android.ThreatForgeApplication.instance)
        } else null
    } catch (e: Throwable) {
        null
    }
) {

    private val _alerts = MutableStateFlow<List<RiskAnalysisResult>>(
        storageManager?.loadAlerts() ?: emptyList()
    )
    val alerts: StateFlow<List<RiskAnalysisResult>> = _alerts.asStateFlow()

    private val _ignoredCount = MutableStateFlow(
        storageManager?.getIgnoredCount() ?: 0
    )
    val ignoredCount: StateFlow<Int> = _ignoredCount.asStateFlow()

    private val _dedupedCount = MutableStateFlow(
        storageManager?.getDedupedCount() ?: 0
    )
    val dedupedCount: StateFlow<Int> = _dedupedCount.asStateFlow()

    val cloudAnalysisEnabled = MutableStateFlow(
        storageManager?.isCloudAnalysisEnabled() ?: true
    )
    val userConsentGranted = MutableStateFlow(
        storageManager?.isUserConsentGranted() ?: false
    )
    val localOnlyMode = MutableStateFlow(
        storageManager?.isLocalOnlyMode() ?: false
    )
    val retentionDays = MutableStateFlow(
        storageManager?.getRetentionDays() ?: 7
    ) // 1, 7, 30, or 0 (memory only)

    init {
        storageManager?.getBaseUrl()?.let { savedUrl ->
            apiClient.baseUrl = savedUrl
        }
    }

    fun setBaseUrl(url: String) {
        apiClient.baseUrl = url
        storageManager?.setBaseUrl(url)
    }

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    private fun recordAlert(alert: RiskAnalysisResult) {
        val updated = listOf(alert) + _alerts.value
        _alerts.value = updated
        storageManager?.saveAlerts(updated)
    }

    private fun incrementIgnored() {
        _ignoredCount.value += 1
        storageManager?.setIgnoredCount(_ignoredCount.value)
    }

    private fun incrementDeduped() {
        _dedupedCount.value += 1
        storageManager?.setDedupedCount(_dedupedCount.value)
    }

    fun setCloudAnalysis(enabled: Boolean) {
        cloudAnalysisEnabled.value = enabled
        storageManager?.setCloudAnalysisEnabled(enabled)
    }

    fun setUserConsent(granted: Boolean) {
        userConsentGranted.value = granted
        storageManager?.setUserConsentGranted(granted)
    }

    fun setLocalOnly(localOnly: Boolean) {
        localOnlyMode.value = localOnly
        storageManager?.setLocalOnlyMode(localOnly)
    }

    fun setRetentionDays(days: Int) {
        retentionDays.value = days
        storageManager?.setRetentionDays(days)
    }

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
            incrementIgnored()
            return null
        }

        // Step 2: Content validation
        if (!PackageFilter.hasUsableContent(event.title, event.text)) {
            incrementIgnored()
            return null
        }

        // Step 3: Deduplication
        val eventKey = eventDeduplicator.generateKey(event.packageName, event.title, event.text)
        if (eventDeduplicator.isDuplicateAndRecord(eventKey)) {
            incrementDeduped()
            return null
        }

        val combinedText = "${event.title} ${event.text}".trim()

        // Step 4: Privacy-gated Analysis Path
        if (localOnlyMode.value) {
            _statusMessage.value = "Local-Only Shield active: 100% on-device analysis without network transmission."
            val localResult = localRiskAnalyzer.analyze(
                title = event.title,
                text = event.text,
                packageName = event.packageName,
                isSynthetic = event.isSynthetic,
                eventKey = eventKey
            )
            recordAlert(localResult)
            return localResult
        }

        if (cloudAnalysisEnabled.value && userConsentGranted.value) {
            _isLoading.value = true
            _statusMessage.value = "Contacting THREATFORGE cloud backend at ${apiClient.baseUrl}..."

            val netResult = apiClient.analyzeText(
                text = combinedText,
                source = event.packageName,
                isSynthetic = event.isSynthetic,
                eventKey = eventKey,
                cloudAnalysisEnabled = true,
                userConsentGranted = true,
                localOnlyMode = false
            )

            _isLoading.value = false

            when (netResult) {
                is NetworkResult.Success -> {
                    _statusMessage.value = "Verified backend analysis result received successfully."
                    recordAlert(netResult.data)
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
                    recordAlert(fallbackResult)
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
                    recordAlert(fallbackResult)
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
                    recordAlert(fallbackResult)
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
            recordAlert(localResult)
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
        storageManager?.clearAllAlerts()
    }
}
