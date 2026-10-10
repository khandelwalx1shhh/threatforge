package com.threatforge.android

import com.threatforge.android.analyzer.LocalRiskAnalyzer
import com.threatforge.android.dedup.EventDeduplicator
import com.threatforge.android.filter.PackageFilter
import com.threatforge.android.model.AnalysisSource
import com.threatforge.android.model.NetworkResult
import com.threatforge.android.model.NotificationEvent
import com.threatforge.android.model.RiskLevel
import com.threatforge.android.network.ThreatForgeApiClient
import com.threatforge.android.pipeline.DetectionPipeline
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class ThreatForgeTests {

    private lateinit var analyzer: LocalRiskAnalyzer
    private lateinit var deduplicator: EventDeduplicator
    private lateinit var apiClient: ThreatForgeApiClient
    private lateinit var pipeline: DetectionPipeline

    @Before
    fun setUp() {
        analyzer = LocalRiskAnalyzer()
        deduplicator = EventDeduplicator(maxEntries = 10)
        apiClient = ThreatForgeApiClient()
        pipeline = DetectionPipeline(analyzer, deduplicator, apiClient)
    }

    // --- 1. Package Filtering Tests ---
    @Test
    fun packageFilter_allowsPermittedMessagingApps() {
        assertTrue(PackageFilter.isPermitted("com.whatsapp"))
        assertTrue(PackageFilter.isPermitted("org.telegram.messenger"))
    }

    @Test
    fun packageFilter_rejectsUnrelatedPackages() {
        assertFalse(PackageFilter.isPermitted("com.google.android.gm"))
        assertFalse(PackageFilter.isPermitted("com.facebook.katana"))
        assertFalse(PackageFilter.isPermitted("com.android.settings"))
        assertFalse(PackageFilter.isPermitted(null))
        assertFalse(PackageFilter.isPermitted(""))
        assertFalse(PackageFilter.isPermitted("   "))
    }

    @Test
    fun packageFilter_validatesUsableContent() {
        assertTrue(PackageFilter.hasUsableContent("Title", "Message text"))
        assertTrue(PackageFilter.hasUsableContent("", "Message text"))
        assertTrue(PackageFilter.hasUsableContent("Title", null))
        assertFalse(PackageFilter.hasUsableContent("", ""))
        assertFalse(PackageFilter.hasUsableContent(null, null))
        assertFalse(PackageFilter.hasUsableContent("   ", "   "))
    }

    // --- 2. Local Risk Analyzer Tests ---
    @Test
    fun localAnalyzer_detectsSuspiciousAccountOtpScam() {
        val sample = "URGENT: Your example.com account will be suspended. Share your OTP immediately to prevent the suspension."
        val result = analyzer.analyze(
            title = "Security Alert",
            text = sample,
            packageName = "com.whatsapp",
            isSynthetic = true
        )

        assertNotNull(result.score)
        assertTrue("Expected score >= 80 for urgent OTP scam, got ${result.score}", result.score!! >= 80)
        assertEquals(RiskLevel.CRITICAL, result.level)
        assertEquals(AnalysisSource.LOCAL_HEURISTIC, result.analysisSource)
        assertTrue(result.isSynthetic)
        assertTrue("Expected safe action to protect OTP", result.safeAction.contains("OTP", ignoreCase = true))
        assertTrue("Expected explainable reason", result.reasons.any { it.contains("OTP", ignoreCase = true) })
    }

    @Test
    fun localAnalyzer_evaluatesBenignControlAsLowRisk() {
        val benign = "Your appointment is confirmed for tomorrow at 10 AM. Thank you."
        val result = analyzer.analyze(
            title = "Reminder",
            text = benign,
            packageName = "com.whatsapp",
            isSynthetic = true
        )

        assertNotNull(result.score)
        assertTrue("Expected benign score < 30, got ${result.score}", result.score!! < 30)
        assertEquals(RiskLevel.LOW, result.level)
        assertFalse("Should not be critical", result.level == RiskLevel.CRITICAL)
    }

    @Test
    fun localAnalyzer_handlesEmptyContentSafelyWithoutCrashing() {
        val result = analyzer.analyze(
            title = "",
            text = "",
            packageName = "com.whatsapp",
            isSynthetic = false
        )

        assertEquals(0, result.score)
        assertEquals(RiskLevel.LOW, result.level)
        assertEquals(AnalysisSource.LOCAL_HEURISTIC, result.analysisSource)
    }

    // --- 3. Deduplication Tests ---
    @Test
    fun deduplicator_suppressesRepeatedEvents() {
        val key = deduplicator.generateKey("com.whatsapp", "Alert", "Your account will be suspended")

        val firstCheck = deduplicator.isDuplicateAndRecord(key)
        assertFalse("First submission must not be duplicate", firstCheck)

        val secondCheck = deduplicator.isDuplicateAndRecord(key)
        assertTrue("Second submission of same key must be flagged as duplicate", secondCheck)
    }

    @Test
    fun deduplicator_distinguishesDifferentMessages() {
        val key1 = deduplicator.generateKey("com.whatsapp", "Alert 1", "Message 1")
        val key2 = deduplicator.generateKey("com.whatsapp", "Alert 2", "Message 2")

        assertFalse(deduplicator.isDuplicateAndRecord(key1))
        assertFalse(deduplicator.isDuplicateAndRecord(key2))
    }

    // --- 4. Privacy Gate & Consent Tests (Phase 2 Task A & D) ---
    @Test
    fun privacyGate_blocksCloudAnalysisWhenConsentMissing() = runBlocking {
        pipeline.cloudAnalysisEnabled.value = true
        pipeline.userConsentGranted.value = false // Consent NOT given

        val event = NotificationEvent(
            packageName = "com.whatsapp",
            title = "Alert",
            text = "Your account will be suspended. Share your OTP immediately.",
            isSynthetic = true
        )

        val result = pipeline.processEvent(event)
        assertNotNull(result)
        // Must NOT be backend analysis when consent is absent
        assertEquals(AnalysisSource.LOCAL_HEURISTIC, result!!.analysisSource)
    }

    @Test
    fun privacyGate_blocksCloudAnalysisWhenCloudToggleDisabled() = runBlocking {
        pipeline.cloudAnalysisEnabled.value = false // Cloud toggle disabled
        pipeline.userConsentGranted.value = true

        val event = NotificationEvent(
            packageName = "com.whatsapp",
            title = "Alert",
            text = "Your account will be suspended. Share your OTP immediately.",
            isSynthetic = true
        )

        val result = pipeline.processEvent(event)
        assertNotNull(result)
        assertEquals(AnalysisSource.LOCAL_HEURISTIC, result!!.analysisSource)
    }

    // --- 5. Backend Response Parsing Tests (Phase 2 Task B & D) ---
    @Test
    fun responseParser_validatesScamSampleResponse() {
        val mockJson = """
            {
                "risk_score": 87.0,
                "risk_level": "CRITICAL",
                "confidence_score": 0.94,
                "uncertainty_range": "±5%",
                "summary": "CRITICAL RISK: Severe credential harvesting pattern",
                "breakdown": [
                    {
                        "code": "OTP_HARVESTING",
                        "label": "Credential & OTP Harvesting",
                        "description": "Explicitly requests sensitive authentication secrets ('OTP').",
                        "severity": "CRITICAL",
                        "score": 45.0
                    }
                ],
                "indicators": [],
                "recommendations": [
                    "NEVER share OTPs or verification codes with anyone."
                ],
                "model_version": "text-v1",
                "analysis_mode": "rules+ml"
            }
        """.trimIndent()

        val parsed = apiClient.parseAndValidateResponse(
            responseText = mockJson,
            packageName = "com.whatsapp",
            isSynthetic = true,
            eventKey = "test-key-1"
        )

        assertTrue(parsed is NetworkResult.Success)
        val data = (parsed as NetworkResult.Success).data
        assertEquals(87, data.score)
        assertEquals(RiskLevel.CRITICAL, data.level)
        assertEquals(AnalysisSource.BACKEND_ANALYSIS, data.analysisSource)
        assertEquals("text-v1", data.modelVersion)
        assertEquals("rules+ml", data.analysisMode)
        assertTrue(data.reasons.any { it.contains("OTP") })
        assertTrue(data.safeAction.contains("OTP"))
    }

    @Test
    fun responseParser_validatesBenignSampleResponse() {
        val mockJson = """
            {
                "risk_score": 0.0,
                "risk_level": "LOW",
                "confidence_score": 0.95,
                "uncertainty_range": "±2%",
                "summary": "LOW RISK: No high-risk indicators found.",
                "breakdown": [],
                "indicators": [],
                "recommendations": [
                    "Message appears benign. Maintain standard cyber hygiene practices."
                ]
            }
        """.trimIndent()

        val parsed = apiClient.parseAndValidateResponse(
            responseText = mockJson,
            packageName = "com.whatsapp",
            isSynthetic = true,
            eventKey = "test-key-2"
        )

        assertTrue(parsed is NetworkResult.Success)
        val data = (parsed as NetworkResult.Success).data
        assertEquals(0, data.score)
        assertEquals(RiskLevel.LOW, data.level)
        assertEquals(AnalysisSource.BACKEND_ANALYSIS, data.analysisSource)
        assertFalse(data.level == RiskLevel.CRITICAL)
    }

    @Test
    fun responseParser_validatesUrlSampleWithIndicators() {
        val mockJson = """
            {
                "risk_score": 35.0,
                "risk_level": "MEDIUM",
                "summary": "MEDIUM RISK: External link detected",
                "breakdown": [
                    {
                        "code": "EXTERNAL_URL",
                        "label": "External URL",
                        "description": "Message contains external link to https://example.com/account-review",
                        "severity": "MEDIUM",
                        "score": 30.0
                    }
                ],
                "indicators": [
                    {
                        "type": "Phishing URL",
                        "value": "https://example.com/account-review"
                    }
                ],
                "recommendations": [
                    "Verify link destination through official bookmarks."
                ]
            }
        """.trimIndent()

        val parsed = apiClient.parseAndValidateResponse(
            responseText = mockJson,
            packageName = "org.telegram.messenger",
            isSynthetic = true,
            eventKey = "test-key-3"
        )

        assertTrue(parsed is NetworkResult.Success)
        val data = (parsed as NetworkResult.Success).data
        assertEquals(35, data.score)
        assertEquals(RiskLevel.MEDIUM, data.level)
        assertTrue(data.indicators.contains("https://example.com/account-review"))
    }

    @Test
    fun responseParser_rejectsMalformedMissingScore() {
        val malformedJson = """
            {
                "summary": "Missing score field entirely"
            }
        """.trimIndent()

        val parsed = apiClient.parseAndValidateResponse(
            responseText = malformedJson,
            packageName = "com.whatsapp",
            isSynthetic = true,
            eventKey = "test-key-4"
        )

        assertTrue("Expected rejection for malformed response missing score", parsed is NetworkResult.Unavailable)
    }

    @Test
    fun responseParser_rejectsOutOfRangeScore() {
        val outOfRangeJson = """
            {
                "risk_score": 999.0,
                "risk_level": "CRITICAL"
            }
        """.trimIndent()

        val parsed = apiClient.parseAndValidateResponse(
            responseText = outOfRangeJson,
            packageName = "com.whatsapp",
            isSynthetic = true,
            eventKey = "test-key-5"
        )

        assertTrue("Expected rejection for score 999 > 100", parsed is NetworkResult.Unavailable)
    }

    // --- 6. End-to-End Pipeline Integration Tests ---
    @Test
    fun pipeline_discardsUnrelatedPackagesBeforeContentAnalysis() = runBlocking {
        val unrelatedEvent = NotificationEvent(
            packageName = "com.google.android.gm",
            title = "Urgent Notice",
            text = "Your account will be suspended immediately. Share your OTP."
        )

        val result = pipeline.processEvent(unrelatedEvent)
        assertNull("Unrelated package must be discarded", result)
        assertEquals(0, pipeline.alerts.value.size)
        assertEquals(1, pipeline.ignoredCount.value)
    }

    @Test
    fun pipeline_discardsEmptyNotification() = runBlocking {
        val emptyEvent = NotificationEvent(
            packageName = "com.whatsapp",
            title = "",
            text = ""
        )

        val result = pipeline.processEvent(emptyEvent)
        assertNull("Empty notification must be discarded", result)
        assertEquals(0, pipeline.alerts.value.size)
        assertEquals(1, pipeline.ignoredCount.value)
    }

    @Test
    fun pipeline_deduplicatesRepeatedNotificationEvents() = runBlocking {
        val scamEvent = NotificationEvent(
            packageName = "com.whatsapp",
            title = "Security Alert",
            text = "URGENT: Your example.com account will be suspended. Share your OTP immediately.",
            isSynthetic = true
        )

        val firstResult = pipeline.processEvent(scamEvent)
        assertNotNull("First event should produce an alert", firstResult)
        assertEquals(1, pipeline.alerts.value.size)

        // Resubmit identical event
        val secondResult = pipeline.processEvent(scamEvent)
        assertNull("Second identical event must be deduplicated", secondResult)
        assertEquals(1, pipeline.alerts.value.size)
        assertEquals(1, pipeline.dedupedCount.value)
    }
}
