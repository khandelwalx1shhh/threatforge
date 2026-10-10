package com.threatforge.android

import com.threatforge.android.analyzer.LocalRiskAnalyzer
import com.threatforge.android.dedup.EventDeduplicator
import com.threatforge.android.filter.PackageFilter
import com.threatforge.android.model.AnalysisSource
import com.threatforge.android.model.NotificationEvent
import com.threatforge.android.model.RiskLevel
import com.threatforge.android.pipeline.DetectionPipeline
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class ThreatForgeTests {

    private lateinit var analyzer: LocalRiskAnalyzer
    private lateinit var deduplicator: EventDeduplicator
    private lateinit var pipeline: DetectionPipeline

    @Before
    fun setUp() {
        analyzer = LocalRiskAnalyzer()
        deduplicator = EventDeduplicator(maxEntries = 5)
        pipeline = DetectionPipeline(analyzer, deduplicator)
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

    // --- 4. End-to-End Pipeline Tests ---
    @Test
    fun pipeline_discardsUnrelatedPackagesBeforeContentAnalysis() {
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
    fun pipeline_discardsEmptyNotification() {
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
    fun pipeline_processesPermittedScamSampleAndSuppressesDuplicate() {
        val scamEvent = NotificationEvent(
            packageName = "com.whatsapp",
            title = "Security Alert",
            text = "URGENT: Your example.com account will be suspended. Share your OTP immediately to prevent the suspension.",
            isSynthetic = true
        )

        val firstResult = pipeline.processEvent(scamEvent)
        assertNotNull("First event should produce a warning result", firstResult)
        assertEquals(RiskLevel.CRITICAL, firstResult!!.level)
        assertEquals(1, pipeline.alerts.value.size)

        // Resubmit identical event
        val secondResult = pipeline.processEvent(scamEvent)
        assertNull("Second identical event must be deduplicated", secondResult)
        assertEquals(1, pipeline.alerts.value.size)
        assertEquals(1, pipeline.dedupedCount.value)
    }
}
