package com.threatforge.android.analyzer

import com.threatforge.android.model.AnalysisSource
import com.threatforge.android.model.RiskAnalysisResult
import com.threatforge.android.model.RiskLevel
import java.util.regex.Pattern

class LocalRiskAnalyzer {

    // Regex patterns for signal categories (case-insensitive)
    private val urgentThreatPattern = Pattern.compile(
        "\\b(urgent|immediately|immediate|suspended|suspend|blocked|block|deactivated|closed|terminated|within\\s+\\d+\\s*(hours?|mins?|minutes?)|act\\s+now)\\b",
        Pattern.CASE_INSENSITIVE
    )

    private val accountPressurePattern = Pattern.compile(
        "\\b(account|wallet|profile|access|banking|kyc|card|subscription)\\b",
        Pattern.CASE_INSENSITIVE
    )

    private val otpPattern = Pattern.compile(
        "\\b(otp|one[ -]time\\s+password|pin|verification\\s+code|security\\s+code|auth\\s+code)\\b",
        Pattern.CASE_INSENSITIVE
    )

    private val credentialRequestPattern = Pattern.compile(
        "\\b(share|send|enter|verify|provide|give|reveal|disclose)\\b",
        Pattern.CASE_INSENSITIVE
    )

    private val paymentDemandPattern = Pattern.compile(
        "\\b(transfer\\s+(money|funds|amount|cash)|urgent\\s+payment|pay\\s+now|deposit\\s+now|send\\s+(money|funds|crypto))\\b",
        Pattern.CASE_INSENSITIVE
    )

    private val urlPattern = Pattern.compile(
        "https?://[\\w\\.-]+(?:\\.[a-zA-Z]{2,})(?:/[^\\s]*)?",
        Pattern.CASE_INSENSITIVE
    )

    private val suspiciousDomainIndicator = Pattern.compile(
        "\\b(?:bit\\.ly|tinyurl\\.com|t\\.co|is\\.gd|rb\\.gy|shorturl\\.at|example\\.com|example\\.invalid|[a-z0-9-]+\\.(?:xyz|top|work|click|loan|gq|cf|ml))\\b",
        Pattern.CASE_INSENSITIVE
    )

    private val apkPattern = Pattern.compile(
        "(?i)\\b(?:https?://[^\\s<>'\"()]+\\.apk|[a-zA-Z0-9_\\-\\.]+\\.apk)\\b"
    )

    private val upiDeepLinkPattern = Pattern.compile(
        "upi://pay\\?[^\\s\"'>]+",
        Pattern.CASE_INSENSITIVE
    )

    /**
     * Evaluates message content and returns an explainable risk assessment.
     * Does not claim certainty or ML capabilities. Clearly marks as Local Heuristic Analysis.
     */
    fun analyze(
        title: String,
        text: String,
        packageName: String? = null,
        isSynthetic: Boolean = false,
        eventKey: String = ""
    ): RiskAnalysisResult {
        val combinedText = "$title $text".trim()
        if (combinedText.isEmpty()) {
            return RiskAnalysisResult(
                score = 0,
                level = RiskLevel.LOW,
                reasons = listOf("Empty or unreadable message content"),
                safeAction = "No action required.",
                analysisSource = AnalysisSource.LOCAL_HEURISTIC,
                isSynthetic = isSynthetic,
                eventKey = eventKey,
                packageName = packageName
            )
        }

        val hasUrgency = urgentThreatPattern.matcher(combinedText).find()
        val hasAccountContext = accountPressurePattern.matcher(combinedText).find()
        val hasOtpMention = otpPattern.matcher(combinedText).find()
        val hasCredentialRequest = credentialRequestPattern.matcher(combinedText).find()
        val hasPaymentDemand = paymentDemandPattern.matcher(combinedText).find()

        val urlMatcher = urlPattern.matcher(combinedText)
        val extractedUrls = mutableListOf<String>()
        while (urlMatcher.find()) {
            extractedUrls.add(urlMatcher.group())
        }

        val hasSuspiciousDomain = suspiciousDomainIndicator.matcher(combinedText).find()
        val hasAnyUrl = extractedUrls.isNotEmpty() || hasSuspiciousDomain
        val hasApk = apkPattern.matcher(combinedText).find()
        val hasUpiDeepLink = upiDeepLinkPattern.matcher(combinedText).find()

        val reasons = mutableListOf<String>()
        var baseScore = 5

        // Compound Signal 0: Sideloaded APK Package Dropper
        if (hasApk) {
            baseScore += 90 // Instant CRITICAL (Score 95+)
            reasons.add("CRITICAL: Distributes sideloaded Android application package (.apk). Extreme spyware/banking trojan risk.")
        }

        // Compound Signal 0b: UPI Deep Link / Reverse-Charge Fraud
        if (hasUpiDeepLink) {
            val isReverseCharge = Pattern.compile("(?i)\\b(receive|refund|cashback|claim|credit|lottery|prize|bonus)\\b").matcher(combinedText).find()
            if (isReverseCharge) {
                baseScore += 80
                reasons.add("Reverse-Charge UPI Fraud: Claims you will receive/claim money, but link will execute a DEBIT payment from your account.")
            } else {
                baseScore += 45
                reasons.add("Contains direct UPI payment deep link.")
            }
        }

        // Compound Signal 1: Urgent Account Threat + Credential/OTP Request
        if ((hasUrgency && hasAccountContext) && (hasOtpMention && hasCredentialRequest)) {
            baseScore += 82 // Total: 87 (CRITICAL)
            reasons.add("Requests an OTP while applying urgent account pressure.")
        } else if (hasOtpMention && hasCredentialRequest) {
            baseScore += 50
            reasons.add("Solicits confidential authentication secrets (OTP/PIN/code).")
        } else if (hasUrgency && hasAccountContext) {
            baseScore += 35
            reasons.add("Applies urgent account suspension or blocking pressure.")
        }

        // Compound Signal 2: Payment demand under pressure
        if (hasPaymentDemand) {
            if (hasUrgency) {
                baseScore += 45
                reasons.add("Demands immediate financial transfer under alleged urgent circumstances.")
            } else {
                baseScore += 25
                reasons.add("Requests funds or payment transfer.")
            }
        }

        // Compound Signal 3: Suspicious link with pressure/action
        if (hasAnyUrl) {
            if (hasUrgency || hasAccountContext || hasOtpMention) {
                baseScore += 20
                reasons.add("Directs user to an unverified link alongside urgent or account-related claims.")
            } else {
                baseScore += 5
                reasons.add("Message contains external web link (unverified destination).")
            }
        }

        // Single isolated keyword dampener (avoid false positives on benign words)
        if (reasons.isEmpty()) {
            reasons.add("No high-risk scam or credential harvesting patterns identified.")
            baseScore = 5
        }

        // Cap score at [0, 100]
        val finalScore = baseScore.coerceIn(0, 100)

        // Map to risk band: 0–29 Low, 30–59 Medium, 60–79 High, 80–100 Critical
        val level = when {
            finalScore >= 80 -> RiskLevel.CRITICAL
            finalScore >= 60 -> RiskLevel.HIGH
            finalScore >= 30 -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }

        // Tailor safe recommendation
        val safeAction = when {
            hasApk -> "CRITICAL: Do NOT download or install this .apk file. Legitimate banks and organizations never distribute APKs over chat."
            hasUpiDeepLink -> "Do NOT approve this UPI transaction or enter your UPI PIN. Verify payee details in your official banking app."
            hasOtpMention -> "Do not share your OTP or PIN. Verify the request using the service's official app or website."
            hasPaymentDemand -> "Do not transfer money based only on this message. Contact the organization through verified official channels."
            hasAnyUrl -> "Avoid opening the link until its destination has been verified through official channels."
            level == RiskLevel.HIGH || level == RiskLevel.CRITICAL -> "Do not reply or follow any instructions in this message. Check your account directly through the official app."
            else -> "Verify any unexpected account claims independently before taking action."
        }

        return RiskAnalysisResult(
            score = finalScore,
            level = level,
            reasons = reasons,
            safeAction = safeAction,
            analysisSource = AnalysisSource.LOCAL_HEURISTIC,
            isSynthetic = isSynthetic,
            eventKey = eventKey,
            packageName = packageName,
            indicators = extractedUrls
        )
    }
}
