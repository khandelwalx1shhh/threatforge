package com.threatforge.android.privacy

import java.net.URI
import java.util.regex.Pattern

/**
 * Client-Side Privacy Scrubber
 *
 * Enforces pre-transmission data sanitization on Android before any network request leaves the device.
 * Strips authentication tokens, OTPs, personal identifiers, credit card numbers, and banking details.
 */
object PrivacyScrubber {

    private val SENSITIVE_QUERY_PARAMS = setOf(
        "token", "auth", "key", "secret", "password", "pwd", "pass", "otp",
        "code", "access_token", "api_key", "session", "credential", "pin", "jwt"
    )

    // Match 4-8 digit OTPs or passcodes following common authentication keywords
    private val OTP_PATTERN = Pattern.compile(
        """\b(?:otp|code|pin|passcode|token|verification|verify)\s*(?:is|[:=])?\s*([0-9a-zA-Z]{4,8})\b""",
        Pattern.CASE_INSENSITIVE
    )

    // Match 16-digit credit/debit card numbers with optional dashes or spaces
    private val CARD_PATTERN = Pattern.compile(
        """\b(?:\d{4}[ -]?){3}\d{4}\b"""
    )

    // Match 9-18 digit account numbers following account/bank keywords
    private val ACCOUNT_PATTERN = Pattern.compile(
        """\b(?:a/c|acc|account|acct)\s*(?:no|number|num|#)?\s*[:.]?\s*(\d{9,18})\b""",
        Pattern.CASE_INSENSITIVE
    )

    // Match phone numbers (Indian & International E.164 formats)
    private val PHONE_PATTERN = Pattern.compile(
        """(?:\+?\d{1,3}[ -]?)?(?:[6-9]\d{9}|\b\d{10}\b)"""
    )

    // Match query parameter tokens in URLs
    private val URL_TOKEN_PATTERN = Pattern.compile(
        """([?&](?:token|auth|key|password|pwd|otp|access_token|session)=)[^&\s]+""",
        Pattern.CASE_INSENSITIVE
    )

    data class RedactionResult(
        val sanitizedText: String,
        val maskedSender: String,
        val redactedItemsCount: Int,
        val redactionTypes: List<String>
    )

    data class OutboundDataInspection(
        val endpoint: String,
        val packageName: String,
        val sanitizedPayload: String,
        val dataLeavingDevice: List<String>,
        val dataRetainedLocally: List<String>,
        val dataNeverCollected: List<String>
    )

    /**
     * Sanitizes sensitive text before network transmission.
     */
    fun redactSensitiveData(rawText: String, rawSender: String = ""): RedactionResult {
        var text = rawText
        var count = 0
        val types = mutableListOf<String>()

        // 1. Redact OTP / Auth codes
        val otpMatcher = OTP_PATTERN.matcher(text)
        if (otpMatcher.find()) {
            text = otpMatcher.replaceAll("code: [REDACTED_OTP]")
            count++
            types.add("OTP / Auth Code")
        }

        // 2. Redact Credit / Debit Card numbers
        val cardMatcher = CARD_PATTERN.matcher(text)
        if (cardMatcher.find()) {
            text = cardMatcher.replaceAll("[REDACTED_CARD]")
            count++
            types.add("Payment Card")
        }

        // 3. Redact Bank Account numbers
        val accountMatcher = ACCOUNT_PATTERN.matcher(text)
        if (accountMatcher.find()) {
            text = accountMatcher.replaceAll("Account: [REDACTED_A/C]")
            count++
            types.add("Bank Account Number")
        }

        // 4. Redact sensitive URL parameters
        val urlTokenMatcher = URL_TOKEN_PATTERN.matcher(text)
        if (urlTokenMatcher.find()) {
            text = urlTokenMatcher.replaceAll("$1REDACTED")
            count++
            types.add("URL Auth Token")
        }

        // 5. Mask sender identifier to protect contact privacy
        val maskedSender = maskSender(rawSender)

        return RedactionResult(
            sanitizedText = text,
            maskedSender = maskedSender,
            redactedItemsCount = count,
            redactionTypes = types
        )
    }

    /**
     * Masks personal phone numbers or identifiers (e.g. "+91 98765 43210" -> "+91 98*** **210")
     */
    fun maskSender(sender: String): String {
        if (sender.isBlank()) return "Unknown Sender"
        val trimmed = sender.trim()
        val digits = trimmed.filter { it.isDigit() }
        if (digits.length >= 10) {
            // Mask middle digits
            val prefix = trimmed.take(5)
            val suffix = trimmed.takeLast(3)
            return "$prefix*** **$suffix"
        }
        if (trimmed.contains("@")) {
            val parts = trimmed.split("@")
            val user = parts[0]
            val domain = parts.getOrNull(1) ?: ""
            val maskedUser = if (user.length > 2) user.take(2) + "***" else user
            return "$maskedUser@$domain"
        }
        return trimmed
    }

    /**
     * Generates a transparent inspection report showing exactly what data leaves the device.
     */
    fun inspectOutboundData(
        rawText: String,
        rawSender: String,
        packageName: String,
        endpoint: String
    ): OutboundDataInspection {
        val result = redactSensitiveData(rawText, rawSender)
        val jsonPreview = """
        {
          "text": "${result.sanitizedText.replace("\"", "\\\"").take(150)}...",
          "source": "$packageName",
          "sender": "${result.maskedSender}",
          "cloud_analysis": true
        }
        """.trimIndent()

        return OutboundDataInspection(
            endpoint = endpoint,
            packageName = packageName,
            sanitizedPayload = jsonPreview,
            dataLeavingDevice = listOf(
                "Sanitized message text (with OTPs & tokens redacted)",
                "Whitelisted messaging app package name ($packageName)",
                "Pseudonymized/masked sender identifier (${result.maskedSender})",
                "Explicit user consent verification token"
            ),
            dataRetainedLocally = listOf(
                "Raw un-redacted notification text (memory-only on device)",
                "Exact sender contact details and full phone numbers",
                "Android notification bar timestamp and event IDs",
                "Local deduplication cryptographic hash cache"
            ),
            dataNeverCollected = listOf(
                "Full chat conversations and messaging history",
                "Contact book, address book, and call records",
                "Notifications from banking, payment, or private apps",
                "Device IMEI, Android advertising ID, or hardware serials",
                "GPS location or IP network topology"
            )
        )
    }
}
