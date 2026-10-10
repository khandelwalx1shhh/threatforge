package com.threatforge.android.filter

object PackageFilter {

    const val PACKAGE_WHATSAPP = "com.whatsapp"
    const val PACKAGE_TELEGRAM = "org.telegram.messenger"

    val PERMITTED_PACKAGES = setOf(
        PACKAGE_WHATSAPP,
        PACKAGE_TELEGRAM
    )

    /**
     * Determines whether the originating package name is permitted for screening.
     * Only WhatsApp and Telegram are permitted. All others are strictly discarded.
     */
    fun isPermitted(packageName: String?): Boolean {
        if (packageName.isNullOrBlank()) return false
        return PERMITTED_PACKAGES.contains(packageName.trim())
    }

    /**
     * Sanitizes message text, rejecting null or blank notification bodies.
     */
    fun hasUsableContent(title: String?, text: String?): Boolean {
        val combined = "${title.orEmpty()} ${text.orEmpty()}".trim()
        return combined.isNotEmpty()
    }
}
