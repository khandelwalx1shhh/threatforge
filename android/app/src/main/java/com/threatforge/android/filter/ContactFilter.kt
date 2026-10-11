package com.threatforge.android.filter

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.ContactsContract
import androidx.core.content.ContextCompat

object ContactFilter {

    /**
     * Determines whether the sender is an unknown/unsaved contact.
     * Per requirement:
     * - Only screen messages from unknown senders.
     * - Discard / ignore messages from saved contacts / saved users.
     */
    fun isUnknownSender(context: Context, senderTitle: String?): Boolean {
        if (senderTitle.isNullOrBlank()) return false

        val title = senderTitle.trim()

        // 1. If READ_CONTACTS permission is available, perform phone & contact lookup
        if (ContextCompat.checkSelfPermission(context, android.Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED) {
            try {
                // Check if title matches a contact by phone number
                val phoneUri = Uri.withAppendedPath(ContactsContract.PhoneLookup.CONTENT_FILTER_URI, Uri.encode(title))
                val phoneProjection = arrayOf(ContactsContract.PhoneLookup._ID)
                context.contentResolver.query(phoneUri, phoneProjection, null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        // Match found in phone contacts: SAVED CONTACT!
                        return false
                    }
                }

                // Check if title matches a contact by display name
                val nameUri = ContactsContract.Contacts.CONTENT_URI
                val selection = "${ContactsContract.Contacts.DISPLAY_NAME} = ? COLLATE NOCASE"
                context.contentResolver.query(nameUri, arrayOf(ContactsContract.Contacts._ID), selection, arrayOf(title), null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        // Match found in display names: SAVED CONTACT!
                        return false
                    }
                }

                // If not found in Contacts book, this sender is UNKNOWN!
                return true
            } catch (e: Exception) {
                // Fall back to heuristic check on lookup exception
            }
        }

        // 2. Heuristic check (works even when READ_CONTACTS is not yet granted):
        // Unsaved senders on WhatsApp and Telegram appear as phone numbers:
        // Examples: "+91 98765 43210", "+1 (555) 234-5678", "~Alex (+91 98765 43210)", "9876543210"
        val digitCount = title.count { it.isDigit() }
        val startsWithPlus = title.startsWith("+")
        val containsTilde = title.contains("~")

        if (startsWithPlus || containsTilde || digitCount >= 7) {
            return true
        }

        // If it's a typical name (e.g. "Mom", "Rahul", "Alice") and no numbers, treat as saved contact
        return false
    }
}
