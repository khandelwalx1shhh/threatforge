package com.threatforge.android.dedup

import java.security.MessageDigest

class EventDeduplicator(private val maxEntries: Int = 100) {

    private val seenEventKeys = object : LinkedHashMap<String, Long>(maxEntries, 0.75f, true) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Long>?): Boolean {
            return size > maxEntries
        }
    }

    private val lock = Any()

    /**
     * Generates a stable composite key for a notification event.
     */
    fun generateKey(packageName: String, title: String, text: String): String {
        val raw = "${packageName.trim()}|${title.trim()}|${text.trim()}"
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val hashBytes = digest.digest(raw.toByteArray(Charsets.UTF_8))
            hashBytes.joinToString("") { "%02x".format(it) }
        } catch (_: Exception) {
            raw.hashCode().toString()
        }
    }

    /**
     * Checks if the event has been seen recently. If not seen, records it and returns false.
     * If seen, returns true (is duplicate).
     */
    fun isDuplicateAndRecord(eventKey: String): Boolean {
        synchronized(lock) {
            if (seenEventKeys.containsKey(eventKey)) {
                return true
            }
            seenEventKeys[eventKey] = System.currentTimeMillis()
            return false
        }
    }

    /**
     * Clears cached keys (useful for test runs).
     */
    fun clear() {
        synchronized(lock) {
            seenEventKeys.clear()
        }
    }

    /**
     * Returns the count of tracked events.
     */
    fun size(): Int {
        synchronized(lock) {
            return seenEventKeys.size
        }
    }
}
