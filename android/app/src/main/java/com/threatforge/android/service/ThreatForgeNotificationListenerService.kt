package com.threatforge.android.service

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.threatforge.android.ThreatForgeApplication
import com.threatforge.android.filter.PackageFilter
import com.threatforge.android.model.NotificationEvent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class ThreatForgeNotificationListenerService : NotificationListenerService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onListenerConnected() {
        super.onListenerConnected()
        _isConnected.value = true
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        _isConnected.value = false
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val packageName = sbn.packageName ?: return

        // Strict package filtering: only proceed for approved packages
        if (!PackageFilter.isPermitted(packageName)) {
            return
        }

        val notification = sbn.notification ?: return
        val extras = notification.extras ?: return

        // Read notification title and text only
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
            ?: extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
            ?: ""

        // Handle missing, empty, or malformed content
        if (!PackageFilter.hasUsableContent(title, text)) {
            return
        }

        val event = NotificationEvent(
            packageName = packageName,
            title = title,
            text = text,
            timestamp = sbn.postTime,
            isSynthetic = false
        )

        // Route to shared downstream processing pipeline asynchronously
        serviceScope.launch {
            ThreatForgeApplication.pipeline.processEvent(event)
        }
    }

    companion object {
        private val _isConnected = MutableStateFlow(false)
        val isConnected: StateFlow<Boolean> = _isConnected.asStateFlow()
    }
}
