package com.threatforge.android

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import com.threatforge.android.filter.PackageFilter
import com.threatforge.android.model.AnalysisSource
import com.threatforge.android.model.NotificationEvent
import com.threatforge.android.model.RiskAnalysisResult
import com.threatforge.android.model.RiskLevel
import com.threatforge.android.network.ThreatForgeApiClient
import com.threatforge.android.service.ThreatForgeNotificationListenerService
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ThreatForgeTheme {
                ThreatForgeApp()
            }
        }
    }
}

fun isNotificationAccessGranted(context: Context): Boolean {
    val enabledPackages = NotificationManagerCompat.getEnabledListenerPackages(context)
    return enabledPackages.contains(context.packageName)
}

fun openNotificationSettings(context: Context) {
    val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    context.startActivity(intent)
}

@Composable
fun ThreatForgeTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Color(0xFF38BDF8),
            onPrimary = Color(0xFF0F172A),
            background = Color(0xFF0B0F19),
            surface = Color(0xFF111827),
            onSurface = Color(0xFFF3F4F6),
            error = Color(0xFFEF4444)
        ),
        content = content
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreatForgeApp() {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val pipeline = ThreatForgeApplication.pipeline

    val alerts by pipeline.alerts.collectAsState()
    val ignoredCount by pipeline.ignoredCount.collectAsState()
    val dedupedCount by pipeline.dedupedCount.collectAsState()
    val isLoading by pipeline.isLoading.collectAsState()
    val statusMessage by pipeline.statusMessage.collectAsState()
    val isServiceConnected by ThreatForgeNotificationListenerService.isConnected.collectAsState()

    var isPermissionGranted by remember { mutableStateOf(isNotificationAccessGranted(context)) }
    var cloudAnalysisEnabled by remember { mutableStateOf(pipeline.cloudAnalysisEnabled.value) }
    var userConsentGranted by remember { mutableStateOf(pipeline.userConsentGranted.value) }
    var currentBaseUrl by remember { mutableStateOf(pipeline.apiClient.baseUrl) }

    var customInput by remember { mutableStateOf("") }
    var selectedPackage by remember { mutableStateOf(PackageFilter.PACKAGE_WHATSAPP) }

    DisposableEffect(Unit) {
        isPermissionGranted = isNotificationAccessGranted(context)
        onDispose { }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(12.dp)
                                .clip(CircleShape)
                                .background(if (isServiceConnected || isPermissionGranted) Color(0xFF10B981) else Color(0xFFF59E0B))
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "THREATFORGE",
                            fontWeight = FontWeight.Bold,
                            fontSize = 18.sp,
                            letterSpacing = 1.sp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            if (cloudAnalysisEnabled && userConsentGranted) "Cloud + Local" else "Local Only",
                            fontSize = 12.sp,
                            color = Color(0xFF94A3B8)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0F172A),
                    titleContentColor = Color(0xFFF8FAFC)
                )
            )
        },
        containerColor = Color(0xFF0B0F19)
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            item { Spacer(modifier = Modifier.height(2.dp)) }

            // 1. Mandatory Privacy & Cloud Consent Panel
            item {
                PrivacyAndConsentCard(
                    isPermissionGranted = isPermissionGranted,
                    isConnected = isServiceConnected,
                    cloudEnabled = cloudAnalysisEnabled,
                    onCloudToggled = {
                        cloudAnalysisEnabled = it
                        pipeline.cloudAnalysisEnabled.value = it
                    },
                    consentGranted = userConsentGranted,
                    onConsentToggled = {
                        userConsentGranted = it
                        pipeline.userConsentGranted.value = it
                    },
                    baseUrl = currentBaseUrl,
                    onBaseUrlChanged = {
                        currentBaseUrl = it
                        pipeline.apiClient.baseUrl = it
                    },
                    onOpenSettings = {
                        openNotificationSettings(context)
                        isPermissionGranted = isNotificationAccessGranted(context)
                    }
                )
            }

            // 2. Loading & Status Banner
            if (isLoading || statusMessage != null) {
                item {
                    StatusBanner(isLoading = isLoading, message = statusMessage)
                }
            }

            // 3. Metrics Bar
            item {
                MetricsBar(
                    alertCount = alerts.size,
                    dedupedCount = dedupedCount,
                    ignoredCount = ignoredCount,
                    onClear = { pipeline.clearAlerts() }
                )
            }

            // 4. Synthetic Verification Harness (Task D: 4 sample categories)
            item {
                SyntheticTestCard(
                    isLoading = isLoading,
                    onRunScamTest = {
                        coroutineScope.launch {
                            pipeline.processEvent(
                                NotificationEvent(
                                    packageName = PackageFilter.PACKAGE_WHATSAPP,
                                    title = "WhatsApp Security Alert",
                                    text = "URGENT: Your example.com account will be suspended. Share your OTP immediately to prevent suspension.",
                                    isSynthetic = true
                                )
                            )
                        }
                    },
                    onRunBenignTest = {
                        coroutineScope.launch {
                            pipeline.processEvent(
                                NotificationEvent(
                                    packageName = PackageFilter.PACKAGE_WHATSAPP,
                                    title = "Appointment Reminder",
                                    text = "Your appointment is confirmed for tomorrow at 10 AM. Thank you.",
                                    isSynthetic = true
                                )
                            )
                        }
                    },
                    onRunUrlTest = {
                        coroutineScope.launch {
                            pipeline.processEvent(
                                NotificationEvent(
                                    packageName = PackageFilter.PACKAGE_TELEGRAM,
                                    title = "Security Verification",
                                    text = "Please check your account status at https://example.com/account-review",
                                    isSynthetic = true
                                )
                            )
                        }
                    },
                    onRunFilterTest = {
                        coroutineScope.launch {
                            pipeline.processEvent(
                                NotificationEvent(
                                    packageName = "com.google.android.gm",
                                    title = "Newsletter Notice",
                                    text = "URGENT: Verify your account now or it will be suspended",
                                    isSynthetic = true
                                )
                            )
                        }
                    },
                    onRunDedupTest = {
                        coroutineScope.launch {
                            val event = NotificationEvent(
                                packageName = PackageFilter.PACKAGE_WHATSAPP,
                                title = "Urgent Notice",
                                text = "Your account will be suspended. Share your OTP immediately.",
                                isSynthetic = true
                            )
                            pipeline.processEvent(event)
                            pipeline.processEvent(event)
                        }
                    },
                    customInput = customInput,
                    onCustomInputChange = { customInput = it },
                    selectedPackage = selectedPackage,
                    onPackageSelected = { selectedPackage = it },
                    onSubmitCustom = {
                        if (customInput.isNotBlank()) {
                            val textToSubmit = customInput
                            customInput = ""
                            coroutineScope.launch {
                                pipeline.processEvent(
                                    NotificationEvent(
                                        packageName = selectedPackage,
                                        title = "Message Input",
                                        text = textToSubmit,
                                        isSynthetic = true
                                    )
                                )
                            }
                        }
                    }
                )
            }

            // 5. Alerts Stream Header
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "LIVE WARNING STREAM (${alerts.size})",
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                        letterSpacing = 1.sp,
                        color = Color(0xFF94A3B8)
                    )
                }
            }

            // Alerts list or empty state
            if (alerts.isEmpty()) {
                item { EmptyAlertsCard() }
            } else {
                items(alerts, key = { it.eventKey + it.timestamp }) { alert ->
                    WarningCard(alert)
                }
            }

            item { Spacer(modifier = Modifier.height(24.dp)) }
        }
    }
}

@Composable
fun PrivacyAndConsentCard(
    isPermissionGranted: Boolean,
    isConnected: Boolean,
    cloudEnabled: Boolean,
    onCloudToggled: (Boolean) -> Unit,
    consentGranted: Boolean,
    onConsentToggled: (Boolean) -> Unit,
    baseUrl: String,
    onBaseUrlChanged: (String) -> Unit,
    onOpenSettings: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF131D31)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "PRIVACY & CLOUD CONSENT",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF38BDF8),
                    letterSpacing = 1.sp
                )
                Surface(
                    shape = RoundedCornerShape(4.dp),
                    color = if (isConnected || isPermissionGranted) Color(0x2010B981) else Color(0x20F59E0B)
                ) {
                    Text(
                        if (isConnected) "LISTENER CONNECTED" else if (isPermissionGranted) "AUTHORIZED" else "ACCESS REQUIRED",
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (isConnected || isPermissionGranted) Color(0xFF10B981) else Color(0xFFF59E0B)
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Mandatory Privacy Notice Quote
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = Color(0xFF0F172A),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = "Android notification access is broad at the operating-system level. THREATFORGE filters notification events inside the app and processes only supported sources: WhatsApp (com.whatsapp) and Telegram (org.telegram.messenger). Notification previews may be incomplete, so the app may not receive the full message. Automated risk results are assessments, not proof of malicious intent or guilt.",
                    fontSize = 11.sp,
                    color = Color(0xFFCBD5E1),
                    lineHeight = 16.sp,
                    modifier = Modifier.padding(10.dp)
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Cloud Analysis Toggle
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Enable Cloud Analysis (POST /api/analyze)", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = Color.White)
                    Text("Queries backend ML & threat intelligence", fontSize = 11.sp, color = Color(0xFF94A3B8))
                }
                Switch(checked = cloudEnabled, onCheckedChange = onCloudToggled)
            }

            // User Consent Checkbox
            if (cloudEnabled) {
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Checkbox(checked = consentGranted, onCheckedChange = onConsentToggled)
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        "I consent to sending eligible notification text to the configured backend for threat analysis.",
                        fontSize = 11.sp,
                        color = if (consentGranted) Color(0xFF38BDF8) else Color(0xFFFCA5A5)
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                // Endpoint configuration
                Text("Backend Host: $baseUrl", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = Color(0xFF94A3B8))
                Spacer(modifier = Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(
                        selected = baseUrl == ThreatForgeApiClient.USB_REVERSE_BASE_URL,
                        onClick = { onBaseUrlChanged(ThreatForgeApiClient.USB_REVERSE_BASE_URL) },
                        label = { Text("USB/ADB", fontSize = 10.sp) }
                    )
                    FilterChip(
                        selected = baseUrl == ThreatForgeApiClient.LAN_WIFI_BASE_URL,
                        onClick = { onBaseUrlChanged(ThreatForgeApiClient.LAN_WIFI_BASE_URL) },
                        label = { Text("LAN Wi-Fi", fontSize = 10.sp) }
                    )
                    FilterChip(
                        selected = baseUrl == ThreatForgeApiClient.EMULATOR_BASE_URL,
                        onClick = { onBaseUrlChanged(ThreatForgeApiClient.EMULATOR_BASE_URL) },
                        label = { Text("Emulator", fontSize = 10.sp) }
                    )
                }
            }

            if (!isPermissionGranted) {
                Spacer(modifier = Modifier.height(8.dp))
                Button(
                    onClick = onOpenSettings,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Grant Notification Listener Permission", fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
fun StatusBanner(isLoading: Boolean, message: String?) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        color = if (isLoading) Color(0x3038BDF8) else Color(0x20F59E0B)
    ) {
        Row(
            modifier = Modifier.padding(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                    color = Color(0xFF38BDF8)
                )
                Spacer(modifier = Modifier.width(10.dp))
            }
            Text(
                text = message ?: "Processing...",
                fontSize = 11.sp,
                color = if (isLoading) Color(0xFFE0F2FE) else Color(0xFFFDE68A),
                lineHeight = 15.sp
            )
        }
    }
}

@Composable
fun MetricsBar(
    alertCount: Int,
    dedupedCount: Int,
    ignoredCount: Int,
    onClear: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        MetricItem(label = "Alerts", value = alertCount.toString(), modifier = Modifier.weight(1f))
        MetricItem(label = "Deduped", value = dedupedCount.toString(), modifier = Modifier.weight(1f))
        MetricItem(label = "Discarded", value = ignoredCount.toString(), modifier = Modifier.weight(1f))
        OutlinedButton(
            onClick = onClear,
            shape = RoundedCornerShape(8.dp),
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
        ) {
            Text("Clear", fontSize = 11.sp, color = Color(0xFF94A3B8))
        }
    }
}

@Composable
fun MetricItem(label: String, value: String, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(8.dp),
        color = Color(0xFF1E293B)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(value, fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF8FAFC))
            Text(label, fontSize = 10.sp, color = Color(0xFF94A3B8))
        }
    }
}

@Composable
fun SyntheticTestCard(
    isLoading: Boolean,
    onRunScamTest: () -> Unit,
    onRunBenignTest: () -> Unit,
    onRunUrlTest: () -> Unit,
    onRunFilterTest: () -> Unit,
    onRunDedupTest: () -> Unit,
    customInput: String,
    onCustomInputChange: (String) -> Unit,
    selectedPackage: String,
    onPackageSelected: (String) -> Unit,
    onSubmitCustom: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF161F30)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                "SYNTHETIC VERIFICATION HARNESS",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFFA855F7),
                letterSpacing = 1.sp
            )
            Text(
                "Dispatches synthetic events into the exact same pipeline and API client.",
                fontSize = 11.sp,
                color = Color(0xFF94A3B8)
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Primary Test Row
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Button(
                    onClick = onRunScamTest,
                    enabled = !isLoading,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("1. Scam Test", fontSize = 11.sp)
                }
                Button(
                    onClick = onRunBenignTest,
                    enabled = !isLoading,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF059669)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("2. Benign Test", fontSize = 11.sp)
                }
                Button(
                    onClick = onRunUrlTest,
                    enabled = !isLoading,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("3. URL Test", fontSize = 11.sp)
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            // Secondary Filter & Dedup tests
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedButton(
                    onClick = onRunFilterTest,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Filter Test", fontSize = 10.sp, color = Color(0xFFCBD5E1))
                }
                OutlinedButton(
                    onClick = onRunDedupTest,
                    enabled = !isLoading,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Dedup Test", fontSize = 10.sp, color = Color(0xFFCBD5E1))
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Custom input
            OutlinedTextField(
                value = customInput,
                onValueChange = onCustomInputChange,
                placeholder = { Text("Or type custom notification text to screen...", fontSize = 11.sp) },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(8.dp),
                maxLines = 3
            )

            Spacer(modifier = Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(
                        selected = selectedPackage == PackageFilter.PACKAGE_WHATSAPP,
                        onClick = { onPackageSelected(PackageFilter.PACKAGE_WHATSAPP) }
                    )
                    Text("WhatsApp", fontSize = 11.sp, color = Color(0xFFCBD5E1))
                    Spacer(modifier = Modifier.width(6.dp))
                    RadioButton(
                        selected = selectedPackage == PackageFilter.PACKAGE_TELEGRAM,
                        onClick = { onPackageSelected(PackageFilter.PACKAGE_TELEGRAM) }
                    )
                    Text("Telegram", fontSize = 11.sp, color = Color(0xFFCBD5E1))
                }

                Button(
                    onClick = onSubmitCustom,
                    enabled = !isLoading,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF38BDF8)),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Screen", fontSize = 11.sp, color = Color(0xFF0F172A), fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
fun WarningCard(alert: RiskAnalysisResult) {
    val levelColor = when (alert.level) {
        RiskLevel.CRITICAL -> Color(0xFFEF4444)
        RiskLevel.HIGH -> Color(0xFFF97316)
        RiskLevel.MEDIUM -> Color(0xFFFBBF24)
        RiskLevel.LOW -> Color(0xFF10B981)
    }

    val sourceLabel = when (alert.analysisSource) {
        AnalysisSource.LOCAL_HEURISTIC -> "Local heuristic analysis"
        AnalysisSource.BACKEND_ANALYSIS -> "Backend API analysis (POST /api/analyze)"
    }

    val formattedTime = remember(alert.timestamp) {
        SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(alert.timestamp))
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, levelColor.copy(alpha = 0.5f), RoundedCornerShape(12.dp)),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF131B2B)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            // Header Row: Level + Score + Synthetic Badge + Time
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        shape = RoundedCornerShape(4.dp),
                        color = levelColor.copy(alpha = 0.2f)
                    ) {
                        Text(
                            text = alert.level.name,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                            color = levelColor,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp
                        )
                    }

                    alert.score?.let { score ->
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Score: $score/100",
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp,
                            color = Color(0xFFF8FAFC)
                        )
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (alert.isSynthetic) {
                        Surface(
                            shape = RoundedCornerShape(4.dp),
                            color = Color(0x30A855F7)
                        ) {
                            Text(
                                "SYNTHETIC TEST",
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFFD8B4FE)
                            )
                        }
                    }
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(formattedTime, fontSize = 10.sp, color = Color(0xFF64748B))
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Origin / Package
            alert.packageName?.let { pkg ->
                Text(
                    text = "App Source: ${pkg.substringAfterLast('.')}",
                    fontSize = 11.sp,
                    color = Color(0xFF94A3B8),
                    fontFamily = FontFamily.Monospace
                )
                Spacer(modifier = Modifier.height(4.dp))
            }

            // Summary if available
            alert.summary?.let { summary ->
                Text(
                    text = summary,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color(0xFFE2E8F0)
                )
                Spacer(modifier = Modifier.height(6.dp))
            }

            // Reasons / Breakdown Factors
            Text(
                "Triggered Indicators & Explainable Reasons:",
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color(0xFFCBD5E1)
            )
            alert.reasons.forEach { reason ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 2.dp)
                ) {
                    Text("• ", color = levelColor, fontSize = 11.sp)
                    Text(reason, fontSize = 11.sp, color = Color(0xFFCBD5E1))
                }
            }

            // Extracted Indicators (e.g. URLs)
            if (alert.indicators.isNotEmpty()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    "Extracted Indicators: ${alert.indicators.joinToString(", ")}",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color(0xFF38BDF8)
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Safe Action Box
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(8.dp),
                color = Color(0xFF1E293B)
            ) {
                Column(modifier = Modifier.padding(8.dp)) {
                    Text(
                        "SAFE RECOMMENDED ACTION",
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF38BDF8),
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.height(3.dp))
                    Text(
                        alert.safeAction,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Medium,
                        color = Color(0xFFF1F5F9)
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Footer: Model version, analysis mode & source
            Column {
                Text(
                    "Source: $sourceLabel",
                    fontSize = 10.sp,
                    color = Color(0xFF64748B),
                    fontStyle = androidx.compose.ui.text.font.FontStyle.Italic
                )
                if (alert.analysisSource == AnalysisSource.BACKEND_ANALYSIS) {
                    Text(
                        "Model: ${alert.modelVersion ?: "rules+ml"} | Mode: ${alert.analysisMode ?: "cloud"}${if (alert.uncertaintyRange != null) " | Uncertainty: ${alert.uncertaintyRange}" else ""}",
                        fontSize = 10.sp,
                        color = Color(0xFF64748B)
                    )
                }
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    "Automated risk scores are assessments, not proof of wrongdoing.",
                    fontSize = 9.sp,
                    color = Color(0xFF475569)
                )
            }
        }
    }
}

@Composable
fun EmptyAlertsCard() {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        color = Color(0xFF111827)
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                "No Active Warnings",
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
                color = Color(0xFF94A3B8)
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "Select a synthetic test above to verify cloud & local screening.",
                fontSize = 11.sp,
                color = Color(0xFF64748B),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )
        }
    }
}

@androidx.compose.ui.tooling.preview.Preview(showBackground = true, showSystemUi = true)
@Composable
fun ThreatForgeAppPreview() {
    ThreatForgeTheme {
        ThreatForgeApp()
    }
}
