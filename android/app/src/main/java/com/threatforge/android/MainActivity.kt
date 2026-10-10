package com.threatforge.android

import android.content.ComponentName
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
import com.threatforge.android.service.ThreatForgeNotificationListenerService
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
    val pipeline = ThreatForgeApplication.pipeline

    val alerts by pipeline.alerts.collectAsState()
    val ignoredCount by pipeline.ignoredCount.collectAsState()
    val dedupedCount by pipeline.dedupedCount.collectAsState()
    val isServiceConnected by ThreatForgeNotificationListenerService.isConnected.collectAsState()

    var isPermissionGranted by remember { mutableStateOf(isNotificationAccessGranted(context)) }
    var customInput by remember { mutableStateOf("") }
    var selectedPackage by remember { mutableStateOf(PackageFilter.PACKAGE_WHATSAPP) }

    // Periodically refresh permission check when screen is visible
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
                            "Screening Engine",
                            fontSize = 13.sp,
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
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item { Spacer(modifier = Modifier.height(4.dp)) }

            // 1. Permission & Privacy Card
            item {
                PermissionStatusCard(
                    isGranted = isPermissionGranted,
                    isConnected = isServiceConnected,
                    onOpenSettings = {
                        openNotificationSettings(context)
                        isPermissionGranted = isNotificationAccessGranted(context)
                    }
                )
            }

            // 2. Metrics & Telemetry Bar
            item {
                MetricsBar(
                    alertCount = alerts.size,
                    dedupedCount = dedupedCount,
                    ignoredCount = ignoredCount,
                    onClear = { pipeline.clearAlerts() }
                )
            }

            // 3. Synthetic Test Suite Card
            item {
                SyntheticTestCard(
                    onRunSuspiciousTest = {
                        pipeline.processEvent(
                            NotificationEvent(
                                packageName = PackageFilter.PACKAGE_WHATSAPP,
                                title = "WhatsApp Security Alert",
                                text = "URGENT: Your example.com account will be suspended. Share your OTP immediately to prevent the suspension.",
                                isSynthetic = true
                            )
                        )
                    },
                    onRunBenignTest = {
                        pipeline.processEvent(
                            NotificationEvent(
                                packageName = PackageFilter.PACKAGE_WHATSAPP,
                                title = "Appointment Reminder",
                                text = "Your appointment is confirmed for tomorrow at 10 AM. Thank you.",
                                isSynthetic = true
                            )
                        )
                    },
                    onRunUnrelatedPackageTest = {
                        pipeline.processEvent(
                            NotificationEvent(
                                packageName = "com.google.android.gm",
                                title = "Newsletter",
                                text = "URGENT: Don't miss out on our deals",
                                isSynthetic = true
                            )
                        )
                    },
                    onRunMalformedTest = {
                        pipeline.processEvent(
                            NotificationEvent(
                                packageName = PackageFilter.PACKAGE_WHATSAPP,
                                title = "",
                                text = "",
                                isSynthetic = true
                            )
                        )
                    },
                    onRunDuplicateTest = {
                        val duplicateSample = NotificationEvent(
                            packageName = PackageFilter.PACKAGE_TELEGRAM,
                            title = "Telegram Support",
                            text = "URGENT: Your account will be blocked. Share your OTP to verify.",
                            isSynthetic = true
                        )
                        pipeline.processEvent(duplicateSample)
                        pipeline.processEvent(duplicateSample)
                    },
                    customInput = customInput,
                    onCustomInputChange = { customInput = it },
                    selectedPackage = selectedPackage,
                    onPackageSelected = { selectedPackage = it },
                    onSubmitCustom = {
                        if (customInput.isNotBlank()) {
                            pipeline.processEvent(
                                NotificationEvent(
                                    packageName = selectedPackage,
                                    title = "Message Preview",
                                    text = customInput,
                                    isSynthetic = true
                                )
                            )
                            customInput = ""
                        }
                    }
                )
            }

            // 4. Alerts Stream Header
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "LIVE WARNING STREAM (${alerts.size})",
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp,
                        letterSpacing = 1.sp,
                        color = Color(0xFF94A3B8)
                    )
                }
            }

            // Empty State
            if (alerts.isEmpty()) {
                item {
                    EmptyAlertsCard()
                }
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
fun PermissionStatusCard(
    isGranted: Boolean,
    isConnected: Boolean,
    onOpenSettings: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF131D31)),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "NOTIFICATION MONITORING",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF38BDF8),
                    letterSpacing = 1.sp
                )
                Surface(
                    shape = RoundedCornerShape(4.dp),
                    color = if (isConnected || isGranted) Color(0x2010B981) else Color(0x20F59E0B)
                ) {
                    Text(
                        if (isConnected) "CONNECTED" else if (isGranted) "AUTHORIZED" else "ACCESS REQUIRED",
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (isConnected || isGranted) Color(0xFF10B981) else Color(0xFFF59E0B)
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                "THREATFORGE screens permitted messaging apps (WhatsApp and Telegram) directly on your device. Only notification text from permitted apps is processed locally. Unrelated notifications are instantly discarded.",
                fontSize = 12.sp,
                color = Color(0xFFCBD5E1),
                lineHeight = 17.sp
            )

            if (!isGranted) {
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = onOpenSettings,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Grant Notification Listener Permission", fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                }
            }
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
            Text("Clear", fontSize = 12.sp, color = Color(0xFF94A3B8))
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
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(value, fontSize = 15.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF8FAFC))
            Text(label, fontSize = 11.sp, color = Color(0xFF94A3B8))
        }
    }
}

@Composable
fun SyntheticTestCard(
    onRunSuspiciousTest: () -> Unit,
    onRunBenignTest: () -> Unit,
    onRunUnrelatedPackageTest: () -> Unit,
    onRunMalformedTest: () -> Unit,
    onRunDuplicateTest: () -> Unit,
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
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "SYNTHETIC VERIFICATION HARNESS",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFA855F7),
                    letterSpacing = 1.sp
                )
            }
            Text(
                "Simulates notification events through the exact same downstream processing pipeline.",
                fontSize = 11.sp,
                color = Color(0xFF94A3B8)
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Presets grid
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = onRunSuspiciousTest,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("1. Scam Test", fontSize = 12.sp)
                }
                Button(
                    onClick = onRunBenignTest,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF059669)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("2. Benign Test", fontSize = 12.sp)
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onRunUnrelatedPackageTest,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("3. Filter Test", fontSize = 11.sp, color = Color(0xFFE2E8F0))
                }
                OutlinedButton(
                    onClick = onRunMalformedTest,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("4. Empty Test", fontSize = 11.sp, color = Color(0xFFE2E8F0))
                }
                OutlinedButton(
                    onClick = onRunDuplicateTest,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text("5. Dedup Test", fontSize = 11.sp, color = Color(0xFFE2E8F0))
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Custom input
            OutlinedTextField(
                value = customInput,
                onValueChange = onCustomInputChange,
                placeholder = { Text("Or enter custom notification message to test...", fontSize = 12.sp) },
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
                    Text("WhatsApp", fontSize = 12.sp, color = Color(0xFFCBD5E1))
                    Spacer(modifier = Modifier.width(8.dp))
                    RadioButton(
                        selected = selectedPackage == PackageFilter.PACKAGE_TELEGRAM,
                        onClick = { onPackageSelected(PackageFilter.PACKAGE_TELEGRAM) }
                    )
                    Text("Telegram", fontSize = 12.sp, color = Color(0xFFCBD5E1))
                }

                Button(
                    onClick = onSubmitCustom,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF38BDF8)),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Analyze", fontSize = 12.sp, color = Color(0xFF0F172A), fontWeight = FontWeight.Bold)
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
        AnalysisSource.BACKEND_ANALYSIS -> "Backend API analysis"
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
        Column(modifier = Modifier.padding(16.dp)) {
            // Header Row: Level + Score + Synthetic Badge
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
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            color = levelColor,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
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
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFFD8B4FE)
                            )
                        }
                    }
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(formattedTime, fontSize = 11.sp, color = Color(0xFF64748B))
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Package / Origin info
            alert.packageName?.let { pkg ->
                Text(
                    text = "App: ${pkg.substringAfterLast('.')}",
                    fontSize = 11.sp,
                    color = Color(0xFF94A3B8),
                    fontFamily = FontFamily.Monospace
                )
                Spacer(modifier = Modifier.height(6.dp))
            }

            // Reasons
            Text(
                "Triggered Indicators & Explainable Reasons:",
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color(0xFFE2E8F0)
            )
            alert.reasons.forEach { reason ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 2.dp)
                ) {
                    Text("• ", color = levelColor, fontSize = 12.sp)
                    Text(reason, fontSize = 12.sp, color = Color(0xFFCBD5E1))
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Safe Action Box
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(8.dp),
                color = Color(0xFF1E293B)
            ) {
                Column(modifier = Modifier.padding(10.dp)) {
                    Text(
                        "SAFE RECOMMENDED ACTION",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF38BDF8),
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        alert.safeAction,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        color = Color(0xFFF1F5F9)
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Footer: Analysis Source
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    "Source: $sourceLabel",
                    fontSize = 11.sp,
                    color = Color(0xFF64748B),
                    fontStyle = androidx.compose.ui.text.font.FontStyle.Italic
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
                fontSize = 14.sp,
                color = Color(0xFF94A3B8)
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "Trigger a test case above or send a message in WhatsApp/Telegram to screen.",
                fontSize = 12.sp,
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
