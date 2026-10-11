package com.threatforge.android

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import androidx.core.content.ContextCompat
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
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

// ─── Color Palette ──────────────────────────────────────────────────────────
object TFColors {
    val Background = Color(0xFF080C14)
    val Surface = Color(0xFF0E1420)
    val SurfaceLight = Color(0xFF141C2C)
    val CardBg = Color(0xFF111827)
    val CardBorder = Color(0xFF1E293B)
    val AccentCyan = Color(0xFF06D6A0)
    val AccentBlue = Color(0xFF38BDF8)
    val AccentPurple = Color(0xFFA855F7)
    val AccentAmber = Color(0xFFFBBF24)
    val TextPrimary = Color(0xFFF1F5F9)
    val TextSecondary = Color(0xFF94A3B8)
    val TextMuted = Color(0xFF64748B)
    val RiskCritical = Color(0xFFEF4444)
    val RiskHigh = Color(0xFFF97316)
    val RiskMedium = Color(0xFFFBBF24)
    val RiskLow = Color(0xFF10B981)
    val GradientStart = Color(0xFF06D6A0)
    val GradientEnd = Color(0xFF38BDF8)
}

class MainActivity : ComponentActivity() {
    companion object {
        val resumeTrigger = kotlinx.coroutines.flow.MutableStateFlow(0L)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ThreatForgeTheme {
                ThreatForgeApp()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        resumeTrigger.value = System.currentTimeMillis()
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

fun isSystemPermissionsGranted(context: Context): Boolean {
    val contactsGranted = ContextCompat.checkSelfPermission(
        context,
        android.Manifest.permission.READ_CONTACTS
    ) == PackageManager.PERMISSION_GRANTED

    val notificationsGranted = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
        ContextCompat.checkSelfPermission(
            context,
            android.Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
    } else {
        true
    }
    return contactsGranted && notificationsGranted
}

fun openAppDetailsSettings(context: Context) {
    try {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.fromParts("package", context.packageName, null)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
    } catch (_: Exception) {
        val fallbackIntent = Intent(Settings.ACTION_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(fallbackIntent)
    }
}

@Composable
fun ThreatForgeTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = TFColors.AccentCyan,
            onPrimary = TFColors.Background,
            background = TFColors.Background,
            surface = TFColors.Surface,
            onSurface = TFColors.TextPrimary,
            error = TFColors.RiskCritical
        ),
        content = content
    )
}

// ─── Main App ──────────────────────────────────────────────────────────────
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

    val storageManager = pipeline.storageManager
    var isPermissionGranted by remember { mutableStateOf(isNotificationAccessGranted(context)) }
    var areSystemPermissionsGranted by remember { mutableStateOf(isSystemPermissionsGranted(context)) }
    var showFirstTimeSetup by remember {
        mutableStateOf(storageManager?.isFirstLaunch() ?: false)
    }
    var notificationConsentGranted by remember {
        mutableStateOf(storageManager?.isNotificationConsentGranted() ?: false)
    }
    var cloudAnalysisEnabled by remember { mutableStateOf(pipeline.cloudAnalysisEnabled.value) }
    var userConsentGranted by remember { mutableStateOf(pipeline.userConsentGranted.value) }
    var localOnlyMode by remember { mutableStateOf(pipeline.localOnlyMode.value) }
    var retentionDays by remember { mutableIntStateOf(pipeline.retentionDays.value) }
    var currentBaseUrl by remember { mutableStateOf(pipeline.apiClient.baseUrl) }

    var customInput by remember { mutableStateOf("") }
    var selectedPackage by remember { mutableStateOf(PackageFilter.PACKAGE_WHATSAPP) }

    var selectedTab by remember { mutableIntStateOf(0) }

    val resumeTimestamp by MainActivity.resumeTrigger.collectAsState()
    LaunchedEffect(resumeTimestamp) {
        isPermissionGranted = isNotificationAccessGranted(context)
        areSystemPermissionsGranted = isSystemPermissionsGranted(context)
    }

    val permissionLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        areSystemPermissionsGranted = isSystemPermissionsGranted(context)
        val allGranted = results.values.isNotEmpty() && results.values.all { it }
        if (!allGranted && !areSystemPermissionsGranted) {
            openAppDetailsSettings(context)
        }
    }

    LaunchedEffect(Unit) {
        com.threatforge.android.service.AlertNotificationHelper.ensureChannel(context)
    }

    DisposableEffect(Unit) {
        isPermissionGranted = isNotificationAccessGranted(context)
        areSystemPermissionsGranted = isSystemPermissionsGranted(context)
        onDispose { }
    }

    if (showFirstTimeSetup) {
        FirstTimeSetupDialog(
            isNotificationAccessGranted = isPermissionGranted,
            onOpenNotificationSettings = {
                openNotificationSettings(context)
                isPermissionGranted = isNotificationAccessGranted(context)
            },
            areSystemPermissionsGranted = areSystemPermissionsGranted,
            onRequestSystemPermissions = {
                val permissions = mutableListOf<String>()
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                    if (ContextCompat.checkSelfPermission(context, android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                        permissions.add(android.Manifest.permission.POST_NOTIFICATIONS)
                    }
                }
                if (ContextCompat.checkSelfPermission(context, android.Manifest.permission.READ_CONTACTS) != PackageManager.PERMISSION_GRANTED) {
                    permissions.add(android.Manifest.permission.READ_CONTACTS)
                }
                if (permissions.isNotEmpty()) {
                    permissionLauncher.launch(permissions.toTypedArray())
                } else {
                    areSystemPermissionsGranted = true
                }
            },
            onOpenAppSettings = {
                openAppDetailsSettings(context)
            },
            notificationConsentGranted = notificationConsentGranted,
            onNotificationConsentChanged = {
                notificationConsentGranted = it
                storageManager?.setNotificationConsentGranted(it)
            },
            onCompleteSetup = {
                storageManager?.setFirstLaunchCompleted(true)
                storageManager?.setNotificationConsentGranted(notificationConsentGranted)
                pipeline.setUserConsent(true)
                userConsentGranted = true
                showFirstTimeSetup = false
            }
        )
    }

    Scaffold(
        containerColor = TFColors.Background,
        bottomBar = {
            NavigationBar(
                containerColor = TFColors.Surface,
                contentColor = TFColors.TextPrimary,
                tonalElevation = 0.dp
            ) {
                BottomNavItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = Icons.Filled.Favorite,
                    label = "Shield"
                )
                BottomNavItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = Icons.Filled.Search,
                    label = "Scanner"
                )
                BottomNavItem(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    icon = Icons.Filled.Settings,
                    label = "Settings"
                )
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            when (selectedTab) {
                0 -> ShieldTab(
                    alerts = alerts,
                    alertCount = alerts.size,
                    dedupedCount = dedupedCount,
                    ignoredCount = ignoredCount,
                    isLoading = isLoading,
                    statusMessage = statusMessage,
                    isPermissionGranted = isPermissionGranted,
                    isServiceConnected = isServiceConnected,
                    cloudEnabled = cloudAnalysisEnabled,
                    userConsentGranted = userConsentGranted,
                    onClear = { pipeline.clearAlerts() },
                    onOpenSettings = {
                        openNotificationSettings(context)
                        isPermissionGranted = isNotificationAccessGranted(context)
                    }
                )
                1 -> ScannerTab(
                    isLoading = isLoading,
                    customInput = customInput,
                    onCustomInputChange = { customInput = it },
                    selectedPackage = selectedPackage,
                    onPackageSelected = { selectedPackage = it },
                    onSubmitCustom = {
                        if (customInput.isNotBlank()) {
                            val textToSubmit = customInput
                            customInput = ""
                            coroutineScope.launch {
                                val event = NotificationEvent(
                                    packageName = selectedPackage,
                                    title = "Unknown Sender",
                                    text = textToSubmit,
                                    isSynthetic = false
                                )
                                val res = pipeline.processEvent(event)
                                if (res != null) {
                                    com.threatforge.android.service.AlertNotificationHelper.sendThreatWarning(context, event.title, event.text, res)
                                }
                            }
                        }
                    }
                )
                2 -> SettingsTab(
                    isPermissionGranted = isPermissionGranted,
                    isConnected = isServiceConnected,
                    localOnlyMode = localOnlyMode,
                    onLocalOnlyToggled = {
                        localOnlyMode = it
                        pipeline.setLocalOnly(it)
                    },
                    retentionDays = retentionDays,
                    onRetentionDaysChanged = {
                        retentionDays = it
                        pipeline.setRetentionDays(it)
                    },
                    cloudEnabled = cloudAnalysisEnabled,
                    onCloudToggled = {
                        cloudAnalysisEnabled = it
                        pipeline.setCloudAnalysis(it)
                    },
                    consentGranted = userConsentGranted,
                    onConsentToggled = {
                        userConsentGranted = it
                        pipeline.setUserConsent(it)
                    },
                    baseUrl = currentBaseUrl,
                    onBaseUrlChanged = {
                        currentBaseUrl = it
                        pipeline.apiClient.baseUrl = it
                    },
                    onClearHistory = {
                        pipeline.clearAlerts()
                    },
                    onOpenSettings = {
                        openNotificationSettings(context)
                        isPermissionGranted = isNotificationAccessGranted(context)
                    },
                    onOpenSetupWizard = {
                        showFirstTimeSetup = true
                    }
                )
            }
        }
    }
}

// ─── Bottom Nav Helper ────────────────────────────────────────────────────
@Composable
fun RowScope.BottomNavItem(
    selected: Boolean,
    onClick: () -> Unit,
    icon: ImageVector,
    label: String
) {
    NavigationBarItem(
        selected = selected,
        onClick = onClick,
        icon = {
            Icon(
                imageVector = icon,
                contentDescription = label,
                tint = if (selected) TFColors.AccentCyan else TFColors.TextMuted,
                modifier = Modifier.size(24.dp)
            )
        },
        label = {
            Text(
                label,
                fontSize = 11.sp,
                fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                color = if (selected) TFColors.AccentCyan else TFColors.TextMuted
            )
        },
        colors = NavigationBarItemDefaults.colors(
            indicatorColor = TFColors.AccentCyan.copy(alpha = 0.12f)
        )
    )
}

// ═══════════════════════════════════════════════════════════════════════════
//  TAB 1: SHIELD (Dashboard)
// ═══════════════════════════════════════════════════════════════════════════
@Composable
fun ShieldTab(
    alerts: List<RiskAnalysisResult>,
    alertCount: Int,
    dedupedCount: Int,
    ignoredCount: Int,
    isLoading: Boolean,
    statusMessage: String?,
    isPermissionGranted: Boolean,
    isServiceConnected: Boolean,
    cloudEnabled: Boolean,
    userConsentGranted: Boolean,
    onClear: () -> Unit,
    onOpenSettings: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item { Spacer(modifier = Modifier.height(8.dp)) }

        // Hero header with animated threat gauge
        item {
            HeroShieldHeader(
                isActive = isServiceConnected || isPermissionGranted,
                alertCount = alertCount,
                cloudEnabled = cloudEnabled && userConsentGranted,
                onOpenSettings = onOpenSettings,
                isPermissionGranted = isPermissionGranted
            )
        }

        // Status banner
        if (isLoading || statusMessage != null) {
            item {
                AnimatedStatusBanner(isLoading = isLoading, message = statusMessage)
            }
        }

        // Metrics row
        item {
            MetricsRow(
                alertCount = alertCount,
                dedupedCount = dedupedCount,
                ignoredCount = ignoredCount,
                onClear = onClear
            )
        }

        // Alerts section header
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    PulsingDot(color = TFColors.RiskCritical)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        "THREAT FEED",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 2.sp,
                        color = TFColors.TextSecondary
                    )
                }
                Text(
                    "${alerts.size} events",
                    fontSize = 11.sp,
                    color = TFColors.TextMuted
                )
            }
        }

        // Alerts or empty state
        if (alerts.isEmpty()) {
            item { EmptyShieldCard() }
        } else {
            items(alerts, key = { it.eventKey + it.timestamp }) { alert ->
                AlertCard(alert)
            }
        }

        item { Spacer(modifier = Modifier.height(16.dp)) }
    }
}

// ─── Hero Shield Header ──────────────────────────────────────────────────
@Composable
fun HeroShieldHeader(
    isActive: Boolean,
    alertCount: Int,
    cloudEnabled: Boolean,
    onOpenSettings: () -> Unit,
    isPermissionGranted: Boolean
) {
    val infiniteTransition = rememberInfiniteTransition(label = "hero")
    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 0.8f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = EaseInOutCubic),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow"
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.Transparent),
        shape = RoundedCornerShape(20.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            TFColors.SurfaceLight,
                            TFColors.Background
                        )
                    ),
                    shape = RoundedCornerShape(20.dp)
                )
                .border(
                    width = 1.dp,
                    brush = Brush.linearGradient(
                        colors = listOf(
                            TFColors.AccentCyan.copy(alpha = 0.3f),
                            TFColors.AccentBlue.copy(alpha = 0.1f),
                            TFColors.AccentPurple.copy(alpha = 0.3f)
                        )
                    ),
                    shape = RoundedCornerShape(20.dp)
                )
                .padding(20.dp)
        ) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Argus Brand Header with Logo
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center,
                    modifier = Modifier.padding(bottom = 12.dp)
                ) {
                    Image(
                        painter = painterResource(id = R.drawable.ic_argus_logo),
                        contentDescription = "Argus Logo",
                        modifier = Modifier.size(28.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "ARGUS",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 3.sp,
                        color = TFColors.AccentCyan
                    )
                }

                // Threat Gauge
                Box(contentAlignment = Alignment.Center) {
                    ThreatGauge(
                        alertCount = alertCount,
                        isActive = isActive,
                        glowAlpha = glowAlpha
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Status text
                Text(
                    text = if (isActive) "SHIELD ACTIVE" else "SHIELD OFFLINE",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 3.sp,
                    color = if (isActive) TFColors.AccentCyan else TFColors.AccentAmber
                )

                Spacer(modifier = Modifier.height(4.dp))

                Text(
                    text = if (cloudEnabled) "Cloud + Local Analysis" else "Local Heuristic Only",
                    fontSize = 12.sp,
                    color = TFColors.TextMuted
                )

                if (!isPermissionGranted) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Button(
                        onClick = onOpenSettings,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = TFColors.AccentAmber,
                            contentColor = TFColors.Background
                        ),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(Icons.Filled.Notifications, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Grant Notification Access", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                }
            }
        }
    }
}

// ─── Circular Threat Gauge ──────────────────────────────────────────────
@Composable
fun ThreatGauge(alertCount: Int, isActive: Boolean, glowAlpha: Float) {
    val sweepAngle by animateFloatAsState(
        targetValue = (alertCount.coerceAtMost(20).toFloat() / 20f) * 280f,
        animationSpec = tween(800, easing = FastOutSlowInEasing),
        label = "sweep"
    )

    val gaugeColor = when {
        alertCount == 0 -> TFColors.AccentCyan
        alertCount <= 3 -> TFColors.RiskLow
        alertCount <= 8 -> TFColors.RiskMedium
        alertCount <= 15 -> TFColors.RiskHigh
        else -> TFColors.RiskCritical
    }

    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier.size(140.dp)
    ) {
        Canvas(modifier = Modifier.size(140.dp)) {
            // Background ring
            drawArc(
                color = TFColors.CardBorder,
                startAngle = 130f,
                sweepAngle = 280f,
                useCenter = false,
                style = Stroke(width = 10f, cap = StrokeCap.Round)
            )
            // Active ring
            drawArc(
                color = gaugeColor,
                startAngle = 130f,
                sweepAngle = sweepAngle,
                useCenter = false,
                style = Stroke(width = 10f, cap = StrokeCap.Round)
            )
            // Glow ring
            if (isActive) {
                drawArc(
                    color = gaugeColor.copy(alpha = glowAlpha * 0.3f),
                    startAngle = 130f,
                    sweepAngle = sweepAngle,
                    useCenter = false,
                    style = Stroke(width = 20f, cap = StrokeCap.Round)
                )
            }
        }

        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "$alertCount",
                fontSize = 36.sp,
                fontWeight = FontWeight.ExtraBold,
                color = gaugeColor
            )
            Text(
                text = "THREATS",
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 2.sp,
                color = TFColors.TextMuted
            )
        }
    }
}

// ─── Pulsing Dot ────────────────────────────────────────────────────────
@Composable
fun PulsingDot(color: Color, size: Int = 8) {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val scale by infiniteTransition.animateFloat(
        initialValue = 0.8f,
        targetValue = 1.4f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )
    val alpha by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 0.4f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseAlpha"
    )

    Box(contentAlignment = Alignment.Center) {
        Box(
            modifier = Modifier
                .size((size * 2).dp)
                .scale(scale)
                .alpha(alpha)
                .clip(CircleShape)
                .background(color.copy(alpha = 0.2f))
        )
        Box(
            modifier = Modifier
                .size(size.dp)
                .clip(CircleShape)
                .background(color)
        )
    }
}

// ─── Animated Status Banner ─────────────────────────────────────────────
@Composable
fun AnimatedStatusBanner(isLoading: Boolean, message: String?) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        color = if (isLoading) TFColors.AccentBlue.copy(alpha = 0.08f) else TFColors.AccentAmber.copy(alpha = 0.08f)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .border(
                    1.dp,
                    if (isLoading) TFColors.AccentBlue.copy(alpha = 0.2f) else TFColors.AccentAmber.copy(alpha = 0.2f),
                    RoundedCornerShape(12.dp)
                )
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                    color = TFColors.AccentBlue
                )
                Spacer(modifier = Modifier.width(10.dp))
            } else {
                Icon(
                    Icons.Filled.Info,
                    contentDescription = null,
                    modifier = Modifier.size(16.dp),
                    tint = TFColors.AccentAmber
                )
                Spacer(modifier = Modifier.width(10.dp))
            }
            Text(
                text = message ?: "Analyzing threat...",
                fontSize = 12.sp,
                color = if (isLoading) TFColors.AccentBlue else TFColors.AccentAmber,
                lineHeight = 16.sp
            )
        }
    }
}

// ─── Metrics Row ────────────────────────────────────────────────────────
@Composable
fun MetricsRow(
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
        GlassMetricChip(
            label = "Alerts",
            value = alertCount.toString(),
            color = TFColors.RiskCritical,
            modifier = Modifier.weight(1f)
        )
        GlassMetricChip(
            label = "Deduped",
            value = dedupedCount.toString(),
            color = TFColors.AccentPurple,
            modifier = Modifier.weight(1f)
        )
        GlassMetricChip(
            label = "Filtered",
            value = ignoredCount.toString(),
            color = TFColors.TextMuted,
            modifier = Modifier.weight(1f)
        )
        IconButton(
            onClick = onClear,
            modifier = Modifier
                .size(40.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(TFColors.SurfaceLight)
        ) {
            Icon(
                Icons.Filled.Delete,
                contentDescription = "Clear",
                tint = TFColors.TextMuted,
                modifier = Modifier.size(18.dp)
            )
        }
    }
}

@Composable
fun GlassMetricChip(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier
            .border(1.dp, color.copy(alpha = 0.15f), RoundedCornerShape(12.dp)),
        shape = RoundedCornerShape(12.dp),
        color = color.copy(alpha = 0.06f)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                value,
                fontSize = 18.sp,
                fontWeight = FontWeight.ExtraBold,
                color = color
            )
            Text(
                label,
                fontSize = 10.sp,
                fontWeight = FontWeight.Medium,
                color = TFColors.TextMuted,
                letterSpacing = 0.5.sp
            )
        }
    }
}

// ─── Alert Card (Premium) ───────────────────────────────────────────────
@Composable
fun AlertCard(alert: RiskAnalysisResult) {
    val levelColor = when (alert.level) {
        RiskLevel.CRITICAL -> TFColors.RiskCritical
        RiskLevel.HIGH -> TFColors.RiskHigh
        RiskLevel.MEDIUM -> TFColors.RiskMedium
        RiskLevel.LOW -> TFColors.RiskLow
    }

    val levelIcon = when (alert.level) {
        RiskLevel.CRITICAL -> Icons.Filled.Warning
        RiskLevel.HIGH -> Icons.Filled.Warning
        RiskLevel.MEDIUM -> Icons.Filled.Info
        RiskLevel.LOW -> Icons.Filled.CheckCircle
    }

    val sourceLabel = when (alert.analysisSource) {
        AnalysisSource.LOCAL_HEURISTIC -> "Local Heuristic"
        AnalysisSource.BACKEND_ANALYSIS -> "Cloud ML API"
    }

    val formattedTime = remember(alert.timestamp) {
        SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(alert.timestamp))
    }

    var expanded by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(
                width = 1.dp,
                brush = Brush.verticalGradient(
                    colors = listOf(levelColor.copy(alpha = 0.4f), levelColor.copy(alpha = 0.1f))
                ),
                shape = RoundedCornerShape(16.dp)
            )
            .clickable { expanded = !expanded },
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            // Top row: icon + level badge + score + time
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Level icon with colored background
                    Box(
                        modifier = Modifier
                            .size(32.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(levelColor.copy(alpha = 0.12f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            levelIcon,
                            contentDescription = null,
                            tint = levelColor,
                            modifier = Modifier.size(18.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(10.dp))

                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                alert.level.name,
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 13.sp,
                                color = levelColor
                            )
                            alert.score?.let { score ->
                                Spacer(modifier = Modifier.width(8.dp))
                                Surface(
                                    shape = RoundedCornerShape(6.dp),
                                    color = TFColors.SurfaceLight
                                ) {
                                    Text(
                                        "$score/100",
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = TFColors.TextPrimary
                                    )
                                }
                            }
                        }
                        alert.packageName?.let { pkg ->
                            Text(
                                pkg.substringAfterLast('.'),
                                fontSize = 10.sp,
                                color = TFColors.TextMuted
                            )
                        }
                    }
                }

                Column(horizontalAlignment = Alignment.End) {
                    Text(
                        formattedTime,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = TFColors.TextMuted
                    )
                    if (alert.isSynthetic) {
                        Surface(
                            shape = RoundedCornerShape(4.dp),
                            color = TFColors.AccentPurple.copy(alpha = 0.15f)
                        ) {
                            Text(
                                "TEST",
                                modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp),
                                fontSize = 8.sp,
                                fontWeight = FontWeight.Bold,
                                color = TFColors.AccentPurple,
                                letterSpacing = 1.sp
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Summary
            alert.summary?.let { summary ->
                Text(
                    text = summary,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium,
                    color = TFColors.TextPrimary,
                    lineHeight = 18.sp
                )
                Spacer(modifier = Modifier.height(8.dp))
            }

            // Reasons (always show first 2, expand for rest)
            val visibleReasons = if (expanded) alert.reasons else alert.reasons.take(2)
            visibleReasons.forEach { reason ->
                Row(
                    modifier = Modifier.padding(vertical = 2.dp),
                    verticalAlignment = Alignment.Top
                ) {
                    Box(
                        modifier = Modifier
                            .padding(top = 6.dp)
                            .size(4.dp)
                            .clip(CircleShape)
                            .background(levelColor)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        reason,
                        fontSize = 11.sp,
                        color = TFColors.TextSecondary,
                        lineHeight = 16.sp
                    )
                }
            }

            if (alert.reasons.size > 2 && !expanded) {
                Text(
                    "+${alert.reasons.size - 2} more indicators ▼",
                    fontSize = 10.sp,
                    color = TFColors.AccentBlue,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }

            // Expanded details
            AnimatedVisibility(visible = expanded) {
                Column {
                    Spacer(modifier = Modifier.height(8.dp))

                    // Indicators
                    if (alert.indicators.isNotEmpty()) {
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = TFColors.AccentBlue.copy(alpha = 0.06f),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(8.dp)) {
                                Text(
                                    "EXTRACTED INDICATORS",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    letterSpacing = 1.sp,
                                    color = TFColors.AccentBlue
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                alert.indicators.forEach { indicator ->
                                    Text(
                                        "⚡ $indicator",
                                        fontSize = 10.sp,
                                        fontFamily = FontFamily.Monospace,
                                        color = TFColors.AccentBlue
                                    )
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Safe action
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        color = TFColors.AccentCyan.copy(alpha = 0.06f)
                    ) {
                        Row(
                            modifier = Modifier.padding(10.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Icon(
                                Icons.Filled.CheckCircle,
                                contentDescription = null,
                                tint = TFColors.AccentCyan,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text(
                                    "RECOMMENDED ACTION",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    letterSpacing = 1.sp,
                                    color = TFColors.AccentCyan
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    alert.safeAction,
                                    fontSize = 11.sp,
                                    color = TFColors.TextPrimary,
                                    lineHeight = 16.sp
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Footer metadata
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            "via $sourceLabel",
                            fontSize = 9.sp,
                            color = TFColors.TextMuted,
                            fontStyle = androidx.compose.ui.text.font.FontStyle.Italic
                        )
                        if (alert.analysisSource == AnalysisSource.BACKEND_ANALYSIS) {
                            Text(
                                "${alert.modelVersion ?: "ml"} · ${alert.analysisMode ?: "cloud"}",
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace,
                                color = TFColors.TextMuted
                            )
                        }
                    }
                    Text(
                        "Risk scores are automated assessments, not proof.",
                        fontSize = 8.sp,
                        color = TFColors.TextMuted.copy(alpha = 0.6f),
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
            }
        }
    }
}

// ─── Empty Shield Card ─────────────────────────────────────────────────
@Composable
fun EmptyShieldCard() {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, TFColors.CardBorder, RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        color = TFColors.CardBg
    ) {
        Column(
            modifier = Modifier.padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                Icons.Filled.Favorite,
                contentDescription = null,
                tint = TFColors.AccentCyan.copy(alpha = 0.3f),
                modifier = Modifier.size(48.dp)
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                "All Clear",
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
                color = TFColors.TextPrimary
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "No threats detected yet.\nIncoming unknown messages will be screened automatically.",
                fontSize = 12.sp,
                color = TFColors.TextMuted,
                textAlign = TextAlign.Center,
                lineHeight = 18.sp
            )
        }
    }
}

// ─── First-Time Setup & Permissions Modal ─────────────────────────────────
@Composable
fun FirstTimeSetupDialog(
    isNotificationAccessGranted: Boolean,
    onOpenNotificationSettings: () -> Unit,
    areSystemPermissionsGranted: Boolean,
    onRequestSystemPermissions: () -> Unit,
    onOpenAppSettings: () -> Unit,
    notificationConsentGranted: Boolean,
    onNotificationConsentChanged: (Boolean) -> Unit,
    onCompleteSetup: () -> Unit
) {
    AlertDialog(
        onDismissRequest = { /* Modal must be completed on first use */ },
        containerColor = TFColors.CardBg,
        shape = RoundedCornerShape(20.dp),
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .clip(CircleShape)
                        .background(TFColors.AccentCyan.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Image(
                        painter = painterResource(id = R.drawable.ic_argus_logo),
                        contentDescription = "Argus Logo",
                        modifier = Modifier.size(26.dp)
                    )
                }
                Spacer(modifier = Modifier.width(10.dp))
                Column {
                    Text(
                        "ARGUS SETUP",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = TFColors.TextPrimary,
                        letterSpacing = 1.sp
                    )
                    Text(
                        "24/7 Real-Time Fraud Shield",
                        fontSize = 11.sp,
                        color = TFColors.AccentCyan
                    )
                }
            }
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Text(
                    "To safeguard your device against scams, APK droppers, and payment fraud, Argus requires the following setup:",
                    fontSize = 12.sp,
                    color = TFColors.TextSecondary,
                    lineHeight = 17.sp
                )

                // 1. Notification Listener Access
                Surface(
                    color = TFColors.Surface,
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(
                        1.dp,
                        if (isNotificationAccessGranted) TFColors.RiskLow.copy(alpha = 0.3f) else TFColors.AccentAmber.copy(alpha = 0.3f)
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                "1. Notification Access",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = TFColors.TextPrimary
                            )
                            if (isNotificationAccessGranted) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        Icons.Filled.CheckCircle,
                                        contentDescription = null,
                                        tint = TFColors.RiskLow,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Granted", fontSize = 11.sp, color = TFColors.RiskLow, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            "Screens incoming WhatsApp & Telegram notifications from unknown senders for fraud links and trojans.",
                            fontSize = 11.sp,
                            color = TFColors.TextMuted,
                            lineHeight = 15.sp
                        )
                        if (!isNotificationAccessGranted) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Button(
                                onClick = onOpenNotificationSettings,
                                colors = ButtonDefaults.buttonColors(containerColor = TFColors.AccentAmber),
                                shape = RoundedCornerShape(8.dp),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                            ) {
                                Text("Enable in Settings", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = TFColors.Background)
                            }
                        }
                    }
                }

                // 2. Alert & Contacts Permission
                Surface(
                    color = TFColors.Surface,
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(
                        1.dp,
                        if (areSystemPermissionsGranted) TFColors.RiskLow.copy(alpha = 0.3f) else TFColors.AccentAmber.copy(alpha = 0.3f)
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                "2. Alerts & Privacy Filtering",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = TFColors.TextPrimary
                            )
                            if (areSystemPermissionsGranted) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        Icons.Filled.CheckCircle,
                                        contentDescription = null,
                                        tint = TFColors.RiskLow,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Granted", fontSize = 11.sp, color = TFColors.RiskLow, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            "Allows posting urgent threat alerts and checking contacts to ignore messages from family and friends.",
                            fontSize = 11.sp,
                            color = TFColors.TextMuted,
                            lineHeight = 15.sp
                        )
                        if (!areSystemPermissionsGranted) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Button(
                                    onClick = onRequestSystemPermissions,
                                    shape = RoundedCornerShape(8.dp),
                                    colors = ButtonDefaults.buttonColors(containerColor = TFColors.AccentCyan),
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Grant Permissions", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = TFColors.Background)
                                }
                                OutlinedButton(
                                    onClick = onOpenAppSettings,
                                    shape = RoundedCornerShape(8.dp),
                                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp)
                                ) {
                                    Text("App Settings", fontSize = 11.sp, color = TFColors.AccentCyan)
                                }
                            }
                        }
                    }
                }

                // 3. Notification Consent Switch
                Surface(
                    color = TFColors.Surface,
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, TFColors.CardBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                            Text(
                                "Threat Alert Consent",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                color = TFColors.TextPrimary
                            )
                            Text(
                                "I consent to receiving immediate alert notifications when high-risk fraud or trojans are detected.",
                                fontSize = 10.sp,
                                color = TFColors.TextMuted,
                                lineHeight = 14.sp
                            )
                        }
                        Switch(
                            checked = notificationConsentGranted,
                            onCheckedChange = onNotificationConsentChanged,
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = TFColors.Background,
                                checkedTrackColor = TFColors.AccentCyan
                            )
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onCompleteSetup,
                colors = ButtonDefaults.buttonColors(containerColor = TFColors.AccentCyan),
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "Activate 24/7 Protection",
                    fontWeight = FontWeight.Bold,
                    color = TFColors.Background,
                    fontSize = 13.sp
                )
            }
        }
    )
}

// ═══════════════════════════════════════════════════════════════════════════
//  TAB 2: SCANNER (MANUAL THREAT AUDIT & CAPABILITIES)
// ═══════════════════════════════════════════════════════════════════════════
@Composable
fun ScannerTab(
    isLoading: Boolean,
    customInput: String,
    onCustomInputChange: (String) -> Unit,
    selectedPackage: String,
    onPackageSelected: (String) -> Unit,
    onSubmitCustom: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item { Spacer(modifier = Modifier.height(8.dp)) }

        // Scanner header
        item {
            Column {
                Text(
                    "MANUAL AUDIT & SCANNER",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 2.sp,
                    color = TFColors.TextPrimary
                )
                Text(
                    "Analyze suspicious text, URLs, APK packages, or UPI deep links",
                    fontSize = 13.sp,
                    color = TFColors.TextMuted
                )
            }
        }

        // Custom message input card
        item {
            CustomScanCard(
                customInput = customInput,
                onCustomInputChange = onCustomInputChange,
                selectedPackage = selectedPackage,
                onPackageSelected = onPackageSelected,
                onSubmitCustom = onSubmitCustom,
                isLoading = isLoading
            )
        }

        // Detection engines overview
        item {
            Text(
                "ACTIVE DEFENSE CAPABILITIES",
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 2.sp,
                color = TFColors.TextSecondary
            )
        }

        item {
            EngineCapabilityCard(
                title = "Sideloaded APK Package Inspector",
                description = "Scans incoming links for deceptive .apk packages (e.g. wedding_card.apk, bank rewards) and banking trojans before download.",
                icon = Icons.Filled.Warning,
                accentColor = TFColors.RiskCritical
            )
        }

        item {
            EngineCapabilityCard(
                title = "UPI Deep Link & QR Code Audit",
                description = "Detects fraudulent reverse-charge UPI intents (upi://pay) masquerading as refunds or cashback to steal account funds.",
                icon = Icons.Filled.CheckCircle,
                accentColor = TFColors.AccentCyan
            )
        }

        item {
            EngineCapabilityCard(
                title = "DistilBERT Phishing Transformer",
                description = "8-bit quantized on-device neural network evaluates social engineering and artificial urgency in ~20 milliseconds.",
                icon = Icons.Filled.Info,
                accentColor = TFColors.AccentBlue
            )
        }

        item {
            EngineCapabilityCard(
                title = "Zero-Leakage Privacy Gate",
                description = "Client-side PII redactor sanitizes phone numbers, tokens, and credentials. Saved contacts are strictly excluded.",
                icon = Icons.Filled.Lock,
                accentColor = TFColors.AccentPurple
            )
        }

        item { Spacer(modifier = Modifier.height(16.dp)) }
    }
}

@Composable
fun EngineCapabilityCard(
    title: String,
    description: String,
    icon: ImageVector,
    accentColor: Color
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, accentColor.copy(alpha = 0.2f), RoundedCornerShape(14.dp)),
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(14.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(accentColor.copy(alpha = 0.1f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(22.dp)
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    title,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = TFColors.TextPrimary
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    description,
                    fontSize = 11.sp,
                    color = TFColors.TextMuted,
                    lineHeight = 16.sp
                )
            }
        }
    }
}

@Composable
fun CustomScanCard(
    customInput: String,
    onCustomInputChange: (String) -> Unit,
    selectedPackage: String,
    onPackageSelected: (String) -> Unit,
    onSubmitCustom: () -> Unit,
    isLoading: Boolean
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(
                1.dp,
                Brush.linearGradient(
                    colors = listOf(
                        TFColors.AccentCyan.copy(alpha = 0.3f),
                        TFColors.AccentPurple.copy(alpha = 0.3f)
                    )
                ),
                RoundedCornerShape(16.dp)
            ),
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.Search,
                    contentDescription = null,
                    tint = TFColors.AccentCyan,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    "CUSTOM SCAN",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp,
                    color = TFColors.AccentCyan
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = customInput,
                onValueChange = onCustomInputChange,
                placeholder = {
                    Text(
                        "Paste suspicious message text...",
                        fontSize = 13.sp,
                        color = TFColors.TextMuted
                    )
                },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                maxLines = 4,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = TFColors.AccentCyan,
                    unfocusedBorderColor = TFColors.CardBorder,
                    cursorColor = TFColors.AccentCyan,
                    focusedTextColor = TFColors.TextPrimary,
                    unfocusedTextColor = TFColors.TextPrimary
                )
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Source selector
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    SourceChip(
                        label = "WhatsApp",
                        selected = selectedPackage == PackageFilter.PACKAGE_WHATSAPP,
                        onClick = { onPackageSelected(PackageFilter.PACKAGE_WHATSAPP) }
                    )
                    SourceChip(
                        label = "Telegram",
                        selected = selectedPackage == PackageFilter.PACKAGE_TELEGRAM,
                        onClick = { onPackageSelected(PackageFilter.PACKAGE_TELEGRAM) }
                    )
                }

                Button(
                    onClick = onSubmitCustom,
                    enabled = !isLoading && customInput.isNotBlank(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = TFColors.AccentCyan,
                        contentColor = TFColors.Background,
                        disabledContainerColor = TFColors.SurfaceLight,
                        disabledContentColor = TFColors.TextMuted
                    ),
                    shape = RoundedCornerShape(10.dp),
                    contentPadding = PaddingValues(horizontal = 20.dp, vertical = 10.dp)
                ) {
                    Icon(Icons.Filled.Search, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Scan", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }
            }
        }
    }
}

@Composable
fun SourceChip(label: String, selected: Boolean, onClick: () -> Unit) {
    Surface(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .border(
                1.dp,
                if (selected) TFColors.AccentCyan.copy(alpha = 0.4f) else TFColors.CardBorder,
                RoundedCornerShape(8.dp)
            ),
        color = if (selected) TFColors.AccentCyan.copy(alpha = 0.1f) else Color.Transparent,
        shape = RoundedCornerShape(8.dp)
    ) {
        Text(
            label,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            fontSize = 12.sp,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            color = if (selected) TFColors.AccentCyan else TFColors.TextMuted
        )
    }
}

@Composable
fun ScenarioCard(
    title: String,
    description: String,
    icon: ImageVector,
    color: Color,
    isLoading: Boolean,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, color.copy(alpha = 0.12f), RoundedCornerShape(14.dp))
            .clickable(enabled = !isLoading, onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(14.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(color.copy(alpha = 0.1f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = color,
                    modifier = Modifier.size(22.dp)
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    title,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    color = TFColors.TextPrimary
                )
                Text(
                    description,
                    fontSize = 11.sp,
                    color = TFColors.TextMuted,
                    lineHeight = 15.sp
                )
            }

            Icon(
                Icons.Filled.PlayArrow,
                contentDescription = "Run",
                tint = color.copy(alpha = 0.6f),
                modifier = Modifier.size(24.dp)
            )
        }
    }
}

@Composable
fun MiniScenarioCard(
    title: String,
    subtitle: String,
    color: Color,
    isLoading: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .border(1.dp, color.copy(alpha = 0.12f), RoundedCornerShape(14.dp))
            .clickable(enabled = !isLoading, onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(14.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .clip(CircleShape)
                        .background(color)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    title,
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp,
                    color = TFColors.TextPrimary
                )
            }
            Text(
                subtitle,
                fontSize = 10.sp,
                color = TFColors.TextMuted,
                modifier = Modifier.padding(top = 2.dp)
            )
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  TAB 3: SETTINGS
// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
//  TAB 3: SETTINGS & PRIVACY
// ═══════════════════════════════════════════════════════════════════════════
@Composable
fun SettingsTab(
    isPermissionGranted: Boolean,
    isConnected: Boolean,
    localOnlyMode: Boolean,
    onLocalOnlyToggled: (Boolean) -> Unit,
    retentionDays: Int,
    onRetentionDaysChanged: (Int) -> Unit,
    cloudEnabled: Boolean,
    onCloudToggled: (Boolean) -> Unit,
    consentGranted: Boolean,
    onConsentToggled: (Boolean) -> Unit,
    baseUrl: String,
    onBaseUrlChanged: (String) -> Unit,
    onClearHistory: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenSetupWizard: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item { Spacer(modifier = Modifier.height(8.dp)) }

        // Settings header
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "PRIVACY & SETTINGS",
                    fontSize = 20.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 2.sp,
                    color = TFColors.TextPrimary
                )
                TextButton(onClick = onOpenSetupWizard) {
                    Text("Re-run Setup", fontSize = 11.sp, color = TFColors.AccentCyan)
                }
            }
        }

        // Visible explanation of notification-access permissions
        item {
            PermissionTransparencyCard(
                isPermissionGranted = isPermissionGranted,
                isConnected = isConnected,
                onOpenSettings = onOpenSettings
            )
        }

        // Local-Only Mode Card (Zero Cloud Transmission)
        item {
            LocalOnlyModeCard(
                localOnlyMode = localOnlyMode,
                onLocalOnlyToggled = onLocalOnlyToggled
            )
        }

        // Cloud analysis card (disabled if localOnlyMode is active)
        if (!localOnlyMode) {
            item {
                CloudSettingsCard(
                    cloudEnabled = cloudEnabled,
                    onCloudToggled = onCloudToggled,
                    consentGranted = consentGranted,
                    onConsentToggled = onConsentToggled,
                    baseUrl = baseUrl,
                    onBaseUrlChanged = onBaseUrlChanged
                )
            }
        }

        // Data Outbound Inspector (shows exactly what data leaves device)
        item {
            OutboundDataInspectorCard(
                baseUrl = baseUrl,
                localOnlyMode = localOnlyMode
            )
        }

        // History Deletion and Data Retention Settings
        item {
            DataRetentionCard(
                retentionDays = retentionDays,
                onRetentionDaysChanged = onRetentionDaysChanged,
                onClearHistory = onClearHistory
            )
        }

        // Privacy notice & guarantees
        item {
            PrivacyNoticeCard()
        }

        // About
        item {
            AboutCard()
        }

        item { Spacer(modifier = Modifier.height(16.dp)) }
    }
}

@Composable
fun PermissionTransparencyCard(
    isPermissionGranted: Boolean,
    isConnected: Boolean,
    onOpenSettings: () -> Unit
) {
    var expanded by remember { mutableStateOf(!isPermissionGranted) }
    val statusColor = when {
        isConnected -> TFColors.AccentCyan
        isPermissionGranted -> TFColors.AccentAmber
        else -> TFColors.RiskCritical
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, statusColor.copy(alpha = 0.25f), RoundedCornerShape(16.dp)),
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    PulsingDot(color = statusColor, size = 10)
                    Spacer(modifier = Modifier.width(10.dp))
                    Column {
                        Text(
                            "NOTIFICATION ACCESS PERMISSION",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.sp,
                            color = TFColors.TextMuted
                        )
                        Text(
                            if (isConnected) "Active & Filtering Permitted Apps" else if (isPermissionGranted) "Authorized — Standby" else "Permission Required",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = statusColor
                        )
                    }
                }
                TextButton(onClick = { expanded = !expanded }) {
                    Text(
                        if (expanded) "Hide Details" else "Why Needed?",
                        fontSize = 11.sp,
                        color = TFColors.AccentCyan
                    )
                }
            }

            AnimatedVisibility(visible = expanded) {
                Column {
                    Spacer(modifier = Modifier.height(10.dp))
                    Divider(color = TFColors.CardBorder)
                    Spacer(modifier = Modifier.height(10.dp))

                    Text(
                        "Why Argus needs this access:",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = TFColors.TextPrimary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        "• Android only offers a single broad Notification Access permission at the OS level.\n" +
                                "• Argus's in-memory filter strictly inspects ONLY WhatsApp and Telegram.\n" +
                                "• 100% of other notifications (SMS, Banking, Emails, System) are dropped immediately without analysis, logging, or storage.\n" +
                                "• Argus cannot read your chats, contacts, private files, or camera.",
                        fontSize = 11.sp,
                        color = TFColors.TextMuted,
                        lineHeight = 16.sp
                    )
                }
            }

            if (!isPermissionGranted) {
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = onOpenSettings,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = statusColor,
                        contentColor = TFColors.Background
                    ),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.Notifications, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Grant Notification Access", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
fun LocalOnlyModeCard(
    localOnlyMode: Boolean,
    onLocalOnlyToggled: (Boolean) -> Unit
) {
    val borderColor = if (localOnlyMode) TFColors.AccentCyan.copy(alpha = 0.4f) else TFColors.CardBorder

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, borderColor, RoundedCornerShape(16.dp)),
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Filled.Lock,
                            contentDescription = null,
                            tint = if (localOnlyMode) TFColors.AccentCyan else TFColors.TextMuted,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            "LOCAL-ONLY SHIELD (ZERO CLOUD)",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.sp,
                            color = if (localOnlyMode) TFColors.AccentCyan else TFColors.TextMuted
                        )
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        if (localOnlyMode) "100% on-device analysis active. Network calls disabled." else "Process threats locally without sending any data to backend",
                        fontSize = 11.sp,
                        color = if (localOnlyMode) TFColors.AccentCyan else TFColors.TextMuted
                    )
                }
                Switch(
                    checked = localOnlyMode,
                    onCheckedChange = onLocalOnlyToggled,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = TFColors.Background,
                        checkedTrackColor = TFColors.AccentCyan,
                        uncheckedThumbColor = TFColors.TextMuted,
                        uncheckedTrackColor = TFColors.SurfaceLight
                    )
                )
            }
        }
    }
}

@Composable
fun OutboundDataInspectorCard(
    baseUrl: String,
    localOnlyMode: Boolean
) {
    var isExpanded by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, TFColors.CardBorder, RoundedCornerShape(16.dp)),
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Info,
                        contentDescription = null,
                        tint = TFColors.AccentBlue,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        "DATA OUTBOUND INSPECTOR",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp,
                        color = TFColors.AccentBlue
                    )
                }
                TextButton(onClick = { isExpanded = !isExpanded }) {
                    Text(
                        if (isExpanded) "Collapse" else "Inspect Payload",
                        fontSize = 11.sp,
                        color = TFColors.AccentBlue
                    )
                }
            }

            Spacer(modifier = Modifier.height(4.dp))
            Text(
                if (localOnlyMode) "Status: Zero data leaves device (Local-Only Mode is active)."
                else "Pre-transmission scrubbing guarantees sensitive OTPs, tokens, and cards are redacted before transmission.",
                fontSize = 11.sp,
                color = TFColors.TextMuted
            )

            AnimatedVisibility(visible = isExpanded) {
                Column {
                    Spacer(modifier = Modifier.height(10.dp))
                    Divider(color = TFColors.CardBorder)
                    Spacer(modifier = Modifier.height(10.dp))

                    Text(
                        "Live Scrubbed Payload Preview (What leaves phone):",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = TFColors.TextPrimary
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        color = TFColors.Background,
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(
                            "{\n" +
                                    "  \"text\": \"URGENT: Verify account at http://bank.xyz/login?token=REDACTED\",\n" +
                                    "  \"source\": \"com.whatsapp\",\n" +
                                    "  \"sender\": \"+91 98*** **210\",\n" +
                                    "  \"cloud_analysis\": true\n" +
                                    "}",
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            color = TFColors.AccentCyan,
                            modifier = Modifier.padding(10.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    Text("✓ Data Never Collected:", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = TFColors.AccentCyan)
                    Text("• Raw OTPs & auth tokens (stripped client-side)\n• Full phone contact books & chat histories\n• Notifications from unwhitelisted banking apps", fontSize = 10.sp, color = TFColors.TextMuted, lineHeight = 15.sp)
                }
            }
        }
    }
}

@Composable
fun DataRetentionCard(
    retentionDays: Int,
    onRetentionDaysChanged: (Int) -> Unit,
    onClearHistory: () -> Unit
) {
    var showConfirmDialog by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, TFColors.CardBorder, RoundedCornerShape(16.dp)),
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "RETENTION & HISTORY DELETION",
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
                color = TFColors.AccentAmber
            )

            Spacer(modifier = Modifier.height(10.dp))
            Text("Retention Policy:", fontSize = 11.sp, fontWeight = FontWeight.SemiBold, color = TFColors.TextPrimary)
            Spacer(modifier = Modifier.height(6.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                RetentionChip(label = "Memory Only", selected = retentionDays == 0, onClick = { onRetentionDaysChanged(0) })
                RetentionChip(label = "24 Hours", selected = retentionDays == 1, onClick = { onRetentionDaysChanged(1) })
                RetentionChip(label = "7 Days", selected = retentionDays == 7, onClick = { onRetentionDaysChanged(7) })
                RetentionChip(label = "30 Days", selected = retentionDays == 30, onClick = { onRetentionDaysChanged(30) })
            }

            Spacer(modifier = Modifier.height(14.dp))
            Button(
                onClick = { showConfirmDialog = true },
                colors = ButtonDefaults.buttonColors(
                    containerColor = TFColors.RiskCritical.copy(alpha = 0.15f),
                    contentColor = TFColors.RiskCritical
                ),
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.Delete, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Delete All Threat History & Cache", fontWeight = FontWeight.Bold, fontSize = 12.sp)
            }

            if (showConfirmDialog) {
                AlertDialog(
                    onDismissRequest = { showConfirmDialog = false },
                    title = { Text("Delete All History?", color = TFColors.TextPrimary) },
                    text = { Text("This will permanently clear all recorded threat events, deduplication hashes, and cached analysis. This cannot be undone.", color = TFColors.TextMuted) },
                    confirmButton = {
                        TextButton(onClick = {
                            onClearHistory()
                            showConfirmDialog = false
                        }) {
                            Text("Delete Now", color = TFColors.RiskCritical, fontWeight = FontWeight.Bold)
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { showConfirmDialog = false }) {
                            Text("Cancel", color = TFColors.TextMuted)
                        }
                    },
                    containerColor = TFColors.CardBg
                )
            }
        }
    }
}

@Composable
fun RetentionChip(label: String, selected: Boolean, onClick: () -> Unit) {
    Surface(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .border(
                1.dp,
                if (selected) TFColors.AccentAmber.copy(alpha = 0.6f) else TFColors.CardBorder,
                RoundedCornerShape(8.dp)
            ),
        color = if (selected) TFColors.AccentAmber.copy(alpha = 0.12f) else Color.Transparent,
        shape = RoundedCornerShape(8.dp)
    ) {
        Text(
            label,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 5.dp),
            fontSize = 10.sp,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            color = if (selected) TFColors.AccentAmber else TFColors.TextMuted
        )
    }
}


@Composable
fun CloudSettingsCard(
    cloudEnabled: Boolean,
    onCloudToggled: (Boolean) -> Unit,
    consentGranted: Boolean,
    onConsentToggled: (Boolean) -> Unit,
    baseUrl: String,
    onBaseUrlChanged: (String) -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, TFColors.CardBorder, RoundedCornerShape(16.dp)),
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "CLOUD ANALYSIS",
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
                color = TFColors.AccentBlue
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Cloud toggle
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        "Enable Backend ML",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = TFColors.TextPrimary
                    )
                    Text(
                        "POST /api/analyze → DistilBERT + threat intelligence",
                        fontSize = 11.sp,
                        color = TFColors.TextMuted
                    )
                }
                Switch(
                    checked = cloudEnabled,
                    onCheckedChange = onCloudToggled,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = TFColors.Background,
                        checkedTrackColor = TFColors.AccentCyan,
                        uncheckedThumbColor = TFColors.TextMuted,
                        uncheckedTrackColor = TFColors.SurfaceLight
                    )
                )
            }

            AnimatedVisibility(visible = cloudEnabled) {
                Column {
                    Spacer(modifier = Modifier.height(12.dp))

                    // Consent
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(
                                if (consentGranted) TFColors.AccentCyan.copy(alpha = 0.06f)
                                else TFColors.RiskCritical.copy(alpha = 0.06f)
                            )
                            .border(
                                1.dp,
                                if (consentGranted) TFColors.AccentCyan.copy(alpha = 0.15f)
                                else TFColors.RiskCritical.copy(alpha = 0.15f),
                                RoundedCornerShape(10.dp)
                            )
                            .clickable { onConsentToggled(!consentGranted) }
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(
                            checked = consentGranted,
                            onCheckedChange = onConsentToggled,
                            colors = CheckboxDefaults.colors(
                                checkedColor = TFColors.AccentCyan,
                                uncheckedColor = TFColors.TextMuted
                            )
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            "I consent to sending notification text to the backend for threat analysis.",
                            fontSize = 11.sp,
                            color = if (consentGranted) TFColors.AccentCyan else TFColors.RiskCritical,
                            lineHeight = 16.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Endpoint selector
                    Text(
                        "ENDPOINT",
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp,
                        color = TFColors.TextMuted
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        baseUrl,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = TFColors.AccentBlue
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        EndpointChip(
                            label = "USB/ADB",
                            selected = baseUrl == com.threatforge.android.network.ThreatForgeApiClient.USB_REVERSE_BASE_URL,
                            onClick = { onBaseUrlChanged(com.threatforge.android.network.ThreatForgeApiClient.USB_REVERSE_BASE_URL) }
                        )
                        EndpointChip(
                            label = "LAN Wi-Fi",
                            selected = baseUrl == com.threatforge.android.network.ThreatForgeApiClient.LAN_WIFI_BASE_URL,
                            onClick = { onBaseUrlChanged(com.threatforge.android.network.ThreatForgeApiClient.LAN_WIFI_BASE_URL) }
                        )
                        EndpointChip(
                            label = "Emulator",
                            selected = baseUrl == com.threatforge.android.network.ThreatForgeApiClient.EMULATOR_BASE_URL,
                            onClick = { onBaseUrlChanged(com.threatforge.android.network.ThreatForgeApiClient.EMULATOR_BASE_URL) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun EndpointChip(label: String, selected: Boolean, onClick: () -> Unit) {
    Surface(
        modifier = Modifier
            .clip(RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .border(
                1.dp,
                if (selected) TFColors.AccentBlue.copy(alpha = 0.4f) else TFColors.CardBorder,
                RoundedCornerShape(8.dp)
            ),
        color = if (selected) TFColors.AccentBlue.copy(alpha = 0.1f) else Color.Transparent,
        shape = RoundedCornerShape(8.dp)
    ) {
        Text(
            label,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            fontSize = 11.sp,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            color = if (selected) TFColors.AccentBlue else TFColors.TextMuted
        )
    }
}

@Composable
fun PrivacyNoticeCard() {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, TFColors.CardBorder, RoundedCornerShape(16.dp)),
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.Lock,
                    contentDescription = null,
                    tint = TFColors.AccentCyan,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    "PRIVACY & TRUST GUARANTEES",
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp,
                    color = TFColors.AccentCyan
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                "• Zero Outbound Web Crawling: URLs are analyzed purely through safe offline lexical features without making network visits.\n" +
                        "• Pre-Transmission Redaction: OTP codes, session tokens, and credit cards are scrubbed client-side before touching the network.\n" +
                        "• Package Filtering: Strictly whitelists WhatsApp and Telegram. All other apps (banking, email, personal SMS) are discarded immediately.\n" +
                        "• Full User Agency: Toggle Local-Only Shield or purge threat history at any time.",
                fontSize = 11.sp,
                color = TFColors.TextMuted,
                lineHeight = 17.sp
            )
        }
    }
}

@Composable
fun AboutCard() {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, TFColors.CardBorder, RoundedCornerShape(16.dp)),
        colors = CardDefaults.cardColors(containerColor = TFColors.CardBg),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Image(
                painter = painterResource(id = R.drawable.ic_argus_logo),
                contentDescription = "Argus Logo",
                modifier = Modifier.size(46.dp)
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                "ARGUS",
                fontSize = 16.sp,
                fontWeight = FontWeight.ExtraBold,
                letterSpacing = 3.sp,
                color = TFColors.AccentCyan
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "Autonomous Cyber Threat Intelligence & Phishing Defense",
                fontSize = 12.sp,
                color = TFColors.TextMuted
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                "v1.0.0 · DistilBERT + Heuristic Engine",
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                color = TFColors.TextMuted.copy(alpha = 0.6f)
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
