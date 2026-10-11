export type SeverityEnum = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type IndicatorTypeEnum = 
  | "Phishing URL"
  | "IP Address"
  | "Crypto Wallet"
  | "Suspicious Phone"
  | "Email Address"
  | "UPI ID"
  | "Bank Account"
  | "Social Engineering"
  | "Other Indicator";

export interface Indicator {
  type: string; // Will typically match IndicatorTypeEnum
  value: string;
  severity: SeverityEnum;
  confidence: number;
  context?: string | null;
  metadata?: Record<string, any> | null;
}

export interface RiskBreakdownFactor {
  factor: string;
  score: number;
  description: string;
  severity: SeverityEnum;
}

export interface AnalysisRequest {
  message: string;
  text?: string;
  sender?: string | null;
  source?: string;
  cloud_analysis?: boolean;
  context?: Record<string, any> | null;
  raw_headers?: string | null;
  headers?: Record<string, string> | null;
}

export interface DistilBertResult {
  model_name: string;
  model_version: string;
  is_available: boolean;
  is_quantized?: boolean;
  latency_ms?: number | null;
  predicted_class_index?: number | null;
  predicted_class_label?: string | null;
  verified_class_label?: string | null;
  candidate_class_label?: string | null;
  class_probabilities?: Record<string, number>;
  candidate_probabilities?: Record<string, number>;
  confidence?: number;
  verification_status: "verified" | "unverified" | "unavailable" | string;
  warning?: string | null;
  explanation?: string;
  risk_assessment?: string | null;
}

export interface EmailHeaderAnalysis {
  has_headers: boolean;
  authentication_mode?: string;
  verification_disclaimer?: string;
  from_header?: string | null;
  from_address?: string | null;
  from_domain?: string | null;
  display_name?: string | null;
  return_path?: string | null;
  return_path_domain?: string | null;
  reply_to?: string | null;
  reply_to_domain?: string | null;
  spf_status?: string | null;
  dkim_status?: string | null;
  dmarc_status?: string | null;
  domain_alignment: boolean;
  display_name_spoofing: boolean;
  anomalies: string[];
  risk_boost: number;
  summary: string;
}

export interface UpiAuditResult {
  is_upi_deeplink: boolean;
  raw_uri?: string | null;
  payee_vpa?: string | null;
  payee_name?: string | null;
  amount?: number | null;
  currency?: string;
  transaction_note?: string | null;
  is_reverse_charge_lure: boolean;
  is_brand_spoofing: boolean;
  risk_boost: number;
  anomalies: string[];
  warning_message?: string | null;
}

export interface ApkAuditResult {
  has_apk_dropper: boolean;
  filename?: string | null;
  download_url?: string | null;
  lure_category?: string | null;
  targeted_threat_family?: string | null;
  risk_score: number;
  is_critical_threat: boolean;
  reasons: string[];
  defensive_warning?: string | null;
}

export interface AnalysisResult {
  risk_score: number;
  risk_level: SeverityEnum;
  summary: string;
  breakdown: RiskBreakdownFactor[];
  indicators: Indicator[];
  recommendations: string[];
  analyzed_at: string;
  reasons?: string[];
  recommended_action?: string;
  model_name?: string;
  predicted_class_index?: number | null;
  predicted_class_label?: string | null;
  verified_class_label?: string | null;
  candidate_class_label?: string | null;
  class_probabilities?: Record<string, number>;
  candidate_probabilities?: Record<string, number>;
  verification_status?: string;
  risk_assessment?: string | null;
  is_quantized?: boolean;
  latency_ms?: number | null;
  warning?: string | null;
  concise_explanation?: string | null;
  distilbert?: DistilBertResult | null;
  header_analysis?: EmailHeaderAnalysis | null;
  gemini_analysis?: Record<string, any> | null;
  upi_audit?: UpiAuditResult | null;
  apk_audit?: ApkAuditResult | null;
}

export interface ChatRequest {
  session_id?: string | null;
  message: string;
  persona?: string | null;
}

export interface ChatResponse {
  session_id: string;
  reply: string;
  persona: string;
  tactics_detected: string[];
  extracted_iocs: Indicator[];
  turn_count: number;
}

export interface ThreatItem {
  id: string;
  type: string;
  value: string;
  severity: SeverityEnum;
  time: string;
  source?: string | null;
  risk_score?: number | null;
}

export interface DashboardMetrics {
  total_sessions: number;
  indicators_captured: number;
  high_severity_count: number;
  active_sessions: number;
  sessions_change: string;
  indicators_change: string;
}

export interface ActivityItem {
  title: string;
  detail: string;
  time: string;
}

export interface ThreatDistributionCategory {
  category: string;
  count: number;
  percentage: number;
}

export interface DashboardResponse {
  metrics: DashboardMetrics;
  threats: ThreatItem[];
  activity: ActivityItem[];
  distribution: ThreatDistributionCategory[];
}

export interface ExtractRequest {
  text: string;
}

export interface ExtractResponse {
  indicators: Indicator[];
  count: number;
}

// Mapped alias for Reason as asked by the prompt (RiskBreakdownFactor is what backend used)
export type Reason = RiskBreakdownFactor;
export type ThreatCase = unknown;
