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
  sender?: string | null;
  context?: Record<string, any> | null;
}

export interface AnalysisResult {
  risk_score: number;
  risk_level: SeverityEnum;
  summary: string;
  breakdown: RiskBreakdownFactor[];
  indicators: Indicator[];
  recommendations: string[];
  analyzed_at: string;
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
export type ThreatCase = unknown; // Documented as missing, backend did not provide ThreatCase schema
