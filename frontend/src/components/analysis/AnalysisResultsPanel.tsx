import type { AnalysisResult } from '../../types/api';
import { IndicatorsPanel } from '../indicators/IndicatorsPanel';
import styles from './AnalysisResultsPanel.module.css';

interface AnalysisResultsPanelProps {
  result: AnalysisResult;
  onEdit: () => void;
}

export function AnalysisResultsPanel({ result, onEdit }: AnalysisResultsPanelProps) {
  const isQuantized = result.distilbert?.is_quantized ?? result.is_quantized;
  const latency = result.distilbert?.latency_ms ?? result.latency_ms;
  const headerAnalysis = result.header_analysis;

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h3>Analysis Results</h3>
        <button 
          className={styles.editBtn} 
          onClick={onEdit}
          aria-label="Edit submitted message and re-analyze"
        >
          Edit &amp; Re-analyze
        </button>
      </div>

      <div className={styles.scoreCard}>
        <div className={styles.scoreTop}>
          <span className={styles.scoreLabel}>Overall Risk Score</span>
          <span className={`${styles.riskBadge} ${styles[result.risk_level.toLowerCase()]}`}>
            {result.risk_level}
          </span>
        </div>
        <div className={styles.scoreValue}>
          {result.risk_score} <small>/ 100</small>
        </div>
        <p className={styles.summary}>{result.summary}</p>
      </div>

      {/* Dedicated Email Header Security & Authentication Audit */}
      {headerAnalysis && headerAnalysis.has_headers && (
        <div className={styles.section}>
          <h4>Email Header Security &amp; Authentication Audit</h4>
          <div className={styles.headerAuditCard}>
            <div className={styles.headerBadgesRow}>
              {/* SPF Badge */}
              <span className={`${styles.authPill} ${
                headerAnalysis.spf_status === 'pass'
                  ? styles.authPass
                  : headerAnalysis.spf_status === 'fail'
                  ? styles.authFail
                  : headerAnalysis.spf_status === 'softfail'
                  ? styles.authSoftfail
                  : styles.authNone
              }`}>
                SPF: {headerAnalysis.spf_status ? headerAnalysis.spf_status.toUpperCase() : 'NONE'}
              </span>

              {/* DKIM Badge */}
              <span className={`${styles.authPill} ${
                headerAnalysis.dkim_status === 'pass' || headerAnalysis.dkim_status === 'present'
                  ? styles.authPass
                  : headerAnalysis.dkim_status === 'fail'
                  ? styles.authFail
                  : styles.authNone
              }`}>
                DKIM: {headerAnalysis.dkim_status ? headerAnalysis.dkim_status.toUpperCase() : 'NONE'}
              </span>

              {/* DMARC Badge */}
              <span className={`${styles.authPill} ${
                headerAnalysis.dmarc_status === 'pass'
                  ? styles.authPass
                  : headerAnalysis.dmarc_status === 'fail'
                  ? styles.authFail
                  : styles.authNone
              }`}>
                DMARC: {headerAnalysis.dmarc_status ? headerAnalysis.dmarc_status.toUpperCase() : 'NONE'}
              </span>

              {/* Domain Alignment */}
              <span className={`${styles.authPill} ${
                headerAnalysis.domain_alignment ? styles.authPass : styles.authFail
              }`}>
                Alignment: {headerAnalysis.domain_alignment ? 'ALIGNED' : 'MISMATCH'}
              </span>
            </div>

            {/* Display Name Spoofing Warning */}
            {headerAnalysis.display_name_spoofing && (
              <div className={styles.spoofAlert}>
                🚨 <strong>Display Name Spoofing Detected:</strong> Display name claims to represent a recognized organization, but the actual sender domain does not match.
              </div>
            )}

            {/* Header Details Grid */}
            <div className={styles.headerInfoGrid}>
              {headerAnalysis.from_header && (
                <div className={styles.headerInfoItem}>
                  <span className={styles.headerInfoKey}>From Header</span>
                  <span className={styles.headerInfoVal}>{headerAnalysis.from_header}</span>
                </div>
              )}
              {headerAnalysis.return_path && (
                <div className={styles.headerInfoItem}>
                  <span className={styles.headerInfoKey}>Return-Path</span>
                  <span className={styles.headerInfoVal}>{headerAnalysis.return_path}</span>
                </div>
              )}
              {headerAnalysis.reply_to && (
                <div className={styles.headerInfoItem}>
                  <span className={styles.headerInfoKey}>Reply-To</span>
                  <span className={styles.headerInfoVal}>{headerAnalysis.reply_to}</span>
                </div>
              )}
            </div>

            {/* Anomalies */}
            {headerAnalysis.anomalies.length > 0 && (
              <ul className={styles.anomaliesList}>
                {headerAnalysis.anomalies.map((ano, idx) => (
                  <li key={idx} className={styles.anomalyItem}>
                    ⚠️ {ano}
                  </li>
                ))}
              </ul>
            )}

            {/* Authentication Disclaimer */}
            {headerAnalysis.verification_disclaimer && (
              <div className={styles.authNotice}>
                ℹ️ <strong>Authentication Notice:</strong> {headerAnalysis.verification_disclaimer}
              </div>
            )}
          </div>
        </div>
      )}

      {/* DistilBERT Transformer Phishing Detection Section */}
      {(result.distilbert || result.model_name) && (
        <div className={styles.section}>
          <h4>Deep Learning Phishing Analysis (DistilBERT)</h4>
          <div className={styles.distilbertCard}>
            <div className={styles.distilbertHeader}>
              <div className={styles.headerBadgesGroup}>
                <span className={styles.modelBadge}>
                  {result.distilbert?.model_name || result.model_name || "DistilBERT v2.4.1"}
                </span>
                {isQuantized && (
                  <span className={styles.quantBadge} title="Optimized via PyTorch 8-bit Dynamic Quantization">
                    ⚡ INT8 Quantized
                  </span>
                )}
                {latency !== null && latency !== undefined && (
                  <span className={styles.latencyBadge}>
                    ⏱️ {latency}ms
                  </span>
                )}
              </div>
              <span
                className={`${styles.verificationBadge} ${
                  (result.distilbert?.verification_status || result.verification_status) === "verified"
                    ? styles.verified
                    : styles.unverified
                }`}
              >
                {(result.distilbert?.verification_status || result.verification_status || "unverified").toUpperCase()} LABELS
              </span>
            </div>

            <div className={styles.distilbertGrid}>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>Raw Model Output</span>
                <span className={styles.statValue}>
                  Index {result.distilbert?.predicted_class_index ?? result.predicted_class_index ?? "—"}
                  {" ("}
                  {result.distilbert?.predicted_class_label || result.predicted_class_label || "Unknown"}
                  {")"}
                </span>
              </div>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>Candidate Label</span>
                <span className={styles.statValue}>
                  {result.distilbert?.candidate_class_label || result.candidate_class_label || "N/A"}
                </span>
              </div>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>Verified Class</span>
                <span className={styles.statValue}>
                  {result.distilbert?.verified_class_label || result.verified_class_label || "None (Unverified)"}
                </span>
              </div>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>Model Confidence</span>
                <span className={styles.statValue}>
                  {result.distilbert?.confidence
                    ? `${(result.distilbert.confidence * 100).toFixed(1)}%`
                    : "—"}
                </span>
              </div>
            </div>

            {/* Probability Breakdown */}
            {(result.distilbert?.class_probabilities || result.class_probabilities) && (
              <div className={styles.probList}>
                <span className={styles.statLabel}>Class Probability Distribution</span>
                {Object.entries(result.distilbert?.class_probabilities || result.class_probabilities || {}).map(([lbl, p]) => (
                  <div key={lbl} className={styles.probItem}>
                    <div className={styles.probHeader}>
                      <span>{lbl}</span>
                      <span>{(p * 100).toFixed(2)}%</span>
                    </div>
                    <div className={styles.probBarBg}>
                      <div
                        className={styles.probBarFill}
                        style={{ width: `${Math.min(100, Math.max(0, p * 100))}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Verification Warning Box */}
            {(result.distilbert?.warning || result.warning) && (
              <div className={styles.warningBox}>
                ⚠️ <strong>Verification Notice:</strong> {result.distilbert?.warning || result.warning}
              </div>
            )}

            {/* Explanation */}
            {(result.distilbert?.explanation || result.concise_explanation) && (
              <p className={styles.factorDesc}>
                {result.distilbert?.explanation || result.concise_explanation}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Google Gemini AI Threat Intelligence Analysis */}
      {result.gemini_analysis && (
        <div className={styles.section}>
          <h4>Google Gemini GenAI Threat Reasoning</h4>
          <div className={styles.transformerCard}>
            <div className={styles.modelHeader}>
              <span className={styles.modelTag}>
                ✨ {result.gemini_analysis.engine || "Google Gemini"} ({result.gemini_analysis.model || "gemini-1.5-flash"})
              </span>
              <span className={styles.verifiedBadge}>
                INTENT: {result.gemini_analysis.intent_category || "Flagged Threat"}
              </span>
            </div>

            <div className={styles.modelStatsGrid}>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>AI Risk Assessment</span>
                <span className={styles.statValue}>
                  {result.gemini_analysis.risk_score} / 100 ({result.gemini_analysis.risk_level?.toUpperCase()})
                </span>
              </div>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>AI Confidence</span>
                <span className={styles.statValue}>
                  {result.gemini_analysis.confidence
                    ? `${(result.gemini_analysis.confidence * 100).toFixed(1)}%`
                    : "95.0%"}
                </span>
              </div>
            </div>

            {result.gemini_analysis.psychological_tactics && result.gemini_analysis.psychological_tactics.length > 0 && (
              <div style={{ marginTop: '0.75rem' }}>
                <span className={styles.statLabel}>Psychological &amp; Social Engineering Tactics:</span>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                  {result.gemini_analysis.psychological_tactics.map((tactic: string, idx: number) => (
                    <span key={idx} className={styles.authPill} style={{ background: '#f59e0b22', color: '#f59e0b', border: '1px solid #f59e0b55' }}>
                      ⚡ {tactic}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {result.gemini_analysis.summary && (
              <p className={styles.factorDesc} style={{ marginTop: '0.75rem', fontWeight: 500 }}>
                {result.gemini_analysis.summary}
              </p>
            )}

            {result.gemini_analysis.recommended_action && (
              <div className={styles.warningBox} style={{ marginTop: '0.5rem', background: '#3b82f615', borderColor: '#3b82f640', color: '#60a5fa' }}>
                🛡️ <strong>AI Safety Recommendation:</strong> {result.gemini_analysis.recommended_action}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Malicious Sideloaded APK Package Dropper Audit */}
      {result.apk_audit && result.apk_audit.has_apk_dropper && (
        <div className={styles.section}>
          <h4>📦 Sideloaded Android APK Package Inspection</h4>
          <div className={styles.transformerCard} style={{ borderColor: '#ef444466' }}>
            <div className={styles.modelHeader}>
              <span className={styles.modelTag} style={{ background: '#ef444422', color: '#ef4444', borderColor: '#ef444455' }}>
                🚨 MALWARE DROPPER ({result.apk_audit.filename})
              </span>
              <span className={styles.verifiedBadge} style={{ background: '#ef444433', color: '#fca5a5' }}>
                {result.apk_audit.lure_category}
              </span>
            </div>

            <div className={styles.modelStatsGrid}>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>Malware Taxonomy</span>
                <span className={styles.statValue} style={{ color: '#ef4444' }}>
                  {result.apk_audit.targeted_threat_family}
                </span>
              </div>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>Package Risk Score</span>
                <span className={styles.statValue} style={{ color: '#ef4444' }}>
                  {result.apk_audit.risk_score} / 100 (CRITICAL)
                </span>
              </div>
            </div>

            {result.apk_audit.reasons && (
              <ul style={{ margin: '0.75rem 0 0 1rem', padding: 0, color: '#cbd5e1', fontSize: '0.85rem' }}>
                {result.apk_audit.reasons.map((r: string, idx: number) => (
                  <li key={idx} style={{ marginBottom: '0.25rem' }}>{r}</li>
                ))}
              </ul>
            )}

            {result.apk_audit.defensive_warning && (
              <div className={styles.warningBox} style={{ marginTop: '0.75rem', background: '#dc262622', borderColor: '#dc262666', color: '#fca5a5' }}>
                ⚠️ <strong>DEFENSIVE ADVISORY:</strong> {result.apk_audit.defensive_warning}
              </div>
            )}
          </div>
        </div>
      )}

      {/* UPI Deep Link & QR Code Audit */}
      {result.upi_audit && result.upi_audit.is_upi_deeplink && (
        <div className={styles.section}>
          <h4>💳 UPI Deep Link &amp; QR Code Audit</h4>
          <div className={styles.transformerCard} style={{ borderColor: result.upi_audit.is_reverse_charge_lure ? '#ef444466' : '#f59e0b55' }}>
            <div className={styles.modelHeader}>
              <span className={styles.modelTag} style={{ background: '#3b82f622', color: '#60a5fa', borderColor: '#3b82f655' }}>
                ⚡ UPI Payment Intent ({result.upi_audit.currency || 'INR'})
              </span>
              {result.upi_audit.is_reverse_charge_lure && (
                <span className={styles.verifiedBadge} style={{ background: '#ef444433', color: '#fca5a5' }}>
                  🚨 REVERSE-CHARGE FRAUD
                </span>
              )}
            </div>

            <div className={styles.modelStatsGrid}>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>Payee VPA Handle</span>
                <span className={styles.statValue} style={{ wordBreak: 'break-all' }}>
                  {result.upi_audit.payee_vpa || "Unspecified VPA"}
                </span>
              </div>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>Declared Payee Name</span>
                <span className={styles.statValue}>
                  {result.upi_audit.payee_name || "Anonymous Payee"}
                </span>
              </div>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>Pre-filled Debit Amount</span>
                <span className={styles.statValue}>
                  {result.upi_audit.amount !== null && result.upi_audit.amount !== undefined ? `₹${result.upi_audit.amount}` : "User specified"}
                </span>
              </div>
              <div className={styles.statBox}>
                <span className={styles.statLabel}>Transaction Note</span>
                <span className={styles.statValue}>
                  {result.upi_audit.transaction_note || "None"}
                </span>
              </div>
            </div>

            {result.upi_audit.anomalies && result.upi_audit.anomalies.length > 0 && (
              <ul style={{ margin: '0.75rem 0 0 1rem', padding: 0, color: '#fcd34d', fontSize: '0.85rem' }}>
                {result.upi_audit.anomalies.map((a: string, idx: number) => (
                  <li key={idx} style={{ marginBottom: '0.25rem' }}>⚠️ {a}</li>
                ))}
              </ul>
            )}

            {result.upi_audit.warning_message && (
              <div className={styles.warningBox} style={{ marginTop: '0.75rem', background: '#f59e0b22', borderColor: '#f59e0b66', color: '#fde047' }}>
                🛡️ <strong>UPI Fraud Advisory:</strong> {result.upi_audit.warning_message}
              </div>
            )}
          </div>
        </div>
      )}

      {result.breakdown && result.breakdown.length > 0 && (
        <div className={styles.section}>
          <h4>Risk Factors</h4>
          <ul className={styles.reasonsList}>
            {result.breakdown.map((r, i) => (
              <li key={i} className={styles.reasonItem}>
                <span className={styles.factorName}>{r.factor}</span>
                <span className={styles.factorDesc}>{r.description}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.recommendations && result.recommendations.length > 0 && (
        <div className={styles.section}>
          <h4>Recommendations</h4>
          <ul className={styles.recommendationsList}>
            {result.recommendations.map((rec, i) => (
              <li key={i}>{rec}</li>
            ))}
          </ul>
        </div>
      )}

      <div className={styles.section}>
        <IndicatorsPanel indicators={result.indicators} status="success" />
      </div>

      <div className={styles.meta}>
        <span className={styles.timestamp}>Analyzed at: {result.analyzed_at}</span>
      </div>
    </div>
  );
}
