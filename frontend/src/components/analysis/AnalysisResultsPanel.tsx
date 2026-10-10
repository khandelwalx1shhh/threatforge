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
                <span className={styles.statLabel}>Predicted Class</span>
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
