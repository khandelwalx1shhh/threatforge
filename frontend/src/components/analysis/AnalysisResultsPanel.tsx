import type { AnalysisResult } from '../../types/api';
import { IndicatorsPanel } from '../indicators/IndicatorsPanel';
import styles from './AnalysisResultsPanel.module.css';

interface AnalysisResultsPanelProps {
  result: AnalysisResult;
  onEdit: () => void;
}

export function AnalysisResultsPanel({ result, onEdit }: AnalysisResultsPanelProps) {
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
        <IndicatorsPanel 
          status="success" 
          indicators={result.indicators || []} 
        />
      </div>

      <div className={styles.disclaimer} role="note">
        <p>
          <strong>Disclaimer:</strong> THREATFORGE provides automated risk assessments based on available evidence. 
          A score or indicator match is not proof of identity, ownership, malicious intent, or guilt. 
          Review the supporting evidence before taking action.
        </p>
      </div>
    </div>
  );
}
