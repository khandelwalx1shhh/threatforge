import { useMemo } from 'react';
import type { Indicator } from '../../types/api';
import { IndicatorChip } from './IndicatorChip';
import styles from './IndicatorsPanel.module.css';

export type AnalysisStatus = 'idle' | 'loading' | 'success' | 'error';

interface IndicatorsPanelProps {
  indicators: Indicator[];
  status: AnalysisStatus;
}

export function IndicatorsPanel({ indicators, status }: IndicatorsPanelProps) {
  // Deduplicate indicators by composite key (type + value)
  const uniqueIndicators = useMemo(() => {
    const map = new Map<string, Indicator>();
    for (const ind of indicators) {
      const key = `${ind.type}::${ind.value}`;
      // In case of duplicates, keep the first one encountered (or we could merge logic)
      if (!map.has(key)) {
        map.set(key, ind);
      }
    }
    return Array.from(map.values());
  }, [indicators]);

  if (status === 'loading') {
    return (
      <div className={`${styles.panel} ${styles.emptyState}`}>
        <div className={styles.spinner}></div>
        <p>Analyzing content for indicators...</p>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className={`${styles.panel} ${styles.emptyState}`}>
        <span className={styles.errorIcon}>⚠</span>
        <p>Analysis failed. Could not extract indicators.</p>
      </div>
    );
  }

  if (status === 'idle') {
    return (
      <div className={`${styles.panel} ${styles.emptyState}`}>
        <span className={styles.idleIcon}>🔍</span>
        <p>Submit text or conversations to extract threat indicators.</p>
      </div>
    );
  }

  if (uniqueIndicators.length === 0) {
    return (
      <div className={`${styles.panel} ${styles.emptyState}`}>
        <span className={styles.safeIcon}>✓</span>
        <p>No indicators were found in the submitted content.</p>
        <small className={styles.disclaimer}>Note: This does not guarantee the content is entirely safe.</small>
      </div>
    );
  }

  return (
    <div className={styles.panel}>
      <div className={styles.header}>
        <h3>Extracted Indicators</h3>
        <span className={styles.badge}>{uniqueIndicators.length} Found</span>
      </div>
      <div className={styles.grid}>
        {uniqueIndicators.map((ind) => (
          <IndicatorChip key={`${ind.type}::${ind.value}`} indicator={ind} />
        ))}
      </div>
    </div>
  );
}
