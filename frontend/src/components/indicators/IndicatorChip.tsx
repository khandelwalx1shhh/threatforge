import { useState, useCallback } from 'react';
import type { Indicator } from '../../types/api';
import styles from './IndicatorChip.module.css';

interface IndicatorChipProps {
  indicator: Indicator;
}

export function IndicatorChip({ indicator }: IndicatorChipProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(indicator.value);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    } catch (err) {
      console.error('Failed to copy text', err);
    }
  }, [indicator.value]);

  return (
    <div className={styles.chip} aria-label={`${indicator.type} indicator`}>
      <div className={styles.header}>
        <span className={styles.type}>
          <span className={styles.icon}>⌁</span>
          {indicator.type}
        </span>
        <div className={styles.badges}>
          {indicator.confidence != null && (
            <span className={styles.confidence} title="Extraction Confidence">
              Conf: {(indicator.confidence * 100).toFixed(0)}%
            </span>
          )}
          <span className={`${styles.severity} ${styles[indicator.severity.toLowerCase()]}`}>
            {indicator.severity}
          </span>
        </div>
      </div>
      
      <div className={styles.body}>
        <code className={styles.value} title={indicator.value}>
          {indicator.value}
        </code>
        <button 
          className={styles.copyBtn} 
          onClick={handleCopy}
          aria-label="Copy indicator value"
          title="Copy to clipboard"
        >
          {copied ? '✓' : '⎘'}
        </button>
      </div>
    </div>
  );
}
