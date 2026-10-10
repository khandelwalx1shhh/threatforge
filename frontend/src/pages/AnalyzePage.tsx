import { useState, useCallback } from 'react';
import type { AnalysisResult } from '../types/api';
import { request } from '../api/client';
import { IndicatorsPanel } from '../components/indicators/IndicatorsPanel';
import styles from './AnalyzePage.module.css';

const SAMPLE_BENIGN = "Hi team, just a reminder about the meeting at 3 PM tomorrow. See you there!";
const SAMPLE_SUSPICIOUS = "URGENT: Your account has been locked. Verify your identity immediately at http://secure-banking-verify.example/login or your account will be permanently suspended.";

export function AnalyzePage() {
  const [message, setMessage] = useState('');
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  // Note: The backend contract for AnalysisRequest requires 'message'.
  // It does not define a 'source' enum or 'text' field. Thus, the source selector
  // is intentionally omitted here to strictly follow the backend Pydantic schema.

  const handleAnalyze = useCallback(async () => {
    const trimmedMessage = message.trim();
    if (!trimmedMessage) return;

    setStatus('loading');
    setErrorMsg(null);

    try {
      // Send exactly the schema defined in backend/app/schemas/analyze.py (AnalyzeRequest)
      const res = await request<AnalysisResult>('/api/analyze', {
        method: 'POST',
        body: JSON.stringify({ message: trimmedMessage })
      });
      
      setResult(res);
      setStatus('success');
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.message || 'Failed to connect to backend analysis endpoint.');
      setStatus('error');
    }
  }, [message]);

  const loadSample = (text: string) => {
    setMessage(text);
    setStatus('idle');
    setResult(null);
  };

  const isSubmitDisabled = !message.trim() || status === 'loading';

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h2>Analyze Content</h2>
        <p>Submit suspicious messages or text to evaluate threat indicators and scam risk.</p>
      </div>

      <div className={styles.grid}>
        {/* Left Column: Form */}
        <div className={styles.formSection}>
          <div className={styles.formGroup}>
            <label htmlFor="analyze-msg">Message Content</label>
            <textarea
              id="analyze-msg"
              className={styles.textarea}
              placeholder="Paste suspicious text, emails, or SMS messages here..."
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              disabled={status === 'loading'}
            />
            <div className={styles.wordCount}>
              {message.trim().length} characters
            </div>
          </div>

          <div className={styles.samples}>
            <span className={styles.samplesLabel}>Test Samples:</span>
            <button 
              className={styles.sampleBtn} 
              onClick={() => loadSample(SAMPLE_BENIGN)}
              disabled={status === 'loading'}
            >
              Benign Control
            </button>
            <button 
              className={styles.sampleBtn} 
              onClick={() => loadSample(SAMPLE_SUSPICIOUS)}
              disabled={status === 'loading'}
            >
              Suspicious URL
            </button>
          </div>

          <button 
            className={styles.submitBtn} 
            onClick={handleAnalyze}
            disabled={isSubmitDisabled}
          >
            {status === 'loading' ? 'Analyzing...' : 'Analyze Content'}
          </button>

          {status === 'error' && (
            <div className={styles.errorMsg}>
              ⚠ {errorMsg}
            </div>
          )}
        </div>

        {/* Right Column: Results */}
        <div className={styles.resultSection}>
          {status === 'idle' && (
            <div className={styles.emptyState}>
              <span>🛡️</span>
              <p>Awaiting submission</p>
            </div>
          )}
          
          {status === 'loading' && (
            <div className={styles.emptyState}>
              <div className={styles.spinner} />
              <p>Analyzing risk factors...</p>
            </div>
          )}

          {status === 'success' && result && (
            <div className={styles.resultContent}>
              <div className={styles.scoreCard}>
                <div className={styles.scoreTop}>
                  <span>Overall Risk Score</span>
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
                <div className={styles.reasonsBox}>
                  <h4>Risk Factors</h4>
                  <ul className={styles.reasonsList}>
                    {result.breakdown.map((r, i) => (
                      <li key={i}>
                        <span className={styles.factorName}>{r.factor}</span>
                        <span className={styles.factorDesc}>{r.description}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <IndicatorsPanel 
                status="success" 
                indicators={result.indicators || []} 
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
