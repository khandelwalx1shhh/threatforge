import { useState, useCallback } from 'react';
import type { AnalysisResult } from '../types/api';
import { request } from '../api/client';
import { AnalysisResultsPanel } from '../components/analysis/AnalysisResultsPanel';
import { ErrorState } from '../components/common/ErrorState';
import styles from './AnalyzePage.module.css';

const SAMPLE_BENIGN = "Hi team, just a reminder about the team standup at 3 PM tomorrow. See you there!";
const SAMPLE_SUSPICIOUS = "URGENT: Your bank account has been locked. Verify your identity immediately at http://secure-banking-verify.example/login or your account will be permanently suspended.";
const SAMPLE_EMAIL_PHISH = `Received-SPF: fail (domain of alert-support.com does not designate sender IP)
Authentication-Results: mx.google.com; dkim=fail; dmarc=fail
From: "PayPal Security Center" <service@alert-support.com>
Return-Path: <bounce@malicious-relay.ru>
Reply-To: <phish-collector@gmail.com>
Subject: Security Alert: Your Account Access Has Been Restricted

Dear Customer,

We detected irregular transactions on your account. To prevent account termination, verify your account details immediately at http://paypal-resolution.login-portal.xyz/restore and submit your confirmation credentials.`;

export function AnalyzePage() {
  const [message, setMessage] = useState('');
  const [rawHeaders, setRawHeaders] = useState('');
  const [showHeadersInput, setShowHeadersInput] = useState(false);
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const handleAnalyze = useCallback(async () => {
    const trimmedMessage = message.trim();
    if (!trimmedMessage) return;

    setStatus('loading');
    setErrorMsg(null);

    try {
      const payload: Record<string, any> = {
        text: trimmedMessage,
        message: trimmedMessage,
      };

      if (rawHeaders.trim()) {
        payload.raw_headers = rawHeaders.trim();
      }

      const res = await request<AnalysisResult>('/api/analyze', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      
      setResult(res);
      setStatus('success');
    } catch (err: any) {
      console.error(err);
      setErrorMsg(err.userMessage || err.message || 'Failed to connect to backend analysis endpoint.');
      setStatus('error');
    }
  }, [message, rawHeaders]);

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
        <p>Submit suspicious messages, text, or full emails to evaluate threat indicators, ML signals, and email security headers.</p>
      </div>

      <div className={styles.grid}>
        {/* Left Column: Form */}
        <div className={styles.formSection}>
          <div className={styles.formGroup}>
            <label htmlFor="analyze-msg">Message or Email Content</label>
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

          {/* Optional Raw Headers Input */}
          <div className={styles.formGroup}>
            <button
              type="button"
              className={styles.sampleBtn}
              onClick={() => setShowHeadersInput(!showHeadersInput)}
              style={{ alignSelf: 'flex-start', marginBottom: '0.4rem' }}
            >
              {showHeadersInput ? '▼ Hide Separate Email Headers' : '▶ Add Separate Email Headers (Optional)'}
            </button>
            {showHeadersInput && (
              <textarea
                id="analyze-headers"
                className={styles.textarea}
                style={{ minHeight: '90px', fontFamily: 'monospace', fontSize: '0.8rem' }}
                placeholder="From: ...&#10;Return-Path: ...&#10;Received-SPF: fail&#10;Authentication-Results: ...&#10;Reply-To: ..."
                value={rawHeaders}
                onChange={(e) => setRawHeaders(e.target.value)}
                disabled={status === 'loading'}
              />
            )}
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
            <button 
              className={styles.sampleBtn} 
              onClick={() => loadSample(SAMPLE_EMAIL_PHISH)}
              disabled={status === 'loading'}
            >
              Phishing Email + Headers
            </button>
          </div>

          <button 
            className={styles.submitBtn} 
            onClick={handleAnalyze}
            disabled={isSubmitDisabled}
          >
            {status === 'loading' ? 'Analyzing...' : 'Analyze Content'}
          </button>
        </div>

        {/* Right Column: Results */}
        <div className={styles.resultSection}>
          {status === 'idle' && (
            <div className={styles.emptyState}>
              <span>🛡️</span>
              <p>Awaiting submission</p>
              <small>Submit a sample message or full email above to begin multi-engine analysis.</small>
            </div>
          )}

          {status === 'loading' && (
            <div className={styles.loadingState}>
              <div className={styles.spinner} />
              <p>Running multi-engine threat detection...</p>
              <small>Evaluating deterministic rules, DistilBERT transformer, and email header records.</small>
            </div>
          )}

          {status === 'error' && (
            <ErrorState 
              message={errorMsg || 'Failed to analyze content.'} 
              onRetry={handleAnalyze} 
            />
          )}

          {status === 'success' && result && (
            <AnalysisResultsPanel 
              result={result} 
              onEdit={() => setStatus('idle')} 
            />
          )}
        </div>
      </div>
    </div>
  );
}
