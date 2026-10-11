import { useState, useEffect } from 'react';
import './App.css';
import { checkBackendHealth } from './api/client';
import { IndicatorsPanel } from './components/indicators/IndicatorsPanel';
import { AnalyzePage } from './pages/AnalyzePage';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

const threats = [
  { type: 'Phishing URL', value: 'secure-banking-verify.example', severity: 'HIGH', time: '2 min ago' },
  { type: 'UPI ID', value: 'support-alert@upi', severity: 'MEDIUM', time: '8 min ago' },
  { type: 'Suspicious Phone', value: '+91 98XXX XX421', severity: 'HIGH', time: '14 min ago' },
  { type: 'Social Engineering', value: 'Urgent account verification', severity: 'LOW', time: '21 min ago' },
]

const activity = [
  { title: 'New honeypot session started', detail: 'Session #TF-1042', time: 'Just now' },
  { title: 'Suspicious indicator extracted', detail: 'Phishing URL · Session #TF-1040', time: '2 min ago' },
  { title: 'Threat severity updated', detail: 'HIGH · Session #TF-1038', time: '8 min ago' },
]

function App() {
  const [healthStatus, setHealthStatus] = useState<'Checking' | 'Connected' | 'Offline'>('Checking');
  const [activeTab, setActiveTab] = useState<'overview' | 'analyze'>('overview');

  useEffect(() => {
    let mounted = true;
    checkBackendHealth()
      .then((res) => {
        if (mounted) {
          setHealthStatus(res.status === 'ok' ? 'Connected' : 'Offline');
        }
      })
      .catch(() => {
        if (mounted) setHealthStatus('Offline');
      });
    return () => { mounted = false; };
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img src="/logo_transparent.png" alt="Argus Logo" className="brand-logo-img" />
          <span>Arg<span className="accent">us</span></span>
        </div>
        <div className="side-label">WORKSPACE</div>
        <a 
          className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`} 
          href="#overview"
          onClick={(e) => { e.preventDefault(); setActiveTab('overview'); }}
        >
          ▦ <span>Overview</span>
        </a>
        <a 
          className={`nav-item ${activeTab === 'analyze' ? 'active' : ''}`} 
          href="#analyze"
          onClick={(e) => { e.preventDefault(); setActiveTab('analyze'); }}
        >
          ⌁ <span>Analyze Content</span>
        </a>
        <div className="sidebar-bottom"><span className="live-dot" /> Systems operational <small>ARGUS SOC</small></div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">Workspace <span>/</span> {activeTab === 'overview' ? 'Overview' : 'Analyze'}</div>
          <div className="top-right">
            <span className="status-pill"><i /> Active Shield</span>
            <div className="avatar" style={{ padding: '2px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <img src="/logo_transparent.png" alt="Argus" style={{ width: '24px', height: '24px', objectFit: 'contain' }} />
            </div>
          </div>
        </header>

        {activeTab === 'overview' ? (
          <div id="overview">
            <section className="page-heading">
              <div><div className="eyebrow">SECURITY OPERATIONS CENTER</div><h1>Threat Intelligence</h1><p>Monitor suspicious activity and track intelligence captured by your honeypot.</p></div>
              <button className="primary-btn" onClick={() => setActiveTab('analyze')}>＋ Analyze Content</button>
            </section>

            <section className="metrics">
              <article className="metric-card"><div className="metric-top"><span>Total sessions</span><span className="metric-icon">◉</span></div><div className="metric-value">128</div><div className="metric-foot"><span className="positive">↑ 12%</span> <span>vs. previous period</span></div><div className="sparkline green">▁▂▁▃▂▄▃▅▃▆▄▇</div></article>
              <article className="metric-card"><div className="metric-top"><span>Indicators captured</span><span className="metric-icon">⌘</span></div><div className="metric-value">346</div><div className="metric-foot"><span className="positive">↑ 8.4%</span> <span>vs. previous period</span></div><div className="sparkline blue">▁▂▃▂▄▃▅▄▆▅▇▆</div></article>
              <article className="metric-card"><div className="metric-top"><span>High severity</span><span className="metric-icon danger">⚠</span></div><div className="metric-value">23</div><div className="metric-foot"><span className="negative">Needs attention</span></div><div className="sparkline red">▂▁▃▂▅▃▆▄▅▃▇▅</div></article>
              <article className="metric-card"><div className="metric-top"><span>Active sessions</span><span className="metric-icon">◎</span></div><div className="metric-value">07</div><div className="metric-foot"><span className="live-dot" /> <span>Currently monitoring</span></div><div className="sparkline purple">▁▃▂▄▃▅▄▃▆▄▅▇</div></article>
            </section>

            <section className="content-grid">
              <div id="threats">
                {/* Development-only mock adapter for Phase 1 demo data. 
                    TODO: Replace with actual backend response from /api/extract when integration is ready */}
                <IndicatorsPanel 
                  status="success"
                  indicators={threats.map(t => ({
                    type: t.type,
                    value: t.value,
                    severity: t.severity as any,
                    confidence: t.severity === 'HIGH' ? 0.95 : t.severity === 'MEDIUM' ? 0.75 : 0.45
                  }))} 
                />
              </div>

              <article className="panel activity-panel" id="sessions">
                <div className="panel-heading"><div><h2>Recent activity</h2><p>Latest events across your honeypot</p></div><span className="live-label"><i /> LIVE</span></div>
                <div className="activity-list">{activity.map((a, i) => <div className="activity-item" key={a.title}><div className={`activity-marker marker-${i}`}>{i === 0 ? '◉' : i === 1 ? '⌁' : '⚑'}</div><div className="activity-copy"><strong>{a.title}</strong><p>{a.detail}</p><small>{a.time}</small></div></div>)}</div>
                <div className="panel-footer">Demo activity · Not connected to backend</div>
              </article>
            </section>

            <section className="bottom-grid" id="indicators">
              <article className="panel mini-panel"><div className="panel-heading"><div><h2>Threat distribution</h2><p>By indicator category</p></div></div><div className="distribution"><div className="dist-row"><span>Phishing URLs</span><div className="bar-track"><div className="bar phishing" style={{ width: '76%' }} /></div><b>76</b></div><div className="dist-row"><span>Phone numbers</span><div className="bar-track"><div className="bar phone" style={{ width: '54%' }} /></div><b>54</b></div><div className="dist-row"><span>UPI IDs</span><div className="bar-track"><div className="bar upi" style={{ width: '42%' }} /></div><b>42</b></div><div className="dist-row"><span>Other indicators</span><div className="bar-track"><div className="bar other" style={{ width: '28%' }} /></div><b>28</b></div></div></article>
              <article className="panel mini-panel">
                <div className="panel-heading">
                  <div>
                    <h2>System health</h2>
                    <p>API: {API_BASE_URL}</p>
                  </div>
                  {healthStatus === 'Checking' && <span className="health-badge" style={{color: '#f1c779', background: '#32251f'}}>● CHECKING</span>}
                  {healthStatus === 'Connected' && <span className="health-badge">● HEALTHY</span>}
                  {healthStatus === 'Offline' && <span className="health-badge" style={{color: '#ff8188', background: '#2b1a24'}}>● OFFLINE</span>}
                </div>
                <div className="health-list">
                  <div><span>Frontend</span><b><i /> Online</b></div>
                  <div>
                    <span>API connection</span>
                    {healthStatus === 'Connected' ? (
                      <b><i /> Connected</b>
                    ) : healthStatus === 'Checking' ? (
                      <b className="waiting"><i /> Checking...</b>
                    ) : (
                      <b style={{color: '#ff8188'}}><i style={{background: '#ff8188', boxShadow: 'none'}} /> Unreachable</b>
                    )}
                  </div>
                  <div><span>Threat analysis</span><b><i /> Demo mode</b></div>
                </div>
                <div className="health-note">Backend integration will be enabled when the API is configured.</div>
              </article>
            </section>
          </div>
        ) : (
          <div id="analyze" style={{ marginTop: '24px' }}>
            <AnalyzePage />
          </div>
        )}
        <footer className="footer"><span>Argus <span className="accent">●</span> Autonomous Cyber Defense Platform</span><span>Production Grade · Zero Leakage</span></footer>
      </main>
    </div>
  )
}

export default App
