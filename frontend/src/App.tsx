import './App.css'

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
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-icon">T</span><span>Threat<span className="accent">Forge</span></span></div>
        <div className="side-label">WORKSPACE</div>
        <a className="nav-item active" href="#overview">▦ <span>Overview</span></a>
        <a className="nav-item" href="#threats">⌁ <span>Threat Intelligence</span></a>
        <a className="nav-item" href="#sessions">◉ <span>Honeypot Sessions</span></a>
        <a className="nav-item" href="#indicators">⌘ <span>Indicators (IOCs)</span></a>
        <div className="sidebar-bottom"><span className="live-dot" /> Systems operational <small>THREATFORGE MVP</small></div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div className="breadcrumb">Workspace <span>/</span> Overview</div>
          <div className="top-right"><span className="status-pill"><i /> Demo environment</span><div className="avatar">TF</div></div>
        </header>

        <section className="page-heading">
          <div><div className="eyebrow">SECURITY OPERATIONS CENTER</div><h1>Threat Intelligence</h1><p>Monitor suspicious activity and track intelligence captured by your honeypot.</p></div>
          <button className="primary-btn" onClick={() => window.location.hash = 'sessions'}>＋ View sessions</button>
        </section>

        <section className="metrics">
          <article className="metric-card"><div className="metric-top"><span>Total sessions</span><span className="metric-icon">◉</span></div><div className="metric-value">128</div><div className="metric-foot"><span className="positive">↑ 12%</span> <span>vs. previous period</span></div><div className="sparkline green">▁▂▁▃▂▄▃▅▃▆▄▇</div></article>
          <article className="metric-card"><div className="metric-top"><span>Indicators captured</span><span className="metric-icon">⌘</span></div><div className="metric-value">346</div><div className="metric-foot"><span className="positive">↑ 8.4%</span> <span>vs. previous period</span></div><div className="sparkline blue">▁▂▃▂▄▃▅▄▆▅▇▆</div></article>
          <article className="metric-card"><div className="metric-top"><span>High severity</span><span className="metric-icon danger">⚠</span></div><div className="metric-value">23</div><div className="metric-foot"><span className="negative">Needs attention</span></div><div className="sparkline red">▂▁▃▂▅▃▆▄▅▃▇▅</div></article>
          <article className="metric-card"><div className="metric-top"><span>Active sessions</span><span className="metric-icon">◎</span></div><div className="metric-value">07</div><div className="metric-foot"><span className="live-dot" /> <span>Currently monitoring</span></div><div className="sparkline purple">▁▃▂▄▃▅▄▃▆▄▅▇</div></article>
        </section>

        <section className="content-grid">
          <article className="panel threat-panel" id="threats">
            <div className="panel-heading"><div><h2>Captured indicators</h2><p>Recently identified threat intelligence</p></div><button className="text-btn" onClick={() => window.location.hash = 'indicators'}>View all ↗</button></div>
            <div className="table-wrap"><table><thead><tr><th>TYPE</th><th>INDICATOR</th><th>SEVERITY</th><th>DETECTED</th></tr></thead><tbody>{threats.map((t) => <tr key={t.value}><td><span className="type-icon">⌁</span>{t.type}</td><td className="indicator">{t.value}</td><td><span className={`severity ${t.severity.toLowerCase()}`}>{t.severity}</span></td><td className="muted">{t.time}</td></tr>)}</tbody></table></div>
            <div className="panel-footer">Showing sample data for demonstration</div>
          </article>

          <article className="panel activity-panel" id="sessions">
            <div className="panel-heading"><div><h2>Recent activity</h2><p>Latest events across your honeypot</p></div><span className="live-label"><i /> LIVE</span></div>
            <div className="activity-list">{activity.map((a, i) => <div className="activity-item" key={a.title}><div className={`activity-marker marker-${i}`}>{i === 0 ? '◉' : i === 1 ? '⌁' : '⚑'}</div><div className="activity-copy"><strong>{a.title}</strong><p>{a.detail}</p><small>{a.time}</small></div></div>)}</div>
            <div className="panel-footer">Demo activity · Not connected to backend</div>
          </article>
        </section>

        <section className="bottom-grid" id="indicators">
          <article className="panel mini-panel"><div className="panel-heading"><div><h2>Threat distribution</h2><p>By indicator category</p></div></div><div className="distribution"><div className="dist-row"><span>Phishing URLs</span><div className="bar-track"><div className="bar phishing" style={{ width: '76%' }} /></div><b>76</b></div><div className="dist-row"><span>Phone numbers</span><div className="bar-track"><div className="bar phone" style={{ width: '54%' }} /></div><b>54</b></div><div className="dist-row"><span>UPI IDs</span><div className="bar-track"><div className="bar upi" style={{ width: '42%' }} /></div><b>42</b></div><div className="dist-row"><span>Other indicators</span><div className="bar-track"><div className="bar other" style={{ width: '28%' }} /></div><b>28</b></div></div></article>
          <article className="panel mini-panel"><div className="panel-heading"><div><h2>System health</h2><p>API: {API_BASE_URL}</p></div><span className="health-badge">● HEALTHY</span></div><div className="health-list"><div><span>Frontend</span><b><i /> Online</b></div><div><span>API connection</span><b className="waiting"><i /> Not connected</b></div><div><span>Threat analysis</span><b><i /> Demo mode</b></div></div><div className="health-note">Backend integration will be enabled when the API is configured.</div></article>
        </section>
        <footer className="footer"><span>ThreatForge <span className="accent">●</span> Threat intelligence platform</span><span>Hackathon MVP · Demo data only</span></footer>
      </main>
    </div>
  )
}

export default App
