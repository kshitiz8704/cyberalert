import { useCallback, useEffect, useState } from 'react';
import {
  Chart as ChartJS, ArcElement, BarElement, CategoryScale, LinearScale,
  LineElement, PointElement, Tooltip, Legend
} from 'chart.js';
import { Doughnut, Bar, Line } from 'react-chartjs-2';
import { getAlerts, getStats } from './api.js';

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, LineElement, PointElement, Tooltip, Legend);
ChartJS.defaults.color = '#94a3b8';

const SEVERITIES = ['Low', 'Medium', 'High', 'Critical'];
const COLORS = { Low: '#3b82f6', Medium: '#eab308', High: '#f97316', Critical: '#ef4444' };

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [pages, setPages] = useState(1);
  const [stats, setStats] = useState(null);
  const [filters, setFilters] = useState({ severity: '', category: '', search: '' });
  const [page, setPage] = useState(1);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const q = { page, limit: 15 };
      Object.entries(filters).forEach(([k, v]) => v && (q[k] = v));
      const [a, s] = await Promise.all([getAlerts(q), getStats()]);
      setAlerts(a.alerts); setPages(a.pages || 1); setStats(s); setError('');
    } catch {
      setError('Cannot reach the backend. Is it running on port 5000?');
    }
  }, [filters, page]);

  // load now, then refresh every 5 seconds (simple "live" updates)
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  const setFilter = (k, v) => { setFilters({ ...filters, [k]: v }); setPage(1); };
  const sev = stats?.bySeverity || {};
  const cat = stats?.byCategory || {};

  return (
    <div className="wrap">
      <header>
        <h1>🛡️ CyberAlert</h1>
        <div className="reports">
          <a href="/api/report/pdf">⬇ PDF report</a>
          <a href="/api/report/csv">⬇ CSV report</a>
        </div>
      </header>
      {error && <div className="error">{error}</div>}

      <section className="cards">
        <Card label="Total events" value={stats?.total ?? 0} />
        <Card label="Host alerts" value={cat.Host ?? 0} />
        <Card label="Network alerts" value={cat.Network ?? 0} />
        <Card label="Malware alerts" value={cat.Malware ?? 0} />
        <Card label="Critical" value={sev.Critical ?? 0} color={COLORS.Critical} />
      </section>

      <section className="charts">
        <div className="panel">
          <h3>Alerts by severity</h3>
          <Doughnut data={{
            labels: SEVERITIES,
            datasets: [{ data: SEVERITIES.map((s) => sev[s] || 0), backgroundColor: SEVERITIES.map((s) => COLORS[s]), borderWidth: 0 }]
          }} />
        </div>
        <div className="panel">
          <h3>Attack categories</h3>
          <Bar options={{ indexAxis: 'y', plugins: { legend: { display: false } } }} data={{
            labels: (stats?.byType || []).slice(0, 8).map((t) => t.name),
            datasets: [{ data: (stats?.byType || []).slice(0, 8).map((t) => t.count), backgroundColor: '#38bdf8' }]
          }} />
        </div>
        <div className="panel">
          <h3>Last 24 hours</h3>
          <Line options={{ plugins: { legend: { display: false } } }} data={{
            labels: (stats?.timeline || []).map((t) => t.hour),
            datasets: [{ data: (stats?.timeline || []).map((t) => t.count), borderColor: '#a78bfa', tension: 0.3 }]
          }} />
        </div>
      </section>

      <section className="panel">
        <div className="filters">
          <select value={filters.severity} onChange={(e) => setFilter('severity', e.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
          <select value={filters.category} onChange={(e) => setFilter('category', e.target.value)}>
            <option value="">All categories</option>
            <option>Malware</option><option>Host</option><option>Network</option>
          </select>
          <input placeholder="Search type, source, details…" value={filters.search}
                 onChange={(e) => setFilter('search', e.target.value)} />
        </div>
        <div className="scroll">
          <table>
            <thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Type</th><th>Source</th><th>Details</th></tr></thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a._id}>
                  <td>{new Date(a.timestamp).toLocaleString()}</td>
                  <td><span className="badge" style={{ background: COLORS[a.severity] }}>{a.severity}</span></td>
                  <td>{a.category}</td><td>{a.type}</td><td className="mono">{a.source}</td><td>{a.details}</td>
                </tr>
              ))}
              {!alerts.length && <tr><td colSpan="6" className="empty">No alerts yet.</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="pager">
          <button disabled={page <= 1} onClick={() => setPage(page - 1)}>← Prev</button>
          <span>Page {page} / {pages}</span>
          <button disabled={page >= pages} onClick={() => setPage(page + 1)}>Next →</button>
        </div>
      </section>
    </div>
  );
}

function Card({ label, value, color }) {
  return <div className="card"><div className="val" style={{ color }}>{value}</div><div>{label}</div></div>;
}
