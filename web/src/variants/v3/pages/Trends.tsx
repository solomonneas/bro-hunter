import React, { useEffect, useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  BarChart,
  Bar,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from 'recharts';

const API_BASE = import.meta.env.VITE_API_BASE || '';

const palette = {
  blue: '#2563EB',
  cyan: '#06B6D4',
  emerald: '#10B981',
  amber: '#F59E0B',
  red: '#EF4444',
  purple: '#8B5CF6',
  axis: '#94A3B8',
  border: '#E2E8F0',
  text: '#1E293B',
};

type TimelinePoint = {
  id: string;
  timestamp: string;
  date: string;
  total_threats: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
};

type SummaryResponse = {
  timeline: TimelinePoint[];
  current: TimelinePoint | null;
  previous_average_threats: number;
};

type HostTrendPoint = {
  timestamp: string;
  score: number;
  threat_level: string;
};

type HostRow = {
  ip: string;
  current_score: number;
  previous_score: number;
  delta: number;
  threat_level: string;
  trend: HostTrendPoint[];
};

type HostsResponse = { hosts: HostRow[] };

type MitreRow = {
  technique: string;
  frequency: number;
  status: 'new' | 'stable' | 'resolved';
};

type MitreResponse = { techniques: MitreRow[] };

const Sparkline: React.FC<{ data: HostTrendPoint[] }> = ({ data }) => (
  <div style={{ width: 110, height: 32 }}>
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data}>
        <Line type="monotone" dataKey="score" stroke={palette.blue} strokeWidth={2} dot={false} />
      </LineChart>
    </ResponsiveContainer>
  </div>
);

const Trends: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [busySnapshot, setBusySnapshot] = useState(false);
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [hosts, setHosts] = useState<HostRow[]>([]);
  const [mitre, setMitre] = useState<MitreRow[]>([]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [s, h, m] = await Promise.all([
        fetch(`${API_BASE}/api/v1/trends/summary?days=7`).then((r) => r.json()),
        fetch(`${API_BASE}/api/v1/trends/hosts?days=7`).then((r) => r.json()),
        fetch(`${API_BASE}/api/v1/trends/mitre?days=7`).then((r) => r.json()),
      ]);
      setSummary(s || null);
      setHosts((h as HostsResponse)?.hosts || []);
      setMitre((m as MitreResponse)?.techniques || []);
    } catch (err) {
      console.error('Failed to load trend data', err);
      setSummary(null);
      setHosts([]);
      setMitre([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const posture = useMemo(() => {
    const timeline = summary?.timeline || [];
    if (!timeline.length) return { status: 'Stable', color: palette.blue, delta: 0 };
    const latest = timeline[timeline.length - 1]?.total_threats || 0;
    const prevAvg = summary?.previous_average_threats || 0;
    const delta = Math.round(latest - prevAvg);
    if (delta <= -1) return { status: 'Improving', color: palette.emerald, delta };
    if (delta >= 1) return { status: 'Degrading', color: palette.red, delta };
    return { status: 'Stable', color: palette.blue, delta };
  }, [summary]);

  const sortedHosts = useMemo(
    () => [...hosts].sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta)),
    [hosts],
  );

  const mitreChartData = useMemo(() => mitre.slice(0, 15), [mitre]);

  const takeSnapshot = async () => {
    try {
      setBusySnapshot(true);
      const res = await fetch(`${API_BASE}/api/v1/trends/snapshot`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await loadData();
    } catch (err) {
      console.error('Snapshot failed', err);
    } finally {
      setBusySnapshot(false);
    }
  };

  if (loading) {
    return <div className="v3-card" style={{ padding: 16 }}>Loading trend analysis...</div>;
  }

  if (!summary?.timeline?.length) {
    return (
      <div style={{ display: 'grid', gap: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h1 className="v3-page-title" style={{ margin: 0 }}>Trend Analysis</h1>
            <p className="v3-page-subtitle" style={{ margin: '4px 0 0' }}>Historical threat posture and changes over time</p>
          </div>
          <button className="v3-btn v3-btn-primary" onClick={takeSnapshot} disabled={busySnapshot}>
            {busySnapshot ? 'Taking Snapshot...' : 'Take Snapshot'}
          </button>
        </div>
        <div className="v3-card" style={{ padding: 16 }}>No trend snapshots yet. Take a snapshot to begin analysis.</div>
      </div>
    );
  }

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="v3-page-title" style={{ margin: 0 }}>Trend Analysis</h1>
          <p className="v3-page-subtitle" style={{ margin: '4px 0 0' }}>Historical threat posture and risk movement</p>
        </div>
        <button className="v3-btn v3-btn-primary" onClick={takeSnapshot} disabled={busySnapshot}>
          {busySnapshot ? 'Taking Snapshot...' : 'Take Snapshot'}
        </button>
      </div>

      <section className="v3-card" style={{ padding: 16 }}>
        <div style={{ fontSize: 13, color: '#64748B' }}>Threat Posture</div>
        <div style={{ fontSize: 32, fontWeight: 800, color: posture.color, lineHeight: 1.1 }}>{posture.status}</div>
        <div style={{ marginTop: 6, color: posture.delta > 0 ? palette.red : posture.delta < 0 ? palette.emerald : palette.blue, fontWeight: 600 }}>
          {posture.delta > 0 ? `+${posture.delta}` : posture.delta} threats from last period
        </div>
      </section>

      <section className="v3-card" style={{ padding: 16 }}>
        <h3 style={{ margin: '0 0 10px', color: palette.text }}>Threat Count Over Time</h3>
        <div style={{ width: '100%', height: 300 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={summary.timeline} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
              <CartesianGrid stroke={palette.border} strokeDasharray="3 3" />
              <XAxis dataKey="date" stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 11 }} />
              <YAxis stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 11 }} />
              <Tooltip />
              <Area type="monotone" dataKey="total_threats" stroke={palette.blue} fill={palette.blue} fillOpacity={0.12} />
              <Line type="monotone" dataKey="total_threats" stroke={palette.blue} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="critical" stroke={palette.red} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="high" stroke={palette.amber} strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="medium" stroke={palette.cyan} strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="v3-card" style={{ padding: 16 }}>
        <h3 style={{ margin: '0 0 10px', color: palette.text }}>Host Risk Score Changes</h3>
        {!sortedHosts.length ? (
          <div>No host trend data available.</div>
        ) : (
          <div className="v3-table-wrapper">
            <table className="v3-table">
              <thead>
                <tr>
                  <th>Host IP</th>
                  <th style={{ textAlign: 'right' }}>Current Score</th>
                  <th style={{ textAlign: 'right' }}>Previous Score</th>
                  <th style={{ textAlign: 'right' }}>Delta</th>
                  <th>Trend</th>
                </tr>
              </thead>
              <tbody>
                {sortedHosts.map((h) => {
                  const up = h.delta > 0;
                  const down = h.delta < 0;
                  return (
                    <tr key={h.ip}>
                      <td className="mono">{h.ip}</td>
                      <td style={{ textAlign: 'right' }}>{h.current_score.toFixed(3)}</td>
                      <td style={{ textAlign: 'right' }}>{h.previous_score.toFixed(3)}</td>
                      <td style={{ textAlign: 'right', color: up ? palette.red : down ? palette.emerald : palette.axis, fontWeight: 700 }}>
                        {up ? '↑' : down ? '↓' : '→'} {h.delta > 0 ? '+' : ''}{h.delta.toFixed(3)}
                      </td>
                      <td><Sparkline data={h.trend || []} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="v3-card" style={{ padding: 16 }}>
        <h3 style={{ margin: '0 0 10px', color: palette.text }}>MITRE Technique Frequency</h3>
        {!mitreChartData.length ? (
          <div>No MITRE trend data available.</div>
        ) : (
          <div style={{ width: '100%', height: 340 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={mitreChartData} layout="vertical" margin={{ top: 8, right: 16, left: 16, bottom: 0 }}>
                <CartesianGrid stroke={palette.border} strokeDasharray="3 3" />
                <XAxis type="number" stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 11 }} />
                <YAxis dataKey="technique" type="category" width={90} stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="frequency" radius={[0, 6, 6, 0]}>
                  {mitreChartData.map((row) => (
                    <Cell
                      key={row.technique}
                      fill={row.status === 'new' ? palette.red : row.status === 'resolved' ? palette.emerald : palette.blue}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </section>
    </div>
  );
};

export default Trends;
