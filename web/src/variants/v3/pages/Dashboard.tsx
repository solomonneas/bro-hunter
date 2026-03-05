import React, { useEffect, useMemo, useState } from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  AreaChart,
  Area,
  Brush,
  Cell,
} from 'recharts';
import LoadingSkeleton from '../../../components/LoadingSkeleton';
import LiveIndicator from '../../../components/LiveIndicator';
import { useLiveRefresh, LiveEvent } from '../../../hooks/useLiveRefresh';

const API_BASE = import.meta.env.VITE_API_BASE || '';
const IS_DEV = import.meta.env.DEV ?? false;

interface GeoSummary {
  connections: number;
  dns_queries: number;
  alerts: number;
  unique_source_ips: number;
  unique_dest_ips: number;
  unique_domains: number;
  time_range?: string;
}

interface ProtocolRow {
  protocol: string;
  connections: number;
  total_bytes: number;
}

interface TalkerRow {
  ip: string;
  bytes_sent: number;
  bytes_recv: number;
  total_bytes: number;
  connections: number;
}

interface TimelineRow {
  timestamp: string;
  time: string;
  connections: number;
  bytes: number;
  alerts: number;
}

interface HeatmapRow {
  src_ip: string;
  dst_ip: string;
  threat_score: number;
  connections: number;
  alerts: number;
}

interface RecentFinding {
  id: string;
  type: 'conn' | 'dns' | 'alert';
  timestamp: string;
  description: string;
  source: string;
}

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

const cardStyle: React.CSSProperties = {
  background: '#fff',
  border: '1px solid #E2E8F0',
  borderRadius: 8,
  boxShadow: '0 1px 3px rgba(0,0,0,0.06)',
};

const getScorePill = (score: number): React.CSSProperties => {
  if (score >= 0.75) return { background: 'rgba(239,68,68,0.14)', color: '#B91C1C' };
  if (score >= 0.5) return { background: 'rgba(245,158,11,0.18)', color: '#B45309' };
  if (score > 0) return { background: 'rgba(37,99,235,0.12)', color: '#1D4ED8' };
  return { background: '#F1F5F9', color: '#64748B' };
};

/**
 * Convert live events to recent findings for display.
 */
function eventsToFindings(events: LiveEvent[]): RecentFinding[] {
  return events.slice(-20).reverse().map(event => {
    let description = '';
    const data = event.data;
    
    switch (event.event_type) {
      case 'conn':
        description = `${data.src_ip}:${data.src_port} → ${data.dst_ip}:${data.dst_port} (${data.proto})`;
        break;
      case 'dns':
        description = `DNS query: ${data.query || 'unknown'} (${data.qtype || '?'})`;
        break;
      case 'alert':
        description = `Alert: ${data.signature || data.category || 'Security event'}`;
        break;
      default:
        description = `${event.event_type} event from ${event.source}`;
    }
    
    return {
      id: event.id,
      type: event.event_type as 'conn' | 'dns' | 'alert',
      timestamp: event.timestamp,
      description,
      source: event.source,
    };
  });
}

const Dashboard: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [demoMode, setDemoMode] = useState(false);
  const [summary, setSummary] = useState<GeoSummary | null>(null);
  const [protocols, setProtocols] = useState<ProtocolRow[]>([]);
  const [topTalkers, setTopTalkers] = useState<TalkerRow[]>([]);
  const [timeline, setTimeline] = useState<TimelineRow[]>([]);
  const [heatmap, setHeatmap] = useState<HeatmapRow[]>([]);

  // Live refresh hook - default ON in dev mode, OFF in production if API errors
  const liveRefresh = useLiveRefresh(IS_DEV);

  // Initial data fetch
  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const safeFetch = async (url: string) => {
          const res = await fetch(url);
          if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
          return res.json();
        };

        const [geo, pb, tt, tl, hm, mode] = await Promise.all([
          safeFetch(`${API_BASE}/api/v1/analytics/geo-summary`),
          safeFetch(`${API_BASE}/api/v1/analytics/protocol-breakdown`),
          safeFetch(`${API_BASE}/api/v1/analytics/top-talkers?limit=10`),
          safeFetch(`${API_BASE}/api/v1/analytics/traffic-timeline?bucket_minutes=5`),
          safeFetch(`${API_BASE}/api/v1/analytics/threat-heatmap`),
          safeFetch(`${API_BASE}/api/v1/settings/mode`),
        ]);

        setSummary(geo || null);
        setProtocols(pb?.protocols || []);
        setTopTalkers(tt?.top_talkers || []);
        setTimeline(tl?.timeline || []);
        setHeatmap(hm?.heatmap || []);
        setDemoMode(Boolean(mode?.demo_mode));
      } catch (error) {
        console.error('Failed to load dashboard analytics', error);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const threatsDetected = useMemo(() => heatmap.filter((h) => (h.threat_score || 0) > 0).length, [heatmap]);

  const scoreDistribution = useMemo(() => {
    const bins = [
      { range: '0.00-0.24', count: 0 },
      { range: '0.25-0.49', count: 0 },
      { range: '0.50-0.74', count: 0 },
      { range: '0.75-1.00', count: 0 },
    ];

    for (const row of heatmap) {
      const score = row.threat_score || 0;
      if (score < 0.25) bins[0].count += 1;
      else if (score < 0.5) bins[1].count += 1;
      else if (score < 0.75) bins[2].count += 1;
      else bins[3].count += 1;
    }

    return bins;
  }, [heatmap]);

  // Convert live events to findings
  const recentFindings = useMemo(() => eventsToFindings(liveRefresh.events), [liveRefresh.events]);

  const statCards = [
    { label: 'Total Connections', value: summary?.connections || 0 },
    { label: 'DNS Queries', value: summary?.dns_queries || 0 },
    { label: 'Unique Sources', value: summary?.unique_source_ips || 0 },
    { label: 'Unique Destinations', value: summary?.unique_dest_ips || 0 },
    { label: 'Unique Domains', value: summary?.unique_domains || 0 },
    { label: 'Threats Detected', value: threatsDetected },
  ];

  if (loading) {
    return <LoadingSkeleton rows={8} />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header with Live Indicator */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <h1 className="v3-page-title" style={{ margin: 0, color: 'var(--v3-text)', fontWeight: 700 }}>Security Dashboard</h1>
            <p className="v3-page-subtitle" style={{ margin: '4px 0 0', color: 'var(--v3-text-secondary)' }}>
              Live SOC telemetry overview with protocol, traffic, and threat analytics
            </p>
          </div>
          <LiveIndicator
            isEnabled={liveRefresh.isEnabled}
            isLive={liveRefresh.isLive}
            lastUpdateAt={liveRefresh.lastUpdateAt}
            lastError={liveRefresh.lastError}
            consecutiveFailures={liveRefresh.consecutiveFailures}
            onToggle={liveRefresh.toggle}
            onResetBackoff={liveRefresh.resetBackoff}
          />
        </div>

        {demoMode && (
          <div
            style={{
              background: '#EFF6FF',
              border: '1px solid #BFDBFE',
              color: '#1D4ED8',
              fontSize: 12,
              borderRadius: 8,
              padding: '8px 12px',
            }}
          >
            Demo mode is enabled — data is sanitized for safe presentation.
          </div>
        )}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        {statCards.map((card) => (
          <div key={card.label} className="v3-stat-card" style={{ ...cardStyle, padding: '14px 16px' }}>
            <div className="v3-stat-card-label">
              {card.label}
            </div>
            <div className="v3-stat-card-value">
              {Number(card.value).toLocaleString()}
            </div>
          </div>
        ))}
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <section style={{ ...cardStyle, padding: 16, minHeight: 320 }}>
          <h3 style={{ margin: 0, marginBottom: 12, color: palette.text, fontSize: 15, fontWeight: 600 }}>Protocol Breakdown</h3>
          <ResponsiveContainer width="100%" height={270}>
            <BarChart data={protocols.slice(0, 10)} layout="vertical" margin={{ top: 4, right: 12, left: 12, bottom: 0 }}>
              <CartesianGrid stroke={palette.border} strokeDasharray="3 3" />
              <XAxis type="number" stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 11 }} />
              <YAxis dataKey="protocol" type="category" stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 11 }} width={80} />
              <Tooltip contentStyle={{ background: '#fff', border: `1px solid ${palette.border}`, boxShadow: '0 1px 6px rgba(15,23,42,0.12)', borderRadius: 8 }} />
              <Bar dataKey="connections" fill={palette.blue} radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </section>

        <section style={{ ...cardStyle, padding: 16, minHeight: 320 }}>
          <h3 style={{ margin: 0, marginBottom: 12, color: palette.text, fontSize: 15, fontWeight: 600 }}>Top Talkers</h3>
          <ResponsiveContainer width="100%" height={270}>
            <BarChart data={topTalkers} margin={{ top: 4, right: 12, left: 0, bottom: 20 }}>
              <CartesianGrid stroke={palette.border} strokeDasharray="3 3" />
              <XAxis dataKey="ip" stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 10 }} interval={0} angle={-25} textAnchor="end" height={50} />
              <YAxis stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#fff', border: `1px solid ${palette.border}`, boxShadow: '0 1px 6px rgba(15,23,42,0.12)', borderRadius: 8 }} formatter={(v: number) => Number(v).toLocaleString()} />
              <Bar dataKey="total_bytes" radius={[6, 6, 0, 0]}>
                {topTalkers.map((_, idx) => (
                  <Cell key={idx} fill={idx % 2 === 0 ? palette.cyan : palette.purple} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </section>
      </div>

      {/* Traffic Timeline */}
      <section style={{ ...cardStyle, padding: 16 }}>
        <h3 style={{ margin: 0, marginBottom: 12, color: palette.text, fontSize: 15, fontWeight: 600 }}>Traffic Timeline</h3>
        <ResponsiveContainer width="100%" height={320}>
          <AreaChart data={timeline} margin={{ top: 4, right: 12, left: 0, bottom: 24 }}>
            <CartesianGrid stroke={palette.border} strokeDasharray="3 3" />
            <XAxis dataKey="time" stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 11 }} />
            <YAxis stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 11 }} />
            <Tooltip contentStyle={{ background: '#fff', border: `1px solid ${palette.border}`, boxShadow: '0 1px 6px rgba(15,23,42,0.12)', borderRadius: 8 }} />
            <Area type="monotone" dataKey="connections" stroke={palette.emerald} fill={palette.emerald} fillOpacity={0.18} strokeWidth={2} />
            <Brush dataKey="time" height={22} stroke={palette.blue} travellerWidth={8} />
          </AreaChart>
        </ResponsiveContainer>
      </section>

      {/* Threats and Recent Findings Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <section style={{ ...cardStyle, padding: 16, minHeight: 320 }}>
          <h3 style={{ margin: 0, marginBottom: 12, color: palette.text, fontSize: 15, fontWeight: 600 }}>Threat Score Distribution</h3>
          <ResponsiveContainer width="100%" height={270}>
            <BarChart data={scoreDistribution} margin={{ top: 4, right: 12, left: 0, bottom: 0 }}>
              <CartesianGrid stroke={palette.border} strokeDasharray="3 3" />
              <XAxis dataKey="range" stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 11 }} />
              <YAxis stroke={palette.axis} tick={{ fill: palette.axis, fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#fff', border: `1px solid ${palette.border}`, boxShadow: '0 1px 6px rgba(15,23,42,0.12)', borderRadius: 8 }} />
              <Bar dataKey="count" fill={palette.red} radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </section>

        <section style={{ ...cardStyle, padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <h3 style={{ margin: 0, color: palette.text, fontSize: 15, fontWeight: 600 }}>Threat Heatmap</h3>
            <span style={{ fontSize: 12, color: '#64748B' }}>Top {Math.min(heatmap.length, 20)} / {heatmap.length}</span>
          </div>

          <div className="v3-table-wrapper">
            <table className="v3-table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Destination</th>
                  <th style={{ textAlign: 'right' }}>Connections</th>
                  <th style={{ textAlign: 'right' }}>Alerts</th>
                  <th style={{ textAlign: 'right' }}>Score</th>
                </tr>
              </thead>
              <tbody>
                {heatmap.slice(0, 20).map((row, idx) => (
                  <tr key={`${row.src_ip}-${row.dst_ip}-${idx}`}>
                    <td className="mono">{row.src_ip}</td>
                    <td className="mono">{row.dst_ip}</td>
                    <td style={{ textAlign: 'right' }}>{Number(row.connections || 0).toLocaleString()}</td>
                    <td style={{ textAlign: 'right' }}>{Number(row.alerts || 0).toLocaleString()}</td>
                    <td style={{ textAlign: 'right' }}>
                      <span style={{ ...getScorePill(row.threat_score || 0), borderRadius: 6, padding: '2px 8px', fontSize: 12, fontWeight: 700 }}>
                        {(row.threat_score || 0).toFixed(2)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      {/* Recent Findings from Live Events */}
      {recentFindings.length > 0 && (
        <section style={{ ...cardStyle, padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <h3 style={{ margin: 0, color: palette.text, fontSize: 15, fontWeight: 600 }}>Recent Live Findings</h3>
            <span style={{ fontSize: 12, color: '#64748B' }}>{recentFindings.length} events</span>
          </div>

          <div className="v3-table-wrapper">
            <table className="v3-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Type</th>
                  <th>Description</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {recentFindings.slice(0, 10).map((finding) => {
                  const typeColors: Record<string, string> = {
                    conn: palette.blue,
                    dns: palette.purple,
                    alert: palette.red,
                  };
                  return (
                    <tr key={finding.id}>
                      <td style={{ fontSize: 12, color: '#64748B', whiteSpace: 'nowrap' }}>
                        {new Date(finding.timestamp).toLocaleTimeString()}
                      </td>
                      <td>
                        <span
                          style={{
                            display: 'inline-block',
                            padding: '2px 8px',
                            borderRadius: 4,
                            fontSize: 11,
                            fontWeight: 600,
                            textTransform: 'uppercase',
                            background: typeColors[finding.type] || palette.axis,
                            color: '#fff',
                          }}
                        >
                          {finding.type}
                        </span>
                      </td>
                      <td style={{ fontSize: 13 }}>{finding.description}</td>
                      <td style={{ fontSize: 12, color: '#64748B' }}>{finding.source}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
};

export default Dashboard;
