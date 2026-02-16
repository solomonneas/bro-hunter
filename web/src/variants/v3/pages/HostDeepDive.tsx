import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

const API_BASE = import.meta.env.VITE_API_BASE || '';

type DeepDive = {
  ip: string;
  threat_profile: any;
  connections: { outbound: any[]; inbound: any[] };
  dns_queries: any[];
  alerts: any[];
  beacons: any[];
  long_connections: any[];
  sessions: any[];
  risk_timeline: Array<{ timestamp: string; type: string; description: string; severity: string }>;
  statistics: any;
};

const tabList = ['overview', 'connections', 'dns', 'alerts', 'beacons', 'timeline'] as const;

const sevColor = (s: string) => ({ critical: '#EF4444', high: '#F59E0B', medium: '#D97706', low: '#10B981' } as any)[s] || '#94A3B8';

const fmtBytes = (n?: number) => {
  const val = n || 0;
  if (val > 1024 ** 3) return `${(val / 1024 ** 3).toFixed(2)} GB`;
  if (val > 1024 ** 2) return `${(val / 1024 ** 2).toFixed(2)} MB`;
  if (val > 1024) return `${(val / 1024).toFixed(2)} KB`;
  return `${val} B`;
};

const HostDeepDive: React.FC = () => {
  const { ip = '' } = useParams();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<(typeof tabList)[number]>('overview');
  const [data, setData] = useState<DeepDive | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        setLoading(true);
        const res = await fetch(`${API_BASE}/api/v1/hosts/${encodeURIComponent(ip)}/deep-dive`);
        if (!res.ok) throw new Error('Failed to load deep dive');
        setData(await res.json());
      } catch (err) {
        console.error(err);
        setData(null);
      } finally {
        setLoading(false);
      }
    })();
  }, [ip]);

  const profile = data?.threat_profile;

  const topIndicators = useMemo(() => {
    if (!profile) return [];
    const items = [
      { label: 'Beacons', val: profile.beacon_count || 0 },
      { label: 'DNS Threats', val: profile.dns_threat_count || 0 },
      { label: 'Alerts', val: profile.alert_count || 0 },
      { label: 'Long Connections', val: profile.long_connection_count || 0 },
    ];
    return items.sort((a, b) => b.val - a.val);
  }, [profile]);

  if (loading) return <div className="v3-card">Loading host deep dive...</div>;
  if (!data) return <div className="v3-card">Host not found.</div>;

  return (
    <div>
      <button className="v3-btn v3-btn-outline" onClick={() => navigate('../hosts')}>← Back to Host Ranking</button>

      <div className="v3-card" style={{ marginTop: 12, marginBottom: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <h1 className="v3-page-title" style={{ marginBottom: 4, fontFamily: 'Source Code Pro, monospace' }}>{data.ip}</h1>
            <p className="v3-page-subtitle" style={{ marginBottom: 6 }}>{profile?.attack_summary || 'No summary available'}</p>
            <span className={`v3-badge ${profile?.threat_level || 'low'}`}>{(profile?.threat_level || 'low').toUpperCase()}</span>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 42, fontWeight: 700, color: sevColor(profile?.threat_level || 'low') }}>{Math.round((profile?.score || 0) * 100)}</div>
            <div style={{ fontSize: 12, color: '#64748B' }}>Threat Score</div>
            <div style={{ marginTop: 10 }}>
              <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4 }}>Confidence {(Math.round((profile?.confidence || 0) * 100))}%</div>
              <div style={{ width: 220, height: 8, background: '#E2E8F0', borderRadius: 9999 }}>
                <div style={{ width: `${Math.round((profile?.confidence || 0) * 100)}%`, height: '100%', background: '#2563EB', borderRadius: 9999 }} />
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="v3-tabs" style={{ marginBottom: 12 }}>
        {tabList.map((t) => (
          <button key={t} className={`v3-tab ${activeTab === t ? 'active' : ''}`} onClick={() => setActiveTab(t)}>{t.toUpperCase()}</button>
        ))}
      </div>

      {activeTab === 'overview' && (
        <div className="v3-card">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0,1fr))', gap: 12, marginBottom: 14 }}>
            <div className="v3-kpi"><div>Bytes Sent</div><strong>{fmtBytes(data.statistics?.total_bytes_sent)}</strong></div>
            <div className="v3-kpi"><div>Bytes Received</div><strong>{fmtBytes(data.statistics?.total_bytes_received)}</strong></div>
            <div className="v3-kpi"><div>Unique Destinations</div><strong>{data.statistics?.unique_destinations || 0}</strong></div>
            <div className="v3-kpi"><div>Unique Sources</div><strong>{data.statistics?.unique_sources || 0}</strong></div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
            <div className="v3-card" style={{ margin: 0 }}>
              <h3 style={{ marginTop: 0 }}>Host Activity</h3>
              <div>Protocols: {(data.statistics?.protocols || []).join(', ') || '—'}</div>
              <div>First Seen: {data.statistics?.first_seen || '—'}</div>
              <div>Last Seen: {data.statistics?.last_seen || '—'}</div>
              <div>Active Duration: {data.statistics?.active_duration || '—'}</div>
            </div>
            <div className="v3-card" style={{ margin: 0 }}>
              <h3 style={{ marginTop: 0 }}>Top Indicators</h3>
              {topIndicators.map((it) => <div key={it.label}>{it.label}: <strong>{it.val}</strong></div>)}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'connections' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div className="v3-card" style={{ padding: 0 }}>
            <div style={{ padding: 14, borderBottom: '1px solid #E2E8F0' }}><strong>Outbound Connections</strong></div>
            <div className="v3-table-wrapper"><table className="v3-table"><thead><tr><th>Dest IP</th><th>Proto</th><th>Bytes</th><th>Duration</th></tr></thead><tbody>
              {data.connections.outbound.map((c, i) => <tr key={i}><td>{c.dst_ip}:{c.dst_port}</td><td>{c.proto}</td><td>{fmtBytes((c.bytes_sent || 0) + (c.bytes_recv || 0))}</td><td>{(c.duration || 0).toFixed(2)}s</td></tr>)}
            </tbody></table></div>
          </div>
          <div className="v3-card" style={{ padding: 0 }}>
            <div style={{ padding: 14, borderBottom: '1px solid #E2E8F0' }}><strong>Inbound Connections</strong></div>
            <div className="v3-table-wrapper"><table className="v3-table"><thead><tr><th>Source IP</th><th>Proto</th><th>Bytes</th><th>Duration</th></tr></thead><tbody>
              {data.connections.inbound.map((c, i) => <tr key={i}><td>{c.src_ip}:{c.src_port}</td><td>{c.proto}</td><td>{fmtBytes((c.bytes_sent || 0) + (c.bytes_recv || 0))}</td><td>{(c.duration || 0).toFixed(2)}s</td></tr>)}
            </tbody></table></div>
          </div>
        </div>
      )}

      {activeTab === 'dns' && (
        <div className="v3-card" style={{ padding: 0 }}>
          <div className="v3-table-wrapper"><table className="v3-table"><thead><tr><th>Domain</th><th>Type</th><th>Response</th><th>Timestamp</th></tr></thead><tbody>
            {data.dns_queries.map((d, i) => <tr key={i}><td>{d.query}</td><td>{d.qtype || 'A'}</td><td>{(d.answers || []).join(', ') || d.rcode || '—'}</td><td>{d.timestamp}</td></tr>)}
          </tbody></table></div>
        </div>
      )}

      {activeTab === 'alerts' && (
        <div className="v3-card" style={{ padding: 0 }}>
          <div className="v3-table-wrapper"><table className="v3-table"><thead><tr><th>Severity</th><th>Description</th><th>Timestamp</th></tr></thead><tbody>
            {data.alerts.map((a, i) => <tr key={i}><td><span className={`v3-badge ${a.severity <= 1 ? 'critical' : a.severity === 2 ? 'high' : 'medium'}`}>{a.severity}</span></td><td>{a.signature}</td><td>{a.timestamp}</td></tr>)}
          </tbody></table></div>
        </div>
      )}

      {activeTab === 'beacons' && (
        <div className="v3-card" style={{ padding: 0 }}>
          <div className="v3-table-wrapper"><table className="v3-table"><thead><tr><th>Destination</th><th>Connections</th><th>Periodicity</th><th>Score</th></tr></thead><tbody>
            {data.beacons.map((b, i) => <tr key={i}><td>{b.dst_ip}:{b.dst_port}</td><td>{b.connection_count}</td><td>{(b.jitter_pct || 0).toFixed(2)}% jitter</td><td>{(b.beacon_score || 0).toFixed(1)}</td></tr>)}
          </tbody></table></div>
        </div>
      )}

      {activeTab === 'timeline' && (
        <div className="v3-card">
          {data.risk_timeline.map((t, idx) => (
            <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 0', borderBottom: '1px solid #F1F5F9' }}>
              <span style={{ width: 10, height: 10, borderRadius: '50%', marginTop: 5, background: sevColor(t.severity) }} />
              <div>
                <div style={{ fontSize: 12, color: '#64748B' }}>{t.timestamp}</div>
                <div style={{ fontSize: 13 }}>{t.description}</div>
                <div style={{ fontSize: 11, color: '#94A3B8' }}>{t.type} · {t.severity}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default HostDeepDive;
