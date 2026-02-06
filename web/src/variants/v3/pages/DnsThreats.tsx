/**
 * V3 DNS Threats — Underline tabs, card layout per category, DGA entropy scatter, summary stats.
 */
import React, { useState, useMemo } from 'react';
import {
  ScatterChart, Scatter, XAxis, YAxis, ZAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import { format } from 'date-fns';
import { Globe, Activity, AlertTriangle, Zap, Radio } from 'lucide-react';
import { mockDnsThreats } from '../../../data/mockData';
import type { DnsThreatResult } from '../../../types';

type TabKey = 'all' | 'tunneling' | 'dga' | 'fast_flux' | 'suspicious_pattern';

const TABS: { key: TabKey; label: string; icon: React.ReactNode }[] = [
  { key: 'all', label: 'All Threats', icon: <Globe size={14} /> },
  { key: 'tunneling', label: 'Tunneling', icon: <Activity size={14} /> },
  { key: 'dga', label: 'DGA', icon: <AlertTriangle size={14} /> },
  { key: 'fast_flux', label: 'Fast Flux', icon: <Zap size={14} /> },
  { key: 'suspicious_pattern', label: 'Suspicious', icon: <Radio size={14} /> },
];

const scoreColor = (score: number): string => {
  if (score >= 85) return '#DC2626';
  if (score >= 65) return '#EA580C';
  if (score >= 40) return '#D97706';
  return '#16A34A';
};

const scoreBg = (score: number): string => {
  if (score >= 85) return 'rgba(220, 38, 38, 0.08)';
  if (score >= 65) return 'rgba(234, 88, 12, 0.08)';
  if (score >= 40) return 'rgba(217, 119, 6, 0.08)';
  return 'rgba(22, 163, 74, 0.08)';
};

const typeLabel = (t: string): string => {
  const map: Record<string, string> = {
    tunneling: 'Tunneling', dga: 'DGA', fast_flux: 'Fast Flux', suspicious_pattern: 'Suspicious',
  };
  return map[t] || t;
};

const typeBadgeColor = (t: string): { bg: string; color: string } => {
  const map: Record<string, { bg: string; color: string }> = {
    tunneling: { bg: 'rgba(220, 38, 38, 0.08)', color: '#DC2626' },
    dga: { bg: 'rgba(234, 88, 12, 0.08)', color: '#EA580C' },
    fast_flux: { bg: 'rgba(37, 99, 235, 0.08)', color: '#2563EB' },
    suspicious_pattern: { bg: 'rgba(100, 116, 139, 0.08)', color: '#64748B' },
  };
  return map[t] || { bg: 'rgba(100, 116, 139, 0.08)', color: '#64748B' };
};

/* DGA Entropy Scatter tooltip */
const EntropyTooltip: React.FC<{ active?: boolean; payload?: any[] }> = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div style={{
      background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: 6, padding: 10,
      fontSize: 12, color: '#1E293B', boxShadow: '0 4px 6px rgba(0,0,0,0.05)',
    }}>
      <p style={{ fontWeight: 600, marginBottom: 4 }}>{d.domain}</p>
      <p>Entropy: {d.entropy.toFixed(2)}</p>
      <p>Score: {d.score}</p>
      <p>Source: {d.src_ip}</p>
    </div>
  );
};

const ThreatCard: React.FC<{ threat: DnsThreatResult }> = ({ threat }) => {
  const tb = typeBadgeColor(threat.threat_type);
  return (
    <div className="v3-card" style={{ padding: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div>
          <span
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px',
              borderRadius: 9999, fontSize: 11, fontWeight: 600, background: tb.bg, color: tb.color,
              border: `1px solid ${tb.color}20`,
            }}
          >
            {typeLabel(threat.threat_type)}
          </span>
        </div>
        <span
          className="v3-score-badge"
          style={{ background: scoreBg(threat.score), color: scoreColor(threat.score), fontWeight: 700 }}
        >
          {threat.score}
        </span>
      </div>

      <div style={{ fontFamily: 'Source Code Pro, monospace', fontSize: 13, fontWeight: 600, color: '#1E293B', marginBottom: 4, wordBreak: 'break-all' }}>
        {threat.domain}
      </div>
      <div style={{ fontSize: 12, color: '#64748B', marginBottom: 10 }}>
        Source: <span className="v3-data">{threat.src_ip}</span>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 10 }}>
        <div style={{ fontSize: 11, color: '#94A3B8' }}>
          Queries: <span style={{ color: '#1E293B', fontWeight: 500 }}>{threat.query_count.toLocaleString()}</span>
        </div>
        <div style={{ fontSize: 11, color: '#94A3B8' }}>
          Confidence: <span style={{ color: '#1E293B', fontWeight: 500 }}>{(threat.confidence * 100).toFixed(0)}%</span>
        </div>
        {threat.unique_subdomains !== undefined && (
          <div style={{ fontSize: 11, color: '#94A3B8' }}>
            Subdomains: <span style={{ color: '#1E293B', fontWeight: 500 }}>{threat.unique_subdomains}</span>
          </div>
        )}
        {threat.domain_entropy !== undefined && (
          <div style={{ fontSize: 11, color: '#94A3B8' }}>
            Entropy: <span style={{ color: '#1E293B', fontWeight: 500 }}>{threat.domain_entropy.toFixed(2)}</span>
          </div>
        )}
        {threat.unique_ips !== undefined && (
          <div style={{ fontSize: 11, color: '#94A3B8' }}>
            Unique IPs: <span style={{ color: '#1E293B', fontWeight: 500 }}>{threat.unique_ips}</span>
          </div>
        )}
        {threat.estimated_bytes_exfiltrated !== undefined && (
          <div style={{ fontSize: 11, color: '#94A3B8' }}>
            Exfiltrated: <span style={{ color: '#1E293B', fontWeight: 500 }}>
              {(threat.estimated_bytes_exfiltrated / 1024).toFixed(0)} KB
            </span>
          </div>
        )}
      </div>

      {/* Reasons */}
      <div style={{ borderTop: '1px solid #E2E8F0', paddingTop: 8, marginTop: 4 }}>
        {threat.reasons.slice(0, 2).map((r, i) => (
          <div key={i} style={{ fontSize: 12, color: '#64748B', marginBottom: 2 }}>• {r}</div>
        ))}
      </div>

      {/* MITRE */}
      {threat.mitre_techniques.length > 0 && (
        <div style={{ marginTop: 8, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {threat.mitre_techniques.map((t) => (
            <span key={t} className="v3-tag" style={{ fontSize: 10, padding: '1px 6px' }}>{t}</span>
          ))}
        </div>
      )}

      <div style={{ fontSize: 11, color: '#94A3B8', marginTop: 8 }}>
        {format(new Date(threat.first_seen * 1000), 'MMM d HH:mm')} — {format(new Date(threat.last_seen * 1000), 'MMM d HH:mm')}
      </div>
    </div>
  );
};

const DnsThreats: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>('all');

  const filtered = useMemo(() => {
    if (activeTab === 'all') return mockDnsThreats;
    return mockDnsThreats.filter((t) => t.threat_type === activeTab);
  }, [activeTab]);

  /* Summary stats */
  const summaryStats = useMemo(() => {
    const byType: Record<string, number> = {};
    let totalQueries = 0;
    let totalBytes = 0;
    mockDnsThreats.forEach((t) => {
      byType[t.threat_type] = (byType[t.threat_type] || 0) + 1;
      totalQueries += t.query_count;
      if (t.estimated_bytes_exfiltrated) totalBytes += t.estimated_bytes_exfiltrated;
    });
    return { byType, totalQueries, totalBytes, total: mockDnsThreats.length };
  }, []);

  /* DGA entropy scatter data */
  const dgaScatterData = useMemo(() => {
    return mockDnsThreats
      .filter((t) => t.threat_type === 'dga' && t.domain_entropy !== undefined)
      .map((t) => ({
        entropy: t.domain_entropy!,
        score: t.score,
        queryCount: t.query_count,
        domain: t.domain,
        src_ip: t.src_ip,
      }));
  }, []);

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>DNS Threat Intelligence</h1>
        <p className="v3-text-secondary" style={{ fontSize: 13, marginTop: 4 }}>
          DNS-based threat detection · {mockDnsThreats.length} threats identified
        </p>
      </div>

      {/* Summary Stats */}
      <div className="v3-grid-12" style={{ marginBottom: 20 }}>
        {[
          { label: 'Total DNS Threats', value: summaryStats.total, color: 'blue' as const },
          { label: 'Tunneling', value: summaryStats.byType.tunneling || 0, color: 'red' as const },
          { label: 'DGA Detected', value: summaryStats.byType.dga || 0, color: 'orange' as const },
          { label: 'Fast Flux', value: summaryStats.byType.fast_flux || 0, color: 'blue' as const },
        ].map((s) => (
          <div key={s.label} className="v3-col-3">
            <div className="v3-kpi" style={{ padding: '14px 16px' }}>
              <div className="v3-kpi-value" style={{ fontSize: 24 }}>{s.value}</div>
              <div className="v3-kpi-label">{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* DGA Entropy Scatter (visible when 'all' or 'dga' tab is active) */}
      {(activeTab === 'all' || activeTab === 'dga') && dgaScatterData.length > 0 && (
        <div className="v3-card" style={{ marginBottom: 20 }}>
          <div className="v3-card-header">
            <div>
              <div className="v3-card-title">DGA Entropy Analysis</div>
              <div className="v3-card-subtitle">Domain entropy vs. threat score — bubble size = query count</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
              <XAxis
                type="number" dataKey="entropy" name="Entropy"
                tick={{ fill: '#64748B', fontSize: 11 }}
                label={{ value: 'Domain Entropy', position: 'insideBottom', offset: -5, fill: '#64748B', fontSize: 11 }}
              />
              <YAxis
                type="number" dataKey="score" name="Score" domain={[0, 100]}
                tick={{ fill: '#64748B', fontSize: 11 }}
                label={{ value: 'Threat Score', angle: -90, position: 'insideLeft', fill: '#64748B', fontSize: 11 }}
              />
              <ZAxis type="number" dataKey="queryCount" range={[40, 300]} name="Queries" />
              <Tooltip content={<EntropyTooltip />} />
              <Scatter data={dgaScatterData} fill="#EA580C" fillOpacity={0.7} />
            </ScatterChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Tabs */}
      <div className="v3-tabs">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            className={`v3-tab${activeTab === tab.key ? ' active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
          >
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              {tab.icon} {tab.label}
              <span style={{
                background: activeTab === tab.key ? 'rgba(37, 99, 235, 0.1)' : '#F1F5F9',
                color: activeTab === tab.key ? '#2563EB' : '#94A3B8',
                padding: '1px 6px', borderRadius: 9999, fontSize: 11, fontWeight: 600,
              }}>
                {tab.key === 'all' ? mockDnsThreats.length : mockDnsThreats.filter((t) => t.threat_type === tab.key).length}
              </span>
            </span>
          </button>
        ))}
      </div>

      {/* Threat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 14 }}>
        {filtered.sort((a, b) => b.score - a.score).map((t) => (
          <ThreatCard key={t.id} threat={t} />
        ))}
      </div>
    </div>
  );
};

export default DnsThreats;
