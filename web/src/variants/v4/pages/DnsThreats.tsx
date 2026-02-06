/**
 * V4 DNS Threats — Neon-underlined tabs, magenta/cyan gradient dots,
 * data-stream animation feel.
 */
import React, { useState, useMemo } from 'react';
import {
  ScatterChart, Scatter, XAxis, YAxis, ZAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell,
} from 'recharts';
import { format } from 'date-fns';
import { Globe, Activity, AlertTriangle, Zap, Radio, Database, Cpu } from 'lucide-react';
import { mockDnsThreats } from '../../../data/mockData';
import type { DnsThreatResult } from '../../../types';

type TabKey = 'all' | 'tunneling' | 'dga' | 'fast_flux' | 'suspicious_pattern';

const TABS: { key: TabKey; label: string; icon: React.ReactNode }[] = [
  { key: 'all', label: 'ALL THREATS', icon: <Globe size={14} /> },
  { key: 'tunneling', label: 'TUNNELING', icon: <Activity size={14} /> },
  { key: 'dga', label: 'DGA', icon: <AlertTriangle size={14} /> },
  { key: 'fast_flux', label: 'FAST FLUX', icon: <Zap size={14} /> },
  { key: 'suspicious_pattern', label: 'SUSPICIOUS', icon: <Radio size={14} /> },
];

const scoreNeon = (score: number): string => {
  if (score >= 85) return '#FF00FF';
  if (score >= 65) return '#FF6600';
  if (score >= 40) return '#FFFF00';
  return '#39FF14';
};

const typeNeon = (t: string): string => {
  const map: Record<string, string> = {
    tunneling: '#FF00FF', dga: '#FF6600', fast_flux: '#00FFFF', suspicious_pattern: '#FFFF00',
  };
  return map[t] || '#8878A8';
};

const typeLabel = (t: string): string => {
  const map: Record<string, string> = {
    tunneling: 'TUNNELING', dga: 'DGA', fast_flux: 'FAST FLUX', suspicious_pattern: 'SUSPICIOUS',
  };
  return map[t] || t.toUpperCase();
};

/* Neon scatter tooltip */
const EntropyTooltip: React.FC<{ active?: boolean; payload?: any[] }> = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div style={{
      background: 'rgba(15, 10, 26, 0.95)', border: '1px solid rgba(0, 255, 255, 0.3)',
      padding: 12, fontFamily: 'Fira Code, monospace', fontSize: 11,
      boxShadow: '0 0 20px rgba(0, 255, 255, 0.15)', color: '#E0D8F0',
    }}>
      <p style={{ margin: '0 0 4px', color: '#FF00FF', fontFamily: 'Orbitron, sans-serif', fontSize: 10 }}>{d.domain}</p>
      <p style={{ margin: '2px 0', color: '#00FFFF' }}>Entropy: {d.entropy.toFixed(2)}</p>
      <p style={{ margin: '2px 0', color: '#FF6600' }}>Score: {d.score}</p>
      <p style={{ margin: '2px 0' }}>Source: {d.src_ip}</p>
    </div>
  );
};

/* Threat Card */
const ThreatCard: React.FC<{ threat: DnsThreatResult; index: number }> = ({ threat, index }) => {
  const neon = typeNeon(threat.threat_type);
  return (
    <div
      className="v4-card"
      style={{
        borderColor: `${neon}25`,
        borderLeft: `3px solid ${neon}`,
        animation: `v4-data-stream 2s ease-in-out ${index * 0.1}s infinite`,
        transition: 'all 0.2s',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = `${neon}50`;
        e.currentTarget.style.boxShadow = `0 0 25px ${neon}15, inset 0 0 25px ${neon}08`;
        e.currentTarget.style.animation = 'none';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = `${neon}25`;
        e.currentTarget.style.boxShadow = '';
        e.currentTarget.style.animation = `v4-data-stream 2s ease-in-out ${index * 0.1}s infinite`;
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <span style={{
          display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 10px',
          fontFamily: "'Orbitron', sans-serif", fontSize: 9, fontWeight: 700,
          letterSpacing: '0.1em', color: neon, background: `${neon}12`,
          border: `1px solid ${neon}30`,
          clipPath: 'polygon(4px 0, 100% 0, calc(100% - 4px) 100%, 0 100%)',
          textShadow: `0 0 6px ${neon}60`,
        }}>
          {typeLabel(threat.threat_type)}
        </span>
        <span style={{
          fontFamily: "'Orbitron', sans-serif", fontSize: 16, fontWeight: 800,
          color: scoreNeon(threat.score),
          textShadow: `0 0 10px ${scoreNeon(threat.score)}80`,
        }}>
          {threat.score}
        </span>
      </div>

      {/* Domain */}
      <div className="v4-data" style={{
        fontSize: 12, fontWeight: 600, color: '#E0D8F0', marginBottom: 4,
        wordBreak: 'break-all',
      }}>
        {threat.domain}
      </div>
      <div className="v4-data" style={{ fontSize: 11, color: '#8878A8', marginBottom: 12 }}>
        <Cpu size={10} style={{ verticalAlign: -1, marginRight: 4 }} />
        {threat.src_ip}
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 10 }}>
        <div>
          <span className="v4-label" style={{ fontSize: 9 }}>QUERIES</span>
          <div className="v4-data" style={{ fontSize: 12, fontWeight: 600, color: '#00FFFF', marginTop: 2 }}>
            {threat.query_count.toLocaleString()}
          </div>
        </div>
        <div>
          <span className="v4-label" style={{ fontSize: 9 }}>CONFIDENCE</span>
          <div className="v4-data" style={{ fontSize: 12, fontWeight: 600, color: '#00FFFF', marginTop: 2 }}>
            {(threat.confidence * 100).toFixed(0)}%
          </div>
        </div>
        {threat.unique_subdomains !== undefined && (
          <div>
            <span className="v4-label" style={{ fontSize: 9 }}>SUBDOMAINS</span>
            <div className="v4-data" style={{ fontSize: 12, fontWeight: 600, color: '#FF00FF', marginTop: 2 }}>
              {threat.unique_subdomains}
            </div>
          </div>
        )}
        {threat.domain_entropy !== undefined && (
          <div>
            <span className="v4-label" style={{ fontSize: 9 }}>ENTROPY</span>
            <div className="v4-data" style={{ fontSize: 12, fontWeight: 600, color: '#FF6600', marginTop: 2 }}>
              {threat.domain_entropy.toFixed(2)}
            </div>
          </div>
        )}
        {threat.unique_ips !== undefined && (
          <div>
            <span className="v4-label" style={{ fontSize: 9 }}>UNIQUE IPS</span>
            <div className="v4-data" style={{ fontSize: 12, fontWeight: 600, color: '#FFFF00', marginTop: 2 }}>
              {threat.unique_ips}
            </div>
          </div>
        )}
        {threat.estimated_bytes_exfiltrated !== undefined && (
          <div>
            <span className="v4-label" style={{ fontSize: 9 }}>EXFILTRATED</span>
            <div className="v4-data" style={{ fontSize: 12, fontWeight: 600, color: '#FF0040', marginTop: 2 }}>
              {(threat.estimated_bytes_exfiltrated / 1024).toFixed(0)} KB
            </div>
          </div>
        )}
      </div>

      {/* Reasons */}
      <div style={{ borderTop: '1px solid rgba(255, 0, 255, 0.1)', paddingTop: 8, marginTop: 4 }}>
        {threat.reasons.slice(0, 2).map((r, i) => (
          <div key={i} style={{ display: 'flex', gap: 6, alignItems: 'flex-start', fontSize: 12, color: '#8878A8', marginBottom: 3 }}>
            <span style={{
              marginTop: 5, width: 5, height: 5, flexShrink: 0,
              background: neon, boxShadow: `0 0 4px ${neon}`,
              clipPath: 'polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%)',
            }} />
            {r}
          </div>
        ))}
      </div>

      {/* MITRE */}
      {threat.mitre_techniques.length > 0 && (
        <div style={{ marginTop: 8, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {threat.mitre_techniques.map((t) => (
            <span key={t} className="v4-tag">{t}</span>
          ))}
        </div>
      )}

      <div className="v4-data" style={{ fontSize: 10, color: '#8878A8', marginTop: 10, opacity: 0.7 }}>
        {format(new Date(threat.first_seen * 1000), 'MMM d HH:mm')} → {format(new Date(threat.last_seen * 1000), 'MMM d HH:mm')}
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
        color: scoreNeon(t.score),
      }));
  }, []);

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 className="v4-heading v4-heading-glow" style={{ fontSize: 22, margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Database size={22} style={{ color: '#00FFFF', filter: 'drop-shadow(0 0 6px rgba(0, 255, 255, 0.5))' }} />
          DNS THREAT INTELLIGENCE
        </h1>
        <p style={{ fontFamily: "'Fira Code', monospace", fontSize: 11, color: '#8878A8', marginTop: 6 }}>
          DNS_THREATS: {mockDnsThreats.length} · TOTAL_QUERIES: {summaryStats.totalQueries.toLocaleString()}
        </p>
      </div>

      {/* Summary Stats */}
      <div className="v4-grid v4-grid-hero" style={{ marginBottom: 20 }}>
        {[
          { label: 'TOTAL THREATS', value: summaryStats.total, color: '#00FFFF' },
          { label: 'TUNNELING', value: summaryStats.byType.tunneling || 0, color: '#FF00FF' },
          { label: 'DGA DETECTED', value: summaryStats.byType.dga || 0, color: '#FF6600' },
          { label: 'FAST FLUX', value: summaryStats.byType.fast_flux || 0, color: '#FFFF00' },
        ].map((s) => (
          <div key={s.label} className="v4-card" style={{ borderColor: `${s.color}20` }}>
            <div className="v4-hero-metric" style={{ padding: '16px 12px' }}>
              <div style={{
                fontFamily: "'Orbitron', sans-serif", fontSize: 32, fontWeight: 900,
                color: s.color,
                textShadow: `0 0 15px ${s.color}60, 0 0 30px ${s.color}30`,
              }}>
                {s.value}
              </div>
              <div className="v4-label" style={{ marginTop: 6 }}>{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* DGA Entropy Scatter */}
      {(activeTab === 'all' || activeTab === 'dga') && dgaScatterData.length > 0 && (
        <div className="v4-card v4-card-glow-magenta" style={{ marginBottom: 20 }}>
          <div className="v4-card-header">
            <div>
              <div className="v4-card-title" style={{ color: '#FF00FF', textShadow: '0 0 8px rgba(255, 0, 255, 0.3)' }}>
                DGA Entropy Analysis
              </div>
              <div className="v4-card-subtitle">Domain entropy × threat score — bubble size = query volume</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 0, 255, 0.06)" />
              <XAxis
                type="number" dataKey="entropy" name="Entropy"
                tick={{ fill: '#8878A8', fontFamily: 'Fira Code', fontSize: 10 }}
                axisLine={{ stroke: 'rgba(255, 0, 255, 0.15)' }} tickLine={false}
                label={{ value: 'Domain Entropy', position: 'insideBottom', offset: -5, fill: '#8878A8', fontFamily: 'Orbitron', fontSize: 9 }}
              />
              <YAxis
                type="number" dataKey="score" name="Score" domain={[0, 100]}
                tick={{ fill: '#8878A8', fontFamily: 'Fira Code', fontSize: 10 }}
                axisLine={{ stroke: 'rgba(255, 0, 255, 0.15)' }} tickLine={false}
                label={{ value: 'Threat Score', angle: -90, position: 'insideLeft', fill: '#8878A8', fontFamily: 'Orbitron', fontSize: 9 }}
              />
              <ZAxis type="number" dataKey="queryCount" range={[40, 300]} name="Queries" />
              <Tooltip content={<EntropyTooltip />} />
              <Scatter data={dgaScatterData} fillOpacity={0.7}>
                {dgaScatterData.map((d, i) => (
                  <Cell key={i} fill={d.color} />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Tabs */}
      <div className="v4-tabs">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            className={`v4-tab${activeTab === tab.key ? ' active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
          >
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              {tab.icon} {tab.label}
              <span style={{
                padding: '1px 6px', borderRadius: 2, fontSize: 10,
                fontFamily: "'Fira Code', monospace", fontWeight: 600,
                background: activeTab === tab.key ? 'rgba(0, 255, 255, 0.15)' : 'rgba(136, 120, 168, 0.15)',
                color: activeTab === tab.key ? '#00FFFF' : '#8878A8',
              }}>
                {tab.key === 'all' ? mockDnsThreats.length : mockDnsThreats.filter((t) => t.threat_type === tab.key).length}
              </span>
            </span>
          </button>
        ))}
      </div>

      {/* Threat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 14 }}>
        {filtered.sort((a, b) => b.score - a.score).map((t, i) => (
          <ThreatCard key={t.id} threat={t} index={i} />
        ))}
      </div>
    </div>
  );
};

export default DnsThreats;
