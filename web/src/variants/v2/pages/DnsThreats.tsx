/**
 * V2 DNS Threats — [TAB] selectors, inline entropy scores, data stream viz.
 */
import React, { useState, useMemo } from 'react';
import { format } from 'date-fns';
import { useDnsThreats } from '../../../hooks/useApi';
import { mockDnsThreats } from '../../../data/mockData';
import type { DnsThreatResult } from '../../../types';

/* ═══ Panel ═══ */
const Panel: React.FC<{ title: string; pid?: number; children: React.ReactNode }> = ({
  title, pid, children,
}) => (
  <div className="v2-panel">
    <div className="v2-panel-header">
      <span>[{title} - pid:{pid ?? Math.floor(Math.random() * 9000 + 1000)}]</span>
      <div className="v2-panel-dots">
        <span className="v2-panel-dot red" />
        <span className="v2-panel-dot amber" />
        <span className="v2-panel-dot green" />
      </div>
    </div>
    <div className="v2-panel-body">{children}</div>
  </div>
);

/* ═══ Inline entropy viz ═══ */
const EntropyViz: React.FC<{ value: number; max?: number }> = ({ value, max = 5 }) => {
  const segments = 8;
  const filled = Math.round((value / max) * segments);
  return (
    <span className="v2-entropy">
      <span className="v2-entropy-bar">
        {Array.from({ length: segments }, (_, i) => {
          let cls = 'v2-entropy-segment';
          if (i < filled) {
            if (value >= 4.0) cls += ' critical';
            else if (value >= 3.0) cls += ' warn';
            else cls += ' active';
          }
          return <span key={i} className={cls} />;
        })}
      </span>
      <span className={value >= 4.0 ? 'v2-red' : value >= 3.0 ? 'v2-amber' : 'v2-green'}>
        {value.toFixed(2)}
      </span>
    </span>
  );
};

/* ═══ Data stream visualization ═══ */
const DataStream: React.FC<{ threats: DnsThreatResult[] }> = ({ threats }) => {
  const stream = useMemo(() => {
    // Generate hex-like data stream from threat data
    const chars: { char: string; cls: string }[] = [];
    threats.forEach((t) => {
      // Encode domain as hex-like
      const hex = t.domain
        .split('')
        .map((c) => c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(' ');

      const cls = t.score >= 80 ? 'alert' : t.score >= 60 ? 'warm' : 'hot';
      hex.split('').forEach((ch) => {
        chars.push({ char: ch, cls });
      });
      chars.push({ char: '  ', cls: '' });
    });
    return chars.slice(0, 800);
  }, [threats]);

  return (
    <div className="v2-data-stream">
      {stream.map((s, i) => (
        <span key={i} className={s.cls}>
          {s.char}
        </span>
      ))}
    </div>
  );
};

/* ═══ Score bar ═══ */
const ScoreBar: React.FC<{ score: number }> = ({ score }) => {
  const filled = Math.round((score / 100) * 12);
  const empty = 12 - filled;
  const cls = score >= 80 ? 'critical' : score >= 60 ? 'amber' : '';
  return (
    <span className={`v2-progress-bar ${cls}`}>
      <span className="v2-progress-filled">{'█'.repeat(filled)}</span>
      <span className="v2-progress-empty">{'░'.repeat(empty)}</span>
    </span>
  );
};

type TabType = 'all' | 'tunneling' | 'dga' | 'fast_flux' | 'suspicious_pattern';

const TAB_LABELS: { key: TabType; label: string }[] = [
  { key: 'all', label: 'ALL' },
  { key: 'tunneling', label: 'TUNNEL' },
  { key: 'dga', label: 'DGA' },
  { key: 'fast_flux', label: 'FLUX' },
  { key: 'suspicious_pattern', label: 'SUSP' },
];

const DnsThreats: React.FC = () => {
  const { data: threats } = useDnsThreats();
  const dns = threats ?? mockDnsThreats;
  const [tab, setTab] = useState<TabType>('all');

  const filtered = useMemo(
    () => (tab === 'all' ? dns : dns.filter((t) => t.threat_type === tab)),
    [dns, tab],
  );

  const sorted = useMemo(
    () => [...filtered].sort((a, b) => b.score - a.score),
    [filtered],
  );

  /* counts per type */
  const counts = useMemo(() => {
    const c: Record<string, number> = { all: dns.length };
    dns.forEach((t) => { c[t.threat_type] = (c[t.threat_type] || 0) + 1; });
    return c;
  }, [dns]);

  return (
    <>
      <div className="v2-heading">
        ╔═ DNS INTELLIGENCE ════════════════════════════════════╗
      </div>

      {/* Tab selectors */}
      <div className="v2-tabs">
        {TAB_LABELS.map((t) => (
          <button
            key={t.key}
            className={`v2-tab ${tab === t.key ? 'active' : ''}`}
            onClick={() => setTab(t.key)}
          >
            [{t.label}] {counts[t.key] ?? 0}
          </button>
        ))}
      </div>

      {/* Data stream viz */}
      <Panel title="DNS_STREAM" pid={7101}>
        <DataStream threats={sorted.slice(0, 10)} />
      </Panel>

      {/* Threat listing */}
      <Panel title="DNS_THREATS" pid={7102}>
        <div style={{ maxHeight: 600, overflowY: 'auto' }}>
          {sorted.map((t) => (
            <div key={t.id} style={{ marginBottom: 12 }}>
              {/* Header line */}
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 12 }}>
                <span className="v2-tag amber">{t.threat_type.toUpperCase()}</span>
                <span className="v2-amber v2-bold" style={{ minWidth: 200 }}>
                  {t.domain}
                </span>
                <span className="v2-dim">│</span>
                <ScoreBar score={t.score} />
                <span className={`v2-score ${t.score >= 80 ? 'critical' : t.score >= 60 ? 'medium' : 'low'}`}>
                  {t.score}
                </span>
                <span className="v2-dim">│</span>
                <span className="v2-dim">src={t.src_ip}</span>
              </div>

              {/* Detail lines */}
              <div className="v2-evidence" style={{ marginTop: 4 }}>
                <div className="v2-evidence-line">
                  <span className="highlight">queries</span> = {t.query_count}
                  <span style={{ margin: '0 8px' }} className="v2-dim">│</span>
                  <span className="highlight">confidence</span> = {(t.confidence * 100).toFixed(0)}%
                  <span style={{ margin: '0 8px' }} className="v2-dim">│</span>
                  <span className="highlight">seen</span> = {format(new Date(t.first_seen * 1000), 'MM-dd HH:mm')} → {format(new Date(t.last_seen * 1000), 'MM-dd HH:mm')}
                </div>

                {/* Type-specific metrics */}
                {t.threat_type === 'tunneling' && t.avg_subdomain_entropy != null && (
                  <div className="v2-evidence-line">
                    <span className="highlight">entropy</span> = <EntropyViz value={t.avg_subdomain_entropy} />
                    <span style={{ margin: '0 8px' }} className="v2-dim">│</span>
                    <span className="highlight">subdomains</span> = {t.unique_subdomains}
                    <span style={{ margin: '0 8px' }} className="v2-dim">│</span>
                    <span className="highlight">exfil_est</span> = <span className="v2-red">{((t.estimated_bytes_exfiltrated ?? 0) / 1024).toFixed(0)}KB</span>
                  </div>
                )}

                {t.threat_type === 'dga' && t.domain_entropy != null && (
                  <div className="v2-evidence-line">
                    <span className="highlight">domain_entropy</span> = <EntropyViz value={t.domain_entropy} />
                    <span style={{ margin: '0 8px' }} className="v2-dim">│</span>
                    <span className="highlight">consonant_ratio</span> = {t.consonant_ratio?.toFixed(2)}
                    <span style={{ margin: '0 8px' }} className="v2-dim">│</span>
                    <span className="highlight">nxdomain</span> = <span className="v2-red">{t.nxdomain_count}</span>
                  </div>
                )}

                {t.threat_type === 'fast_flux' && t.unique_ips != null && (
                  <div className="v2-evidence-line">
                    <span className="highlight">unique_ips</span> = {t.unique_ips}
                    <span style={{ margin: '0 8px' }} className="v2-dim">│</span>
                    <span className="highlight">ip_changes/h</span> = <span className="v2-amber">{t.ip_changes_per_hour?.toFixed(1)}</span>
                    <span style={{ margin: '0 8px' }} className="v2-dim">│</span>
                    <span className="highlight">avg_ttl</span> = {t.avg_ttl?.toFixed(0)}s
                  </div>
                )}

                {/* Reasons */}
                {t.reasons.map((r, ri) => (
                  <div key={ri} className="v2-evidence-line">
                    └─ {r}
                  </div>
                ))}

                {/* MITRE */}
                {t.mitre_techniques.length > 0 && (
                  <div className="v2-evidence-line" style={{ marginTop: 2 }}>
                    <span className="highlight">mitre</span> ={' '}
                    {t.mitre_techniques.map((m) => (
                      <span key={m} className="v2-tag" style={{ marginLeft: 2 }}>{m}</span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
};

export default DnsThreats;
