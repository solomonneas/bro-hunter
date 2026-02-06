/**
 * V5 DNS Threats — Section-based (NOT tabs).
 * Each category titled with thin rule separator.
 * Publication-quality scatter with serif annotations.
 */
import React, { useMemo } from 'react';
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ZAxis,
} from 'recharts';
import { format } from 'date-fns';
import { mockDnsThreats } from '../../../data/mockData';
import type { DnsThreatResult } from '../../../types';

const scoreColor = (score: number): string => {
  if (score >= 85) return '#E54D2E';
  if (score >= 65) return '#F97316';
  if (score >= 40) return '#EAB308';
  return '#0D9488';
};

/* Group threats by type */
const useGrouped = () =>
  useMemo(() => {
    const groups: Record<string, DnsThreatResult[]> = {
      tunneling: [],
      dga: [],
      fast_flux: [],
      suspicious_pattern: [],
    };
    mockDnsThreats.forEach((t) => {
      if (groups[t.threat_type]) groups[t.threat_type].push(t);
    });
    // Sort each group by score desc
    Object.values(groups).forEach((arr) => arr.sort((a, b) => b.score - a.score));
    return groups;
  }, []);

const typeTitle: Record<string, string> = {
  tunneling: 'DNS Tunneling',
  dga: 'Domain Generation Algorithms',
  fast_flux: 'Fast Flux Networks',
  suspicious_pattern: 'Suspicious Patterns',
};

const typeSubhead: Record<string, string> = {
  tunneling:
    'High-entropy subdomain queries indicative of covert data channels. Each row represents a unique tunneling session.',
  dga: 'Algorithmically generated domains with high consonant ratios and entropy scores. Often associated with malware C2.',
  fast_flux:
    'Domains with rapidly rotating DNS records and low TTL values spanning multiple autonomous systems.',
  suspicious_pattern:
    'Anomalous DNS query patterns that warrant further investigation but fall below confirmed threat thresholds.',
};

/* Scatter tooltip */
const ScatterTooltip: React.FC<{ active?: boolean; payload?: any[] }> = ({
  active,
  payload,
}) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div
      style={{
        background: '#FAFAF8',
        border: '1px solid #E7E5E4',
        padding: '10px 14px',
        fontFamily: 'DM Sans, sans-serif',
        fontSize: 12,
        maxWidth: 280,
      }}
    >
      <div
        style={{
          fontFamily: 'IBM Plex Mono, monospace',
          fontWeight: 600,
          fontSize: 13,
          marginBottom: 4,
          wordBreak: 'break-all',
        }}
      >
        {d.domain}
      </div>
      <div style={{ color: '#78716C', lineHeight: 1.5 }}>
        Score: <strong style={{ color: scoreColor(d.score) }}>{d.score}</strong>
        <br />
        Queries: {d.query_count?.toLocaleString()}
        <br />
        {d.domain_entropy !== undefined && (
          <>Entropy: {d.domain_entropy?.toFixed(2)}<br /></>
        )}
        {d.unique_subdomains !== undefined && (
          <>Unique subdomains: {d.unique_subdomains}<br /></>
        )}
        {d.unique_ips !== undefined && (
          <>Unique IPs: {d.unique_ips}<br /></>
        )}
        Source: {d.src_ip}
      </div>
    </div>
  );
};

/* Threat row component */
const ThreatRow: React.FC<{ threat: DnsThreatResult }> = ({ threat }) => (
  <div
    style={{
      padding: '16px 0',
      borderBottom: '1px solid #E7E5E4',
      display: 'grid',
      gridTemplateColumns: '56px 1fr auto',
      gap: 16,
      alignItems: 'start',
    }}
  >
    <div
      style={{
        fontFamily: 'Playfair Display, Georgia, serif',
        fontWeight: 700,
        fontSize: 26,
        lineHeight: 1,
        color: scoreColor(threat.score),
      }}
    >
      {threat.score}
    </div>
    <div>
      <div
        style={{
          fontFamily: 'IBM Plex Mono, monospace',
          fontSize: 14,
          fontWeight: 600,
          color: '#1C1917',
          marginBottom: 3,
          wordBreak: 'break-all',
        }}
      >
        {threat.domain}
      </div>
      <div style={{ fontSize: 13, color: '#78716C', lineHeight: 1.5 }}>
        {threat.reasons[0]}
      </div>
      {threat.mitre_techniques.length > 0 && (
        <div style={{ marginTop: 6, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {threat.mitre_techniques.map((t) => (
            <span key={t} className="v5-tag">
              {t}
            </span>
          ))}
        </div>
      )}
    </div>
    <div
      style={{
        fontFamily: 'IBM Plex Mono, monospace',
        fontSize: 12,
        color: '#A8A29E',
        textAlign: 'right',
        whiteSpace: 'nowrap',
      }}
    >
      <div>{threat.query_count.toLocaleString()} queries</div>
      <div style={{ marginTop: 2 }}>
        {format(new Date(threat.last_seen * 1000), 'MMM d, HH:mm')}
      </div>
      {threat.estimated_bytes_exfiltrated !== undefined && (
        <div style={{ marginTop: 2, color: '#E54D2E' }}>
          ~{(threat.estimated_bytes_exfiltrated / 1024).toFixed(0)} KB exfil
        </div>
      )}
      {threat.domain_entropy !== undefined && (
        <div style={{ marginTop: 2 }}>
          entropy: {threat.domain_entropy.toFixed(2)}
        </div>
      )}
      {threat.unique_ips !== undefined && (
        <div style={{ marginTop: 2 }}>
          {threat.unique_ips} IPs
        </div>
      )}
    </div>
  </div>
);

const DnsThreats: React.FC = () => {
  const groups = useGrouped();

  /* Scatter data for DGA section: entropy vs consonant ratio */
  const dgaScatterData = useMemo(
    () =>
      groups.dga.map((t) => ({
        ...t,
        x: t.domain_entropy ?? 0,
        y: t.consonant_ratio ?? 0,
        z: t.query_count,
      })),
    [groups.dga],
  );

  /* Scatter data for tunneling: query count vs estimated bytes */
  const tunnelingScatterData = useMemo(
    () =>
      groups.tunneling.map((t) => ({
        ...t,
        x: t.query_count,
        y: (t.estimated_bytes_exfiltrated ?? 0) / 1024,
        z: t.score,
      })),
    [groups.tunneling],
  );

  const sectionOrder = ['tunneling', 'dga', 'fast_flux', 'suspicious_pattern'] as const;

  return (
    <div>
      {/* Headline */}
      <header style={{ marginBottom: 8 }}>
        <h1 className="v5-headline v5-headline-lg">DNS Threat Intelligence</h1>
        <p className="v5-subhead">
          {mockDnsThreats.length} DNS-based threats across tunneling, DGA, fast-flux,
          and anomalous patterns
        </p>
      </header>

      <hr className="v5-rule" />

      {/* Summary metrics */}
      <div className="v5-grid-4" style={{ marginBottom: 0 }}>
        {sectionOrder.map((type) => (
          <div className="v5-metric" key={type}>
            <div className="v5-metric-number" style={{ fontSize: 36 }}>
              {groups[type].length}
            </div>
            <div className="v5-metric-label">{typeTitle[type]}</div>
          </div>
        ))}
      </div>

      {/* Sections */}
      {sectionOrder.map((type) => {
        const threats = groups[type];
        if (threats.length === 0) return null;

        return (
          <section key={type} className="v5-section">
            <h2 className="v5-headline v5-headline-md">{typeTitle[type]}</h2>
            <p className="v5-subhead" style={{ marginBottom: 24, maxWidth: 720 }}>
              {typeSubhead[type]}
            </p>

            {/* Publication-quality scatter for certain types */}
            {type === 'dga' && dgaScatterData.length > 0 && (
              <div className="v5-chart-container" style={{ marginBottom: 32 }}>
                <div className="v5-small-caps" style={{ marginBottom: 12 }}>
                  Domain Entropy vs. Consonant Ratio
                </div>
                <ResponsiveContainer width="100%" height={260}>
                  <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 10 }}>
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="#E7E5E4"
                      vertical={false}
                    />
                    <XAxis
                      type="number"
                      dataKey="x"
                      name="Entropy"
                      tick={{
                        fill: '#78716C',
                        fontSize: 11,
                        fontFamily: 'IBM Plex Mono, monospace',
                      }}
                      tickLine={false}
                      axisLine={{ stroke: '#E7E5E4' }}
                      label={{
                        value: 'Domain Entropy',
                        position: 'insideBottom',
                        offset: -4,
                        style: {
                          fontFamily: 'Playfair Display, Georgia, serif',
                          fontSize: 12,
                          fill: '#78716C',
                        },
                      }}
                    />
                    <YAxis
                      type="number"
                      dataKey="y"
                      name="Consonant Ratio"
                      tick={{
                        fill: '#78716C',
                        fontSize: 11,
                        fontFamily: 'IBM Plex Mono, monospace',
                      }}
                      tickLine={false}
                      axisLine={false}
                      label={{
                        value: 'Consonant Ratio',
                        angle: -90,
                        position: 'insideLeft',
                        offset: 10,
                        style: {
                          fontFamily: 'Playfair Display, Georgia, serif',
                          fontSize: 12,
                          fill: '#78716C',
                        },
                      }}
                    />
                    <ZAxis type="number" dataKey="z" range={[40, 400]} />
                    <Tooltip content={<ScatterTooltip />} />
                    <Scatter
                      data={dgaScatterData}
                      fill="#E54D2E"
                      fillOpacity={0.6}
                      stroke="#E54D2E"
                      strokeWidth={1}
                    />
                  </ScatterChart>
                </ResponsiveContainer>
              </div>
            )}

            {type === 'tunneling' && tunnelingScatterData.length > 0 && (
              <div className="v5-chart-container" style={{ marginBottom: 32 }}>
                <div className="v5-small-caps" style={{ marginBottom: 12 }}>
                  Query Volume vs. Estimated Data Exfiltrated
                </div>
                <ResponsiveContainer width="100%" height={260}>
                  <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 10 }}>
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="#E7E5E4"
                      vertical={false}
                    />
                    <XAxis
                      type="number"
                      dataKey="x"
                      name="Queries"
                      tick={{
                        fill: '#78716C',
                        fontSize: 11,
                        fontFamily: 'IBM Plex Mono, monospace',
                      }}
                      tickLine={false}
                      axisLine={{ stroke: '#E7E5E4' }}
                      label={{
                        value: 'Query Count',
                        position: 'insideBottom',
                        offset: -4,
                        style: {
                          fontFamily: 'Playfair Display, Georgia, serif',
                          fontSize: 12,
                          fill: '#78716C',
                        },
                      }}
                    />
                    <YAxis
                      type="number"
                      dataKey="y"
                      name="KB Exfiltrated"
                      tick={{
                        fill: '#78716C',
                        fontSize: 11,
                        fontFamily: 'IBM Plex Mono, monospace',
                      }}
                      tickLine={false}
                      axisLine={false}
                      label={{
                        value: 'KB Exfiltrated',
                        angle: -90,
                        position: 'insideLeft',
                        offset: 10,
                        style: {
                          fontFamily: 'Playfair Display, Georgia, serif',
                          fontSize: 12,
                          fill: '#78716C',
                        },
                      }}
                    />
                    <ZAxis type="number" dataKey="z" range={[40, 400]} />
                    <Tooltip content={<ScatterTooltip />} />
                    <Scatter
                      data={tunnelingScatterData}
                      fill="#4F46E5"
                      fillOpacity={0.6}
                      stroke="#4F46E5"
                      strokeWidth={1}
                    />
                  </ScatterChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Threat list */}
            <div>
              {threats.map((threat) => (
                <ThreatRow key={threat.id} threat={threat} />
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
};

export default DnsThreats;
