/**
 * V1 Beacons — Beacon table sorted by score, BeaconScatter above, expandable detail.
 */
import React, { useState, useMemo } from 'react';
import { Radio, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react';
import { format } from 'date-fns';
import { BeaconScatter } from '../../../components/charts';
import type { BeaconResult, ChartTheme } from '../../../types';
import { mockBeacons } from '../../../data/mockData';

const v1Theme: ChartTheme = {
  colors: {
    primary: '#06B6D4',
    secondary: '#8B5CF6',
    accent: '#F59E0B',
    danger: '#EF4444',
    warning: '#F59E0B',
    success: '#22C55E',
    info: '#3B82F6',
    background: '#0B1426',
    surface: '#162035',
    text: '#E2E8F0',
    textSecondary: '#94A3B8',
    gridLine: '#1E293B',
    series: ['#06B6D4', '#8B5CF6', '#F59E0B', '#EF4444', '#22C55E'],
  },
  fonts: {
    family: "'Barlow Condensed', sans-serif",
    monoFamily: "'JetBrains Mono', monospace",
    sizeSmall: 10,
    sizeBase: 12,
    sizeLarge: 14,
  },
  spacing: { chartPadding: 16, legendGap: 10, tooltipPadding: 8 },
};

function scoreClass(score: number): string {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function sevLabel(score: number): string {
  if (score >= 85) return 'CRITICAL';
  if (score >= 65) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

const Beacons: React.FC = () => {
  const sorted = useMemo(
    () => [...mockBeacons].sort((a, b) => b.beacon_score - a.beacon_score),
    [],
  );

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  const filtered = useMemo(() => {
    if (!search) return sorted;
    const q = search.toLowerCase();
    return sorted.filter(
      (b) =>
        b.src_ip.includes(q) ||
        b.dst_ip.includes(q) ||
        b.dst_port.toString().includes(q),
    );
  }, [sorted, search]);

  const critCount = sorted.filter((b) => b.beacon_score >= 85).length;
  const highCount = sorted.filter((b) => b.beacon_score >= 65 && b.beacon_score < 85).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="v1-section-title">
        <Radio size={22} />
        Beacon Detection
        <span style={{ fontSize: 12, fontWeight: 400, color: '#64748B', marginLeft: 8 }}>
          {sorted.length} beacons detected
        </span>
      </div>

      {/* Summary stats */}
      <div style={{ display: 'flex', gap: 12 }}>
        <div className="v1-panel" style={{ flex: 1 }}>
          <div className="v1-panel-body" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#EF4444', fontFamily: "'JetBrains Mono', monospace" }}>{critCount}</div>
            <div style={{ fontSize: 11, color: '#94A3B8', textTransform: 'uppercase', letterSpacing: 0.5 }}>Critical Beacons</div>
          </div>
        </div>
        <div className="v1-panel" style={{ flex: 1 }}>
          <div className="v1-panel-body" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#F97316', fontFamily: "'JetBrains Mono', monospace" }}>{highCount}</div>
            <div style={{ fontSize: 11, color: '#94A3B8', textTransform: 'uppercase', letterSpacing: 0.5 }}>High Beacons</div>
          </div>
        </div>
        <div className="v1-panel" style={{ flex: 1 }}>
          <div className="v1-panel-body" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#E2E8F0', fontFamily: "'JetBrains Mono', monospace" }}>{sorted.length}</div>
            <div style={{ fontSize: 11, color: '#94A3B8', textTransform: 'uppercase', letterSpacing: 0.5 }}>Total Detected</div>
          </div>
        </div>
      </div>

      {/* Scatter Chart */}
      <div className="v1-panel">
        <div className="v1-panel-header">
          Beacon Scatter — Interval vs Score
        </div>
        <div className="v1-panel-body">
          <BeaconScatter data={mockBeacons} theme={v1Theme} height={280} />
        </div>
      </div>

      {/* Search */}
      <div>
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Filter beacons by IP or port…"
          style={{
            width: '100%',
            maxWidth: 360,
            padding: '6px 12px',
            fontSize: 12,
            fontFamily: "'JetBrains Mono', monospace",
            background: '#0B1426',
            border: '1px solid rgba(6,182,212,0.15)',
            borderRadius: 4,
            color: '#E2E8F0',
            outline: 'none',
          }}
        />
      </div>

      {/* Beacon Table with Expandable Rows */}
      <div className="v1-panel">
        <div className="v1-panel-body-flush">
          <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(6,182,212,0.12)' }}>
                <th style={{ padding: '8px 12px', textAlign: 'left', color: '#64748B', fontFamily: "'Barlow Condensed', sans-serif", fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5, width: 24 }}></th>
                <th style={{ padding: '8px 8px', textAlign: 'left', color: '#64748B', fontFamily: "'Barlow Condensed', sans-serif", fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>Source</th>
                <th style={{ padding: '8px 8px', textAlign: 'left', color: '#64748B', fontFamily: "'Barlow Condensed', sans-serif", fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>Destination</th>
                <th style={{ padding: '8px 8px', textAlign: 'center', color: '#64748B', fontFamily: "'Barlow Condensed', sans-serif", fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>Port</th>
                <th style={{ padding: '8px 8px', textAlign: 'right', color: '#64748B', fontFamily: "'Barlow Condensed', sans-serif", fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>Interval</th>
                <th style={{ padding: '8px 8px', textAlign: 'right', color: '#64748B', fontFamily: "'Barlow Condensed', sans-serif", fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>Jitter</th>
                <th style={{ padding: '8px 8px', textAlign: 'right', color: '#64748B', fontFamily: "'Barlow Condensed', sans-serif", fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>Conns</th>
                <th style={{ padding: '8px 8px', textAlign: 'center', color: '#64748B', fontFamily: "'Barlow Condensed', sans-serif", fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>Level</th>
                <th style={{ padding: '8px 12px', textAlign: 'right', color: '#64748B', fontFamily: "'Barlow Condensed', sans-serif", fontWeight: 600, fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5 }}>Score</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((b) => {
                const isExpanded = expandedId === b.id;
                return (
                  <React.Fragment key={b.id}>
                    <tr
                      className="v1-expandable-row"
                      onClick={() => setExpandedId(isExpanded ? null : b.id)}
                      style={{ borderBottom: isExpanded ? 'none' : '1px solid rgba(6,182,212,0.06)' }}
                    >
                      <td style={{ padding: '6px 12px', color: '#64748B' }}>
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </td>
                      <td style={{ padding: '6px 8px', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94A3B8' }}>{b.src_ip}</td>
                      <td style={{ padding: '6px 8px', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94A3B8' }}>{b.dst_ip}</td>
                      <td style={{ padding: '6px 8px', textAlign: 'center' }}>
                        <span className="v1-proto-badge">{b.dst_port}</span>
                      </td>
                      <td style={{ padding: '6px 8px', textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#E2E8F0' }}>
                        {b.avg_interval_seconds}s
                      </td>
                      <td style={{ padding: '6px 8px', textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: b.jitter_pct < 3 ? '#EF4444' : '#94A3B8' }}>
                        {b.jitter_pct.toFixed(1)}%
                      </td>
                      <td style={{ padding: '6px 8px', textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94A3B8' }}>
                        {b.connection_count}
                      </td>
                      <td style={{ padding: '6px 8px', textAlign: 'center' }}>
                        <span className={`v1-sev-pill ${scoreClass(b.beacon_score)}`}>
                          {sevLabel(b.beacon_score)}
                        </span>
                      </td>
                      <td style={{ padding: '6px 12px', textAlign: 'right' }}>
                        <span className={`v1-score-inline ${scoreClass(b.beacon_score)}`}>
                          {b.beacon_score}
                        </span>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr>
                        <td colSpan={9}>
                          <BeaconDetail beacon={b} />
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const BeaconDetail: React.FC<{ beacon: BeaconResult }> = ({ beacon }) => {
  const b = beacon;
  return (
    <div className="v1-expand-content">
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        {/* Timing Details */}
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#64748B', textTransform: 'uppercase', marginBottom: 6, fontFamily: "'Barlow Condensed', sans-serif" }}>
            Timing Analysis
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '3px 12px', fontSize: 11 }}>
            <span style={{ color: '#64748B' }}>Avg Interval:</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", color: '#E2E8F0' }}>{b.avg_interval_seconds.toFixed(1)}s</span>
            <span style={{ color: '#64748B' }}>Median:</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", color: '#E2E8F0' }}>{b.median_interval_seconds.toFixed(1)}s</span>
            <span style={{ color: '#64748B' }}>Min / Max:</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", color: '#E2E8F0' }}>
              {b.min_interval_seconds.toFixed(1)}s / {b.max_interval_seconds.toFixed(1)}s
            </span>
            <span style={{ color: '#64748B' }}>Std Dev:</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", color: '#E2E8F0' }}>{b.interval_std_dev.toFixed(2)}</span>
            <span style={{ color: '#64748B' }}>Jitter:</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", color: b.jitter_pct < 3 ? '#EF4444' : '#E2E8F0' }}>
              {b.jitter_pct.toFixed(1)}%
            </span>
          </div>
        </div>

        {/* Data Details */}
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#64748B', textTransform: 'uppercase', marginBottom: 6, fontFamily: "'Barlow Condensed', sans-serif" }}>
            Data Profile
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '3px 12px', fontSize: 11 }}>
            <span style={{ color: '#64748B' }}>Avg Size:</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", color: '#E2E8F0' }}>{b.data_size_avg?.toFixed(0) ?? '-'} bytes</span>
            <span style={{ color: '#64748B' }}>Variance:</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", color: '#E2E8F0' }}>{b.data_size_variance?.toFixed(0) ?? '-'}</span>
            <span style={{ color: '#64748B' }}>Connections:</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", color: '#E2E8F0' }}>{b.connection_count}</span>
            <span style={{ color: '#64748B' }}>Time Span:</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", color: '#E2E8F0' }}>{(b.time_span_seconds / 3600).toFixed(1)}h</span>
            <span style={{ color: '#64748B' }}>Confidence:</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", color: '#06B6D4' }}>{(b.confidence * 100).toFixed(0)}%</span>
          </div>
        </div>

        {/* Reasons & MITRE */}
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#64748B', textTransform: 'uppercase', marginBottom: 6, fontFamily: "'Barlow Condensed', sans-serif" }}>
            Detection Reasons
          </div>
          <ul style={{ margin: 0, paddingLeft: 12, fontSize: 11, color: '#94A3B8' }}>
            {b.reasons.map((r, i) => (
              <li key={i} style={{ marginBottom: 2 }}>{r}</li>
            ))}
          </ul>
          {b.mitre_techniques.length > 0 && (
            <div style={{ marginTop: 8, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {b.mitre_techniques.map((t) => (
                <a
                  key={t}
                  href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="v1-mitre-tag"
                  style={{ textDecoration: 'none' }}
                >
                  {t} <ExternalLink size={9} />
                </a>
              ))}
            </div>
          )}
          <div style={{ marginTop: 8, fontSize: 10, color: '#64748B' }}>
            First seen: {format(new Date(b.first_seen * 1000), 'MMM d HH:mm')} · Last seen: {format(new Date(b.last_seen * 1000), 'MMM d HH:mm')}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Beacons;
