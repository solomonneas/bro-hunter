/**
 * V2 Beacons — Log-style output, CSS block-char progress bars, wireframe histogram.
 */
import React, { useState, useMemo } from 'react';
import { format } from 'date-fns';
import { useBeacons } from '../../../hooks/useApi';
import { mockBeacons } from '../../../data/mockData';
import type { BeaconResult } from '../../../types';

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

/* ═══ Block-char progress bar ═══ */
const ProgressBar: React.FC<{ value: number; max?: number; width?: number; cls?: string }> = ({
  value,
  max = 100,
  width = 16,
  cls = '',
}) => {
  const pct = Math.min(value / max, 1);
  const filled = Math.round(pct * width);
  const empty = width - filled;
  const scoreClass = value >= 85 ? 'critical' : value >= 65 ? 'amber' : '';
  return (
    <span className={`v2-progress-bar ${scoreClass} ${cls}`}>
      <span className="v2-progress-filled">{'█'.repeat(filled)}</span>
      <span className="v2-progress-empty">{'░'.repeat(empty)}</span>
      <span className="v2-dim" style={{ marginLeft: 6 }}>
        {value.toFixed(0)}
      </span>
    </span>
  );
};

/* ═══ Wireframe histogram from score buckets ═══ */
const ScoreHistogram: React.FC<{ beacons: BeaconResult[] }> = ({ beacons }) => {
  const buckets = useMemo(() => {
    const b = new Array(10).fill(0);
    beacons.forEach((bc) => {
      const idx = Math.min(Math.floor(bc.beacon_score / 10), 9);
      b[idx]++;
    });
    return b;
  }, [beacons]);

  const max = Math.max(...buckets, 1);

  return (
    <div>
      <div className="v2-heading-section">score distribution</div>
      <div className="v2-histogram">
        {buckets.map((count, i) => (
          <div
            key={i}
            className="v2-histogram-bar"
            style={{ height: `${(count / max) * 100}%` }}
            title={`${i * 10}-${i * 10 + 9}: ${count} beacons`}
          />
        ))}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9 }} className="v2-dim">
        <span>0</span>
        <span>10</span>
        <span>20</span>
        <span>30</span>
        <span>40</span>
        <span>50</span>
        <span>60</span>
        <span>70</span>
        <span>80</span>
        <span>90+</span>
      </div>
    </div>
  );
};

const Beacons: React.FC = () => {
  const { data: beacons } = useBeacons();
  const bc = beacons ?? mockBeacons;
  const [expanded, setExpanded] = useState<string | null>(null);

  /* sort by score desc */
  const sorted = useMemo(
    () => [...bc].sort((a, b) => b.beacon_score - a.beacon_score),
    [bc],
  );

  /* summary stats */
  const highRisk = sorted.filter((b) => b.beacon_score >= 85).length;
  const medRisk = sorted.filter((b) => b.beacon_score >= 65 && b.beacon_score < 85).length;

  return (
    <>
      <div className="v2-heading">
        ╔═ BEACON SCANNER ═════════════════════════════════════╗
      </div>

      {/* Summary */}
      <Panel title="BEACON_STATS" pid={6101}>
        <div className="v2-stats-grid">
          <div className="v2-stat-line">
            <span className="v2-stat-key">total_beacons</span>
            <span className="v2-stat-eq">=</span>
            <span className="v2-stat-value">{bc.length}</span>
          </div>
          <div className="v2-stat-line">
            <span className="v2-stat-key">high_risk (&gt;=85)</span>
            <span className="v2-stat-eq">=</span>
            <span className="v2-stat-value critical">{highRisk}</span>
          </div>
          <div className="v2-stat-line">
            <span className="v2-stat-key">med_risk (65-84)</span>
            <span className="v2-stat-eq">=</span>
            <span className="v2-stat-value amber">{medRisk}</span>
          </div>
          <div className="v2-stat-line">
            <span className="v2-stat-key">low_risk (&lt;65)</span>
            <span className="v2-stat-eq">=</span>
            <span className="v2-stat-value green">{bc.length - highRisk - medRisk}</span>
          </div>
        </div>
      </Panel>

      {/* Histogram */}
      <Panel title="SCORE_HISTOGRAM" pid={6102}>
        <ScoreHistogram beacons={bc} />
      </Panel>

      {/* Log-style beacon listing */}
      <Panel title="BEACON_LOG" pid={6103}>
        <div style={{ maxHeight: 600, overflowY: 'auto' }}>
          {sorted.map((b) => {
            const isExpanded = expanded === b.id;
            const scoreClass = b.beacon_score >= 85 ? 'critical' : b.beacon_score >= 65 ? 'amber' : 'green';
            return (
              <div key={b.id} style={{ marginBottom: 6 }}>
                {/* Main log line */}
                <div
                  className="v2-log-line"
                  style={{ cursor: 'pointer', borderBottom: isExpanded ? 'none' : undefined }}
                  onClick={() => setExpanded(isExpanded ? null : b.id)}
                >
                  <span className="v2-log-ts">
                    {format(new Date(b.first_seen * 1000), 'HH:mm')}
                  </span>
                  <span className={`v2-log-level ${scoreClass === 'critical' ? 'critical' : scoreClass === 'amber' ? 'medium' : 'low'}`}>
                    {b.beacon_score >= 85 ? 'HIGH' : b.beacon_score >= 65 ? 'MED' : 'LOW'}
                  </span>
                  <span className="v2-log-msg">
                    <span className="v2-log-entity">{b.src_ip}</span>
                    <span className="v2-dim"> → </span>
                    <span className="v2-amber">{b.dst_ip}</span>
                    <span className="v2-dim">:{b.dst_port}</span>
                    <span className="v2-dim"> │ </span>
                    <ProgressBar value={b.beacon_score} width={12} />
                    <span className="v2-dim"> │ int={b.avg_interval_seconds}s jit={b.jitter_pct}%</span>
                  </span>
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="v2-evidence" style={{ marginLeft: 88 }}>
                    <div className="v2-evidence-line">
                      <span className="highlight">connection_count</span> = {b.connection_count}
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">time_span</span> = {(b.time_span_seconds / 3600).toFixed(1)}h
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">avg_interval</span> = {b.avg_interval_seconds.toFixed(1)}s
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">median_interval</span> = {b.median_interval_seconds.toFixed(1)}s
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">interval_range</span> = [{b.min_interval_seconds.toFixed(1)}s, {b.max_interval_seconds.toFixed(1)}s]
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">std_dev</span> = {b.interval_std_dev.toFixed(2)}
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">jitter</span> = {b.jitter_pct.toFixed(1)}%
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">data_size_avg</span> = {b.data_size_avg?.toFixed(0) ?? 'N/A'} bytes
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">confidence</span> = {(b.confidence * 100).toFixed(0)}%
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">mitre</span> = [{b.mitre_techniques.join(', ')}]
                    </div>
                    <div className="v2-divider" />
                    {b.reasons.map((r, ri) => (
                      <div key={ri} className="v2-evidence-line">
                        └─ {r}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Panel>
    </>
  );
};

export default Beacons;
