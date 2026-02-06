/**
 * V5 Beacons — Editorial cards per beacon.
 * Headline = IP pair, subtext = score, inline mini chart.
 * Article-style expanded detail on click.
 */
import React, { useState, useMemo } from 'react';
import { format } from 'date-fns';
import {
  BarChart,
  Bar,
  ResponsiveContainer,
} from 'recharts';
import { Search, X, ChevronDown, ChevronUp } from 'lucide-react';
import { mockBeacons } from '../../../data/mockData';
import type { BeaconResult } from '../../../types';

const scoreColor = (score: number): string => {
  if (score >= 85) return '#E54D2E';
  if (score >= 65) return '#F97316';
  if (score >= 40) return '#EAB308';
  return '#0D9488';
};

const scoreLabel = (score: number): string => {
  if (score >= 85) return 'Critical';
  if (score >= 65) return 'High';
  if (score >= 40) return 'Medium';
  return 'Low';
};

/* Generate fake interval histogram data for mini chart */
const generateMiniData = (beacon: BeaconResult) => {
  const points = [];
  const base = beacon.avg_interval_seconds;
  // Use beacon id as seed for deterministic output
  let seed = beacon.id.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
  const pseudoRandom = () => {
    seed = (seed * 9301 + 49297) % 233280;
    return seed / 233280;
  };
  for (let i = 0; i < 12; i++) {
    const variance = (pseudoRandom() - 0.5) * base * (beacon.jitter_pct / 50);
    points.push({ i, v: Math.max(0, base + variance) });
  }
  return points;
};

type SortKey = 'score' | 'interval' | 'connections';

/* Individual beacon card component (avoids hooks-in-loop) */
const BeaconCard: React.FC<{
  beacon: BeaconResult;
  expanded: boolean;
  onToggle: () => void;
}> = ({ beacon, expanded, onToggle }) => {
  const miniData = useMemo(() => generateMiniData(beacon), [beacon.id]);
  const color = scoreColor(beacon.beacon_score);

  return (
    <div className="v5-beacon-card" onClick={onToggle}>
      {/* Card header */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 180px 40px',
          alignItems: 'center',
          gap: 16,
        }}
      >
        <div>
          <div className="v5-beacon-headline">
            {beacon.src_ip}{' '}
            <span style={{ color: '#A8A29E', fontWeight: 400 }}>→</span>{' '}
            {beacon.dst_ip}:{beacon.dst_port}
          </div>
          <div className="v5-beacon-sub">
            <span style={{ color, fontWeight: 600 }}>{beacon.beacon_score}</span>
            <span style={{ margin: '0 8px', color: '#D6D3D1' }}>·</span>
            <span>{scoreLabel(beacon.beacon_score)} risk</span>
            <span style={{ margin: '0 8px', color: '#D6D3D1' }}>·</span>
            <span>
              {beacon.avg_interval_seconds}s interval, {beacon.jitter_pct.toFixed(1)}% jitter
            </span>
          </div>
        </div>

        {/* Mini bar chart */}
        <div style={{ height: 32, opacity: 0.6 }}>
          <ResponsiveContainer width="100%" height={32}>
            <BarChart data={miniData} margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
              <Bar dataKey="v" fill={color} radius={[1, 1, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Expand indicator */}
        <div style={{ color: '#A8A29E', textAlign: 'right' }}>
          {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="v5-beacon-detail">
          {/* Stats row */}
          <div style={{ marginBottom: 16 }}>
            {[
              { label: 'Connections', value: beacon.connection_count.toLocaleString() },
              { label: 'Avg Interval', value: `${beacon.avg_interval_seconds}s` },
              {
                label: 'Median Interval',
                value: `${beacon.median_interval_seconds.toFixed(1)}s`,
              },
              { label: 'Jitter', value: `${beacon.jitter_pct.toFixed(1)}%` },
              { label: 'Std Dev', value: `${beacon.interval_std_dev.toFixed(1)}s` },
              {
                label: 'Avg Data Size',
                value: beacon.data_size_avg ? `${beacon.data_size_avg} bytes` : '—',
              },
              { label: 'Confidence', value: `${(beacon.confidence * 100).toFixed(0)}%` },
              {
                label: 'Time Span',
                value: `${(beacon.time_span_seconds / 3600).toFixed(0)}h`,
              },
            ].map((stat) => (
              <span className="v5-beacon-stat" key={stat.label}>
                <span className="v5-beacon-stat-label">{stat.label}</span>
                <span className="v5-beacon-stat-value">{stat.value}</span>
              </span>
            ))}
          </div>

          {/* Reasons */}
          <div style={{ marginBottom: 12 }}>
            <span className="v5-small-caps" style={{ display: 'block', marginBottom: 8 }}>
              Analysis
            </span>
            {beacon.reasons.map((r, j) => (
              <p key={j} className="v5-body" style={{ margin: '0 0 4px', fontSize: 14 }}>
                — {r}
              </p>
            ))}
          </div>

          {/* MITRE + timestamps */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-end',
              flexWrap: 'wrap',
              gap: 12,
            }}
          >
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {beacon.mitre_techniques.map((t) => (
                <span key={t} className="v5-tag">
                  {t}
                </span>
              ))}
            </div>
            <span
              style={{
                fontFamily: 'IBM Plex Mono, monospace',
                fontSize: 12,
                color: '#A8A29E',
              }}
            >
              {format(new Date(beacon.first_seen * 1000), 'MMM d, HH:mm')} –{' '}
              {format(new Date(beacon.last_seen * 1000), 'MMM d, HH:mm')}
            </span>
          </div>
        </div>
      )}
    </div>
  );
};

const Beacons: React.FC = () => {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<SortKey>('score');

  const filtered = useMemo(() => {
    let data = [...mockBeacons];
    if (search) {
      const q = search.toLowerCase();
      data = data.filter(
        (b) =>
          b.src_ip.includes(q) ||
          b.dst_ip.includes(q) ||
          String(b.dst_port).includes(q),
      );
    }
    data.sort((a, b) => {
      switch (sortBy) {
        case 'score':
          return b.beacon_score - a.beacon_score;
        case 'interval':
          return a.avg_interval_seconds - b.avg_interval_seconds;
        case 'connections':
          return b.connection_count - a.connection_count;
        default:
          return b.beacon_score - a.beacon_score;
      }
    });
    return data;
  }, [search, sortBy]);

  const handleToggle = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  return (
    <div>
      {/* Headline */}
      <header style={{ marginBottom: 8 }}>
        <h1 className="v5-headline v5-headline-lg">Beacon Analysis</h1>
        <p className="v5-subhead">
          {mockBeacons.length} periodic communication patterns detected across the network
        </p>
      </header>

      <hr className="v5-rule" />

      {/* Controls */}
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-end',
          gap: 32,
          marginBottom: 28,
          flexWrap: 'wrap',
        }}
      >
        <div className="v5-search" style={{ flex: '1 1 300px' }}>
          <Search size={14} className="v5-search-icon" />
          <input
            placeholder="Filter by IP address or port…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button className="v5-search-clear" onClick={() => setSearch('')}>
              <X size={14} />
            </button>
          )}
        </div>

        <div style={{ display: 'flex', gap: 16 }}>
          {(['score', 'interval', 'connections'] as SortKey[]).map((key) => (
            <button
              key={key}
              onClick={() => setSortBy(key)}
              style={{
                fontFamily: 'DM Sans, sans-serif',
                fontSize: 12,
                fontWeight: sortBy === key ? 600 : 400,
                color: sortBy === key ? '#1C1917' : '#78716C',
                background: 'none',
                border: 'none',
                borderBottom:
                  sortBy === key ? '2px solid #1C1917' : '2px solid transparent',
                padding: '4px 0',
                cursor: 'pointer',
                textTransform: 'capitalize',
                transition: 'color 0.15s',
              }}
            >
              {key === 'connections'
                ? 'Conn. Count'
                : key === 'interval'
                ? 'Interval'
                : 'Score'}
            </button>
          ))}
        </div>
      </div>

      {/* Beacon list */}
      <div>
        {filtered.length === 0 ? (
          <div className="v5-empty">No beacons match your filter.</div>
        ) : (
          filtered.map((beacon) => (
            <BeaconCard
              key={beacon.id}
              beacon={beacon}
              expanded={expandedId === beacon.id}
              onToggle={() => handleToggle(beacon.id)}
            />
          ))
        )}
      </div>
    </div>
  );
};

export default Beacons;
