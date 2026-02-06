/**
 * V1 Connections — Full DataTable with connection logs, filter bar, protocol breakdown.
 * Uses mock alert data as proxy for connection log entries (since ConnLog mock isn't generated).
 */
import React, { useState, useMemo } from 'react';
import { Network } from 'lucide-react';
import { format } from 'date-fns';
import { DataTable } from '../../../components/data';
import { FilterBar, defaultFilterState } from '../../../components/data';
import type { Column } from '../../../components/data/DataTable';
import type { FilterState } from '../../../types';
import { mockAlerts } from '../../../data/mockData';

/**
 * Synthesize connection-like rows from threat alert data.
 * In production these would come from the Zeek conn.log API.
 */
interface ConnRow {
  id: string;
  ts: number;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: string;
  service: string;
  duration: number;
  orig_bytes: number;
  resp_bytes: number;
  conn_state: string;
  score: number;
  level: string;
}

function synthesizeConnections(): ConnRow[] {
  const protos = ['tcp', 'udp', 'icmp'];
  const services = ['http', 'https', 'dns', 'ssh', 'smtp', 'ssl', '-'];
  const states = ['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'SHR', 'OTH'];

  return mockAlerts.map((a, i) => ({
    id: `conn-${i.toString(16).padStart(6, '0')}`,
    ts: a.first_seen,
    src_ip: a.entity,
    src_port: 1024 + Math.floor(Math.random() * 64000),
    dst_ip: a.related_ips[0] || a.indicators[0] || '0.0.0.0',
    dst_port: [80, 443, 53, 22, 8080, 8443, 4443, 3389][i % 8],
    proto: protos[i % protos.length],
    service: services[i % services.length],
    duration: Math.random() * 3600,
    orig_bytes: Math.floor(Math.random() * 500000),
    resp_bytes: Math.floor(Math.random() * 2000000),
    conn_state: states[i % states.length],
    score: a.score,
    level: a.level,
  }));
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)}K`;
  return `${(bytes / 1048576).toFixed(1)}M`;
}

function stateClass(state: string): string {
  if (state === 'SF') return 'established';
  if (state === 'REJ') return 'rejected';
  if (state === 'S0' || state === 'SH') return 'timeout';
  return 'closed';
}

function scoreClass(score: number): string {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

const columns: Column<ConnRow>[] = [
  {
    key: 'ts',
    header: 'Time',
    width: '140px',
    accessor: (r) => (
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94A3B8' }}>
        {format(new Date(r.ts * 1000), 'MM-dd HH:mm:ss')}
      </span>
    ),
    sortValue: (r) => r.ts,
  },
  {
    key: 'src',
    header: 'Source',
    accessor: (r) => (
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>
        {r.src_ip}
        <span style={{ color: '#64748B', margin: '0 2px' }}>:</span>
        <span style={{ color: '#64748B' }}>{r.src_port}</span>
      </span>
    ),
    sortValue: (r) => r.src_ip,
  },
  {
    key: 'dst',
    header: 'Destination',
    accessor: (r) => (
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>
        {r.dst_ip}
        <span style={{ color: '#64748B', margin: '0 2px' }}>:</span>
        <span style={{ color: '#06B6D4' }}>{r.dst_port}</span>
      </span>
    ),
    sortValue: (r) => r.dst_ip,
  },
  {
    key: 'proto',
    header: 'Proto',
    width: '60px',
    align: 'center',
    accessor: (r) => <span className="v1-proto-badge">{r.proto}</span>,
    sortValue: (r) => r.proto,
  },
  {
    key: 'service',
    header: 'Service',
    width: '70px',
    align: 'center',
    accessor: (r) => (
      <span style={{ fontSize: 11, color: r.service === '-' ? '#475569' : '#94A3B8' }}>
        {r.service}
      </span>
    ),
    sortValue: (r) => r.service,
  },
  {
    key: 'duration',
    header: 'Duration',
    width: '80px',
    align: 'right',
    accessor: (r) => (
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94A3B8' }}>
        {r.duration < 1 ? `${(r.duration * 1000).toFixed(0)}ms` : `${r.duration.toFixed(1)}s`}
      </span>
    ),
    sortValue: (r) => r.duration,
  },
  {
    key: 'orig_bytes',
    header: 'Sent',
    width: '70px',
    align: 'right',
    accessor: (r) => (
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94A3B8' }}>
        {formatBytes(r.orig_bytes)}
      </span>
    ),
    sortValue: (r) => r.orig_bytes,
  },
  {
    key: 'resp_bytes',
    header: 'Recv',
    width: '70px',
    align: 'right',
    accessor: (r) => (
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94A3B8' }}>
        {formatBytes(r.resp_bytes)}
      </span>
    ),
    sortValue: (r) => r.resp_bytes,
  },
  {
    key: 'state',
    header: 'State',
    width: '60px',
    align: 'center',
    accessor: (r) => (
      <span className={`v1-conn-state ${stateClass(r.conn_state)}`}>
        {r.conn_state}
      </span>
    ),
    sortValue: (r) => r.conn_state,
  },
  {
    key: 'score',
    header: 'Score',
    width: '55px',
    align: 'right',
    accessor: (r) => (
      <span className={`v1-score-inline ${scoreClass(r.score)}`}>
        {r.score}
      </span>
    ),
    sortValue: (r) => r.score,
  },
];

const Connections: React.FC = () => {
  const allConns = useMemo(() => synthesizeConnections(), []);
  const [filters, setFilters] = useState<FilterState>(defaultFilterState);

  const filtered = useMemo(() => {
    let data = allConns;

    if (filters.search) {
      const q = filters.search.toLowerCase();
      data = data.filter(
        (r) =>
          r.src_ip.includes(q) ||
          r.dst_ip.includes(q) ||
          r.proto.includes(q) ||
          r.service.includes(q) ||
          r.conn_state.toLowerCase().includes(q),
      );
    }

    if (filters.severity.length > 0) {
      data = data.filter((r) => filters.severity.includes(r.level as any));
    }

    if (filters.minScore > 0 || filters.maxScore < 100) {
      data = data.filter((r) => r.score >= filters.minScore && r.score <= filters.maxScore);
    }

    return data;
  }, [allConns, filters]);

  // Protocol breakdown
  const protoCounts = useMemo(() => {
    const m: Record<string, number> = {};
    allConns.forEach((c) => {
      m[c.proto] = (m[c.proto] || 0) + 1;
    });
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [allConns]);

  const serviceCounts = useMemo(() => {
    const m: Record<string, number> = {};
    allConns.forEach((c) => {
      if (c.service !== '-') m[c.service] = (m[c.service] || 0) + 1;
    });
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [allConns]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="v1-section-title">
        <Network size={22} />
        Connection Logs
      </div>

      {/* Protocol + Service Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div className="v1-panel">
          <div className="v1-panel-header">Protocol Breakdown</div>
          <div className="v1-panel-body" style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            {protoCounts.map(([proto, count]) => (
              <div key={proto} style={{ textAlign: 'center' }}>
                <div className="v1-proto-badge" style={{ marginBottom: 4, fontSize: 12, padding: '2px 10px' }}>{proto}</div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 16, fontWeight: 700, color: '#E2E8F0' }}>
                  {count}
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="v1-panel">
          <div className="v1-panel-header">Service Breakdown</div>
          <div className="v1-panel-body" style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            {serviceCounts.map(([service, count]) => (
              <div key={service} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 11, color: '#06B6D4', fontWeight: 600, textTransform: 'uppercase', marginBottom: 4 }}>{service}</div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 16, fontWeight: 700, color: '#E2E8F0' }}>
                  {count}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <FilterBar
        filters={filters}
        onChange={setFilters}
        showSeverity={true}
        showScoreRange={true}
        placeholder="Search by IP, protocol, service, state…"
      />

      {/* Data Table */}
      <DataTable<ConnRow>
        data={filtered}
        columns={columns}
        keyExtractor={(r) => r.id}
        pageSize={15}
        emptyMessage="No connections match filters."
      />
    </div>
  );
};

export default Connections;
