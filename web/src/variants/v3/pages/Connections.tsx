/**
 * V3 Connections — Enterprise DataTable with filters, search, export.
 * Clean alternating rows, sticky header, filter dropdowns.
 */
import React, { useState, useMemo } from 'react';
import { Download, Filter, Search, X, ChevronUp, ChevronDown, ChevronsUpDown, ChevronLeft, ChevronRight } from 'lucide-react';
import { format } from 'date-fns';
import { mockAlerts } from '../../../data/mockData';
import AddToCase from '../../../components/AddToCase';

type SortDir = 'asc' | 'desc';

const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;

const Connections: React.FC = () => {
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState<string>('all');
  const [sortKey, setSortKey] = useState<string>('score');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [page, setPage] = useState(1);
  const pageSize = 12;

  const filtered = useMemo(() => {
    let data = [...mockAlerts];
    if (severity !== 'all') {
      data = data.filter((a) => a.level === severity);
    }
    if (search) {
      const q = search.toLowerCase();
      data = data.filter(
        (a) =>
          a.entity.toLowerCase().includes(q) ||
          a.indicators.some((ind) => ind.toLowerCase().includes(q)) ||
          a.mitre_techniques.some((t) => t.toLowerCase().includes(q))
      );
    }
    return data;
  }, [search, severity]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      let va: any, vb: any;
      switch (sortKey) {
        case 'entity': va = a.entity; vb = b.entity; break;
        case 'level': {
          const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          va = order[a.level as keyof typeof order] ?? 5;
          vb = order[b.level as keyof typeof order] ?? 5;
          break;
        }
        case 'score': va = a.score; vb = b.score; break;
        case 'occurrences': va = a.occurrence_count; vb = b.occurrence_count; break;
        case 'last_seen': va = a.last_seen; vb = b.last_seen; break;
        default: va = a.score; vb = b.score;
      }
      if (typeof va === 'number' && typeof vb === 'number') {
        return sortDir === 'asc' ? va - vb : vb - va;
      }
      return sortDir === 'asc'
        ? String(va).localeCompare(String(vb))
        : String(vb).localeCompare(String(va));
    });
    return arr;
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const paged = sorted.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  };

  const SortIcon: React.FC<{ col: string }> = ({ col }) => {
    if (sortKey !== col) return <ChevronsUpDown size={12} style={{ opacity: 0.3 }} />;
    return sortDir === 'asc'
      ? <ChevronUp size={12} style={{ color: '#2563EB' }} />
      : <ChevronDown size={12} style={{ color: '#2563EB' }} />;
  };

  const severityColor = (level: string) => {
    const map: Record<string, string> = {
      critical: '#DC2626', high: '#EA580C', medium: '#D97706', low: '#2563EB', info: '#64748B',
    };
    return map[level] || '#64748B';
  };

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>Connections</h1>
        <p className="v3-text-secondary" style={{ fontSize: 13, marginTop: 4 }}>
          Network connection log with threat correlation · {sorted.length} records
        </p>
      </div>

      {/* Toolbar */}
      <div className="v3-card" style={{ marginBottom: 16, padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          {/* Search */}
          <div style={{ position: 'relative', flex: '1 1 260px', maxWidth: 360 }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#94A3B8' }} />
            <input
              className="v3-input"
              style={{ width: '100%', paddingLeft: 32, paddingRight: search ? 28 : 12 }}
              placeholder="Search IP, domain, technique…"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#94A3B8', padding: 0 }}
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Severity filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Filter size={14} style={{ color: '#64748B' }} />
            <select
              className="v3-select"
              value={severity}
              onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
            >
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s === 'all' ? 'All Severities' : s.charAt(0).toUpperCase() + s.slice(1)}
                </option>
              ))}
            </select>
          </div>

          {/* Export button (UI only) */}
          <button className="v3-btn v3-btn-outline" style={{ marginLeft: 'auto' }}>
            <Download size={14} />
            Export CSV
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="v3-card" style={{ padding: 0 }}>
        <div className="v3-table-wrapper" style={{ maxHeight: 560, overflowY: 'auto' }}>
          <table className="v3-table">
            <thead>
              <tr>
                <th className="sortable" onClick={() => handleSort('level')} style={{ width: 90 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    Severity <SortIcon col="level" />
                  </span>
                </th>
                <th className="sortable" onClick={() => handleSort('entity')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    Entity <SortIcon col="entity" />
                  </span>
                </th>
                <th className="sortable" onClick={() => handleSort('score')} style={{ width: 70 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    Score <SortIcon col="score" />
                  </span>
                </th>
                <th>Indicators</th>
                <th>MITRE</th>
                <th className="sortable" onClick={() => handleSort('occurrences')} style={{ width: 90 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    Count <SortIcon col="occurrences" />
                  </span>
                </th>
                <th className="sortable" onClick={() => handleSort('last_seen')} style={{ width: 130 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    Last Seen <SortIcon col="last_seen" />
                  </span>
                </th>
                <th style={{ width: 120 }}>Case</th>
              </tr>
            </thead>
            <tbody>
              {paged.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '32px 16px', color: '#94A3B8' }}>
                    No connections match your filters.
                  </td>
                </tr>
              ) : (
                paged.map((a, i) => (
                  <tr key={i}>
                    <td>
                      <span className={`v3-badge ${a.level}`}>{a.level}</span>
                    </td>
                    <td className="mono">{a.entity}</td>
                    <td>
                      <span
                        className="v3-score-badge"
                        style={{
                          background: `${severityColor(a.level as string)}10`,
                          color: severityColor(a.level as string),
                        }}
                      >
                        {a.score}
                      </span>
                    </td>
                    <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <span className="mono" style={{ fontSize: 12, color: '#64748B' }}>
                        {a.indicators.slice(0, 2).join(', ') || '—'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {a.mitre_techniques.slice(0, 2).map((t) => (
                          <span key={t} className="v3-tag" style={{ fontSize: 10, padding: '1px 6px' }}>{t}</span>
                        ))}
                      </div>
                    </td>
                    <td className="mono" style={{ color: '#64748B' }}>{a.occurrence_count}</td>
                    <td style={{ color: '#64748B', fontSize: 12 }}>
                      {format(new Date(a.last_seen * 1000), 'MMM d, HH:mm')}
                    </td>
                    <td>
                      <AddToCase
                        findingType="connection"
                        summary={`Suspicious connection: ${a.entity}`}
                        severity={a.level as string}
                        data={{ entity: a.entity, indicators: a.indicators, mitre_techniques: a.mitre_techniques }}
                      />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 16px', borderTop: '1px solid #E2E8F0', fontSize: 12, color: '#64748B',
          }}>
            <span>{sorted.length} results · Page {currentPage} of {totalPages}</span>
            <div style={{ display: 'flex', gap: 4 }}>
              <button
                className="v3-btn v3-btn-outline"
                style={{ padding: '4px 8px' }}
                disabled={currentPage <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                <ChevronLeft size={14} />
              </button>
              <button
                className="v3-btn v3-btn-outline"
                style={{ padding: '4px 8px' }}
                disabled={currentPage >= totalPages}
                onClick={() => setPage((p) => p + 1)}
              >
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Connections;
