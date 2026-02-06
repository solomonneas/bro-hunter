/**
 * V5 Connections — Elegant table with thin rules only.
 * No backgrounds, no alternating rows. Small-caps headers.
 * Clean text filter. Minimal number-only pagination.
 */
import React, { useState, useMemo } from 'react';
import { Search, X, ChevronUp, ChevronDown } from 'lucide-react';
import { format } from 'date-fns';
import { mockAlerts } from '../../../data/mockData';

type SortDir = 'asc' | 'desc';

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const severityLabel = (level: string): string => {
  if (level === 'critical') return 'Critical';
  if (level === 'high') return 'High';
  if (level === 'medium') return 'Medium';
  if (level === 'low') return 'Low';
  return 'Info';
};

const Connections: React.FC = () => {
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState<string>('score');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [page, setPage] = useState(1);
  const pageSize = 15;

  const filtered = useMemo(() => {
    if (!search) return [...mockAlerts];
    const q = search.toLowerCase();
    return mockAlerts.filter(
      (a) =>
        a.entity.toLowerCase().includes(q) ||
        a.indicators.some((ind) => ind.toLowerCase().includes(q)) ||
        a.mitre_techniques.some((t) => t.toLowerCase().includes(q)),
    );
  }, [search]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      let va: any, vb: any;
      switch (sortKey) {
        case 'entity':
          va = a.entity;
          vb = b.entity;
          break;
        case 'level':
          va = severityOrder[a.level as string] ?? 5;
          vb = severityOrder[b.level as string] ?? 5;
          break;
        case 'score':
          va = a.score;
          vb = b.score;
          break;
        case 'occurrences':
          va = a.occurrence_count;
          vb = b.occurrence_count;
          break;
        case 'last_seen':
          va = a.last_seen;
          vb = b.last_seen;
          break;
        default:
          va = a.score;
          vb = b.score;
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

  const SortIndicator: React.FC<{ col: string }> = ({ col }) => {
    if (sortKey !== col) return null;
    return sortDir === 'asc' ? (
      <ChevronUp size={12} style={{ display: 'inline', verticalAlign: -1, marginLeft: 2 }} />
    ) : (
      <ChevronDown size={12} style={{ display: 'inline', verticalAlign: -1, marginLeft: 2 }} />
    );
  };

  // Generate page numbers for minimal pagination
  const pageNumbers = useMemo(() => {
    const pages: number[] = [];
    const maxVisible = 7;
    if (totalPages <= maxVisible) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      const start = Math.max(2, currentPage - 1);
      const end = Math.min(totalPages - 1, currentPage + 1);
      if (start > 2) pages.push(-1); // ellipsis
      for (let i = start; i <= end; i++) pages.push(i);
      if (end < totalPages - 1) pages.push(-2); // ellipsis
      pages.push(totalPages);
    }
    return pages;
  }, [totalPages, currentPage]);

  return (
    <div>
      {/* Headline */}
      <header style={{ marginBottom: 8 }}>
        <h1 className="v5-headline v5-headline-lg">Connections</h1>
        <p className="v5-subhead">
          {sorted.length} network connections with threat correlation
        </p>
      </header>

      <hr className="v5-rule" />

      {/* Search */}
      <div style={{ marginBottom: 28 }}>
        <div className="v5-search">
          <Search size={14} className="v5-search-icon" />
          <input
            placeholder="Filter by IP, domain, or technique…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
          {search && (
            <button className="v5-search-clear" onClick={() => setSearch('')}>
              <X size={14} />
            </button>
          )}
        </div>
      </div>

      {/* Table */}
      <table className="v5-table">
        <thead>
          <tr>
            <th
              className="sortable"
              onClick={() => handleSort('level')}
              style={{ width: 80 }}
            >
              Severity
              <SortIndicator col="level" />
            </th>
            <th className="sortable" onClick={() => handleSort('entity')}>
              Entity
              <SortIndicator col="entity" />
            </th>
            <th
              className="sortable"
              onClick={() => handleSort('score')}
              style={{ width: 64 }}
            >
              Score
              <SortIndicator col="score" />
            </th>
            <th style={{ width: 200 }}>Indicators</th>
            <th style={{ width: 140 }}>MITRE</th>
            <th
              className="sortable"
              onClick={() => handleSort('occurrences')}
              style={{ width: 70 }}
            >
              Events
              <SortIndicator col="occurrences" />
            </th>
            <th
              className="sortable"
              onClick={() => handleSort('last_seen')}
              style={{ width: 110 }}
            >
              Last Seen
              <SortIndicator col="last_seen" />
            </th>
          </tr>
        </thead>
        <tbody>
          {paged.length === 0 ? (
            <tr>
              <td colSpan={7} className="v5-empty">
                No connections match your filter.
              </td>
            </tr>
          ) : (
            paged.map((a, i) => (
              <tr key={i}>
                <td>
                  <span
                    style={{
                      fontFamily: 'DM Sans, sans-serif',
                      fontSize: 12,
                      fontWeight: 600,
                      textTransform: 'capitalize',
                      color:
                        (a.level as string) === 'critical'
                          ? '#E54D2E'
                          : (a.level as string) === 'high'
                          ? '#F97316'
                          : (a.level as string) === 'medium'
                          ? '#EAB308'
                          : (a.level as string) === 'low'
                          ? '#4F46E5'
                          : '#A8A29E',
                    }}
                  >
                    {severityLabel(a.level as string)}
                  </span>
                </td>
                <td className="mono">{a.entity}</td>
                <td>
                  <span className="v5-data-value" style={{ fontSize: 14 }}>
                    {a.score}
                  </span>
                </td>
                <td
                  style={{
                    fontFamily: 'IBM Plex Mono, monospace',
                    fontSize: 12,
                    color: '#78716C',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    maxWidth: 200,
                  }}
                >
                  {a.indicators.slice(0, 2).join(', ') || '—'}
                </td>
                <td>
                  {a.mitre_techniques.slice(0, 2).map((t) => (
                    <span key={t} className="v5-tag" style={{ marginBottom: 2 }}>
                      {t}
                    </span>
                  ))}
                </td>
                <td className="mono" style={{ color: '#78716C' }}>
                  {a.occurrence_count}
                </td>
                <td style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: 12, color: '#78716C' }}>
                  {format(new Date(a.last_seen * 1000), 'MMM d, HH:mm')}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>

      {/* Minimal number-only pagination */}
      {totalPages > 1 && (
        <div className="v5-pagination">
          {pageNumbers.map((p, idx) =>
            p < 0 ? (
              <span
                key={`ellipsis-${idx}`}
                style={{
                  fontFamily: 'IBM Plex Mono, monospace',
                  fontSize: 14,
                  color: '#A8A29E',
                  padding: '6px 4px',
                }}
              >
                …
              </span>
            ) : (
              <button
                key={p}
                className={p === currentPage ? 'active' : ''}
                onClick={() => setPage(p)}
              >
                {p}
              </button>
            ),
          )}
        </div>
      )}
    </div>
  );
};

export default Connections;
