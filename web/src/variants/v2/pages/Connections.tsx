/**
 * V2 Connections — CLI output table with | separators, query prompt filter, [PAGE X/Y].
 */
import React, { useState, useMemo } from 'react';
import { format } from 'date-fns';
import { useAlerts } from '../../../hooks/useApi';
import { mockAlerts } from '../../../data/mockData';

const PAGE_SIZE = 15;

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

/* ═══ severity color ═══ */
function sevTd(level: string): string {
  if (level === 'critical' || level === 'high') return 'red';
  if (level === 'medium') return 'amber';
  return '';
}

const Connections: React.FC = () => {
  const { data: alerts } = useAlerts();
  const al = alerts ?? mockAlerts;
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [sortKey, setSortKey] = useState<'score' | 'entity' | 'level' | 'count'>('score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  /* filter */
  const filtered = useMemo(() => {
    if (!query.trim()) return al;
    const q = query.toLowerCase();
    return al.filter(
      (a) =>
        a.entity.toLowerCase().includes(q) ||
        a.level.toLowerCase().includes(q) ||
        a.reasons.some((r) => r.toLowerCase().includes(q)) ||
        a.indicators.some((ind) => ind.toLowerCase().includes(q)) ||
        a.mitre_techniques.some((t) => t.toLowerCase().includes(q)),
    );
  }, [al, query]);

  /* sort */
  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      let va: string | number, vb: string | number;
      switch (sortKey) {
        case 'score': va = a.score; vb = b.score; break;
        case 'entity': va = a.entity; vb = b.entity; break;
        case 'level': va = a.score; vb = b.score; break;
        case 'count': va = a.occurrence_count; vb = b.occurrence_count; break;
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

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const paged = sorted.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  const handleSort = (key: typeof sortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  };

  const sortIndicator = (key: typeof sortKey) =>
    sortKey === key ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '';

  return (
    <>
      <div className="v2-heading">
        ╔═ CONNECTION DUMP ═════════════════════════════════════╗
      </div>

      <Panel title="CONN_QUERY" pid={5101}>
        {/* Query prompt */}
        <div className="v2-query-prompt">
          <span className="prompt-prefix">bh-query $</span>
          <input
            className="v2-query-input"
            type="text"
            placeholder="filter by ip, domain, technique, severity..."
            value={query}
            onChange={(e) => { setQuery(e.target.value); setPage(1); }}
          />
        </div>

        <div className="v2-dim" style={{ fontSize: 11, marginBottom: 8 }}>
          {sorted.length} records matched | showing {(safePage - 1) * PAGE_SIZE + 1}-
          {Math.min(safePage * PAGE_SIZE, sorted.length)} of {sorted.length}
        </div>

        {/* CLI table */}
        <div style={{ overflowX: 'auto' }}>
          <table className="v2-cli-table">
            <thead>
              <tr>
                <th>#</th>
                <th className="sep">│</th>
                <th onClick={() => handleSort('entity')} style={{ cursor: 'pointer' }}>
                  Entity{sortIndicator('entity')}
                </th>
                <th className="sep">│</th>
                <th>Type</th>
                <th className="sep">│</th>
                <th onClick={() => handleSort('level')} style={{ cursor: 'pointer' }}>
                  Level{sortIndicator('level')}
                </th>
                <th className="sep">│</th>
                <th onClick={() => handleSort('score')} style={{ cursor: 'pointer' }}>
                  Score{sortIndicator('score')}
                </th>
                <th className="sep">│</th>
                <th onClick={() => handleSort('count')} style={{ cursor: 'pointer' }}>
                  Count{sortIndicator('count')}
                </th>
                <th className="sep">│</th>
                <th>MITRE</th>
                <th className="sep">│</th>
                <th>Indicators</th>
                <th className="sep">│</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {paged.map((a, i) => (
                <tr key={`${a.entity}-${i}`}>
                  <td className="dim">{(safePage - 1) * PAGE_SIZE + i + 1}</td>
                  <td className="sep">│</td>
                  <td className="amber">{a.entity}</td>
                  <td className="sep">│</td>
                  <td className="dim">{a.entity_type}</td>
                  <td className="sep">│</td>
                  <td className={sevTd(a.level)}>
                    {a.level.toUpperCase()}
                  </td>
                  <td className="sep">│</td>
                  <td className={sevTd(a.level)} style={{ fontWeight: 700 }}>
                    {a.score}
                  </td>
                  <td className="sep">│</td>
                  <td>{a.occurrence_count}</td>
                  <td className="sep">│</td>
                  <td className="dim" style={{ maxWidth: 160 }}>
                    {a.mitre_techniques.join(', ') || '—'}
                  </td>
                  <td className="sep">│</td>
                  <td style={{ maxWidth: 180 }}>
                    {a.indicators.slice(0, 2).join(', ') || '—'}
                  </td>
                  <td className="sep">│</td>
                  <td className="dim">
                    {format(new Date(a.last_seen * 1000), 'MM-dd HH:mm')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="v2-pagination">
          <span className="v2-pagination-info">
            [PAGE {safePage}/{totalPages}]  {sorted.length} total records
          </span>
          <div className="v2-pagination-controls">
            <button
              className="v2-page-btn"
              disabled={safePage <= 1}
              onClick={() => setPage((p) => p - 1)}
            >
              « PREV
            </button>
            <button
              className="v2-page-btn"
              disabled={safePage >= totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
              NEXT »
            </button>
          </div>
        </div>
      </Panel>
    </>
  );
};

export default Connections;
