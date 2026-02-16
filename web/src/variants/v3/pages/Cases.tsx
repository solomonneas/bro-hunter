import React, { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import CaseCard from '../../../components/CaseCard';
import CaseDetail from '../../../components/CaseDetail';

const API_BASE = import.meta.env.VITE_API_URL || '';

const Cases: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedId = searchParams.get('id');

  const [items, setItems] = useState<any[]>([]);
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [loading, setLoading] = useState(false);

  const loadCases = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (statusFilter !== 'all') params.set('status', statusFilter);
      if (severityFilter !== 'all') params.set('severity', severityFilter);
      const res = await fetch(`${API_BASE}/api/v1/cases?${params.toString()}`);
      if (!res.ok) return;
      const data = await res.json();
      setItems(Array.isArray(data) ? data : []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, [statusFilter, severityFilter]);

  const selected = useMemo(() => items.find((i) => i.id === selectedId), [items, selectedId]);

  const createCase = async () => {
    const title = window.prompt('Case title');
    if (!title) return;
    const res = await fetch(`${API_BASE}/api/v1/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, description: '', status: 'open', severity: 'medium', tags: [] }),
    });
    if (!res.ok) return;
    const created = await res.json();
    setItems((prev) => [created, ...prev]);
    setSearchParams({ id: created.id });
  };

  const openCase = (id: string) => setSearchParams({ id });

  const updateCase = (updated: any) => {
    setItems((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
  };

  if (selected) {
    return (
      <div>
        <div style={{ marginBottom: 12 }}>
          <button className="v3-btn v3-btn-outline" onClick={() => setSearchParams({})}>← Back to Cases</button>
        </div>
        <CaseDetail item={selected} onUpdated={updateCase} />
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 16 }}>
        <div>
          <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>Cases</h1>
          <p className="v3-text-secondary" style={{ marginTop: 4 }}>Manage investigations, notes, and IOCs.</p>
        </div>
        <button className="v3-btn v3-btn-primary" onClick={createCase}>New Case</button>
      </div>

      <div className="v3-card" style={{ marginBottom: 14, padding: 12, display: 'flex', gap: 10 }}>
        <select className="v3-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="all">All Status</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="escalated">Escalated</option>
          <option value="resolved">Resolved</option>
          <option value="closed">Closed</option>
        </select>

        <select className="v3-select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="all">All Severity</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      {loading ? <div className="v3-text-secondary">Loading…</div> : (
        <div className="v3-grid-12">
          {items.map((item) => (
            <div key={item.id} className="v3-col-4">
              <CaseCard item={item} onOpen={openCase} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Cases;
