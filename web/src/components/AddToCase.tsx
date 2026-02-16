import React, { useEffect, useState } from 'react';
import { Plus } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || '';

interface AddToCaseProps {
  findingType: 'connection' | 'dns' | 'alert' | 'rule_match' | 'manual';
  summary: string;
  severity?: string;
  data?: Record<string, any>;
  className?: string;
}

const AddToCase: React.FC<AddToCaseProps> = ({ findingType, summary, severity = 'medium', data = {}, className }) => {
  const [open, setOpen] = useState(false);
  const [cases, setCases] = useState<any[]>([]);
  const [selectedCase, setSelectedCase] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open) return;
    const loadCases = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/v1/cases`);
        if (!res.ok) return;
        const data = await res.json();
        setCases(Array.isArray(data) ? data : []);
      } catch {
        // no-op
      }
    };
    loadCases();
  }, [open]);

  const submit = async () => {
    if (!selectedCase) return;
    setLoading(true);
    try {
      await fetch(`${API_BASE}/api/v1/cases/${selectedCase}/findings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: findingType, summary, severity, data }),
      });
      setOpen(false);
      setSelectedCase('');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ position: 'relative', display: 'inline-flex' }} className={className}>
      <button
        className="v3-btn v3-btn-outline"
        style={{ padding: '4px 8px', fontSize: 12 }}
        type="button"
        onClick={() => setOpen((v) => !v)}
      >
        <Plus size={12} /> Add to Case
      </button>

      {open && (
        <div
          className="v3-card"
          style={{ position: 'absolute', top: '110%', right: 0, minWidth: 220, zIndex: 30, padding: 10 }}
        >
          <select className="v3-select" style={{ width: '100%', marginBottom: 8 }} value={selectedCase} onChange={(e) => setSelectedCase(e.target.value)}>
            <option value="">Select case…</option>
            {cases.map((c) => (
              <option key={c.id} value={c.id}>{c.title}</option>
            ))}
          </select>
          <button className="v3-btn v3-btn-primary" style={{ width: '100%', justifyContent: 'center' }} onClick={submit} disabled={!selectedCase || loading}>
            {loading ? 'Adding…' : 'Add Finding'}
          </button>
        </div>
      )}
    </div>
  );
};

export default AddToCase;
