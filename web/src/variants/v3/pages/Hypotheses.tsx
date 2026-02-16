import React, { useEffect, useMemo, useState } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE || import.meta.env.VITE_API_URL || '';

type HypothesisStatus = 'draft' | 'active' | 'completed';

interface HypothesisStep {
  index: number;
  description: string;
  query_hint: string;
  expected_result: string;
  actual_result: string | null;
  completed: boolean;
}

interface Hypothesis {
  id: string;
  title: string;
  description: string;
  mitre_techniques: string[];
  data_sources: string[];
  steps: HypothesisStep[];
  status: HypothesisStatus;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  tags: string[];
}

interface NewStep {
  description: string;
  query_hint: string;
  expected_result: string;
}

const statusColor = (status: HypothesisStatus) => {
  if (status === 'completed') return { bg: 'rgba(22, 163, 74, 0.1)', color: '#16A34A' };
  if (status === 'active') return { bg: 'rgba(37, 99, 235, 0.1)', color: '#2563EB' };
  return { bg: 'rgba(100, 116, 139, 0.12)', color: '#64748B' };
};

const Hypotheses: React.FC = () => {
  const [items, setItems] = useState<Hypothesis[]>([]);
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState<'all' | HypothesisStatus>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [showCreate, setShowCreate] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newTechniques, setNewTechniques] = useState('');
  const [newDataSources, setNewDataSources] = useState('');
  const [newTags, setNewTags] = useState('');
  const [newSteps, setNewSteps] = useState<NewStep[]>([
    { description: '', query_hint: '', expected_result: '' },
  ]);

  const loadHypotheses = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (statusFilter !== 'all') params.set('status', statusFilter);
      const res = await fetch(`${API_BASE}/api/v1/hypotheses?${params.toString()}`);
      if (!res.ok) return;
      const data = await res.json();
      setItems(Array.isArray(data) ? data : []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHypotheses();
  }, [statusFilter]);

  const selected = useMemo(() => items.find((h) => h.id === selectedId) || null, [items, selectedId]);

  const refreshSelected = async (id: string) => {
    const res = await fetch(`${API_BASE}/api/v1/hypotheses/${id}`);
    if (!res.ok) return;
    const updated = await res.json();
    setItems((prev) => prev.map((h) => (h.id === id ? updated : h)));
  };

  const completeStep = async (hypothesisId: string, stepIndex: number, actualResult: string) => {
    const res = await fetch(`${API_BASE}/api/v1/hypotheses/${hypothesisId}/steps/${stepIndex}/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actual_result: actualResult }),
    });
    if (!res.ok) return;
    await refreshSelected(hypothesisId);
  };

  const addStepField = () => setNewSteps((prev) => [...prev, { description: '', query_hint: '', expected_result: '' }]);

  const updateNewStep = (index: number, field: keyof NewStep, value: string) => {
    setNewSteps((prev) => prev.map((s, i) => (i === index ? { ...s, [field]: value } : s)));
  };

  const createHypothesis = async () => {
    if (!newTitle.trim()) return;
    const payload = {
      title: newTitle.trim(),
      description: newDescription.trim(),
      mitre_techniques: newTechniques.split(',').map((t) => t.trim()).filter(Boolean),
      data_sources: newDataSources.split(',').map((s) => s.trim()).filter(Boolean),
      tags: newTags.split(',').map((t) => t.trim()).filter(Boolean),
      status: 'draft',
      steps: newSteps
        .filter((s) => s.description.trim())
        .map((s, idx) => ({
          index: idx,
          description: s.description.trim(),
          query_hint: s.query_hint.trim(),
          expected_result: s.expected_result.trim(),
          actual_result: null,
          completed: false,
        })),
    };

    const res = await fetch(`${API_BASE}/api/v1/hypotheses`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) return;

    const created = await res.json();
    setItems((prev) => [created, ...prev]);
    setShowCreate(false);
    setNewTitle('');
    setNewDescription('');
    setNewTechniques('');
    setNewDataSources('');
    setNewTags('');
    setNewSteps([{ description: '', query_hint: '', expected_result: '' }]);
  };

  if (selected) {
    const totalSteps = selected.steps.length;
    const completedSteps = selected.steps.filter((s) => s.completed).length;
    const progress = totalSteps ? Math.round((completedSteps / totalSteps) * 100) : 0;

    return (
      <div>
        <div style={{ marginBottom: 12 }}>
          <button className="v3-btn v3-btn-outline" onClick={() => setSelectedId(null)}>← Back to Hypotheses</button>
        </div>

        <div className="v3-card" style={{ padding: 16, marginBottom: 14 }}>
          <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>{selected.title}</h1>
          <p className="v3-text-secondary" style={{ marginTop: 6, marginBottom: 10 }}>{selected.description}</p>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
            {selected.mitre_techniques.map((t) => <span key={t} className="v3-tag">{t}</span>)}
          </div>

          <div style={{ marginBottom: 6, fontSize: 12, color: '#64748B' }}>Progress: {completedSteps}/{totalSteps} steps ({progress}%)</div>
          <div style={{ height: 8, background: '#E2E8F0', borderRadius: 9999, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${progress}%`, background: '#2563EB', transition: 'width 200ms ease' }} />
          </div>
        </div>

        <div style={{ display: 'grid', gap: 10 }}>
          {selected.steps.map((step) => (
            <StepCard key={step.index} step={step} onComplete={(actualResult) => completeStep(selected.id, step.index, actualResult)} />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 16 }}>
        <div>
          <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>Hunt Hypotheses</h1>
          <p className="v3-text-secondary" style={{ marginTop: 4 }}>Template-driven threat hunting plans with step-by-step execution.</p>
        </div>
        <button className="v3-btn v3-btn-primary" onClick={() => setShowCreate((v) => !v)}>
          {showCreate ? 'Close' : 'Create New Hypothesis'}
        </button>
      </div>

      <div className="v3-tabs" style={{ marginBottom: 14 }}>
        {[
          ['all', 'All'],
          ['draft', 'Draft'],
          ['active', 'Active'],
          ['completed', 'Completed'],
        ].map(([value, label]) => (
          <button
            key={value}
            className={`v3-tab${statusFilter === value ? ' active' : ''}`}
            onClick={() => setStatusFilter(value as 'all' | HypothesisStatus)}
          >
            {label}
          </button>
        ))}
      </div>

      {showCreate && (
        <div className="v3-card" style={{ padding: 16, marginBottom: 14 }}>
          <h3 style={{ marginTop: 0, marginBottom: 10 }}>Create Hypothesis</h3>
          <div style={{ display: 'grid', gap: 8 }}>
            <input className="v3-input" placeholder="Title" value={newTitle} onChange={(e) => setNewTitle(e.target.value)} />
            <textarea className="v3-textarea" rows={3} placeholder="Description" value={newDescription} onChange={(e) => setNewDescription(e.target.value)} />
            <input className="v3-input" placeholder="MITRE techniques (comma-separated)" value={newTechniques} onChange={(e) => setNewTechniques(e.target.value)} />
            <input className="v3-input" placeholder="Data sources (comma-separated)" value={newDataSources} onChange={(e) => setNewDataSources(e.target.value)} />
            <input className="v3-input" placeholder="Tags (comma-separated)" value={newTags} onChange={(e) => setNewTags(e.target.value)} />
          </div>

          <div style={{ marginTop: 12, display: 'grid', gap: 10 }}>
            {newSteps.map((step, idx) => (
              <div key={idx} className="v3-card" style={{ padding: 12 }}>
                <div style={{ fontWeight: 600, marginBottom: 8 }}>Step {idx + 1}</div>
                <div style={{ display: 'grid', gap: 8 }}>
                  <input className="v3-input" placeholder="Step description" value={step.description} onChange={(e) => updateNewStep(idx, 'description', e.target.value)} />
                  <input className="v3-input" placeholder="Query hint" value={step.query_hint} onChange={(e) => updateNewStep(idx, 'query_hint', e.target.value)} />
                  <textarea className="v3-textarea" rows={2} placeholder="Expected result" value={step.expected_result} onChange={(e) => updateNewStep(idx, 'expected_result', e.target.value)} />
                </div>
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button className="v3-btn v3-btn-outline" onClick={addStepField}>Add Step</button>
            <button className="v3-btn v3-btn-primary" onClick={createHypothesis}>Save Hypothesis</button>
          </div>
        </div>
      )}

      {loading ? (
        <div className="v3-text-secondary">Loading…</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
          {items.map((item) => {
            const total = item.steps.length;
            const done = item.steps.filter((s) => s.completed).length;
            const progress = total ? Math.round((done / total) * 100) : 0;
            const badge = statusColor(item.status);

            return (
              <button
                key={item.id}
                className="v3-card"
                style={{ padding: 14, textAlign: 'left', cursor: 'pointer', background: '#fff' }}
                onClick={() => setSelectedId(item.id)}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h3 style={{ margin: 0, fontSize: 16 }}>{item.title}</h3>
                  <span style={{ padding: '2px 8px', borderRadius: 9999, fontSize: 11, fontWeight: 600, background: badge.bg, color: badge.color }}>
                    {item.status}
                  </span>
                </div>
                <p className="v3-text-secondary" style={{ fontSize: 13, marginTop: 6, marginBottom: 10 }}>{item.description}</p>

                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
                  {item.mitre_techniques.map((t) => <span key={t} className="v3-tag" style={{ fontSize: 11 }}>{t}</span>)}
                </div>

                <div style={{ fontSize: 12, color: '#64748B', marginBottom: 4 }}>Steps: {done}/{total} completed</div>
                <div style={{ height: 6, background: '#E2E8F0', borderRadius: 9999, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${progress}%`, background: '#2563EB' }} />
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};

const StepCard: React.FC<{ step: HypothesisStep; onComplete: (actualResult: string) => Promise<void> }> = ({ step, onComplete }) => {
  const [actualResult, setActualResult] = useState(step.actual_result || '');
  const [saving, setSaving] = useState(false);

  const submitComplete = async () => {
    setSaving(true);
    try {
      await onComplete(actualResult);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="v3-card" style={{ padding: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0, fontSize: 16 }}>Step {step.index + 1}</h3>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#475569' }}>
          <input type="checkbox" checked={step.completed} onChange={submitComplete} disabled={step.completed || saving} />
          {step.completed ? 'Completed' : 'Mark complete'}
        </label>
      </div>

      <div style={{ marginTop: 8, fontSize: 14, color: '#1E293B' }}>{step.description}</div>
      <div style={{ marginTop: 8, padding: '8px 10px', borderRadius: 6, background: '#F8FAFC', border: '1px solid #E2E8F0', fontFamily: 'Source Code Pro, monospace', fontSize: 12 }}>
        {step.query_hint || 'No query hint provided'}
      </div>
      <div style={{ marginTop: 8, fontSize: 13, color: '#334155' }}>
        <strong>Expected:</strong> {step.expected_result || 'No expected result provided'}
      </div>

      <textarea
        className="v3-textarea"
        rows={3}
        style={{ marginTop: 10 }}
        placeholder="Document actual result from execution"
        value={actualResult}
        onChange={(e) => setActualResult(e.target.value)}
        disabled={step.completed}
      />

      {!step.completed && (
        <button className="v3-btn v3-btn-primary" onClick={submitComplete} disabled={saving}>
          {saving ? 'Saving…' : 'Complete Step'}
        </button>
      )}
    </div>
  );
};

export default Hypotheses;
