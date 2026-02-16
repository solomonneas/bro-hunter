import React, { useEffect, useMemo, useState } from 'react';
import CaseTimeline from './CaseTimeline';
import MarkdownEditor from './MarkdownEditor';

const API_BASE = import.meta.env.VITE_API_URL || '';

interface CaseDetailProps {
  item: any;
  onUpdated: (item: any) => void;
}

const tabs = ['Findings', 'Notes', 'IOCs', 'Timeline'] as const;

const CaseDetail: React.FC<CaseDetailProps> = ({ item, onUpdated }) => {
  const [tab, setTab] = useState<(typeof tabs)[number]>('Findings');
  const [noteText, setNoteText] = useState('');
  const [tagsInput, setTagsInput] = useState((item.tags || []).join(', '));

  const statusOptions = ['open', 'investigating', 'escalated', 'resolved', 'closed'];
  const severityOptions = ['low', 'medium', 'high', 'critical'];

  const saveMeta = async (patch: Record<string, any>) => {
    const res = await fetch(`${API_BASE}/api/v1/cases/${item.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    });
    if (!res.ok) return;
    onUpdated(await res.json());
  };

  const addNote = async () => {
    if (!noteText.trim()) return;
    const res = await fetch(`${API_BASE}/api/v1/cases/${item.id}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: noteText, author: 'analyst' }),
    });
    if (!res.ok) return;
    const note = await res.json();
    onUpdated({ ...item, notes: [...(item.notes || []), note] });
    setNoteText('');
  };

  const exportBundle = async (format: 'json' | 'stix') => {
    window.open(`${API_BASE}/api/v1/cases/${item.id}/export/download?format=${format}`, '_blank');
  };

  const findings = useMemo(() => item.findings || [], [item]);
  const notes = useMemo(() => item.notes || [], [item]);
  const iocs = useMemo(() => item.iocs || [], [item]);
  const timeline = useMemo(() => item.timeline || [], [item]);

  return (
    <div>
      <div className="v3-card" style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'flex-start' }}>
          <div style={{ flex: 1 }}>
            <h2 className="v3-heading" style={{ fontSize: 20, margin: 0 }}>{item.title}</h2>
            <p className="v3-text-secondary" style={{ margin: '6px 0 0' }}>{item.description || 'No description'}</p>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="v3-btn v3-btn-outline" onClick={() => window.open(`${API_BASE}/api/v1/cases/${item.id}/export/html`, '_blank')}>Preview HTML</button>
            <button className="v3-btn v3-btn-outline" onClick={() => exportBundle('json')}>Export JSON</button>
            <button className="v3-btn v3-btn-outline" onClick={() => exportBundle('stix')}>Export STIX</button>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '200px 200px 1fr', gap: 10, marginTop: 14 }}>
          <select className="v3-select" value={item.status} onChange={(e) => saveMeta({ status: e.target.value })}>
            {statusOptions.map((s) => <option value={s} key={s}>{s}</option>)}
          </select>
          <select className="v3-select" value={item.severity} onChange={(e) => saveMeta({ severity: e.target.value })}>
            {severityOptions.map((s) => <option value={s} key={s}>{s}</option>)}
          </select>
          <input
            className="v3-input"
            placeholder="Comma-separated tags"
            value={(item.tags || []).join(', ')}
            onBlur={(e) => saveMeta({ tags: e.target.value.split(',').map((t) => t.trim()).filter(Boolean) })}
            onChange={() => null}
          />
        </div>
      </div>

      <div className="v3-tabs">
        {tabs.map((t) => (
          <button key={t} className={`v3-tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>{t}</button>
        ))}
      </div>

      <div className="v3-card">
        {tab === 'Findings' && (
          <div className="v3-table-wrapper">
            <table className="v3-table">
              <thead><tr><th>Type</th><th>Summary</th><th>Severity</th><th>View</th></tr></thead>
              <tbody>
                {findings.length === 0 ? (
                  <tr><td colSpan={4}>No findings yet.</td></tr>
                ) : findings.map((f: any) => (
                  <tr key={f.id}>
                    <td>{f.type}</td>
                    <td>{f.summary}</td>
                    <td><span className={`v3-badge ${f.severity}`}>{f.severity}</span></td>
                    <td><a href="#" onClick={(e) => e.preventDefault()}>View</a></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'Notes' && (
          <div>
            <MarkdownEditor value={noteText} onChange={setNoteText} />
            <button className="v3-btn v3-btn-primary" style={{ marginTop: 8 }} onClick={addNote}>Add Note</button>
            <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
              {notes.map((n: any) => (
                <div className="v3-card" key={n.id} style={{ background: '#F8FAFC' }}>
                  <div className="v3-text-muted" style={{ fontSize: 11 }}>{n.author} · {new Date(n.created_at).toLocaleString()}</div>
                  <div style={{ marginTop: 6, whiteSpace: 'pre-wrap' }}>{n.content}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === 'IOCs' && (
          <div className="v3-table-wrapper">
            <table className="v3-table">
              <thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Verdict</th></tr></thead>
              <tbody>
                {iocs.length === 0 ? (
                  <tr><td colSpan={4}>No IOCs yet.</td></tr>
                ) : iocs.map((ioc: any) => (
                  <tr key={ioc.id}>
                    <td>{ioc.type}</td>
                    <td className="mono">{ioc.value}</td>
                    <td>{ioc.source}</td>
                    <td>{ioc.verdict}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'Timeline' && <CaseTimeline timeline={timeline} />}
      </div>
    </div>
  );
};

export default CaseDetail;
