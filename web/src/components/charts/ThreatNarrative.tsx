import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Globe, Network, Shield, ChevronDown, ChevronUp } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

interface TimelineEvent {
  timestamp: string;
  type: 'connection' | 'dns' | 'alert' | 'threat' | 'cluster';
  severity: Severity;
  summary: string;
  details: Record<string, unknown>;
  src_ip?: string;
  dst_ip?: string;
  mitre_techniques: string[];
}

const severityStyles: Record<Severity, string> = {
  critical: 'border-red-500 text-red-300',
  high: 'border-orange-500 text-orange-300',
  medium: 'border-amber-500 text-amber-300',
  low: 'border-cyan-500 text-cyan-300',
  info: 'border-gray-500 text-gray-300',
};

const typeIcon = {
  connection: <Network size={14} />,
  dns: <Globe size={14} />,
  alert: <AlertTriangle size={14} />,
  threat: <Shield size={14} />,
  cluster: <Network size={14} />,
};

const ThreatNarrative: React.FC = () => {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [ip, setIp] = useState('');
  const [timeStart, setTimeStart] = useState('');
  const [timeEnd, setTimeEnd] = useState('');
  const [offset, setOffset] = useState(0);
  const [sortDesc, setSortDesc] = useState(true);

  const fetchEvents = async (append = false) => {
    try {
      const qs = new URLSearchParams({ limit: '50', offset: String(offset) });
      if (severity) qs.set('severity_min', severity);
      if (ip) {
        qs.set('src_ip', ip);
        qs.set('dst_ip', ip);
      }
      if (timeStart) qs.set('time_start', new Date(timeStart).toISOString());
      if (timeEnd) qs.set('time_end', new Date(timeEnd).toISOString());

      const res = await fetch(`${API_BASE}/api/data/timeline?${qs.toString()}`);
      if (!res.ok) {
        console.error(`Timeline fetch failed: ${res.status} ${res.statusText}`);
        return;
      }
      const payload = await res.json();
      const incoming = (payload.events ?? []) as TimelineEvent[];
      setEvents((prev) => (append ? [...prev, ...incoming] : incoming));
    } catch (err) {
      console.error('Timeline fetch error:', err);
    }
  };

  useEffect(() => {
    setOffset(0);
  }, [severity, ip, timeStart, timeEnd]);

  useEffect(() => {
    void fetchEvents(offset > 0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [offset, severity, ip, timeStart, timeEnd]);

  const sorted = useMemo(() => {
    const copy = [...events];
    copy.sort((a, b) => sortDesc
      ? new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      : new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    return copy;
  }, [events, sortDesc]);

  return (
    <div className="rounded-lg border border-gray-700 bg-surface/40 p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | '')} className="bg-background border border-gray-700 rounded px-2 py-1 text-xs">
          <option value="">All Severities</option>
          <option value="info">Info+</option>
          <option value="low">Low+</option>
          <option value="medium">Medium+</option>
          <option value="high">High+</option>
          <option value="critical">Critical</option>
        </select>
        <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="IP filter" className="bg-background border border-gray-700 rounded px-2 py-1 text-xs" />
        <input type="datetime-local" value={timeStart} onChange={(e) => setTimeStart(e.target.value)} className="bg-background border border-gray-700 rounded px-2 py-1 text-xs" />
        <input type="datetime-local" value={timeEnd} onChange={(e) => setTimeEnd(e.target.value)} className="bg-background border border-gray-700 rounded px-2 py-1 text-xs" />
        <button onClick={() => setSortDesc((s) => !s)} className="text-xs px-2 py-1 border border-gray-700 rounded">
          {sortDesc ? 'Newest first' : 'Oldest first'}
        </button>
      </div>

      <div className="space-y-2">
        {sorted.map((event) => {
          const stableKey = `${event.timestamp}-${event.type}-${event.src_ip ?? ''}-${event.dst_ip ?? ''}`;
          return (
            <div key={stableKey} className={`border-l-4 rounded border border-gray-700 p-3 bg-background ${severityStyles[event.severity]}`}>
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-xs">
                  {typeIcon[event.type]}
                  <span>{new Date(event.timestamp).toLocaleString()}</span>
                  <span className="uppercase">{event.type}</span>
                  <span className="px-1.5 py-0.5 border border-current rounded">{event.severity}</span>
                </div>
                <button onClick={() => setExpanded((p) => ({ ...p, [stableKey]: !p[stableKey] }))}>
                  {expanded[stableKey] ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </button>
              </div>
              <p className="text-sm mt-1 text-gray-200">{event.summary}</p>
              {(event.src_ip || event.dst_ip) && (
                <p className="text-xs text-gray-400 mt-1">{event.src_ip || 'n/a'} → {event.dst_ip || 'n/a'}</p>
              )}

              {expanded[stableKey] && (
                <div className="mt-2 text-xs text-gray-400 space-y-1">
                  {event.mitre_techniques.length > 0 && (
                    <div>MITRE: {event.mitre_techniques.join(', ')}</div>
                  )}
                  <pre className="bg-surface p-2 rounded overflow-x-auto text-[10px]">{JSON.stringify(event.details, null, 2)}</pre>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <button onClick={() => setOffset((o) => o + 50)} className="text-xs px-3 py-1.5 border border-gray-700 rounded hover:border-accent-cyan">
        Load more
      </button>
    </div>
  );
};

export default ThreatNarrative;
