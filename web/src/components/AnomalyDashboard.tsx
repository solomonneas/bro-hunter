import React, { useMemo, useState } from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import AnomalyTimeline from './AnomalyTimeline';
import HostAnomalyMap from './HostAnomalyMap';
import BaselineView from './BaselineView';

export type Anomaly = {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | string;
  description: string;
  evidence: Record<string, unknown>;
  affected_hosts: string[];
  affected_connections: string[];
  detected_at: string;
};

const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#a855f7'];

const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const AnomalyDashboard: React.FC<{ anomalies: Anomaly[] }> = ({ anomalies }) => {
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [hostFilter, setHostFilter] = useState<string>('');
  const [expandedId, setExpandedId] = useState<string>('');

  const filtered = useMemo(() => anomalies.filter((a) => {
    if (severityFilter !== 'all' && a.severity !== severityFilter) return false;
    if (typeFilter !== 'all' && a.type !== typeFilter) return false;
    if (hostFilter && !a.affected_hosts.includes(hostFilter)) return false;
    return true;
  }), [anomalies, severityFilter, typeFilter, hostFilter]);

  const severityData = useMemo(() => {
    const counts = new Map<string, number>();
    filtered.forEach((a) => counts.set(a.severity, (counts.get(a.severity) || 0) + 1));
    return Array.from(counts.entries()).map(([name, value]) => ({ name, value }));
  }, [filtered]);

  const typeData = useMemo(() => {
    const counts = new Map<string, number>();
    filtered.forEach((a) => counts.set(a.type, (counts.get(a.type) || 0) + 1));
    return Array.from(counts.entries()).map(([name, value]) => ({ name, value }));
  }, [filtered]);

  const sorted = useMemo(() => [...filtered].sort((a, b) => (severityRank[a.severity] ?? 10) - (severityRank[b.severity] ?? 10)), [filtered]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {['critical', 'high', 'medium', 'low'].map((s) => (
          <div key={s} className="bg-gray-900/40 border border-gray-700/50 rounded-lg p-3">
            <div className="text-xs text-gray-500 uppercase">{s}</div>
            <div className="text-xl text-gray-100 mt-1">{filtered.filter((a) => a.severity === s).length}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4 h-72">
          <h3 className="text-sm text-gray-300 mb-3">Anomaly Type Breakdown</h3>
          <ResponsiveContainer width="100%" height="90%">
            <PieChart>
              <Pie data={typeData} dataKey="value" nameKey="name" outerRadius={100}>
                {typeData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4 h-72">
          <h3 className="text-sm text-gray-300 mb-3">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height="90%">
            <BarChart data={severityData}>
              <CartesianGrid stroke="#2a2a38" strokeDasharray="3 3" />
              <XAxis dataKey="name" stroke="#888" />
              <YAxis stroke="#888" />
              <Tooltip />
              <Bar dataKey="value" fill="#ef4444" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <AnomalyTimeline anomalies={filtered} />
      <HostAnomalyMap anomalies={filtered} onSelectHost={setHostFilter} />
      <BaselineView />

      <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4">
        <div className="flex flex-wrap gap-3 mb-4">
          <select className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
            <option value="all">All types</option>
            {[...new Set(anomalies.map((a) => a.type))].map((type) => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>
          {hostFilter && <button className="text-xs text-cyan-300" onClick={() => setHostFilter('')}>Clear host filter: {hostFilter}</button>}
        </div>

        <div className="space-y-2">
          {sorted.map((a) => (
            <div key={a.id} className="border border-gray-700/50 rounded-lg p-3">
              <button className="w-full text-left" onClick={() => setExpandedId(expandedId === a.id ? '' : a.id)}>
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm text-gray-100">{a.description}</div>
                  <div className={`text-xs px-2 py-0.5 rounded ${a.severity === 'critical' ? 'bg-red-500/20 text-red-300' : a.severity === 'high' ? 'bg-orange-500/20 text-orange-300' : a.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-300' : 'bg-green-500/20 text-green-300'}`}>{a.severity}</div>
                </div>
                <div className="text-xs text-gray-500 mt-1">{a.type} · {new Date(a.detected_at).toLocaleString()} · Hosts: {a.affected_hosts.join(', ') || 'n/a'}</div>
              </button>
              {expandedId === a.id && (
                <div className="mt-3 bg-gray-950/40 rounded p-3 text-xs text-gray-300">
                  <div><span className="text-gray-500">Evidence:</span> <pre className="whitespace-pre-wrap inline">{JSON.stringify(a.evidence, null, 2)}</pre></div>
                  <div className="mt-2"><span className="text-gray-500">Connections:</span> {a.affected_connections.join(', ') || 'n/a'}</div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default AnomalyDashboard;
