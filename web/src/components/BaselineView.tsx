import React, { useEffect, useMemo, useState } from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';

type Deviation = {
  metric: string;
  current: number;
  baseline: number;
  sigma: number;
  status: 'warning' | 'critical';
};

type BaselineData = {
  built_at: string;
  protocol_distribution: Record<string, number>;
  traffic_volume: {
    bytes_per_hour_mean: number;
    connections_per_hour_mean: number;
  };
  host_profile: {
    internal_hosts: number;
    external_hosts: number;
  };
  dns_profile: {
    unique_queries_per_hour_mean: number;
    avg_query_length: number;
  };
};

const API_BASE = import.meta.env.VITE_API_URL || '';

const BaselineView: React.FC = () => {
  const [baseline, setBaseline] = useState<BaselineData | null>(null);
  const [compare, setCompare] = useState<{ deviations: Deviation[]; current?: BaselineData } | null>(null);
  const [loading, setLoading] = useState(false);

  const loadBaseline = async () => {
    const response = await fetch(`${API_BASE}/api/v1/baseline`);
    const data = await response.json();
    setBaseline(data.baseline || null);
  };

  const buildBaseline = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/v1/baseline/build`, { method: 'POST' });
      const data = await response.json();
      setBaseline(data.baseline || null);
      setCompare(null);
    } finally {
      setLoading(false);
    }
  };

  const runCompare = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/v1/baseline/compare`, { method: 'POST' });
      const data = await response.json();
      setCompare({ deviations: data.deviations || [], current: data.current });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void loadBaseline(); }, []);

  const protoChart = useMemo(() => {
    if (!baseline) return [];
    return Object.entries(baseline.protocol_distribution).map(([protocol, pct]) => ({
      protocol,
      baseline: Math.round(pct * 100),
      current: compare?.current?.protocol_distribution?.[protocol] ? Math.round(compare.current.protocol_distribution[protocol] * 100) : Math.round(pct * 100),
    }));
  }, [baseline, compare]);

  const deviationColor = (sigma: number) => {
    if (sigma > 2) return 'text-red-400';
    if (sigma > 1) return 'text-yellow-300';
    return 'text-green-400';
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <button className="px-3 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-sm" onClick={buildBaseline} disabled={loading}>
          {loading ? 'Working…' : 'Build Baseline'}
        </button>
        <button className="px-3 py-2 rounded bg-gray-700 hover:bg-gray-600 text-white text-sm" onClick={runCompare} disabled={loading || !baseline}>
          Compare Current Traffic
        </button>
      </div>

      {baseline && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="bg-gray-900/40 border border-gray-700/50 rounded-lg p-3">
              <div className="text-xs text-gray-500">Built At</div>
              <div className="text-sm text-gray-100 mt-1">{new Date(baseline.built_at).toLocaleString()}</div>
            </div>
            <div className="bg-gray-900/40 border border-gray-700/50 rounded-lg p-3">
              <div className="text-xs text-gray-500">Avg Bytes / Hour</div>
              <div className="text-lg text-gray-100 mt-1">{Math.round(baseline.traffic_volume.bytes_per_hour_mean).toLocaleString()}</div>
            </div>
            <div className="bg-gray-900/40 border border-gray-700/50 rounded-lg p-3">
              <div className="text-xs text-gray-500">Hosts (Internal / External)</div>
              <div className="text-lg text-gray-100 mt-1">{baseline.host_profile.internal_hosts} / {baseline.host_profile.external_hosts}</div>
            </div>
            <div className="bg-gray-900/40 border border-gray-700/50 rounded-lg p-3">
              <div className="text-xs text-gray-500">Avg DNS Query Length</div>
              <div className="text-lg text-gray-100 mt-1">{baseline.dns_profile.avg_query_length.toFixed(1)}</div>
            </div>
          </div>

          <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4 h-72">
            <h3 className="text-sm text-gray-300 mb-3">Protocol Mix: Baseline vs Current</h3>
            <ResponsiveContainer width="100%" height="90%">
              <BarChart data={protoChart}>
                <CartesianGrid stroke="#2a2a38" strokeDasharray="3 3" />
                <XAxis dataKey="protocol" stroke="#888" />
                <YAxis stroke="#888" />
                <Tooltip />
                <Legend />
                <Bar dataKey="baseline" fill="#3b82f6" />
                <Bar dataKey="current" fill="#22d3ee" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </>
      )}

      {compare && compare.deviations.length > 0 && (
        <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4">
          <h3 className="text-sm text-gray-300 mb-3">Deviation Indicators</h3>
          <div className="space-y-2">
            {compare.deviations.map((d) => (
              <div key={d.metric} className="flex justify-between text-sm border-b border-gray-800/50 pb-2">
                <span className="text-gray-300">{d.metric}</span>
                <span className={deviationColor(d.sigma)}>{d.sigma.toFixed(2)}σ</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default BaselineView;
