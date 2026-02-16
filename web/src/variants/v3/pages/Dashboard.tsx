import React, { useEffect, useMemo, useState } from 'react';
import AnalyticsDashboard from '../../../components/AnalyticsDashboard';
import LoadingSkeleton from '../../../components/LoadingSkeleton';

const API_BASE = import.meta.env.VITE_API_BASE || '';

const Dashboard: React.FC = () => {
  const [summary, setSummary] = useState<any>(null);
  const [protocols, setProtocols] = useState<any[]>([]);
  const [mode, setMode] = useState<boolean>(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const [geo, pb, m] = await Promise.all([
          fetch(`${API_BASE}/api/v1/analytics/geo-summary`).then(r => r.json()),
          fetch(`${API_BASE}/api/v1/analytics/protocol-breakdown`).then(r => r.json()),
          fetch(`${API_BASE}/api/v1/settings/mode`).then(r => r.json()),
        ]);
        setSummary(geo);
        setProtocols(pb.protocols || []);
        setMode(Boolean(m.demo_mode));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const topProtocol = useMemo(() => protocols[0]?.protocol || 'N/A', [protocols]);
  const avgScore = useMemo(() => {
    return 0; // placeholder until scoring summary endpoint is added
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Security Dashboard</h1>
        <p className="text-sm text-gray-500 mt-1">Operational overview with packet and analytics insights</p>
      </div>

      {mode && (
        <div className="text-xs rounded-lg px-3 py-2 border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
          Running with sanitized demo data
        </div>
      )}

      {loading ? <LoadingSkeleton rows={4} /> : (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
          {[
            ['Total Connections', summary?.connections || 0],
            ['Threats Found', summary?.alerts || 0],
            ['Avg Score', avgScore.toFixed(1)],
            ['Top Protocol', topProtocol],
            ['Mode', mode ? 'Demo' : 'Live'],
          ].map(([label, value], idx) => (
            <div key={String(label)} className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4 animate-[v3-fade-in_0.25s_ease]" style={{ animationDelay: `${idx * 60}ms` }}>
              <div className="text-xs text-gray-500">{label}</div>
              <div className="text-xl font-semibold text-gray-100 mt-1">{value as any}</div>
            </div>
          ))}
        </div>
      )}

      <AnalyticsDashboard />
    </div>
  );
};

export default Dashboard;
