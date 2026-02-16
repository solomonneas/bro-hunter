import React, { useEffect, useMemo, useState } from 'react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, AreaChart, Area,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Brush,
} from 'recharts';
import LoadingSkeleton from './LoadingSkeleton';

const API_BASE = import.meta.env.VITE_API_URL || '';
const chartTheme = { grid: '#2a2a38', text: '#888', cyan: '#22d3ee', blue: '#3b82f6', red: '#ef4444', purple: '#a855f7', green: '#22c55e' };

const AnalyticsDashboard: React.FC<{ className?: string }> = ({ className = '' }) => {
  const [topTalkers, setTopTalkers] = useState<any[]>([]);
  const [protocols, setProtocols] = useState<any[]>([]);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [heatmap, setHeatmap] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>({});
  const [loading, setLoading] = useState(true);
  const [ipFilter, setIpFilter] = useState<string>('');

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const safe = (u: string) => fetch(u).then(r => r.json());
        const [tt, pb, tl, hm, geo] = await Promise.all([
          safe(`${API_BASE}/api/v1/analytics/top-talkers?limit=10`),
          safe(`${API_BASE}/api/v1/analytics/protocol-breakdown`),
          safe(`${API_BASE}/api/v1/analytics/traffic-timeline?bucket_minutes=5`),
          safe(`${API_BASE}/api/v1/analytics/threat-heatmap`),
          safe(`${API_BASE}/api/v1/analytics/geo-summary`),
        ]);
        setTopTalkers(tt.top_talkers || []);
        setProtocols(pb.protocols || []);
        setTimeline(tl.timeline || []);
        setHeatmap(hm.heatmap || []);
        setSummary(geo || {});
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const filteredHeatmap = useMemo(() => {
    if (!ipFilter) return heatmap;
    return heatmap.filter((h) => h.src_ip === ipFilter || h.dst_ip === ipFilter);
  }, [heatmap, ipFilter]);

  const scoreDist = useMemo(() => {
    const bins = Array.from({ length: 10 }).map((_, i) => ({ range: `${i * 10}-${i * 10 + 9}`, count: 0 }));
    heatmap.forEach((h) => {
      const idx = Math.min(9, Math.max(0, Math.floor((h.threat_score || 0) * 10)));
      bins[idx].count += 1;
    });
    return bins;
  }, [heatmap]);

  const mitreCoverage = [
    { tactic: 'Recon', value: 6 },
    { tactic: 'Initial', value: 8 },
    { tactic: 'Execution', value: 5 },
    { tactic: 'C2', value: 7 },
    { tactic: 'Exfil', value: 4 },
  ];

  if (loading) return <LoadingSkeleton rows={10} className={className} />;

  return (
    <div className={`space-y-6 ${className}`}>
      <div className="grid grid-cols-5 gap-3 text-center">
        {[
          ['Connections', summary.connections || 0],
          ['DNS Queries', summary.dns_queries || 0],
          ['Alerts', summary.alerts || 0],
          ['Src IPs', summary.unique_source_ips || 0],
          ['Domains', summary.unique_domains || 0],
        ].map(([label, value]) => (
          <div key={String(label)} className="bg-gray-900/40 border border-gray-700/50 rounded-lg p-3">
            <div className="text-xl font-semibold text-gray-100">{Number(value).toLocaleString()}</div>
            <div className="text-xs text-gray-500">{label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4 h-72">
          <h3 className="text-sm text-gray-300 mb-3">Protocol Breakdown</h3>
          <ResponsiveContainer width="100%" height="90%">
            <BarChart layout="vertical" data={protocols.slice(0, 8)}>
              <CartesianGrid stroke={chartTheme.grid} strokeDasharray="3 3" />
              <XAxis type="number" stroke={chartTheme.text} />
              <YAxis type="category" dataKey="protocol" stroke={chartTheme.text} />
              <Tooltip />
              <Bar dataKey="connections" fill={chartTheme.blue} radius={[0, 6, 6, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4 h-72">
          <h3 className="text-sm text-gray-300 mb-3">Top Talkers (click to filter)</h3>
          <ResponsiveContainer width="100%" height="90%">
            <BarChart data={topTalkers} onClick={(state: any) => state?.activePayload?.[0] && setIpFilter(state.activePayload[0].payload.ip)}>
              <CartesianGrid stroke={chartTheme.grid} strokeDasharray="3 3" />
              <XAxis dataKey="ip" stroke={chartTheme.text} tick={{ fontSize: 10 }} />
              <YAxis stroke={chartTheme.text} />
              <Tooltip />
              <Bar dataKey="total_bytes" fill={chartTheme.cyan} radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4 h-80">
        <h3 className="text-sm text-gray-300 mb-3">Traffic Timeline</h3>
        <ResponsiveContainer width="100%" height="90%">
          <AreaChart data={timeline}>
            <CartesianGrid stroke={chartTheme.grid} strokeDasharray="3 3" />
            <XAxis dataKey="time" stroke={chartTheme.text} tick={{ fontSize: 10 }} />
            <YAxis stroke={chartTheme.text} />
            <Tooltip />
            <Area type="monotone" dataKey="connections" stroke={chartTheme.green} fill={chartTheme.green} fillOpacity={0.2} />
            <Brush dataKey="time" height={20} stroke={chartTheme.cyan} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4 h-72">
          <h3 className="text-sm text-gray-300 mb-3">Threat Score Distribution</h3>
          <ResponsiveContainer width="100%" height="90%">
            <BarChart data={scoreDist}>
              <CartesianGrid stroke={chartTheme.grid} strokeDasharray="3 3" />
              <XAxis dataKey="range" stroke={chartTheme.text} />
              <YAxis stroke={chartTheme.text} />
              <Tooltip />
              <Bar dataKey="count" fill={chartTheme.red} radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4 h-72">
          <h3 className="text-sm text-gray-300 mb-3">MITRE Coverage Radar</h3>
          <ResponsiveContainer width="100%" height="90%">
            <RadarChart data={mitreCoverage}>
              <PolarGrid stroke={chartTheme.grid} />
              <PolarAngleAxis dataKey="tactic" stroke={chartTheme.text} />
              <PolarRadiusAxis stroke={chartTheme.text} />
              <Radar dataKey="value" stroke={chartTheme.purple} fill={chartTheme.purple} fillOpacity={0.3} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4">
        <h3 className="text-sm text-gray-300 mb-3">Threat Heatmap {ipFilter && <span className="text-cyan-400">(filtered: {ipFilter})</span>}</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-gray-500 text-xs border-b border-gray-700"><th className="text-left py-2">Source</th><th className="text-left py-2">Destination</th><th className="text-right py-2">Score</th></tr></thead>
            <tbody>
              {filteredHeatmap.slice(0, 20).map((h, i) => (
                <tr key={i} className="border-b border-gray-800/50">
                  <td className="font-mono text-xs py-2">{h.src_ip}</td>
                  <td className="font-mono text-xs py-2">{h.dst_ip}</td>
                  <td className="text-right py-2">
                    <span className="px-2 py-0.5 rounded" style={{ background: `rgba(239,68,68,${Math.max(0.1, h.threat_score)})` }}>{(h.threat_score * 100).toFixed(0)}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default AnalyticsDashboard;
