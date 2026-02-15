/**
 * Analytics Dashboard - Traffic trends, top talkers, protocol breakdown, threat heatmap.
 */
import React, { useState, useEffect } from 'react';
import {
  BarChart3, Activity, Globe, Shield, ArrowUpDown,
  RefreshCw, Network, Clock, Loader2,
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

interface TopTalker {
  ip: string;
  bytes_sent: number;
  bytes_recv: number;
  total_bytes: number;
  connections: number;
}

interface ProtocolEntry {
  protocol: string;
  connections: number;
  total_bytes: number;
}

interface TimelinePoint {
  timestamp: number;
  time: string;
  connections: number;
  bytes: number;
  alerts: number;
}

interface HeatmapEntry {
  src_ip: string;
  dst_ip: string;
  threat_score: number;
  connections: number;
  alerts: number;
}

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`;
  return `${(b / 1073741824).toFixed(2)} GB`;
}

interface AnalyticsDashboardProps {
  className?: string;
}

const AnalyticsDashboard: React.FC<AnalyticsDashboardProps> = ({ className = '' }) => {
  const [topTalkers, setTopTalkers] = useState<TopTalker[]>([]);
  const [protocols, setProtocols] = useState<ProtocolEntry[]>([]);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [heatmap, setHeatmap] = useState<HeatmapEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState<Record<string, any>>({});

  useEffect(() => {
    fetchAll();
  }, []);

  const fetchAll = async () => {
    setLoading(true);
    try {
      const safeFetch = (url: string) => fetch(url).then(r => {
        if (!r.ok) throw new Error(`${url} returned ${r.status}`);
        return r.json();
      });
      const [tt, proto, tl, hm, geo] = await Promise.all([
        safeFetch(`${API_BASE}/api/v1/analytics/top-talkers?limit=10`),
        safeFetch(`${API_BASE}/api/v1/analytics/protocol-breakdown`),
        safeFetch(`${API_BASE}/api/v1/analytics/traffic-timeline?bucket_minutes=5`),
        safeFetch(`${API_BASE}/api/v1/analytics/threat-heatmap`),
        safeFetch(`${API_BASE}/api/v1/analytics/geo-summary`),
      ]);
      setTopTalkers(tt.top_talkers || []);
      setProtocols(proto.protocols || []);
      setTimeline(tl.timeline || []);
      setHeatmap(hm.heatmap || []);
      setSummary(geo);
    } catch (err) {
      console.error('Failed to fetch analytics:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className={`flex items-center justify-center py-20 ${className}`}>
        <Loader2 size={24} className="animate-spin text-cyan-500" />
      </div>
    );
  }

  const maxBytes = Math.max(...topTalkers.map(t => t.total_bytes), 1);
  const maxTimelineConn = Math.max(...timeline.map(t => t.connections), 1);
  const maxHeatScore = Math.max(...heatmap.map(h => h.threat_score), 0.01);

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Summary Row */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: 'Connections', value: summary.connections?.toLocaleString() || '0', icon: Network },
          { label: 'DNS Queries', value: summary.dns_queries?.toLocaleString() || '0', icon: Globe },
          { label: 'Alerts', value: summary.alerts?.toLocaleString() || '0', icon: Shield },
          { label: 'Source IPs', value: summary.unique_source_ips?.toLocaleString() || '0', icon: Activity },
          { label: 'Domains', value: summary.unique_domains?.toLocaleString() || '0', icon: Globe },
        ].map(({ label, value, icon: Icon }) => (
          <div key={label} className="bg-gray-900/50 border border-gray-700/50 rounded-lg p-3 text-center">
            <Icon size={16} className="mx-auto mb-1 text-cyan-500" />
            <div className="text-xl font-bold text-gray-100">{value}</div>
            <div className="text-xs text-gray-500">{label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Top Talkers */}
        <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
            <BarChart3 size={16} className="text-cyan-400" /> Top Talkers
          </h3>
          <div className="space-y-2">
            {topTalkers.map((t, i) => (
              <div key={t.ip} className="flex items-center gap-3">
                <span className="text-xs text-gray-600 w-4">{i + 1}</span>
                <span className="font-mono text-xs text-gray-300 w-32 truncate">{t.ip}</span>
                <div className="flex-1 h-4 bg-gray-800 rounded overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-600 to-cyan-400 rounded"
                    style={{ width: `${(t.total_bytes / maxBytes) * 100}%` }}
                  />
                </div>
                <span className="text-xs text-gray-400 w-20 text-right">{formatBytes(t.total_bytes)}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Protocol Breakdown */}
        <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
            <Activity size={16} className="text-cyan-400" /> Protocol Breakdown
          </h3>
          <div className="space-y-3">
            {protocols.slice(0, 8).map(p => {
              const maxConn = Math.max(...protocols.map(x => x.connections), 1);
              const pct = (p.connections / maxConn) * 100;
              const colors: Record<string, string> = {
                tcp: 'bg-cyan-500', udp: 'bg-blue-500', icmp: 'bg-yellow-500',
              };
              return (
                <div key={p.protocol}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono text-gray-300 uppercase">{p.protocol}</span>
                    <span className="text-xs text-gray-500">{p.connections.toLocaleString()} conn</span>
                  </div>
                  <div className="h-2 bg-gray-800 rounded overflow-hidden">
                    <div
                      className={`h-full rounded ${colors[p.protocol] || 'bg-purple-500'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Traffic Timeline */}
      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <Clock size={16} className="text-cyan-400" /> Traffic Timeline
        </h3>
        <div className="flex items-end gap-px h-32">
          {timeline.map((point, i) => {
            const connHeight = (point.connections / maxTimelineConn) * 100;
            const hasAlerts = point.alerts > 0;
            return (
              <div
                key={i}
                className="flex-1 relative group"
                title={`${point.time}: ${point.connections} conn, ${point.alerts} alerts`}
              >
                <div
                  className={`w-full rounded-t transition-all ${hasAlerts ? 'bg-red-500' : 'bg-cyan-600'} hover:opacity-80`}
                  style={{ height: `${Math.max(connHeight, 2)}%` }}
                />
                <div className="hidden group-hover:block absolute bottom-full left-1/2 -translate-x-1/2 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 whitespace-nowrap z-10 mb-1">
                  {point.connections} conn {point.alerts > 0 && `| ${point.alerts} alerts`}
                </div>
              </div>
            );
          })}
        </div>
        <div className="flex justify-between mt-1 text-xs text-gray-600">
          <span>{timeline[0]?.time.split('T')[1]?.slice(0, 5) || ''}</span>
          <span>{timeline[timeline.length - 1]?.time.split('T')[1]?.slice(0, 5) || ''}</span>
        </div>
      </div>

      {/* Threat Heatmap */}
      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <Shield size={16} className="text-cyan-400" /> Threat Heatmap (Top Pairs)
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 border-b border-gray-700/50">
                <th className="text-left py-2 px-2">Source</th>
                <th className="text-left py-2 px-2">Destination</th>
                <th className="text-right py-2 px-2">Score</th>
                <th className="text-right py-2 px-2">Conn</th>
                <th className="text-right py-2 px-2">Alerts</th>
                <th className="py-2 px-2 w-32"></th>
              </tr>
            </thead>
            <tbody>
              {heatmap.slice(0, 15).map((h, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="py-1.5 px-2 font-mono text-xs text-gray-300">{h.src_ip}</td>
                  <td className="py-1.5 px-2 font-mono text-xs text-gray-300">{h.dst_ip}</td>
                  <td className="py-1.5 px-2 text-right font-semibold text-gray-200">
                    {(h.threat_score * 100).toFixed(0)}
                  </td>
                  <td className="py-1.5 px-2 text-right text-gray-400">{h.connections}</td>
                  <td className="py-1.5 px-2 text-right">
                    <span className={h.alerts > 0 ? 'text-red-400 font-medium' : 'text-gray-500'}>
                      {h.alerts}
                    </span>
                  </td>
                  <td className="py-1.5 px-2">
                    <div className="h-2 bg-gray-800 rounded overflow-hidden">
                      <div
                        className={`h-full rounded ${
                          h.threat_score >= 0.8 ? 'bg-red-500' :
                          h.threat_score >= 0.6 ? 'bg-orange-500' :
                          h.threat_score >= 0.4 ? 'bg-yellow-500' : 'bg-cyan-600'
                        }`}
                        style={{ width: `${(h.threat_score / maxHeatScore) * 100}%` }}
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <button
        onClick={fetchAll}
        className="flex items-center gap-2 mx-auto px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm rounded-lg transition-colors"
      >
        <RefreshCw size={14} /> Refresh Analytics
      </button>
    </div>
  );
};

export default AnalyticsDashboard;
