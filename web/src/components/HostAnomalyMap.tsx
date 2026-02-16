import React from 'react';

type AnomalyItem = {
  affected_hosts: string[];
  severity: 'low' | 'medium' | 'high' | 'critical' | string;
};

const scoreWeight: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const HostAnomalyMap: React.FC<{ anomalies: AnomalyItem[]; onSelectHost: (host: string) => void }> = ({ anomalies, onSelectHost }) => {
  const hostScores = new Map<string, number>();

  anomalies.forEach((anomaly) => {
    anomaly.affected_hosts.forEach((host) => {
      hostScores.set(host, (hostScores.get(host) || 0) + (scoreWeight[anomaly.severity] || 1));
    });
  });

  const rows = Array.from(hostScores.entries())
    .map(([host, score]) => ({ host, score }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 20);

  return (
    <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4">
      <h3 className="text-sm text-gray-300 mb-3">Host Anomaly Map</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 text-xs border-b border-gray-700">
              <th className="text-left py-2">Host</th>
              <th className="text-right py-2">Anomaly Score</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.host} className="border-b border-gray-800/50 cursor-pointer hover:bg-gray-800/30" onClick={() => onSelectHost(row.host)}>
                <td className="font-mono text-xs py-2">{row.host}</td>
                <td className="text-right py-2 text-cyan-300">{row.score}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default HostAnomalyMap;
