import React from 'react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';

type AnomalyItem = {
  id: string;
  detected_at: string;
  severity: string;
  type: string;
};

const AnomalyTimeline: React.FC<{ anomalies: AnomalyItem[] }> = ({ anomalies }) => {
  const buckets = new Map<string, number>();

  anomalies.forEach((a) => {
    const hour = new Date(a.detected_at);
    hour.setMinutes(0, 0, 0);
    const key = hour.toISOString();
    buckets.set(key, (buckets.get(key) || 0) + 1);
  });

  const data = Array.from(buckets.entries())
    .map(([time, count]) => ({ time, count }))
    .sort((a, b) => a.time.localeCompare(b.time));

  return (
    <div className="bg-gray-900/40 border border-gray-700/50 rounded-xl p-4 h-72">
      <h3 className="text-sm text-gray-300 mb-3">Anomaly Timeline</h3>
      <ResponsiveContainer width="100%" height="90%">
        <AreaChart data={data}>
          <CartesianGrid stroke="#2a2a38" strokeDasharray="3 3" />
          <XAxis dataKey="time" stroke="#888" tick={{ fontSize: 10 }} />
          <YAxis stroke="#888" />
          <Tooltip />
          <Area type="monotone" dataKey="count" stroke="#22d3ee" fill="#22d3ee" fillOpacity={0.2} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export default AnomalyTimeline;
