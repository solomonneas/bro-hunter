import React, { useEffect, useState } from 'react';
import AnomalyDashboard, { Anomaly } from '../../../components/AnomalyDashboard';

const API_BASE = import.meta.env.VITE_API_URL || '';

const Anomalies: React.FC = () => {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      await fetch(`${API_BASE}/api/v1/anomalies/detect`, { method: 'POST' });
      const response = await fetch(`${API_BASE}/api/v1/anomalies`);
      const data = await response.json();
      setAnomalies(data.anomalies || []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Anomalies</h1>
        <p className="text-sm text-gray-500 mt-1">Statistical anomaly detection with baseline profiling and host-level risk trends</p>
      </div>
      {loading ? <div className="text-sm text-gray-400">Running anomaly detection…</div> : <AnomalyDashboard anomalies={anomalies} />}
    </div>
  );
};

export default Anomalies;
