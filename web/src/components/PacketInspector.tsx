import React, { useEffect, useMemo, useState } from 'react';
import FlowTimeline from './FlowTimeline';
import HexViewer from './HexViewer';
import LoadingSkeleton from './LoadingSkeleton';

const API_BASE = import.meta.env.VITE_API_BASE || '';

type Tab = 'http' | 'dns' | 'tls' | 'files' | 'raw';

const PacketInspector: React.FC<{ uid: string }> = ({ uid }) => {
  const [detail, setDetail] = useState<any>(null);
  const [flow, setFlow] = useState<any[]>([]);
  const [payload, setPayload] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<Tab>('http');
  const [error, setError] = useState<string>('');

  useEffect(() => {
    const run = async () => {
      setLoading(true);
      setError('');
      try {
        const [d, f, p] = await Promise.all([
          fetch(`${API_BASE}/api/v1/packets/${uid}`).then(r => r.json()),
          fetch(`${API_BASE}/api/v1/packets/${uid}/flow`).then(r => r.json()),
          fetch(`${API_BASE}/api/v1/packets/payload-preview/${uid}`).then(r => r.json()),
        ]);
        if (d.detail) throw new Error(d.detail);
        setDetail(d);
        setFlow(f.events || []);
        setPayload(p.preview || '');
      } catch (e: any) {
        setError(e?.message || 'Failed to load packet details');
      } finally {
        setLoading(false);
      }
    };
    run();
  }, [uid]);

  const protocolRows = useMemo(() => detail?.protocol_details?.[tab] || [], [detail, tab]);

  if (loading) return <LoadingSkeleton rows={8} />;
  if (error) return <div className="text-red-400 text-sm">{error}</div>;
  if (!detail) return <div className="text-gray-500 text-sm">No packet detail found.</div>;

  return (
    <div className="space-y-5">
      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-4">
        <div className="text-sm text-gray-400">Connection Summary</div>
        <div className="mt-2 font-mono text-sm text-gray-100">
          {detail.src.ip}:{detail.src.port} ↔ {detail.dst.ip}:{detail.dst.port} ({detail.protocol})
        </div>
        <div className="text-xs text-gray-500 mt-2">Duration: {detail.duration || 0}s · Bytes: {(detail.bytes_sent || 0) + (detail.bytes_recv || 0)}</div>
      </div>

      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">Flow Timeline</h3>
        <FlowTimeline events={flow} />
      </div>

      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-4">
        <div className="flex gap-2 mb-3 text-xs">
          {(['http', 'dns', 'tls', 'files', 'raw'] as Tab[]).map((t) => (
            <button key={t} onClick={() => setTab(t)} className={`px-2 py-1 rounded border ${tab === t ? 'border-cyan-500 text-cyan-300' : 'border-gray-700 text-gray-500'}`}>
              {t.toUpperCase()}
            </button>
          ))}
        </div>
        <pre className="text-xs bg-gray-950/60 border border-gray-800 rounded p-3 overflow-x-auto text-gray-300">{JSON.stringify(protocolRows, null, 2)}</pre>
      </div>

      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">Payload Preview</h3>
        <HexViewer preview={payload} />
      </div>
    </div>
  );
};

export default PacketInspector;
