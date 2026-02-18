import React, { useEffect, useState } from 'react';
import { ShieldCheck, Copy, ChevronDown, ChevronUp, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';

const API = import.meta.env.VITE_API_URL || '';

interface TlsSession {
  uid: string; ts: string; src_ip: string; dst_ip: string; dst_port: number;
  server_name: string; ja3: string; ja3s: string; issuer: string; subject: string;
  not_before: string; not_after: string; self_signed: boolean; expired: boolean;
  cn_mismatch: boolean; ja3_match: any; score: string; reasons: string[]; mitre: string[];
}

interface Stats { total_sessions: number; ja3_matches: number; cert_anomalies: number; unique_servers: number; malicious: number; suspicious: number; clean: number; }

const ScoreBadge: React.FC<{score: string}> = ({ score }) => {
  const colors: Record<string, string> = {
    malicious: 'bg-red-500/20 text-red-400 border-red-500/30',
    suspicious: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    clean: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  };
  return <span className={`px-2 py-0.5 rounded text-xs font-medium border ${colors[score] || colors.clean}`}>{score}</span>;
};

const TlsIntelligence: React.FC = () => {
  const [sessions, setSessions] = useState<TlsSession[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [ja3Db, setJa3Db] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<TlsSession | null>(null);
  const [showDb, setShowDb] = useState(false);
  const [filter, setFilter] = useState('all');

  const load = async () => {
    setLoading(true);
    try {
      await fetch(`${API}/api/v1/tls/analyze`, { method: 'POST' });
      const [sessRes, statsRes, dbRes] = await Promise.all([
        fetch(`${API}/api/v1/tls/sessions`), fetch(`${API}/api/v1/tls/stats`), fetch(`${API}/api/v1/tls/ja3-database`),
      ]);
      const sessData = await sessRes.json(); const statsData = await statsRes.json(); const dbData = await dbRes.json();
      setSessions(sessData.sessions || []); setStats(statsData); setJa3Db(dbData.entries || []);
    } finally { setLoading(false); }
  };

  useEffect(() => { void load(); }, []);

  const filtered = filter === 'all' ? sessions : sessions.filter(s => s.score === filter);

  const copyHash = (hash: string) => { navigator.clipboard.writeText(hash); };

  return (
    <div className="space-y-6">
      {/* Stats cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'TLS Sessions', value: stats.total_sessions, icon: ShieldCheck },
            { label: 'JA3 Matches', value: stats.ja3_matches, icon: XCircle, color: 'text-red-400' },
            { label: 'Cert Anomalies', value: stats.cert_anomalies, icon: AlertTriangle, color: 'text-amber-400' },
            { label: 'Unique Servers', value: stats.unique_servers, icon: CheckCircle },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-1">
                <Icon size={16} className={color || 'text-gray-400'} />
                <span className="text-xs text-gray-500">{label}</span>
              </div>
              <div className={`text-2xl font-bold ${color || 'text-gray-100'}`}>{value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filter tabs */}
      <div className="flex gap-2">
        {['all', 'malicious', 'suspicious', 'clean'].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            className={`px-3 py-1 rounded text-sm ${filter === f ? 'bg-cyan-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-gray-200'}`}>
            {f} {f !== 'all' && stats ? `(${(stats as any)[f] || 0})` : ''}
          </button>
        ))}
      </div>

      {/* Sessions table */}
      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl overflow-hidden">
        {loading ? <div className="p-8 text-center text-gray-500">Analyzing TLS sessions...</div> : (
          <table className="w-full text-sm">
            <thead><tr className="border-b border-gray-700/50 text-gray-500 text-xs">
              <th className="text-left p-3">Server</th><th className="text-left p-3">JA3</th>
              <th className="text-left p-3 hidden md:table-cell">Issuer</th><th className="text-left p-3">Validity</th><th className="text-left p-3">Score</th>
            </tr></thead>
            <tbody>
              {filtered.map(s => (
                <tr key={s.uid} onClick={() => setSelected(selected?.uid === s.uid ? null : s)}
                  className="border-b border-gray-800/50 hover:bg-gray-800/30 cursor-pointer">
                  <td className="p-3 text-gray-100 font-mono text-xs">{s.server_name || s.dst_ip}</td>
                  <td className="p-3">
                    <div className="flex items-center gap-1">
                      <span className="font-mono text-xs text-gray-400">{s.ja3.slice(0, 12)}...</span>
                      <button onClick={(e) => { e.stopPropagation(); copyHash(s.ja3); }} className="text-gray-600 hover:text-cyan-400"><Copy size={12} /></button>
                    </div>
                  </td>
                  <td className="p-3 text-gray-400 text-xs hidden md:table-cell truncate max-w-[200px]">{s.issuer.split(',')[0]}</td>
                  <td className="p-3 text-xs">
                    <span className={s.expired ? 'text-red-400' : s.self_signed ? 'text-amber-400' : 'text-gray-400'}>
                      {s.expired ? 'Expired' : s.self_signed ? 'Self-signed' : `Until ${s.not_after}`}
                    </span>
                  </td>
                  <td className="p-3"><ScoreBadge score={s.score} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5 space-y-4">
          <h3 className="text-lg font-semibold text-gray-100">{selected.server_name || selected.dst_ip}</h3>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="text-gray-500">JA3:</span> <span className="font-mono text-gray-300 text-xs break-all">{selected.ja3}</span></div>
            <div><span className="text-gray-500">JA3S:</span> <span className="font-mono text-gray-300 text-xs break-all">{selected.ja3s}</span></div>
            <div><span className="text-gray-500">Issuer:</span> <span className="text-gray-300">{selected.issuer}</span></div>
            <div><span className="text-gray-500">Subject:</span> <span className="text-gray-300">{selected.subject}</span></div>
            <div><span className="text-gray-500">Valid:</span> <span className="text-gray-300">{selected.not_before} to {selected.not_after}</span></div>
            <div><span className="text-gray-500">Connection:</span> <span className="text-gray-300">{selected.src_ip} → {selected.dst_ip}:{selected.dst_port}</span></div>
          </div>
          {selected.reasons.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-2">Anomalies</h4>
              {selected.reasons.map((r, i) => <div key={i} className="text-sm text-amber-400 flex items-center gap-1"><AlertTriangle size={12} />{r}</div>)}
            </div>
          )}
          {selected.mitre.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-2">MITRE ATT&CK</h4>
              {selected.mitre.map((m, i) => <span key={i} className="inline-block bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs px-2 py-0.5 rounded mr-2 mb-1">{m}</span>)}
            </div>
          )}
          {selected.ja3_match && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
              <span className="text-red-400 font-medium text-sm">⚠ Known Malware: {selected.ja3_match.threat}</span>
              <p className="text-red-300 text-xs mt-1">{selected.ja3_match.description}</p>
            </div>
          )}
        </div>
      )}

      {/* JA3 Database */}
      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl">
        <button onClick={() => setShowDb(!showDb)} className="w-full flex items-center justify-between p-4 text-gray-400 hover:text-gray-200">
          <span className="text-sm font-medium">Known-Bad JA3 Database ({ja3Db.length} entries)</span>
          {showDb ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </button>
        {showDb && (
          <div className="border-t border-gray-700/50 max-h-64 overflow-y-auto">
            <table className="w-full text-xs">
              <thead><tr className="text-gray-500"><th className="text-left p-2 pl-4">Hash</th><th className="text-left p-2">Threat</th><th className="text-left p-2">Description</th></tr></thead>
              <tbody>
                {ja3Db.map((e, i) => (
                  <tr key={i} className="border-t border-gray-800/30">
                    <td className="p-2 pl-4 font-mono text-gray-400">{e.hash}</td>
                    <td className="p-2 text-red-400 font-medium">{e.threat}</td>
                    <td className="p-2 text-gray-500">{e.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default TlsIntelligence;
