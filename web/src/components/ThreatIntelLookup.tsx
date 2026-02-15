/**
 * Threat Intel Lookup - Search IPs/domains against threat intelligence feeds.
 */
import React, { useState } from 'react';
import { Search, Shield, AlertTriangle, CheckCircle, ExternalLink, Loader2 } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

interface IntelResult {
  source: string;
  malicious: boolean;
  confidence: number;
  description: string;
  categories: string[];
  references: string[];
}

interface LookupResult {
  indicator: string;
  type: string;
  is_malicious: boolean;
  max_confidence: number;
  sources_checked: number;
  sources_flagged: number;
  categories: string[];
  results: IntelResult[];
}

interface ThreatIntelLookupProps {
  className?: string;
  initialIp?: string;
}

const ThreatIntelLookup: React.FC<ThreatIntelLookupProps> = ({ className = '', initialIp }) => {
  const [query, setQuery] = useState(initialIp || '');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LookupResult | null>(null);
  const [error, setError] = useState('');
  const [status, setStatus] = useState<Record<string, any> | null>(null);

  const isIp = (s: string) => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s.trim());

  const handleLookup = async () => {
    const q = query.trim();
    if (!q) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const type = isIp(q) ? 'ip' : 'domain';
      const res = await fetch(`${API_BASE}/api/v1/intel/${type}/${encodeURIComponent(q)}`);
      if (!res.ok) throw new Error(`Lookup failed: ${res.status}`);
      setResult(await res.json());
    } catch (err: any) {
      setError(err.message || 'Lookup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleCheckStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/intel/status`);
      if (res.ok) setStatus(await res.json());
    } catch {}
  };

  return (
    <div className={`bg-gray-900/50 border border-gray-700/50 rounded-xl p-5 ${className}`}>
      <div className="flex items-center gap-2 mb-4">
        <Shield size={18} className="text-cyan-400" />
        <h3 className="text-lg font-semibold text-gray-100">Threat Intelligence</h3>
        <button onClick={handleCheckStatus} className="ml-auto text-xs text-gray-500 hover:text-gray-300">
          Check Sources
        </button>
      </div>

      {/* Status */}
      {status && (
        <div className="flex gap-2 mb-3 flex-wrap">
          {Object.entries(status.sources || {}).map(([name, info]: [string, any]) => (
            <span key={name} className={`text-xs px-2 py-1 rounded ${
              info.configured ? 'bg-green-500/20 text-green-400' : 'bg-gray-700/50 text-gray-500'
            }`}>
              {name}: {info.configured ? '✓' : '✗'}
            </span>
          ))}
        </div>
      )}

      {/* Search */}
      <div className="flex gap-2 mb-4">
        <div className="flex-1 relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleLookup()}
            placeholder="Enter IP or domain..."
            className="w-full bg-gray-800 text-gray-200 text-sm border border-gray-700 rounded-lg pl-9 pr-3 py-2"
          />
        </div>
        <button
          onClick={handleLookup}
          disabled={loading || !query.trim()}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 text-white text-sm font-medium rounded-lg transition-colors"
        >
          {loading ? <Loader2 size={16} className="animate-spin" /> : 'Lookup'}
        </button>
      </div>

      {error && <p className="text-red-400 text-sm mb-3">{error}</p>}

      {/* Results */}
      {result && (
        <div className="space-y-3">
          {/* Verdict */}
          <div className={`flex items-center gap-3 p-3 rounded-lg border ${
            result.is_malicious
              ? 'bg-red-500/10 border-red-500/50'
              : 'bg-green-500/10 border-green-500/50'
          }`}>
            {result.is_malicious ? (
              <AlertTriangle size={20} className="text-red-400" />
            ) : (
              <CheckCircle size={20} className="text-green-400" />
            )}
            <div>
              <span className={`font-semibold ${result.is_malicious ? 'text-red-300' : 'text-green-300'}`}>
                {result.indicator}
              </span>
              <span className="text-gray-400 text-sm ml-2">
                {result.is_malicious ? 'MALICIOUS' : 'CLEAN'} — {result.sources_flagged}/{result.sources_checked} sources flagged
              </span>
            </div>
            <span className="ml-auto text-sm font-mono text-gray-400">
              {(result.max_confidence * 100).toFixed(0)}% confidence
            </span>
          </div>

          {/* Categories */}
          {result.categories.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              {result.categories.map((cat, i) => (
                <span key={i} className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded">{cat}</span>
              ))}
            </div>
          )}

          {/* Per-source results */}
          {result.results.map((r, i) => (
            <div key={i} className="bg-gray-800/50 rounded-lg p-3 text-sm">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-medium text-gray-300">{r.source}</span>
                <span className={`text-xs px-2 py-0.5 rounded ${
                  r.malicious ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                }`}>
                  {r.malicious ? 'Flagged' : 'Clean'}
                </span>
                <span className="text-xs text-gray-500 ml-auto">
                  {(r.confidence * 100).toFixed(0)}%
                </span>
              </div>
              <p className="text-gray-400 text-xs">{r.description}</p>
              {r.references.length > 0 && (
                <div className="mt-1 flex gap-2 flex-wrap">
                  {r.references.map((ref, j) => (
                    <span key={j} className="text-xs text-cyan-400 flex items-center gap-1">
                      <ExternalLink size={10} />{ref}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ThreatIntelLookup;
