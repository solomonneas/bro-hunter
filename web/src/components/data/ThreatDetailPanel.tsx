/**
 * ThreatDetailPanel — Expanded detail view for a selected threat.
 * Shows full information: scores, indicators, timeline, MITRE mapping.
 */
import React from 'react';
import { X, ExternalLink, Clock, Target, Activity } from 'lucide-react';
import { format } from 'date-fns';
import type { ThreatScore } from '../../types';
import { ScoreGauge } from '../charts/ScoreGauge';

export interface ThreatDetailPanelProps {
  threat: ThreatScore | null;
  onClose: () => void;
}

const SeverityBadge: React.FC<{ level: string }> = ({ level }) => {
  const colorMap: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/40',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
    medium: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
    info: 'bg-gray-500/20 text-gray-400 border-gray-500/40',
  };
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase border ${colorMap[level] || colorMap.info}`}>
      {level}
    </span>
  );
};

export const ThreatDetailPanel: React.FC<ThreatDetailPanelProps> = ({ threat, onClose }) => {
  if (!threat) return null;

  const firstSeen = format(new Date(threat.first_seen * 1000), 'MMM d, yyyy HH:mm:ss');
  const lastSeen = format(new Date(threat.last_seen * 1000), 'MMM d, yyyy HH:mm:ss');

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-lg bg-surface border-l border-gray-700 shadow-2xl z-50 overflow-y-auto" role="dialog" aria-label={`Threat detail: ${threat.entity}`}>
      {/* Header */}
      <div className="sticky top-0 bg-surface/95 backdrop-blur border-b border-gray-700 px-5 py-4 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-100">Threat Detail</h2>
          <p className="text-xs text-gray-500 font-mono mt-0.5">{threat.entity}</p>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded hover:bg-gray-700 text-gray-400 hover:text-gray-200 transition-colors"
          aria-label="Close threat detail panel"
        >
          <X size={18} aria-hidden="true" />
        </button>
      </div>

      <div className="p-5 space-y-6">
        {/* Score & Severity */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <SeverityBadge level={threat.level} />
            <span className="text-xs text-gray-500">
              Confidence: {(threat.confidence * 100).toFixed(0)}%
            </span>
          </div>
          <ScoreGauge score={threat.score} label="Threat Score" size={100} />
        </div>

        {/* Timeline */}
        <div className="grid grid-cols-2 gap-3">
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <Clock size={14} aria-hidden="true" />
            <div>
              <p className="text-gray-500">First Seen</p>
              <p className="text-gray-300 font-mono">{firstSeen}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <Clock size={14} aria-hidden="true" />
            <div>
              <p className="text-gray-500">Last Seen</p>
              <p className="text-gray-300 font-mono">{lastSeen}</p>
            </div>
          </div>
        </div>

        {/* Occurrences */}
        <div className="flex items-center gap-2 text-sm text-gray-300">
          <Activity size={14} className="text-accent-cyan" aria-hidden="true" />
          <span>{threat.occurrence_count} total occurrences</span>
        </div>

        {/* Reasons */}
        <div>
          <h3 className="text-sm font-semibold text-gray-300 mb-2">Detection Reasons</h3>
          <ul className="space-y-1.5">
            {threat.reasons.map((r, i) => (
              <li key={i} className="text-xs text-gray-400 flex items-start gap-2">
                <span className="mt-1 w-1 h-1 rounded-full bg-accent-amber flex-shrink-0" aria-hidden="true" />
                {r}
              </li>
            ))}
          </ul>
        </div>

        {/* MITRE ATT&CK */}
        {threat.mitre_techniques.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-gray-300 mb-2 flex items-center gap-2">
              <Target size={14} aria-hidden="true" />
              MITRE ATT&CK
            </h3>
            <div className="flex flex-wrap gap-2">
              {threat.mitre_techniques.map((t) => (
                <a
                  key={t}
                  href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-mono bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20 hover:bg-accent-cyan/20 transition-colors"
                  aria-label={`View MITRE technique ${t} (opens in new tab)`}
                >
                  {t}
                  <ExternalLink size={10} aria-hidden="true" />
                </a>
              ))}
            </div>
          </div>
        )}

        {/* Indicators */}
        {threat.indicators.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-gray-300 mb-2">Indicators</h3>
            <div className="space-y-1">
              {threat.indicators.map((ind, i) => (
                <p key={i} className="text-xs font-mono text-gray-400 bg-background/50 px-2 py-1 rounded">
                  {ind}
                </p>
              ))}
            </div>
          </div>
        )}

        {/* Related IPs */}
        {threat.related_ips.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-gray-300 mb-2">Related IPs</h3>
            <div className="flex flex-wrap gap-2">
              {threat.related_ips.map((ip) => (
                <span key={ip} className="text-xs font-mono text-gray-400 bg-background/50 px-2 py-0.5 rounded">
                  {ip}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Related Domains */}
        {threat.related_domains.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold text-gray-300 mb-2">Related Domains</h3>
            <div className="space-y-1">
              {threat.related_domains.map((d) => (
                <p key={d} className="text-xs font-mono text-gray-400 bg-background/50 px-2 py-1 rounded">
                  {d}
                </p>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatDetailPanel;
