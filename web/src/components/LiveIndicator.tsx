/**
 * Live indicator component for dashboard.
 * Shows live status, last update time, and toggle control.
 */
import React from 'react';
import { Radio, PauseCircle, AlertTriangle, RefreshCw } from 'lucide-react';
import { formatLastUpdate } from '../hooks/useLiveRefresh';

interface LiveIndicatorProps {
  isEnabled: boolean;
  isLive: boolean;
  lastUpdateAt: Date | null;
  lastError: string | null;
  consecutiveFailures: number;
  onToggle: () => void;
  onResetBackoff?: () => void;
}

const LiveIndicator: React.FC<LiveIndicatorProps> = ({
  isEnabled,
  isLive,
  lastUpdateAt,
  lastError,
  consecutiveFailures,
  onToggle,
  onResetBackoff,
}) => {
  const hasFailed = consecutiveFailures >= 3;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
      {/* Live Status Badge */}
      <button
        onClick={onToggle}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          padding: '6px 12px',
          borderRadius: 6,
          border: '1px solid',
          borderColor: hasFailed ? '#FCA5A5' : isEnabled && isLive ? '#86EFAC' : '#E2E8F0',
          background: hasFailed ? '#FEF2F2' : isEnabled && isLive ? '#F0FDF4' : '#F8FAFC',
          color: hasFailed ? '#DC2626' : isEnabled && isLive ? '#16A34A' : '#64748B',
          fontSize: 12,
          fontWeight: 600,
          cursor: 'pointer',
          transition: 'all 0.15s ease',
        }}
        title={isEnabled ? 'Click to disable live refresh' : 'Click to enable live refresh'}
        aria-label={isEnabled ? 'Disable live refresh' : 'Enable live refresh'}
      >
        {isEnabled && isLive ? (
          <>
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: '#22C55E',
                animation: 'pulse 2s infinite',
              }}
            />
            <Radio size={14} />
            <span>Live: On</span>
          </>
        ) : hasFailed ? (
          <>
            <AlertTriangle size={14} />
            <span>Live: Error</span>
          </>
        ) : (
          <>
            <PauseCircle size={14} />
            <span>Live: Off</span>
          </>
        )}
      </button>

      {/* Last Update Time */}
      <span
        style={{
          fontSize: 12,
          color: '#64748B',
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
        }}
      >
        Last update: {formatLastUpdate(lastUpdateAt)}
      </span>

      {/* Warning Banner for failures */}
      {hasFailed && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '8px 12px',
            background: '#FEF2F2',
            border: '1px solid #FECACA',
            borderRadius: 6,
            color: '#DC2626',
            fontSize: 12,
          }}
        >
          <AlertTriangle size={14} />
          <span>
            Live refresh paused after {consecutiveFailures} failed attempts.
            {lastError && ` Error: ${lastError}`}
          </span>
          {onResetBackoff && (
            <button
              onClick={onResetBackoff}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 4,
                marginLeft: 8,
                padding: '4px 8px',
                background: '#DC2626',
                color: '#fff',
                border: 'none',
                borderRadius: 4,
                fontSize: 11,
                fontWeight: 600,
                cursor: 'pointer',
              }}
              title="Retry live refresh"
            >
              <RefreshCw size={12} />
              Retry
            </button>
          )}
        </div>
      )}

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  );
};

export default LiveIndicator;
