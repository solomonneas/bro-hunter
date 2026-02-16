import React, { useMemo, useState } from 'react';

const HexViewer: React.FC<{ preview: string }> = ({ preview }) => {
  const [mode, setMode] = useState<'combined' | 'hex' | 'ascii'>('combined');
  const lines = useMemo(() => preview.split('\n').filter(Boolean), [preview]);

  return (
    <div className="space-y-2">
      <div className="flex gap-2 text-xs">
        {(['combined', 'hex', 'ascii'] as const).map((m) => (
          <button
            key={m}
            onClick={() => setMode(m)}
            className={`px-2 py-1 rounded border ${mode === m ? 'border-cyan-500 text-cyan-300' : 'border-gray-700 text-gray-400'}`}
          >
            {m}
          </button>
        ))}
      </div>
      <pre className="bg-gray-900/60 border border-gray-800 rounded p-3 text-[11px] text-gray-300 font-mono overflow-x-auto max-h-64">
        {lines.map((line, i) => {
          const parts = line.split('  ');
          if (mode === 'combined') return <div key={i}>{line}</div>;
          if (mode === 'hex') return <div key={i}>{[parts[0], parts[1]].filter(Boolean).join('  ')}</div>;
          return <div key={i}>{[parts[0], parts[2]].filter(Boolean).join('  ')}</div>;
        })}
      </pre>
    </div>
  );
};

export default HexViewer;
