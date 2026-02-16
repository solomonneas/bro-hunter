import React, { useState } from 'react';

interface SigmaTemplate {
  filename: string;
  name: string;
  description: string;
  severity: string;
  logic: string;
  conditions: Array<{ field: string; operator: string; value: unknown }>;
}

interface SigmaImportProps {
  onImported: () => void;
}

const API_BASE = import.meta.env.VITE_API_BASE || '';

const SigmaImport: React.FC<SigmaImportProps> = ({ onImported }) => {
  const [templates, setTemplates] = useState<SigmaTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);

  const loadTemplates = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/sigma/templates`);
      if (!res.ok) return;
      const data = await res.json();
      setTemplates(data.templates || []);
    } finally {
      setLoading(false);
    }
  };

  const upload = async (file: File) => {
    const form = new FormData();
    form.append('file', file);
    setUploading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/sigma/import`, {
        method: 'POST',
        body: form,
      });
      if (res.ok) onImported();
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-200">Import Sigma</h3>
        <button onClick={loadTemplates} className="px-3 py-1.5 text-xs rounded border border-gray-700 bg-gray-800 text-gray-300">
          {loading ? 'Loading…' : 'Load Templates'}
        </button>
      </div>

      <input
        type="file"
        accept=".yml,.yaml"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) upload(file);
        }}
        className="text-sm text-gray-300"
      />
      {uploading && <p className="text-xs text-cyan-300">Importing…</p>}

      {templates.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs text-gray-500">Bundled templates preview</p>
          <div className="max-h-64 overflow-auto space-y-2">
            {templates.map((tpl) => (
              <div key={tpl.filename} className="border border-gray-700 rounded-lg p-3 bg-gray-800/50">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-gray-100 font-medium">{tpl.name}</span>
                  <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300">Sigma</span>
                </div>
                <p className="text-xs text-gray-400 mt-1">{tpl.description}</p>
                <pre className="mt-2 text-[11px] text-gray-300 overflow-auto">{JSON.stringify(tpl.conditions, null, 2)}</pre>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default SigmaImport;
