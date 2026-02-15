import React, { useRef, useState } from 'react';

const MAX_SIZE_BYTES = 100 * 1024 * 1024;
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

type UploadState = 'idle' | 'uploading' | 'parsing' | 'analyzing' | 'done' | 'error';

interface IngestStats {
  file_count: number;
  record_count: number;
  time_range: [string | null, string | null];
  unique_src_ips: number;
  unique_dst_ips: number;
  connections: number;
  dns_queries: number;
  alerts: number;
}

export interface PcapUploadProps {
  onComplete?: (stats: IngestStats) => void;
}

const PcapUpload: React.FC<PcapUploadProps> = ({ onComplete }) => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [state, setState] = useState<UploadState>('idle');
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<IngestStats | null>(null);

  const validateFile = (file: File): string | null => {
    const lower = file.name.toLowerCase();
    if (!lower.endsWith('.pcap') && !lower.endsWith('.pcapng')) {
      return 'Only .pcap and .pcapng files are supported.';
    }
    if (file.size > MAX_SIZE_BYTES) {
      return 'File exceeds 100MB limit.';
    }
    return null;
  };

  const uploadFile = async (file: File) => {
    const validationError = validateFile(file);
    if (validationError) {
      setState('error');
      setError(validationError);
      return;
    }

    setState('uploading');
    setProgress(0);
    setError(null);
    setStats(null);

    await new Promise<void>((resolve) => {
      const form = new FormData();
      form.append('file', file);

      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${API_BASE}/api/ingest/pcap`);

      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) {
          setProgress(Math.round((event.loaded / event.total) * 100));
        }
      };

      xhr.onload = async () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          setState('parsing');
          setProgress(100);
          await new Promise((r) => setTimeout(r, 300));
          setState('analyzing');
          await new Promise((r) => setTimeout(r, 300));

          const payload = JSON.parse(xhr.responseText);
          const ingestStats = payload.stats as IngestStats;
          setStats(ingestStats);
          setState('done');
          onComplete?.(ingestStats);
        } else {
          let message = 'Upload failed.';
          try {
            const payload = JSON.parse(xhr.responseText);
            message = payload.detail || message;
            if (xhr.status === 501) {
              message = 'tshark is not installed on the backend server.';
            }
          } catch {
            // noop
          }
          setState('error');
          setError(message);
        }
        resolve();
      };

      xhr.onerror = () => {
        setState('error');
        setError('Network error while uploading file.');
        resolve();
      };

      xhr.send(form);
    });
  };

  const onDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragActive(false);
    const file = event.dataTransfer.files?.[0];
    if (file) void uploadFile(file);
  };

  const statusLabel = {
    idle: 'Drop a PCAP file or browse',
    uploading: `Uploading… ${progress}%`,
    parsing: 'Parsing packets…',
    analyzing: 'Analyzing threats…',
    done: 'Upload complete',
    error: 'Upload failed',
  }[state];

  return (
    <div className="rounded-lg border border-gray-700 bg-surface/40 p-4">
      <h3 className="text-sm font-semibold text-gray-200 mb-3">PCAP Upload</h3>

      <div
        className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
          dragActive ? 'border-accent-cyan bg-accent-cyan/5' : 'border-gray-600'
        }`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragActive(true);
        }}
        onDragLeave={() => setDragActive(false)}
        onDrop={onDrop}
      >
        <p className="text-sm text-gray-300">{statusLabel}</p>
        <p className="text-xs text-gray-500 mt-1">Accepted formats: .pcap, .pcapng (max 100MB)</p>

        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          className="mt-3 px-3 py-1.5 text-xs rounded border border-gray-600 hover:border-accent-cyan text-gray-200"
        >
          Browse Files
        </button>
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void uploadFile(file);
          }}
        />

        {state === 'uploading' && (
          <div className="mt-4 h-2 w-full max-w-md mx-auto bg-gray-800 rounded overflow-hidden">
            <div className="h-full bg-accent-cyan transition-all" style={{ width: `${progress}%` }} />
          </div>
        )}
      </div>

      {error && <p className="mt-3 text-xs text-red-400">{error}</p>}

      {stats && (
        <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
          <div className="p-2 rounded bg-background border border-gray-700">Connections: {stats.connections}</div>
          <div className="p-2 rounded bg-background border border-gray-700">DNS Queries: {stats.dns_queries}</div>
          <div className="p-2 rounded bg-background border border-gray-700">Alerts: {stats.alerts}</div>
          <div className="p-2 rounded bg-background border border-gray-700">Records: {stats.record_count}</div>
          <div className="col-span-2 md:col-span-4 p-2 rounded bg-background border border-gray-700">
            Time Range: {stats.time_range[0] || 'n/a'} → {stats.time_range[1] || 'n/a'}
          </div>
        </div>
      )}
    </div>
  );
};

export default PcapUpload;
