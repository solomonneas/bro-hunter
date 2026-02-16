/**
 * Reports Page - Generate and view threat assessment reports for Variant 3.
 */
import React, { useState } from 'react';
import { FileText, Download, ExternalLink, Loader2 } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || '';

const Reports: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [jsonReport, setJsonReport] = useState<Record<string, any> | null>(null);

  const generateJson = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/reports/json`);
      if (!res.ok) throw new Error(`Failed: ${res.status}`);
      setJsonReport(await res.json());
    } catch (err) {
      console.error('Failed to generate report:', err);
    } finally {
      setLoading(false);
    }
  };

  const openHtml = () => {
    window.open(`${API_BASE}/api/v1/reports/html`, '_blank');
  };

  const downloadJson = () => {
    if (!jsonReport) return;
    const blob = new Blob([JSON.stringify(jsonReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bro-hunter-report-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Threat Reports</h1>
        <p className="text-sm text-gray-500 mt-1">Generate comprehensive threat assessment reports</p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* HTML Report Card */}
        <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <FileText size={18} className="text-cyan-400" />
            <h3 className="font-semibold text-gray-200">HTML Report</h3>
          </div>
          <p className="text-sm text-gray-400 mb-4">
            Full visual report with executive summary, top threats, MITRE coverage, and IOC listing.
            Opens in a new browser tab.
          </p>
          <button
            onClick={openHtml}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <ExternalLink size={16} /> Open HTML Report
          </button>
        </div>

        {/* JSON Report Card */}
        <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <FileText size={18} className="text-orange-400" />
            <h3 className="font-semibold text-gray-200">JSON Report</h3>
          </div>
          <p className="text-sm text-gray-400 mb-4">
            Structured data export for integration with SIEM, SOAR, or custom analysis tools.
          </p>
          <div className="flex gap-2">
            <button
              onClick={generateJson}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-2 bg-orange-600 hover:bg-orange-500 disabled:bg-gray-700 text-white text-sm font-medium rounded-lg transition-colors"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <FileText size={16} />}
              Generate
            </button>
            {jsonReport && (
              <button
                onClick={downloadJson}
                className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 text-sm rounded-lg transition-colors"
              >
                <Download size={16} /> Download
              </button>
            )}
          </div>
        </div>
      </div>

      {/* JSON Preview */}
      {jsonReport && (
        <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-3">Executive Summary</h3>
          <div className="grid grid-cols-4 gap-3 mb-4">
            {[
              { label: 'Critical', value: jsonReport.executive_summary?.critical_count, color: 'text-red-400' },
              { label: 'High', value: jsonReport.executive_summary?.high_count, color: 'text-orange-400' },
              { label: 'Medium', value: jsonReport.executive_summary?.medium_count, color: 'text-yellow-400' },
              { label: 'MITRE Techniques', value: jsonReport.executive_summary?.mitre_techniques_observed, color: 'text-blue-400' },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-gray-800/50 rounded-lg p-3 text-center">
                <div className={`text-2xl font-bold ${color}`}>{value ?? 0}</div>
                <div className="text-xs text-gray-500">{label}</div>
              </div>
            ))}
          </div>

          <h3 className="text-sm font-semibold text-gray-300 mb-2">Top Threats</h3>
          <div className="space-y-1 max-h-60 overflow-y-auto">
            {jsonReport.top_threats?.slice(0, 10).map((t: any, i: number) => (
              <div key={i} className="flex items-center gap-3 text-sm py-1">
                <span className="font-mono text-xs text-gray-300 w-32">{t.ip}</span>
                <span className={`text-xs px-2 py-0.5 rounded ${
                  t.threat_level === 'critical' ? 'bg-red-500/20 text-red-400' :
                  t.threat_level === 'high' ? 'bg-orange-500/20 text-orange-400' :
                  'bg-yellow-500/20 text-yellow-400'
                }`}>
                  {t.threat_level}
                </span>
                <span className="text-gray-400 text-xs truncate flex-1">{t.summary}</span>
                <span className="text-gray-500 font-mono text-xs">{(t.score * 100).toFixed(0)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;
