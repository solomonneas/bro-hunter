import React, { useEffect, useMemo, useState } from 'react';
import { Download, Eye, FileText, Loader2, Plus, ShieldAlert, Trash2 } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE || '';

type SeverityDistribution = {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
};

interface ReportHistoryItem {
  report_id: string;
  title: string;
  generated_at: string;
  threat_count: number;
  severity_distribution: SeverityDistribution;
  file_size_bytes: number;
  files: {
    json: string;
    html: string;
    pdf: string;
  };
}

const Reports: React.FC = () => {
  const [reports, setReports] = useState<ReportHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);

  const selectedReport = useMemo(
    () => reports.find((r) => r.report_id === selectedReportId) || null,
    [reports, selectedReportId],
  );

  const lastGeneratedDate = useMemo(() => {
    if (!reports.length) return '—';
    return new Date(reports[0].generated_at).toLocaleString();
  }, [reports]);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/reports/history`);
      if (!res.ok) throw new Error(`Failed loading history: ${res.status}`);
      const data = await res.json();
      setReports(Array.isArray(data?.reports) ? data.reports : []);
      if (!selectedReportId && data?.reports?.length) {
        setSelectedReportId(data.reports[0].report_id);
      }
    } catch (error) {
      console.error('Failed to load report history', error);
      setReports([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/reports/generate`, { method: 'POST' });
      if (!res.ok) throw new Error(`Failed generating report: ${res.status}`);
      const metadata: ReportHistoryItem = await res.json();
      await loadHistory();
      setSelectedReportId(metadata.report_id);
    } catch (error) {
      console.error('Failed to generate report', error);
    } finally {
      setGenerating(false);
    }
  };

  const handleDelete = async (reportId: string) => {
    setDeletingId(reportId);
    try {
      const res = await fetch(`${API_BASE}/api/v1/reports/history/${reportId}`, { method: 'DELETE' });
      if (!res.ok) throw new Error(`Failed deleting report: ${res.status}`);
      await loadHistory();
      if (selectedReportId === reportId) {
        setSelectedReportId(null);
      }
    } catch (error) {
      console.error('Failed to delete report', error);
    } finally {
      setDeletingId(null);
    }
  };

  const formatBytes = (bytes?: number) => {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let idx = 0;
    while (size >= 1024 && idx < units.length - 1) {
      size /= 1024;
      idx += 1;
    }
    return `${size.toFixed(idx === 0 ? 0 : 1)} ${units[idx]}`;
  };

  const severityBadge = (level: keyof SeverityDistribution, count: number | undefined) => (
    <span key={level} className={`v3-badge ${level}`} style={{ marginRight: 6 }}>
      {level.toUpperCase()}: {count ?? 0}
    </span>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
        <div>
          <h1 className="v3-page-title" style={{ margin: 0 }}>Threat Reports</h1>
          <p className="v3-page-subtitle" style={{ marginTop: 4 }}>
            Generate, track, and review PDF threat assessment reports.
          </p>
        </div>

        <button className="v3-btn v3-btn-primary" onClick={handleGenerate} disabled={generating}>
          {generating ? <Loader2 size={16} className="animate-spin" /> : <Plus size={16} />}
          <span>{generating ? 'Generating…' : 'Generate New Report'}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="v3-kpi">
          <div className="label">Total Reports</div>
          <div className="value">{reports.length}</div>
        </div>
        <div className="v3-kpi">
          <div className="label">Last Generated</div>
          <div className="value" style={{ fontSize: 20 }}>{lastGeneratedDate}</div>
        </div>
      </div>

      <div className="v3-card" style={{ padding: 16 }}>
        <h3 style={{ marginTop: 0, marginBottom: 12 }}>Report History</h3>

        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#64748B' }}>
            <Loader2 size={16} className="animate-spin" />
            Loading report history...
          </div>
        ) : reports.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '30px 16px', color: '#64748B' }}>
            <ShieldAlert size={26} style={{ marginBottom: 8 }} />
            <div style={{ fontWeight: 600, marginBottom: 4 }}>No reports generated yet</div>
            <div>Click "Generate New Report" to create your first threat report.</div>
          </div>
        ) : (
          <div className="v3-table-wrapper">
            <table className="v3-table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Title / ID</th>
                  <th style={{ textAlign: 'right' }}>Threats</th>
                  <th>Severity Breakdown</th>
                  <th style={{ textAlign: 'right' }}>File Size</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((report) => (
                  <tr key={report.report_id}>
                    <td>{new Date(report.generated_at).toLocaleString()}</td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{report.title || report.report_id}</div>
                      <div className="mono" style={{ color: '#64748B', fontSize: 12 }}>{report.report_id}</div>
                    </td>
                    <td style={{ textAlign: 'right' }}>{report.threat_count}</td>
                    <td>
                      {severityBadge('critical', report.severity_distribution?.critical)}
                      {severityBadge('high', report.severity_distribution?.high)}
                      {severityBadge('medium', report.severity_distribution?.medium)}
                      {severityBadge('low', report.severity_distribution?.low)}
                    </td>
                    <td style={{ textAlign: 'right' }}>{formatBytes(report.file_size_bytes)}</td>
                    <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <button
                        className="v3-btn v3-btn-outline"
                        style={{ marginRight: 8 }}
                        onClick={() => window.open(`${API_BASE}/api/v1/reports/history/${report.report_id}/download`, '_blank')}
                      >
                        <Download size={14} />
                        <span>Download PDF</span>
                      </button>
                      <button
                        className="v3-btn v3-btn-outline"
                        style={{ marginRight: 8 }}
                        onClick={() => setSelectedReportId(report.report_id)}
                      >
                        <Eye size={14} />
                        <span>View HTML</span>
                      </button>
                      <button
                        className="v3-btn v3-btn-outline"
                        onClick={() => handleDelete(report.report_id)}
                        disabled={deletingId === report.report_id}
                      >
                        {deletingId === report.report_id ? <Loader2 size={14} className="animate-spin" /> : <Trash2 size={14} />}
                        <span>Delete</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="v3-card" style={{ padding: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
          <FileText size={16} />
          <h3 style={{ margin: 0 }}>HTML Report Preview</h3>
        </div>

        {selectedReport ? (
          <iframe
            title="Report Preview"
            src={`${API_BASE}/api/v1/reports/history/${selectedReport.report_id}/html`}
            style={{ width: '100%', minHeight: 720, border: '1px solid #E2E8F0', borderRadius: 8 }}
          />
        ) : (
          <div style={{ color: '#64748B' }}>Select a report from history to preview its HTML output.</div>
        )}
      </div>
    </div>
  );
};

export default Reports;
