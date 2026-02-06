/**
 * V3 Dashboard — Corporate SOC overview.
 * 12-col grid: KPI cards, area chart, donut, threat summary table, recent alerts.
 */
import React from 'react';
import {
  AlertTriangle,
  Shield,
  Radio,
  Globe,
  TrendingUp,
  TrendingDown,
  Minus,
  Activity,
  Target,
  Users,
} from 'lucide-react';
import { format } from 'date-fns';
import {
  mockDashboardStats,
  mockTimeline,
  mockSeverityDistribution,
  mockAlerts,
} from '../../../data/mockData';
import { ThreatTimeline } from '../../../components/charts/ThreatTimeline';
import { SeverityDonut } from '../../../components/charts/SeverityDonut';
import type { ChartTheme, ThreatScore } from '../../../types';

/* V3 chart theme: light background, blue primary, professional palette */
const v3ChartTheme: ChartTheme = {
  colors: {
    primary: '#2563EB',
    secondary: '#7C3AED',
    accent: '#EA580C',
    danger: '#DC2626',
    warning: '#EA580C',
    success: '#16A34A',
    info: '#2563EB',
    background: '#FFFFFF',
    surface: '#F8FAFC',
    text: '#1E293B',
    textSecondary: '#64748B',
    gridLine: '#E2E8F0',
    series: [
      '#2563EB', '#7C3AED', '#EA580C', '#DC2626', '#16A34A',
      '#0891B2', '#DB2777', '#059669', '#D97706', '#6D28D9',
    ],
  },
  fonts: {
    family: 'Source Sans 3, system-ui, sans-serif',
    monoFamily: 'Source Code Pro, monospace',
    sizeSmall: 11,
    sizeBase: 12,
    sizeLarge: 14,
  },
  spacing: { chartPadding: 20, legendGap: 12, tooltipPadding: 10 },
};

const stats = mockDashboardStats;

interface KPIProps {
  icon: React.ReactNode;
  iconColor: string;
  value: string | number;
  label: string;
  trend?: number;
  trendLabel?: string;
}

const KPICard: React.FC<KPIProps> = ({ icon, iconColor, value, label, trend, trendLabel }) => {
  const trendDir = trend === undefined || trend === 0 ? 'flat' : trend > 0 ? 'up' : 'down';
  const TrendIcon = trendDir === 'up' ? TrendingUp : trendDir === 'down' ? TrendingDown : Minus;

  return (
    <div className="v3-kpi">
      <div className="v3-kpi-header">
        <div className={`v3-kpi-icon ${iconColor}`}>{icon}</div>
        {trend !== undefined && (
          <span className={`v3-kpi-trend ${trendDir}`}>
            <TrendIcon size={14} />
            {Math.abs(trend).toFixed(1)}%
            {trendLabel && <span style={{ color: '#94A3B8', marginLeft: 2 }}>{trendLabel}</span>}
          </span>
        )}
      </div>
      <div className="v3-kpi-value">{value}</div>
      <div className="v3-kpi-label">{label}</div>
    </div>
  );
};

const severityColor = (level: string): string => {
  const map: Record<string, string> = {
    critical: '#DC2626', high: '#EA580C', medium: '#D97706',
    low: '#2563EB', info: '#64748B',
  };
  return map[level] || '#64748B';
};

const SummaryRow: React.FC<{ alert: ThreatScore }> = ({ alert }) => (
  <tr>
    <td>
      <span className={`v3-badge ${alert.level}`}>{alert.level}</span>
    </td>
    <td className="mono">{alert.entity}</td>
    <td>
      <span
        className="v3-score-badge"
        style={{
          background: `${severityColor(alert.level as string)}10`,
          color: severityColor(alert.level as string),
        }}
      >
        {alert.score}
      </span>
    </td>
    <td className="mono" style={{ fontSize: 12, color: '#64748B' }}>
      {alert.mitre_techniques.slice(0, 2).join(', ')}
    </td>
    <td style={{ color: '#64748B', fontSize: 12 }}>
      {format(new Date(alert.last_seen * 1000), 'MMM d, HH:mm')}
    </td>
  </tr>
);

const Dashboard: React.FC = () => {
  const topAlerts = [...mockAlerts]
    .sort((a, b) => b.score - a.score)
    .slice(0, 8);

  const recentCritical = mockAlerts
    .filter((a) => a.level === ('critical' as any))
    .slice(0, 4);

  return (
    <div>
      {/* Page header */}
      <div style={{ marginBottom: 24 }}>
        <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>Security Operations Dashboard</h1>
        <p className="v3-text-secondary" style={{ fontSize: 13, marginTop: 4 }}>
          Real-time threat visibility · Last updated {format(new Date(stats.lastUpdated), 'MMM d, HH:mm')}
        </p>
      </div>

      {/* KPI Row */}
      <div className="v3-grid-12" style={{ marginBottom: 20 }}>
        <div className="v3-col-3">
          <KPICard
            icon={<AlertTriangle size={18} />}
            iconColor="red"
            value={stats.totalAlerts}
            label="Total Alerts"
            trend={stats.alertsTrend}
            trendLabel="vs prev"
          />
        </div>
        <div className="v3-col-3">
          <KPICard
            icon={<Shield size={18} />}
            iconColor="red"
            value={stats.criticalAlerts}
            label="Critical Alerts"
            trend={8.2}
          />
        </div>
        <div className="v3-col-3">
          <KPICard
            icon={<Radio size={18} />}
            iconColor="orange"
            value={stats.totalBeacons}
            label="Active Beacons"
            trend={-3.1}
          />
        </div>
        <div className="v3-col-3">
          <KPICard
            icon={<Globe size={18} />}
            iconColor="blue"
            value={stats.totalDnsThreats}
            label="DNS Threats"
            trend={5.7}
          />
        </div>
      </div>

      {/* Second KPI Row */}
      <div className="v3-grid-12" style={{ marginBottom: 20 }}>
        <div className="v3-col-3">
          <KPICard
            icon={<Users size={18} />}
            iconColor="blue"
            value={stats.uniqueSourceIPs}
            label="Unique Source IPs"
          />
        </div>
        <div className="v3-col-3">
          <KPICard
            icon={<Target size={18} />}
            iconColor="blue"
            value={stats.uniqueDestIPs}
            label="Unique Dest IPs"
          />
        </div>
        <div className="v3-col-3">
          <KPICard
            icon={<Activity size={18} />}
            iconColor="green"
            value={stats.averageThreatScore.toFixed(1)}
            label="Avg Threat Score"
          />
        </div>
        <div className="v3-col-3">
          <KPICard
            icon={<Target size={18} />}
            iconColor="blue"
            value={stats.topMitreTechniques.length}
            label="MITRE Techniques"
          />
        </div>
      </div>

      {/* Charts Row */}
      <div className="v3-grid-12" style={{ marginBottom: 20 }}>
        <div className="v3-col-8">
          <div className="v3-card">
            <div className="v3-card-header">
              <div>
                <div className="v3-card-title">Threat Activity Timeline</div>
                <div className="v3-card-subtitle">72-hour stacked area by severity</div>
              </div>
            </div>
            <ThreatTimeline data={mockTimeline} theme={v3ChartTheme} height={280} />
          </div>
        </div>
        <div className="v3-col-4">
          <div className="v3-card" style={{ height: '100%' }}>
            <div className="v3-card-header">
              <div>
                <div className="v3-card-title">Severity Distribution</div>
                <div className="v3-card-subtitle">Alert breakdown by level</div>
              </div>
            </div>
            <SeverityDonut
              data={mockSeverityDistribution}
              theme={v3ChartTheme}
              height={240}
              innerRadius={50}
              outerRadius={85}
            />
          </div>
        </div>
      </div>

      {/* Bottom Row: Table + Alert Cards */}
      <div className="v3-grid-12">
        <div className="v3-col-8">
          <div className="v3-card">
            <div className="v3-card-header">
              <div>
                <div className="v3-card-title">Top Threats Summary</div>
                <div className="v3-card-subtitle">Highest scored detections</div>
              </div>
            </div>
            <div className="v3-table-wrapper">
              <table className="v3-table">
                <thead>
                  <tr>
                    <th style={{ width: 90 }}>Severity</th>
                    <th>Entity</th>
                    <th style={{ width: 70 }}>Score</th>
                    <th>MITRE</th>
                    <th style={{ width: 120 }}>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {topAlerts.map((a, i) => (
                    <SummaryRow key={i} alert={a} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
        <div className="v3-col-4">
          <div className="v3-card" style={{ height: '100%' }}>
            <div className="v3-card-header">
              <div>
                <div className="v3-card-title">Critical Alerts</div>
                <div className="v3-card-subtitle">Requires immediate attention</div>
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {recentCritical.map((a, i) => (
                <div
                  key={i}
                  style={{
                    padding: '12px 14px',
                    border: '1px solid rgba(220, 38, 38, 0.15)',
                    borderRadius: 6,
                    background: 'rgba(220, 38, 38, 0.03)',
                    borderLeft: '3px solid #DC2626',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontFamily: 'Source Code Pro, monospace', fontSize: 13, fontWeight: 600, color: '#1E293B' }}>
                      {a.entity}
                    </span>
                    <span style={{ fontFamily: 'Source Code Pro, monospace', fontSize: 12, fontWeight: 700, color: '#DC2626' }}>
                      {a.score}
                    </span>
                  </div>
                  <p style={{ fontSize: 12, color: '#64748B', margin: 0, lineHeight: 1.4 }}>
                    {a.reasons[0]}
                  </p>
                  <div style={{ marginTop: 6, display: 'flex', gap: 4 }}>
                    {a.mitre_techniques.slice(0, 2).map((t) => (
                      <span key={t} className="v3-tag" style={{ fontSize: 10, padding: '1px 6px' }}>
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
