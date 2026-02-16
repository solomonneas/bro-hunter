/**
 * Variant 3: Corporate SOC / Enterprise SIEM
 * Professional enterprise layout with collapsible sidebar, header, breadcrumbs.
 * Splunk/Elastic-inspired clean aesthetic.
 *
 * Now the primary (and only shipped) variant. Other variants live under /dev/N for development only.
 */
import React, { useState, useEffect } from 'react';
import { Routes, Route, NavLink, Navigate, Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Network,
  Radio,
  Shield,
  Search,
  Globe,
  ListTree,
  ArrowLeft,
  ChevronRight,
  PanelLeftClose,
  PanelLeftOpen,
  Bell,
  ShieldCheck,
  Sliders,
  Link2,
  BarChart3,
  FileText,
  Crosshair,
  Antenna,
  Upload,
  Settings as SettingsIcon,
  Binary,
} from 'lucide-react';
import { format } from 'date-fns';
import { mockDashboardStats } from '../../data/mockData';
import Dashboard from './pages/Dashboard';
import Connections from './pages/Connections';
import Beacons from './pages/Beacons';
import DnsThreats from './pages/DnsThreats';
import Threats from './pages/Threats';
import HuntResults from './pages/HuntResults';
import TimelinePage from './pages/Timeline';
import Sessions from './pages/Sessions';
import Tuning from './pages/Tuning';
import Analytics from './pages/Analytics';
import Intel from './pages/Intel';
import Capture from './pages/Capture';
import Reports from './pages/Reports';
import Workflow from './pages/Workflow';
import Settings from './pages/Settings';
import Packets from './pages/Packets';
import GlobalSearch from '../../components/GlobalSearch';
import NotificationToast from '../../components/NotificationToast';
import './styles.css';

interface V3AppProps {
  /** Base path prefix for routes. '/' in production, '/dev/3' in dev mode. */
  basePath?: string;
}

function buildNav(base: string) {
  const b = base === '/' ? '' : base;
  return [
    { to: base, icon: LayoutDashboard, label: 'Dashboard', end: true },
    { to: `${b}/connections`, icon: Network, label: 'Connections', end: false },
    { to: `${b}/beacons`, icon: Radio, label: 'Beacons', end: false },
    { to: `${b}/dns`, icon: Globe, label: 'DNS Threats', end: false },
    { to: `${b}/threats`, icon: Shield, label: 'Threats', end: false },
    { to: `${b}/hunts`, icon: Search, label: 'Hunt Results', end: false },
    { to: `${b}/timeline`, icon: ListTree, label: 'Threat Timeline', end: false },
    { to: `${b}/sessions`, icon: Link2, label: 'Sessions', end: false },
    { to: `${b}/packets`, icon: Binary, label: 'Packets', end: false },
    { to: `${b}/analytics`, icon: BarChart3, label: 'Analytics', end: false },
    { to: `${b}/intel`, icon: Crosshair, label: 'Threat Intel', end: false },
    { to: `${b}/capture`, icon: Antenna, label: 'Live Capture', end: false },
    { to: `${b}/reports`, icon: FileText, label: 'Reports', end: false },
    { to: `${b}/workflow`, icon: Upload, label: 'PCAP Workflow', end: false },
    { to: `${b}/settings`, icon: SettingsIcon, label: 'Settings', end: false },
    { to: `${b}/tuning`, icon: Sliders, label: 'Tuning', end: false },
  ];
}

function buildBreadcrumbs(base: string): Record<string, string> {
  const b = base === '/' ? '' : base;
  const map: Record<string, string> = {};
  map[base] = 'Dashboard';
  const pages = ['connections', 'beacons', 'dns', 'threats', 'hunts', 'timeline', 'sessions', 'packets', 'analytics', 'intel', 'capture', 'reports', 'workflow', 'settings', 'tuning'];
  const labels = ['Connections', 'Beacons', 'DNS Threats', 'Threats', 'Hunt Results', 'Threat Timeline', 'Sessions', 'Packets', 'Analytics', 'Threat Intel', 'Live Capture', 'Reports', 'PCAP Workflow', 'Settings', 'Tuning'];
  pages.forEach((p, i) => { map[`${b}/${p}`] = labels[i]; });
  return map;
}

const Clock: React.FC = () => {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span className="v3-header-time" aria-label="Current time">
      {format(now, 'MMM d, yyyy')} · {format(now, 'HH:mm:ss')}
    </span>
  );
};

const V3App: React.FC<V3AppProps> = ({ basePath = '/' }) => {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();
  const critCount = mockDashboardStats.criticalAlerts;

  const NAV_ITEMS = buildNav(basePath);
  const BREADCRUMB_MAP = buildBreadcrumbs(basePath);
  const isDevMode = basePath !== '/';

  const currentPage = BREADCRUMB_MAP[location.pathname] || 'Dashboard';
  const homeLink = basePath;

  return (
    <div className={`v3-root${collapsed ? ' collapsed' : ''}`}>
      <GlobalSearch />
      <NotificationToast />
      {/* Sidebar */}
      <nav className="v3-sidebar" aria-label="Main navigation">
        <div className="v3-sidebar-brand">
          <ShieldCheck size={22} aria-hidden="true" />
          <span className="v3-sidebar-brand-text">Bro Hunter</span>
        </div>

        <div className="v3-sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `v3-nav-item${isActive ? ' active' : ''}`
              }
              title={item.label}
              aria-label={item.label}
            >
              <item.icon size={20} aria-hidden="true" />
              <span className="v3-nav-label">{item.label}</span>
            </NavLink>
          ))}
        </div>

        <div className="v3-sidebar-footer">
          <button
            className="v3-collapse-btn"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <PanelLeftOpen size={16} aria-hidden="true" /> : <PanelLeftClose size={16} aria-hidden="true" />}
            {!collapsed && <span>Collapse</span>}
          </button>
          {isDevMode && (
            <Link to="/dev" aria-label="Back to dev variants">
              <ArrowLeft size={14} aria-hidden="true" />
              {!collapsed && <span>Dev Variants</span>}
            </Link>
          )}
        </div>
      </nav>

      {/* Header */}
      <header className="v3-header">
        <div className="v3-header-left">
          <nav className="v3-breadcrumb" aria-label="Breadcrumb">
            <Link to={homeLink}>SOC</Link>
            <ChevronRight size={12} className="v3-breadcrumb-sep" aria-hidden="true" />
            <span className="v3-breadcrumb-current" aria-current="page">{currentPage}</span>
          </nav>
        </div>

        <div className="v3-header-search" onClick={() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }))}>
          <Search size={14} aria-hidden="true" />
          <input
            type="text"
            placeholder="Search (Ctrl+K)…"
            aria-label="Search IPs, domains, techniques"
            readOnly
            style={{ cursor: 'pointer' }}
          />
        </div>

        <div className="v3-header-right">
          <Clock />
          {isDevMode && (
            <span className="text-xs px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-400 font-mono">DEV</span>
          )}
          <div
            role="status"
            aria-label={`${critCount} critical alerts`}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '4px 12px',
              borderRadius: 9999,
              background: critCount > 0 ? 'rgba(220, 38, 38, 0.08)' : 'rgba(22, 163, 74, 0.08)',
              color: critCount > 0 ? '#DC2626' : '#16A34A',
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            <Bell size={14} aria-hidden="true" />
            {critCount} Critical
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="v3-content">
        <Routes>
          <Route index element={<Dashboard />} />
          <Route path="connections" element={<Connections />} />
          <Route path="beacons" element={<Beacons />} />
          <Route path="dns" element={<DnsThreats />} />
          <Route path="threats" element={<Threats />} />
          <Route path="hunts" element={<HuntResults />} />
          <Route path="timeline" element={<TimelinePage />} />
          <Route path="sessions" element={<Sessions />} />
          <Route path="packets" element={<Packets />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="intel" element={<Intel />} />
          <Route path="capture" element={<Capture />} />
          <Route path="reports" element={<Reports />} />
          <Route path="workflow" element={<Workflow />} />
          <Route path="settings" element={<Settings />} />
          <Route path="tuning" element={<Tuning />} />
          <Route path="*" element={<Navigate to={homeLink} replace />} />
        </Routes>
      </main>
    </div>
  );
};

export default V3App;
