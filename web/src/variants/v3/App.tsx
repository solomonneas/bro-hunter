/**
 * Variant 3: Corporate SOC / Enterprise SIEM
 * Professional enterprise layout with collapsible sidebar, header, breadcrumbs.
 * Splunk/Elastic-inspired clean aesthetic.
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
import './styles.css';

const NAV_ITEMS = [
  { to: '/3', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/3/connections', icon: Network, label: 'Connections', end: false },
  { to: '/3/beacons', icon: Radio, label: 'Beacons', end: false },
  { to: '/3/dns', icon: Globe, label: 'DNS Threats', end: false },
  { to: '/3/threats', icon: Shield, label: 'Threats', end: false },
  { to: '/3/hunts', icon: Search, label: 'Hunt Results', end: false },
  { to: '/3/timeline', icon: ListTree, label: 'Threat Timeline', end: false },
  { to: '/3/sessions', icon: Link2, label: 'Sessions', end: false },
  { to: '/3/analytics', icon: BarChart3, label: 'Analytics', end: false },
  { to: '/3/intel', icon: Crosshair, label: 'Threat Intel', end: false },
  { to: '/3/capture', icon: Antenna, label: 'Live Capture', end: false },
  { to: '/3/reports', icon: FileText, label: 'Reports', end: false },
  { to: '/3/tuning', icon: Sliders, label: 'Tuning', end: false },
];

const BREADCRUMB_MAP: Record<string, string> = {
  '/3': 'Dashboard',
  '/3/connections': 'Connections',
  '/3/beacons': 'Beacons',
  '/3/dns': 'DNS Threats',
  '/3/threats': 'Threats',
  '/3/hunts': 'Hunt Results',
  '/3/timeline': 'Threat Timeline',
  '/3/sessions': 'Sessions',
  '/3/analytics': 'Analytics',
  '/3/intel': 'Threat Intel',
  '/3/capture': 'Live Capture',
  '/3/reports': 'Reports',
  '/3/tuning': 'Tuning',
};

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

const V3App: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();
  const critCount = mockDashboardStats.criticalAlerts;

  const currentPage = BREADCRUMB_MAP[location.pathname] || 'Dashboard';

  return (
    <div className={`v3-root${collapsed ? ' collapsed' : ''}`}>
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
          <Link to="/" aria-label="Back to all variants">
            <ArrowLeft size={14} aria-hidden="true" />
            {!collapsed && <span>All Variants</span>}
          </Link>
        </div>
      </nav>

      {/* Header */}
      <header className="v3-header">
        <div className="v3-header-left">
          <nav className="v3-breadcrumb" aria-label="Breadcrumb">
            <Link to="/3">SOC</Link>
            <ChevronRight size={12} className="v3-breadcrumb-sep" aria-hidden="true" />
            <span className="v3-breadcrumb-current" aria-current="page">{currentPage}</span>
          </nav>
        </div>

        <div className="v3-header-search">
          <Search size={14} aria-hidden="true" />
          <input
            type="text"
            placeholder="Search IPs, domains, techniques…"
            aria-label="Search IPs, domains, techniques"
            readOnly
          />
        </div>

        <div className="v3-header-right">
          <Clock />
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
          <Route path="analytics" element={<Analytics />} />
          <Route path="intel" element={<Intel />} />
          <Route path="capture" element={<Capture />} />
          <Route path="reports" element={<Reports />} />
          <Route path="tuning" element={<Tuning />} />
          <Route path="*" element={<Navigate to="/3" replace />} />
        </Routes>
      </main>
    </div>
  );
};

export default V3App;
