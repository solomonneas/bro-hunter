/**
 * Settings page: API keys, scoring weights, display preferences.
 */
import React, { useState, useEffect } from 'react';
import { Save, Loader2, Eye, EyeOff } from 'lucide-react';
import { useNotificationStore } from '../../../stores/notificationStore';
import LoadingSkeleton from '../../../components/LoadingSkeleton';

const API_BASE = import.meta.env.VITE_API_BASE || '';

interface AppSettings {
  threat_intel: {
    otx_key: string;
    abuseipdb_key: string;
    enabled_sources: string[];
  };
  scoring: {
    beacon_weight: number;
    dns_weight: number;
    threat_weight: number;
    connection_weight: number;
    high_threshold: number;
    medium_threshold: number;
    low_threshold: number;
  };
  export: {
    default_format: string;
    include_evidence: boolean;
  };
  display: {
    theme: string;
    rows_per_page: number;
    auto_refresh_seconds: number;
  };
}

const Settings: React.FC = () => {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [showOtx, setShowOtx] = useState(false);
  const [showAbuse, setShowAbuse] = useState(false);
  const [demoMode, setDemoMode] = useState(false);
  const notify = useNotificationStore.add;

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      const [res, modeRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/settings`),
        fetch(`${API_BASE}/api/v1/settings/mode`),
      ]);
      if (res.ok) setSettings(await res.json());
      if (modeRes.ok) {
        const mode = await modeRes.json();
        setDemoMode(Boolean(mode.demo_mode));
      }
    } catch (err) {
      console.error('Failed to load settings:', err);
    } finally {
      setLoading(false);
    }
  };

  const saveSettings = async () => {
    if (!settings) return;
    setSaving(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      });
      if (res.ok) {
        notify('success', 'Settings saved');
      } else {
        notify('error', 'Failed to save settings');
      }
    } catch {
      notify('error', 'Network error saving settings');
    } finally {
      setSaving(false);
    }
  };

  const toggleDataMode = async (nextDemoMode: boolean) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/settings/mode`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ demo_mode: nextDemoMode }),
      });
      if (res.ok) {
        setDemoMode(nextDemoMode);
        notify('success', nextDemoMode ? 'Demo mode enabled' : 'Live mode enabled');
      } else {
        notify('error', 'Failed to switch data mode');
      }
    } catch {
      notify('error', 'Network error switching data mode');
    }
  };

  const updateNested = (section: keyof AppSettings, key: string, value: any) => {
    if (!settings) return;
    setSettings({
      ...settings,
      [section]: { ...settings[section], [key]: value },
    });
  };

  if (loading) {
    return <LoadingSkeleton rows={8} className="py-8" />;
  }

  if (!settings) {
    return <div className="text-gray-500 py-8">Failed to load settings.</div>;
  }

  const inputClass = 'bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:border-cyan-500 focus:outline-none w-full';
  const labelClass = 'block text-sm text-gray-400 mb-1';
  const sectionClass = 'bg-gray-900/50 border border-gray-800 rounded-xl p-6 space-y-4';

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-100">Settings</h2>
          <p className="text-gray-500 text-sm mt-1">Configure threat intel, scoring, and display preferences.</p>
        </div>
        <button
          onClick={saveSettings}
          disabled={saving}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
        >
          {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
          Save
        </button>
      </div>

      <div className={sectionClass}>
        <h3 className="text-base font-medium text-gray-200">Data Mode</h3>
        <p className="text-sm text-gray-500">Demo mode uses bundled sanitized Zeek logs. Live mode expects local Zeek/Suricata ingestion.</p>
        <div className="flex gap-2">
          <button
            onClick={() => toggleDataMode(true)}
            className={`px-3 py-2 rounded-lg text-sm border ${demoMode ? 'border-cyan-500 bg-cyan-500/20 text-cyan-300' : 'border-gray-700 text-gray-400'}`}
          >
            Demo Mode
          </button>
          <button
            onClick={() => toggleDataMode(false)}
            className={`px-3 py-2 rounded-lg text-sm border ${!demoMode ? 'border-cyan-500 bg-cyan-500/20 text-cyan-300' : 'border-gray-700 text-gray-400'}`}
          >
            Live Mode
          </button>
        </div>
      </div>

      {/* Threat Intel */}
      <div className={sectionClass}>
        <h3 className="text-base font-medium text-gray-200">Threat Intelligence</h3>

        <div>
          <label className={labelClass}>AlienVault OTX API Key</label>
          <div className="relative">
            <input
              type={showOtx ? 'text' : 'password'}
              value={settings.threat_intel.otx_key}
              onChange={(e) => updateNested('threat_intel', 'otx_key', e.target.value)}
              className={inputClass}
              placeholder="Enter OTX API key"
            />
            <button
              onClick={() => setShowOtx(!showOtx)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
            >
              {showOtx ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </div>

        <div>
          <label className={labelClass}>AbuseIPDB API Key</label>
          <div className="relative">
            <input
              type={showAbuse ? 'text' : 'password'}
              value={settings.threat_intel.abuseipdb_key}
              onChange={(e) => updateNested('threat_intel', 'abuseipdb_key', e.target.value)}
              className={inputClass}
              placeholder="Enter AbuseIPDB API key"
            />
            <button
              onClick={() => setShowAbuse(!showAbuse)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
            >
              {showAbuse ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </div>
      </div>

      {/* Scoring */}
      <div className={sectionClass}>
        <h3 className="text-base font-medium text-gray-200">Scoring Weights</h3>
        <div className="grid grid-cols-2 gap-4">
          {(['beacon_weight', 'dns_weight', 'threat_weight', 'connection_weight'] as const).map((key) => (
            <div key={key}>
              <label className={labelClass}>{key.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())}</label>
              <input
                type="number"
                step="0.1"
                min="0"
                max="5"
                value={settings.scoring[key]}
                onChange={(e) => updateNested('scoring', key, parseFloat(e.target.value) || 0)}
                className={inputClass}
              />
            </div>
          ))}
        </div>

        <div className="grid grid-cols-3 gap-4">
          {(['high_threshold', 'medium_threshold', 'low_threshold'] as const).map((key) => (
            <div key={key}>
              <label className={labelClass}>{key.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())}</label>
              <input
                type="number"
                min="0"
                max="100"
                value={settings.scoring[key]}
                onChange={(e) => updateNested('scoring', key, parseInt(e.target.value) || 0)}
                className={inputClass}
              />
            </div>
          ))}
        </div>
      </div>

      {/* Export */}
      <div className={sectionClass}>
        <h3 className="text-base font-medium text-gray-200">Export</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className={labelClass}>Default Format</label>
            <select
              value={settings.export.default_format}
              onChange={(e) => updateNested('export', 'default_format', e.target.value)}
              className={inputClass}
            >
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
            </select>
          </div>
          <div className="flex items-center gap-2 pt-6">
            <input
              type="checkbox"
              id="include-evidence"
              checked={settings.export.include_evidence}
              onChange={(e) => updateNested('export', 'include_evidence', e.target.checked)}
              className="accent-cyan-500"
            />
            <label htmlFor="include-evidence" className="text-sm text-gray-400">Include evidence in exports</label>
          </div>
        </div>
      </div>

      {/* Display */}
      <div className={sectionClass}>
        <h3 className="text-base font-medium text-gray-200">Display</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className={labelClass}>Rows per Page</label>
            <input
              type="number"
              min="10"
              max="200"
              value={settings.display.rows_per_page}
              onChange={(e) => updateNested('display', 'rows_per_page', parseInt(e.target.value) || 50)}
              className={inputClass}
            />
          </div>
          <div>
            <label className={labelClass}>Auto-refresh (seconds)</label>
            <input
              type="number"
              min="5"
              max="300"
              value={settings.display.auto_refresh_seconds}
              onChange={(e) => updateNested('display', 'auto_refresh_seconds', parseInt(e.target.value) || 30)}
              className={inputClass}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
