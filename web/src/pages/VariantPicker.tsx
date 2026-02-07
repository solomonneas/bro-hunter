/**
 * VariantPicker — Landing page for selecting one of 5 frontend variants.
 */
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Layout, BarChart3, Terminal, Zap } from 'lucide-react';

interface VariantCard {
  id: number;
  name: string;
  description: string;
  icon: React.ReactNode;
  gradient: string;
  borderColor: string;
}

const VARIANTS: VariantCard[] = [
  {
    id: 1,
    name: 'NOC Command Center',
    description: 'Dense dashboard with real-time threat feeds, MITRE heatmap, and multi-panel layout for SOC analysts.',
    icon: <Terminal size={28} aria-hidden="true" />,
    gradient: 'from-cyan-500/20 to-blue-600/20',
    borderColor: 'border-cyan-500/40',
  },
  {
    id: 2,
    name: 'Executive Overview',
    description: 'Clean, minimal dashboard focused on KPIs, trend lines, and high-level threat summaries for leadership.',
    icon: <BarChart3 size={28} aria-hidden="true" />,
    gradient: 'from-violet-500/20 to-purple-600/20',
    borderColor: 'border-violet-500/40',
  },
  {
    id: 3,
    name: 'Threat Hunter Workbench',
    description: 'Investigation-focused layout with pivot tables, entity graphs, and deep-dive analysis panels.',
    icon: <Shield size={28} aria-hidden="true" />,
    gradient: 'from-amber-500/20 to-orange-600/20',
    borderColor: 'border-amber-500/40',
  },
  {
    id: 4,
    name: 'Beacon Analyzer',
    description: 'Specialized view for C2 beacon detection with scatter plots, interval histograms, and timeline overlays.',
    icon: <Zap size={28} aria-hidden="true" />,
    gradient: 'from-red-500/20 to-rose-600/20',
    borderColor: 'border-red-500/40',
  },
  {
    id: 5,
    name: 'DNS Intelligence',
    description: 'DNS-centric threat view with tunneling detection, DGA analysis, fast-flux monitoring, and query heatmaps.',
    icon: <Layout size={28} aria-hidden="true" />,
    gradient: 'from-green-500/20 to-emerald-600/20',
    borderColor: 'border-green-500/40',
  },
];

export const VariantPicker: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-gray-800">
        <div className="max-w-5xl mx-auto px-6 py-8">
          <h1 className="text-3xl font-bold text-accent-cyan">
            Bro Hunter
          </h1>
          <p className="text-gray-400 mt-2 max-w-2xl">
            Network threat hunting and analysis platform. Choose a frontend variant to explore
            Zeek and Suricata log analysis with different visualization approaches.
          </p>
        </div>
      </header>

      {/* Variant Grid */}
      <main className="max-w-5xl mx-auto px-6 py-10">
        <h2 className="text-sm font-medium text-gray-500 uppercase tracking-wider mb-6">
          Select a Variant
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5" role="list" aria-label="Available dashboard variants">
          {VARIANTS.map((v) => (
            <button
              key={v.id}
              onClick={() => navigate(`/${v.id}`)}
              aria-label={`Open variant ${v.id}: ${v.name}`}
              className={`group text-left rounded-xl border ${v.borderColor} bg-gradient-to-br ${v.gradient} p-5 transition-all hover:scale-[1.02] hover:shadow-lg hover:shadow-black/30 focus:outline-none focus:ring-2 focus:ring-accent-cyan/50`}
              role="listitem"
            >
              <div className="flex items-center gap-3 mb-3">
                <span className="text-gray-300 group-hover:text-white transition-colors">
                  {v.icon}
                </span>
                <div>
                  <span className="text-xs font-mono text-gray-500">V{v.id}</span>
                  <h3 className="text-base font-semibold text-gray-200 group-hover:text-white transition-colors">
                    {v.name}
                  </h3>
                </div>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed">
                {v.description}
              </p>
            </button>
          ))}
        </div>

        {/* Status bar */}
        <div className="mt-10 flex items-center gap-4 text-xs text-gray-600" role="status" aria-live="polite" aria-label="Data source status">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-green-500/60" aria-hidden="true" />
            <span aria-label="Data source: mock data is active">Mock data active</span>
          </span>
          <span aria-hidden="true">·</span>
          <span>5 variants available</span>
          <span aria-hidden="true">·</span>
          <span>55 alerts · 25 beacons · 32 DNS threats</span>
        </div>
      </main>
    </div>
  );
};

export default VariantPicker;
