/**
 * Variant 1: NOC Command Center
 * Dense dashboard with real-time threat feeds, MITRE heatmap, and multi-panel layout.
 * TODO: Implement full variant layout.
 */
import React from 'react';
import { Link } from 'react-router-dom';
import { Terminal, ArrowLeft } from 'lucide-react';

const V1App: React.FC = () => {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-cyan-500/20 bg-surface/80 px-4 py-3 flex items-center gap-3">
        <Link to="/" className="text-gray-500 hover:text-gray-300 transition-colors">
          <ArrowLeft size={18} />
        </Link>
        <Terminal size={20} className="text-cyan-400" />
        <h1 className="text-lg font-semibold text-cyan-400">V1 — NOC Command Center</h1>
      </header>
      <main className="p-6">
        <div className="rounded-lg border border-cyan-500/20 bg-surface/30 p-8 text-center">
          <p className="text-gray-400">Variant 1 shell — implementation pending.</p>
        </div>
      </main>
    </div>
  );
};

export default V1App;
