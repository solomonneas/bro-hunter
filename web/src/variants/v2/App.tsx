/**
 * Variant 2: Executive Overview
 * Clean, minimal dashboard focused on KPIs, trend lines, and summaries.
 * TODO: Implement full variant layout.
 */
import React from 'react';
import { Link } from 'react-router-dom';
import { BarChart3, ArrowLeft } from 'lucide-react';

const V2App: React.FC = () => {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-violet-500/20 bg-surface/80 px-4 py-3 flex items-center gap-3">
        <Link to="/" className="text-gray-500 hover:text-gray-300 transition-colors">
          <ArrowLeft size={18} />
        </Link>
        <BarChart3 size={20} className="text-violet-400" />
        <h1 className="text-lg font-semibold text-violet-400">V2 — Executive Overview</h1>
      </header>
      <main className="p-6">
        <div className="rounded-lg border border-violet-500/20 bg-surface/30 p-8 text-center">
          <p className="text-gray-400">Variant 2 shell — implementation pending.</p>
        </div>
      </main>
    </div>
  );
};

export default V2App;
