/**
 * Variant 3: Threat Hunter Workbench
 * Investigation-focused layout with pivot tables and deep-dive panels.
 * TODO: Implement full variant layout.
 */
import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, ArrowLeft } from 'lucide-react';

const V3App: React.FC = () => {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-amber-500/20 bg-surface/80 px-4 py-3 flex items-center gap-3">
        <Link to="/" className="text-gray-500 hover:text-gray-300 transition-colors">
          <ArrowLeft size={18} />
        </Link>
        <Shield size={20} className="text-amber-400" />
        <h1 className="text-lg font-semibold text-amber-400">V3 — Threat Hunter Workbench</h1>
      </header>
      <main className="p-6">
        <div className="rounded-lg border border-amber-500/20 bg-surface/30 p-8 text-center">
          <p className="text-gray-400">Variant 3 shell — implementation pending.</p>
        </div>
      </main>
    </div>
  );
};

export default V3App;
