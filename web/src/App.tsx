import { useState } from 'react'

function App() {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-surface">
        <div className="container mx-auto px-4 py-4">
          <h1 className="text-2xl font-bold text-accent-cyan">
            Hunter - Network Threat Hunting Platform
          </h1>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <div className="grid gap-6">
          <div className="p-6 rounded-lg bg-surface border border-accent-cyan/20">
            <h2 className="text-xl font-semibold text-accent-cyan mb-4">
              Welcome to Hunter
            </h2>
            <p className="text-gray-300 mb-4">
              Network threat hunting and analysis platform for Zeek and Suricata logs.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 rounded bg-background border border-accent-amber/30">
                <h3 className="text-accent-amber font-semibold mb-2">Log Analysis</h3>
                <p className="text-sm text-gray-400">
                  Parse and analyze Zeek and Suricata network logs
                </p>
              </div>
              <div className="p-4 rounded bg-background border border-accent-red/30">
                <h3 className="text-accent-red font-semibold mb-2">Threat Hunting</h3>
                <p className="text-sm text-gray-400">
                  Execute threat hunting queries with MITRE ATT&CK mapping
                </p>
              </div>
              <div className="p-4 rounded bg-background border border-accent-green/30">
                <h3 className="text-accent-green font-semibold mb-2">Visualization</h3>
                <p className="text-sm text-gray-400">
                  Interactive charts and timelines for network events
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}

export default App
