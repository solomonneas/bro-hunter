import React from 'react';
import TlsIntelligence from '../../../components/TlsIntelligence';

const TlsIntel: React.FC = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold text-gray-100">TLS Intelligence</h1>
      <p className="text-sm text-gray-500 mt-1">JA3 fingerprinting, certificate anomalies, and known-bad TLS signatures</p>
    </div>
    <TlsIntelligence />
  </div>
);

export default TlsIntel;
