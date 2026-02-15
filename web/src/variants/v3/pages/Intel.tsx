/**
 * Threat Intel Page - IP/domain reputation lookups for Variant 3.
 */
import React from 'react';
import ThreatIntelLookup from '../../../components/ThreatIntelLookup';

const Intel: React.FC = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold text-gray-100">Threat Intelligence</h1>
      <p className="text-sm text-gray-500 mt-1">Look up IPs and domains against AbuseIPDB, AlienVault OTX, and local blocklists</p>
    </div>
    <ThreatIntelLookup />
  </div>
);

export default Intel;
