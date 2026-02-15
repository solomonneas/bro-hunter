/**
 * Live Capture Page - Packet capture management for Variant 3.
 */
import React from 'react';
import LiveCapture from '../../../components/LiveCapture';

const Capture: React.FC = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold text-gray-100">Live Capture</h1>
      <p className="text-sm text-gray-500 mt-1">Capture live network traffic for analysis</p>
    </div>
    <LiveCapture />
  </div>
);

export default Capture;
