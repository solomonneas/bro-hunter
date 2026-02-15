/**
 * Tuning Page - Scoring weight adjustment for Variant 3.
 */
import React from 'react';
import ScoringTuner from '../../../components/ScoringTuner';

const Tuning: React.FC = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold text-gray-100">Scoring Tuner</h1>
      <p className="text-sm text-gray-500 mt-1">Adjust threat scoring weights to prioritize detection types</p>
    </div>
    <ScoringTuner />
  </div>
);

export default Tuning;
