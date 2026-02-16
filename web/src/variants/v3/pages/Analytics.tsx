/**
 * Analytics Page - Traffic analytics and threat heatmaps for Variant 3.
 */
import React from 'react';
import AnalyticsDashboard from '../../../components/AnalyticsDashboard';
import { QueryErrorMessage } from '../../../components/ErrorBoundary';

const Analytics: React.FC = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold text-gray-100">Analytics</h1>
      <p className="text-sm text-gray-500 mt-1">Traffic trends, top talkers, protocol breakdown, and threat heatmap</p>
    </div>
    <QueryErrorMessage error={null} />
    <AnalyticsDashboard />
  </div>
);

export default Analytics;
