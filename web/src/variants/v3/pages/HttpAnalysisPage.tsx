import React from 'react';
import HttpAnalysis from '../../../components/HttpAnalysis';

const HttpAnalysisPage: React.FC = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold text-gray-100">HTTP Analysis</h1>
      <p className="text-sm text-gray-500 mt-1">Detect anomalous HTTP traffic: suspicious user-agents, methods, traversal attempts</p>
    </div>
    <HttpAnalysis />
  </div>
);

export default HttpAnalysisPage;
