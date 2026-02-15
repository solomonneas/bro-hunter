/**
 * Sessions Page - Reconstructed network sessions view for Variant 3.
 */
import React from 'react';
import SessionView from '../../../components/SessionView';
import IocExport from '../../../components/IocExport';

const Sessions: React.FC = () => (
  <div className="space-y-6">
    <div className="flex items-center justify-between">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Network Sessions</h1>
        <p className="text-sm text-gray-500 mt-1">Reconstructed sessions from connection, DNS, and alert data</p>
      </div>
      <IocExport compact />
    </div>
    <SessionView />
  </div>
);

export default Sessions;
