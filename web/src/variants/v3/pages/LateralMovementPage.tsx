import React from 'react';
import LateralMovement from '../../../components/LateralMovement';

const LateralMovementPage: React.FC = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold text-gray-100">Lateral Movement</h1>
      <p className="text-sm text-gray-500 mt-1">Detect internal-to-internal scanning via SMB, RDP, WMI, and SSH</p>
    </div>
    <LateralMovement />
  </div>
);

export default LateralMovementPage;
