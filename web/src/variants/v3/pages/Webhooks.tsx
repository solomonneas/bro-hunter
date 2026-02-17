import React from 'react';
import WebhookManager from '../../../components/WebhookManager';

const Webhooks: React.FC = () => (
  <div className="space-y-6">
    <div>
      <h1 className="text-2xl font-bold text-gray-100">Webhooks</h1>
      <p className="text-sm text-gray-500 mt-1">Configure alert webhooks for Discord, Slack, or custom endpoints</p>
    </div>
    <WebhookManager />
  </div>
);

export default Webhooks;
