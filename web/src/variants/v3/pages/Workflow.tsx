/**
 * Workflow page: PCAP upload and analysis wizard.
 */
import React from 'react';
import WorkflowWizard from '../../../components/WorkflowWizard';

const Workflow: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-gray-100">PCAP Analysis Workflow</h2>
        <p className="text-gray-500 text-sm mt-1">
          Upload a PCAP file to run the full analysis pipeline: Zeek, Suricata, threat scoring, and more.
        </p>
      </div>
      <WorkflowWizard
        className="max-w-2xl"
        onComplete={(jobId) => console.log('Job complete:', jobId)}
      />
    </div>
  );
};

export default Workflow;
