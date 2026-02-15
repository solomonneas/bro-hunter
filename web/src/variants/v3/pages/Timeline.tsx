import React, { useState } from 'react';
import { PcapUpload } from '../../../components/data';
import { ThreatNarrative } from '../../../components/charts';

const TimelinePage: React.FC = () => {
  const [uploadCount, setUploadCount] = useState(0);
  const hasData = uploadCount > 0;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>Upload → Analyze → Timeline</h1>
        <p className="v3-text-secondary" style={{ fontSize: 13, marginTop: 4 }}>
          Upload a packet capture to auto-parse and build a chronological threat narrative.
        </p>
      </div>

      <PcapUpload onComplete={() => setUploadCount((c) => c + 1)} />

      <div className="v3-card" style={{ padding: 16 }}>
        {!hasData && (
          <p style={{ fontSize: 12, color: '#64748B', marginBottom: 12 }}>
            No uploaded dataset yet. Upload a PCAP above to generate timeline events.
          </p>
        )}
        {hasData && <ThreatNarrative key={uploadCount} />}
      </div>
    </div>
  );
};

export default TimelinePage;
