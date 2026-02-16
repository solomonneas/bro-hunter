import React from 'react';

interface TimelineEvent {
  id: string;
  timestamp: string;
  event_type: string;
  description: string;
  auto_generated: boolean;
}

interface CaseTimelineProps {
  timeline: TimelineEvent[];
}

const CaseTimeline: React.FC<CaseTimelineProps> = ({ timeline }) => {
  const sorted = [...timeline].sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  if (!sorted.length) {
    return <p className="v3-text-muted">No timeline events yet.</p>;
  }

  return (
    <div style={{ borderLeft: '2px solid #E2E8F0', marginLeft: 8, paddingLeft: 16 }}>
      {sorted.map((event) => (
        <div key={event.id} style={{ position: 'relative', marginBottom: 14 }}>
          <span
            style={{
              position: 'absolute',
              left: -22,
              top: 4,
              width: 10,
              height: 10,
              borderRadius: 9999,
              background: event.auto_generated ? '#2563EB' : '#16A34A',
              border: '2px solid #FFFFFF',
              boxShadow: '0 0 0 1px #CBD5E1',
            }}
          />
          <div style={{ fontSize: 12, color: '#64748B', fontFamily: 'Source Code Pro, monospace' }}>
            {new Date(event.timestamp).toLocaleString()}
          </div>
          <div style={{ fontSize: 13, color: '#1E293B' }}>{event.description}</div>
        </div>
      ))}
    </div>
  );
};

export default CaseTimeline;
