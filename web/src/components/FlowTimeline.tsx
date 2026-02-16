import React from 'react';

interface FlowEvent {
  timestamp: number;
  direction: string;
  type: string;
  summary: string;
}

const colorByType: Record<string, string> = {
  dns: 'bg-blue-500',
  http: 'bg-green-500',
  alert: 'bg-red-500',
  tls: 'bg-purple-500',
  connection: 'bg-gray-500',
};

const FlowTimeline: React.FC<{ events: FlowEvent[] }> = ({ events }) => {
  if (!events.length) {
    return <div className="text-sm text-gray-500">No flow events found.</div>;
  }

  return (
    <div className="space-y-3">
      {events.map((event, idx) => (
        <div key={idx} className="grid grid-cols-[1fr_auto_1fr] items-center gap-3 text-xs">
          <div className={`text-right ${event.direction.startsWith('orig') ? 'text-gray-200' : 'text-gray-600'}`}>
            {event.direction.startsWith('orig') ? event.summary : ''}
          </div>
          <div className="flex flex-col items-center">
            <span className={`w-2.5 h-2.5 rounded-full ${colorByType[event.type] || 'bg-gray-500'}`} />
            {idx < events.length - 1 && <span className="w-px h-5 bg-gray-700" />}
          </div>
          <div className={`${event.direction.startsWith('resp') ? 'text-gray-200' : 'text-gray-600'}`}>
            {event.direction.startsWith('resp') ? event.summary : ''}
          </div>
        </div>
      ))}
    </div>
  );
};

export default FlowTimeline;
