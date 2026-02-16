import React, { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import PacketInspector from '../../../components/PacketInspector';

const Packets: React.FC = () => {
  const [params, setParams] = useSearchParams();
  const [input, setInput] = useState(params.get('uid') || '');
  const uid = params.get('uid') || '';

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Packet View</h1>
        <p className="text-sm text-gray-500 mt-1">Deep-dive packet and flow details by connection UID</p>
      </div>

      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-4 flex gap-2">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Enter connection UID..."
          className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
        />
        <button
          onClick={() => setParams({ uid: input })}
          className="px-3 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-sm text-white"
        >
          Inspect
        </button>
      </div>

      {!uid ? (
        <div className="text-sm text-gray-500">
          Upload a PCAP or enable demo mode to get started.
        </div>
      ) : (
        <PacketInspector uid={uid} />
      )}

      {uid && (
        <div className="text-xs text-gray-500">
          Shareable link: <Link className="text-cyan-400" to={`?uid=${uid}`}>{uid}</Link>
        </div>
      )}
    </div>
  );
};

export default Packets;
