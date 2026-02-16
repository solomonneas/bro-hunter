import React from 'react';

interface CaseCardProps {
  item: any;
  onOpen: (id: string) => void;
}

const severityColor: Record<string, string> = {
  low: '#2563EB',
  medium: '#D97706',
  high: '#EA580C',
  critical: '#DC2626',
};

const CaseCard: React.FC<CaseCardProps> = ({ item, onOpen }) => {
  return (
    <button
      className="v3-card"
      style={{ textAlign: 'left', cursor: 'pointer' }}
      onClick={() => onOpen(item.id)}
      type="button"
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
        <div>
          <div className="v3-heading" style={{ fontSize: 16 }}>{item.title}</div>
          <div className="v3-text-secondary" style={{ fontSize: 12 }}>{item.assignee || 'Unassigned'}</div>
        </div>
        <span className={`v3-badge ${item.status}`.replace('investigating', 'medium')}>{item.status}</span>
      </div>

      <p className="v3-text-secondary" style={{ fontSize: 13, margin: '0 0 8px' }}>{item.description || 'No description'}</p>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span
          className="v3-score-badge"
          style={{ background: `${severityColor[item.severity] || '#64748B'}14`, color: severityColor[item.severity] || '#64748B' }}
        >
          {item.severity}
        </span>
        <span className="v3-text-muted" style={{ fontSize: 11 }}>{new Date(item.updated_at).toLocaleString()}</span>
      </div>
    </button>
  );
};

export default CaseCard;
