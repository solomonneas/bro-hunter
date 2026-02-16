import React, { useMemo, useState } from 'react';

interface MarkdownEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}

function renderMarkdown(markdown: string): string {
  const escaped = markdown
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  return escaped
    .replace(/^### (.*)$/gm, '<h3>$1</h3>')
    .replace(/^## (.*)$/gm, '<h2>$1</h2>')
    .replace(/^# (.*)$/gm, '<h1>$1</h1>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\n/g, '<br/>');
}

const MarkdownEditor: React.FC<MarkdownEditorProps> = ({ value, onChange, placeholder }) => {
  const [preview, setPreview] = useState(false);
  const html = useMemo(() => renderMarkdown(value), [value]);

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
        <button
          className={`v3-btn ${!preview ? 'v3-btn-primary' : 'v3-btn-outline'}`}
          style={{ padding: '6px 10px' }}
          onClick={() => setPreview(false)}
          type="button"
        >
          Write
        </button>
        <button
          className={`v3-btn ${preview ? 'v3-btn-primary' : 'v3-btn-outline'}`}
          style={{ padding: '6px 10px' }}
          onClick={() => setPreview(true)}
          type="button"
        >
          Preview
        </button>
      </div>

      {!preview ? (
        <textarea
          className="v3-input"
          style={{ width: '100%', minHeight: 140, resize: 'vertical' }}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder || 'Write note in markdown…'}
        />
      ) : (
        <div
          className="v3-card"
          style={{ background: '#F8FAFC', minHeight: 140 }}
          dangerouslySetInnerHTML={{ __html: html }}
        />
      )}
    </div>
  );
};

export default MarkdownEditor;
