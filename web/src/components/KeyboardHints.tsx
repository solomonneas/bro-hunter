/**
 * KeyboardHints — Floating help button + overlay showing keyboard shortcuts.
 * Shows a persistent "?" FAB in bottom-right. Click to expand full shortcut list.
 * Also shows a brief toast when switching variants via keyboard.
 */
import React, { useState, useEffect } from 'react';

interface Shortcut {
  key: string;
  label: string;
}

interface KeyboardHintsProps {
  shortcuts?: Shortcut[];
  variant?: 'picker' | 'app';
}

const DEFAULT_SHORTCUTS: Shortcut[] = [
  { key: '1-5', label: 'Switch variant' },
  { key: '0', label: 'Variant picker' },
  { key: 'Esc', label: 'Back to picker' },
];

export const KeyboardHints: React.FC<KeyboardHintsProps> = ({
  shortcuts = DEFAULT_SHORTCUTS,
  variant = 'app',
}) => {
  const [open, setOpen] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.key === '?') {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, []);

  // Show toast on variant switch
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      const num = parseInt(e.key);
      if (num >= 1 && num <= 5) {
        setToast(`Variant ${num}`);
      } else if (e.key === 'Escape' || e.key === '0') {
        setToast('Variant Picker');
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, []);

  // Auto-hide toast
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 1500);
    return () => clearTimeout(t);
  }, [toast]);

  return (
    <>
      {/* Toast notification */}
      {toast && (
        <div
          style={{
            position: 'fixed',
            top: 24,
            left: '50%',
            transform: 'translateX(-50%)',
            background: 'rgba(6, 182, 212, 0.9)',
            color: '#fff',
            padding: '6px 16px',
            borderRadius: 8,
            fontSize: 13,
            fontWeight: 600,
            fontFamily: 'monospace',
            zIndex: 10001,
            pointerEvents: 'none',
            animation: 'fadeIn 0.15s ease-out',
          }}
        >
          {toast}
        </div>
      )}

      {/* FAB button */}
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label="Keyboard shortcuts"
        title="Keyboard shortcuts (?)"
        style={{
          position: 'fixed',
          bottom: 20,
          right: 20,
          width: 40,
          height: 40,
          borderRadius: '50%',
          background: open ? 'rgba(6, 182, 212, 0.9)' : 'rgba(255, 255, 255, 0.08)',
          border: '1px solid rgba(255, 255, 255, 0.15)',
          color: open ? '#fff' : 'rgba(255, 255, 255, 0.5)',
          fontSize: 18,
          fontWeight: 700,
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 10000,
          transition: 'all 0.2s ease',
          boxShadow: '0 2px 8px rgba(0,0,0,0.3)',
          backdropFilter: 'blur(8px)',
        }}
      >
        {open ? '✕' : '?'}
      </button>

      {/* Shortcuts panel */}
      {open && (
        <>
          <div
            onClick={() => setOpen(false)}
            style={{
              position: 'fixed',
              inset: 0,
              zIndex: 9998,
            }}
          />
          <div
            style={{
              position: 'fixed',
              bottom: 68,
              right: 20,
              background: 'rgba(17, 24, 39, 0.95)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: 12,
              padding: '16px 20px',
              zIndex: 9999,
              minWidth: 200,
              boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
              backdropFilter: 'blur(12px)',
              animation: 'slideUp 0.15s ease-out',
            }}
          >
            <div
              style={{
                fontSize: 11,
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                color: 'rgba(255,255,255,0.4)',
                marginBottom: 10,
              }}
            >
              Keyboard Shortcuts
            </div>
            {shortcuts.map((s) => (
              <div
                key={s.key}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '4px 0',
                  fontSize: 13,
                }}
              >
                <kbd
                  style={{
                    display: 'inline-block',
                    padding: '2px 6px',
                    background: 'rgba(255,255,255,0.08)',
                    border: '1px solid rgba(255,255,255,0.15)',
                    borderRadius: 4,
                    fontFamily: 'monospace',
                    fontSize: 11,
                    color: 'rgba(255,255,255,0.7)',
                    minWidth: 28,
                    textAlign: 'center',
                  }}
                >
                  {s.key}
                </kbd>
                <span style={{ color: 'rgba(255,255,255,0.55)' }}>{s.label}</span>
              </div>
            ))}
            <div
              style={{
                marginTop: 10,
                paddingTop: 8,
                borderTop: '1px solid rgba(255,255,255,0.08)',
                fontSize: 11,
                color: 'rgba(255,255,255,0.3)',
              }}
            >
              Press <kbd style={{
                padding: '1px 4px',
                background: 'rgba(255,255,255,0.08)',
                border: '1px solid rgba(255,255,255,0.12)',
                borderRadius: 3,
                fontFamily: 'monospace',
                fontSize: 10,
              }}>?</kbd> to toggle
            </div>
          </div>
        </>
      )}

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateX(-50%) translateY(-8px); }
          to { opacity: 1; transform: translateX(-50%) translateY(0); }
        }
        @keyframes slideUp {
          from { opacity: 0; transform: translateY(8px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </>
  );
};

export default KeyboardHints;
