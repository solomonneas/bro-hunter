/**
 * VariantSettings — Floating gear icon that opens a panel to set/clear default variant.
 * Sits in bottom-left to complement the keyboard hints FAB in bottom-right.
 */
import React, { useState } from 'react';

interface VariantSettingsProps {
  currentVariant: number | null;
  defaultVariant: number | null;
  onSetDefault: (variant: number | null) => void;
  variantNames?: string[];
}

const DEFAULT_NAMES = ['Variant 1', 'Variant 2', 'Variant 3', 'Variant 4', 'Variant 5'];

export const VariantSettings: React.FC<VariantSettingsProps> = ({
  currentVariant,
  defaultVariant,
  onSetDefault,
  variantNames = DEFAULT_NAMES,
}) => {
  const [open, setOpen] = useState(false);

  return (
    <>
      {/* Gear FAB */}
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label="Variant settings"
        title="Variant settings"
        style={{
          position: 'fixed',
          bottom: 20,
          left: 20,
          width: 40,
          height: 40,
          borderRadius: '50%',
          background: open ? 'rgba(6, 182, 212, 0.9)' : 'rgba(255, 255, 255, 0.08)',
          border: '1px solid rgba(255, 255, 255, 0.15)',
          color: open ? '#fff' : 'rgba(255, 255, 255, 0.5)',
          fontSize: 18,
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
        {open ? '✕' : '⚙'}
      </button>

      {/* Settings panel */}
      {open && (
        <>
          <div
            onClick={() => setOpen(false)}
            style={{ position: 'fixed', inset: 0, zIndex: 9998 }}
          />
          <div
            style={{
              position: 'fixed',
              bottom: 68,
              left: 20,
              background: 'rgba(17, 24, 39, 0.95)',
              border: '1px solid rgba(255, 255, 255, 0.1)',
              borderRadius: 12,
              padding: '16px 20px',
              zIndex: 9999,
              minWidth: 240,
              maxWidth: 300,
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
                marginBottom: 12,
              }}
            >
              Default Variant
            </div>

            <p style={{ fontSize: 12, color: 'rgba(255,255,255,0.45)', marginBottom: 12, lineHeight: 1.5 }}>
              Set a default to skip the variant picker on load. You can always switch variants with keys 1-5.
            </p>

            {/* Variant options */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {/* Show picker option */}
              <button
                type="button"
                onClick={() => { onSetDefault(null); setOpen(false); }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '6px 10px',
                  borderRadius: 6,
                  border: 'none',
                  background: defaultVariant === null ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                  color: defaultVariant === null ? 'rgba(6, 182, 212, 0.9)' : 'rgba(255,255,255,0.5)',
                  fontSize: 12,
                  cursor: 'pointer',
                  textAlign: 'left',
                  transition: 'all 0.15s ease',
                }}
              >
                <span style={{
                  width: 16, height: 16, borderRadius: '50%',
                  border: `2px solid ${defaultVariant === null ? 'rgba(6, 182, 212, 0.9)' : 'rgba(255,255,255,0.2)'}`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  {defaultVariant === null && (
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'rgba(6, 182, 212, 0.9)' }} />
                  )}
                </span>
                Show variant picker (default)
              </button>

              {variantNames.map((name, i) => {
                const num = i + 1;
                const isSelected = defaultVariant === num;
                const isCurrent = currentVariant === num;
                return (
                  <button
                    type="button"
                    key={num}
                    onClick={() => { onSetDefault(num); setOpen(false); }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      padding: '6px 10px',
                      borderRadius: 6,
                      border: 'none',
                      background: isSelected ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                      color: isSelected ? 'rgba(6, 182, 212, 0.9)' : 'rgba(255,255,255,0.5)',
                      fontSize: 12,
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <span style={{
                      width: 16, height: 16, borderRadius: '50%',
                      border: `2px solid ${isSelected ? 'rgba(6, 182, 212, 0.9)' : 'rgba(255,255,255,0.2)'}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      flexShrink: 0,
                    }}>
                      {isSelected && (
                        <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'rgba(6, 182, 212, 0.9)' }} />
                      )}
                    </span>
                    <span>
                      <kbd style={{
                        padding: '1px 4px', background: 'rgba(255,255,255,0.06)',
                        border: '1px solid rgba(255,255,255,0.1)', borderRadius: 3,
                        fontFamily: 'monospace', fontSize: 10, marginRight: 6,
                      }}>{num}</kbd>
                      {name}
                    </span>
                    {isCurrent && (
                      <span style={{ marginLeft: 'auto', fontSize: 10, color: 'rgba(255,255,255,0.3)' }}>current</span>
                    )}
                  </button>
                );
              })}
            </div>

            {defaultVariant !== null && (
              <div style={{
                marginTop: 10, paddingTop: 8,
                borderTop: '1px solid rgba(255,255,255,0.08)',
                fontSize: 11, color: 'rgba(255,255,255,0.3)',
              }}>
                App will load directly into V{defaultVariant}
              </div>
            )}
          </div>
        </>
      )}

      <style>{`
        @keyframes slideUp {
          from { opacity: 0; transform: translateY(8px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </>
  );
};

export default VariantSettings;
