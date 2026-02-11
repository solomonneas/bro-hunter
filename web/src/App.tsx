/**
 * Root App component with React Router.
 * / = VariantPicker (or auto-redirect if default set), /1/* through /5/* = variant apps.
 */
import React, { lazy, Suspense, useEffect } from 'react';
import { BrowserRouter, Routes, Route, useNavigate, useLocation } from 'react-router-dom';
import VariantPicker from './pages/VariantPicker';
import KeyboardHints from './components/KeyboardHints';
import VariantSettings from './components/VariantSettings';
import { useDefaultVariant } from './hooks/useDefaultVariant';

// Lazy-load variant apps for code splitting
const V1App = lazy(() => import('./variants/v1/App'));
const V2App = lazy(() => import('./variants/v2/App'));
const V3App = lazy(() => import('./variants/v3/App'));
const V4App = lazy(() => import('./variants/v4/App'));
const V5App = lazy(() => import('./variants/v5/App'));

const APP_ID = 'bro-hunter';
const VARIANT_NAMES = [
  'NOC Command Center',
  'Executive Overview',
  'Threat Hunter Workbench',
  'Beacon Analyzer',
  'DNS Intelligence',
];

const LoadingFallback: React.FC = () => (
  <div className="min-h-screen bg-background flex items-center justify-center">
    <div className="text-center">
      <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin mx-auto mb-3" />
      <p className="text-sm text-gray-500">Loading variant…</p>
    </div>
  </div>
);

function VariantKeyboardNav() {
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement || t.isContentEditable) return;
      const num = parseInt(e.key);
      if (num >= 1 && num <= 5) {
        navigate(`/${num}`);
      } else if (e.key === 'Escape' || e.key === '0') {
        navigate('/');
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [navigate, location]);

  return null;
}

function DefaultVariantRedirect({ defaultVariant }: { defaultVariant: number | null }) {
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (location.pathname === '/' && defaultVariant) {
      navigate(`/${defaultVariant}`, { replace: true });
    }
  }, [location.pathname, defaultVariant, navigate]);

  return null;
}

function AppContent() {
  const location = useLocation();
  const { defaultVariant, setDefaultVariant } = useDefaultVariant(APP_ID);

  // Extract current variant from path
  const variantMatch = location.pathname.match(/^\/([1-5])/);
  const currentVariant = variantMatch ? parseInt(variantMatch[1], 10) : null;

  return (
    <>
      <VariantKeyboardNav />
      <DefaultVariantRedirect defaultVariant={defaultVariant} />
      <KeyboardHints />
      <VariantSettings
        currentVariant={currentVariant}
        defaultVariant={defaultVariant}
        onSetDefault={setDefaultVariant}
        variantNames={VARIANT_NAMES}
      />
      <Suspense fallback={<LoadingFallback />}>
        <Routes>
          <Route path="/" element={<VariantPicker />} />
          <Route path="/1/*" element={<V1App />} />
          <Route path="/2/*" element={<V2App />} />
          <Route path="/3/*" element={<V3App />} />
          <Route path="/4/*" element={<V4App />} />
          <Route path="/5/*" element={<V5App />} />
        </Routes>
      </Suspense>
    </>
  );
}

function GitHubFooter() {
  return (
    <a
      href="https://github.com/solomonneas/bro-hunter"
      target="_blank"
      rel="noopener noreferrer"
      style={{
        position: 'fixed', bottom: 8, right: 12, zIndex: 50,
        display: 'flex', alignItems: 'center', gap: 6,
        fontSize: 11, color: '#888', textDecoration: 'none',
        opacity: 0.4, transition: 'opacity 0.2s',
      }}
      onMouseEnter={e => (e.currentTarget.style.opacity = '0.8')}
      onMouseLeave={e => (e.currentTarget.style.opacity = '0.4')}
    >
      <svg viewBox="0 0 16 16" fill="currentColor" width="16" height="16"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      Solomon Neas
    </a>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AppContent />
      <GitHubFooter />
    </BrowserRouter>
  );
}

export default App;
