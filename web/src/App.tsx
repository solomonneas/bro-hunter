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

function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}

export default App;
