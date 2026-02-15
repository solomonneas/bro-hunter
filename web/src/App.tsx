/**
 * Root App component with React Router.
 *
 * / = V3 (Threat Hunter Workbench) — the shipped product
 * /dev = Variant picker for development (1-5 keyboard shortcuts)
 * /dev/1 through /dev/5 = Development variant shells
 *
 * The variant picker and alternatives are dev-only tools, not shipped to users.
 */
import React, { lazy, Suspense, useEffect } from 'react';
import { BrowserRouter, Routes, Route, useNavigate, useLocation } from 'react-router-dom';
import V3App from './variants/v3/App';

// Dev-only: lazy-load variant apps and picker
const V1App = lazy(() => import('./variants/v1/App'));
const V2App = lazy(() => import('./variants/v2/App'));
const V4App = lazy(() => import('./variants/v4/App'));
const V5App = lazy(() => import('./variants/v5/App'));
const VariantPicker = lazy(() => import('./pages/VariantPicker'));

const LoadingFallback: React.FC = () => (
  <div className="min-h-screen bg-background flex items-center justify-center">
    <div className="text-center">
      <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin mx-auto mb-3" />
      <p className="text-sm text-gray-500">Loading…</p>
    </div>
  </div>
);

/**
 * Dev-only keyboard navigation.
 * Press 1-5 to jump to /dev/N, 0 or Escape to go to /dev picker.
 * Only active when on /dev/* routes.
 */
function DevKeyboardNav() {
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      // Only respond on /dev routes
      if (!location.pathname.startsWith('/dev')) return;

      const t = e.target as HTMLElement;
      if (t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement || t.isContentEditable) return;

      const num = parseInt(e.key);
      if (num >= 1 && num <= 5) {
        navigate(`/dev/${num}`);
      } else if (e.key === 'Escape' || e.key === '0') {
        navigate('/dev');
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [navigate, location]);

  return null;
}

function AppContent() {
  return (
    <>
      <DevKeyboardNav />
      <Routes>
        {/* Production: V3 at root */}
        <Route path="/*" element={<V3App basePath="/" />} />

        {/* Dev-only: variant picker and alternatives */}
        <Route path="/dev" element={
          <Suspense fallback={<LoadingFallback />}>
            <VariantPicker />
          </Suspense>
        } />
        <Route path="/dev/1/*" element={
          <Suspense fallback={<LoadingFallback />}><V1App /></Suspense>
        } />
        <Route path="/dev/2/*" element={
          <Suspense fallback={<LoadingFallback />}><V2App /></Suspense>
        } />
        <Route path="/dev/3/*" element={<V3App basePath="/dev/3" />} />
        <Route path="/dev/4/*" element={
          <Suspense fallback={<LoadingFallback />}><V4App /></Suspense>
        } />
        <Route path="/dev/5/*" element={
          <Suspense fallback={<LoadingFallback />}><V5App /></Suspense>
        } />
      </Routes>
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
