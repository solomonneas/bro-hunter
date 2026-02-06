/**
 * Root App component with React Router.
 * / = VariantPicker, /1/* through /5/* = variant apps.
 */
import React, { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import VariantPicker from './pages/VariantPicker';

// Lazy-load variant apps for code splitting
const V1App = lazy(() => import('./variants/v1/App'));
const V2App = lazy(() => import('./variants/v2/App'));
const V3App = lazy(() => import('./variants/v3/App'));
const V4App = lazy(() => import('./variants/v4/App'));
const V5App = lazy(() => import('./variants/v5/App'));

const LoadingFallback: React.FC = () => (
  <div className="min-h-screen bg-background flex items-center justify-center">
    <div className="text-center">
      <div className="w-8 h-8 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin mx-auto mb-3" />
      <p className="text-sm text-gray-500">Loading variant…</p>
    </div>
  </div>
);

function App() {
  return (
    <BrowserRouter>
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
    </BrowserRouter>
  );
}

export default App;
