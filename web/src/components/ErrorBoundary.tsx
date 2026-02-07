/**
 * ErrorBoundary — Catches unhandled React errors and shows a fallback UI.
 * Also exports a compact QueryErrorMessage for React Query error states.
 */
import React, { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

// ============================================================================
// ErrorBoundary (class component — required by React error boundary API)
// ============================================================================

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('[ErrorBoundary] Uncaught error:', error, info.componentStack);
  }

  private handleReset = (): void => {
    this.setState({ hasError: false, error: null });
  };

  render(): ReactNode {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="min-h-screen bg-background flex items-center justify-center p-6" role="alert">
          <div className="max-w-md w-full rounded-xl border border-red-500/30 bg-red-500/5 p-8 text-center space-y-4">
            <AlertTriangle size={40} className="mx-auto text-red-400" aria-hidden="true" />
            <h1 className="text-xl font-semibold text-gray-100">Something went wrong</h1>
            <p className="text-sm text-gray-400">
              An unexpected error occurred. This has been logged.
            </p>
            {this.state.error && (
              <pre className="mt-2 text-xs text-red-300/70 bg-background/50 rounded p-3 overflow-auto max-h-32 text-left">
                {this.state.error.message}
              </pre>
            )}
            <button
              onClick={this.handleReset}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/20 text-red-300 border border-red-500/30 hover:bg-red-500/30 transition-colors text-sm"
              aria-label="Try again"
            >
              <RefreshCw size={14} aria-hidden="true" />
              Try Again
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// ============================================================================
// QueryErrorMessage — Compact error display for React Query hook errors
// ============================================================================

interface QueryErrorMessageProps {
  error: Error | null;
  onRetry?: () => void;
  className?: string;
}

export const QueryErrorMessage: React.FC<QueryErrorMessageProps> = ({
  error,
  onRetry,
  className = '',
}) => {
  if (!error) return null;

  return (
    <div
      className={`flex items-center gap-3 px-4 py-3 rounded-lg border border-red-500/30 bg-red-500/5 ${className}`}
      role="alert"
    >
      <AlertTriangle size={16} className="text-red-400 flex-shrink-0" aria-hidden="true" />
      <p className="text-sm text-red-300 flex-1 truncate">{error.message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="flex items-center gap-1.5 px-3 py-1 rounded text-xs border border-red-500/30 text-red-300 hover:bg-red-500/10 transition-colors flex-shrink-0"
          aria-label="Retry failed request"
        >
          <RefreshCw size={12} aria-hidden="true" />
          Retry
        </button>
      )}
    </div>
  );
};

export default ErrorBoundary;
