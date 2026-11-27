import { Component, type ReactNode, type ErrorInfo } from 'react';
import { AlertTriangle, RefreshCw, Home, ChevronDown, ChevronUp, Download } from 'lucide-react';
import { isAbortError } from '../lib/abort-error';

/**
 * Detect "stale chunk" failures: when a deploy bumped Vite's content-hashed
 * filenames, an already-loaded SPA shell tries to import e.g.
 *   /assets/DFIR-LooD3RJ-.js
 * which no longer exists, throwing one of these messages depending on the
 * browser. Treating these as "update available, please reload" gives a
 * much friendlier recovery than the generic stack trace.
 */
function isChunkLoadError(err: Error): boolean {
  const msg = `${err.name} ${err.message}`.toLowerCase();
  if (
    msg.includes('dynamically imported module') ||
    msg.includes('importing a module script failed') ||
    msg.includes('chunkloaderror') ||
    msg.includes('loading chunk') ||
    msg.includes('loading css chunk')
  ) {
    return true;
  }
  if (msg.includes('failed to fetch')) {
    const stack = (err.stack ?? '').toLowerCase();
    return stack.includes('/assets/') || stack.includes('.js:') || stack.includes('.mjs:');
  }
  return false;
}

/**
 * React reconciliation can throw `insertBefore ... parameter 1 is not of type
 * 'Node'` when the live DOM was changed underneath it (stale prerendered
 * markup, a removed sibling, or a browser extension mutating nodes). The
 * component tree is unrecoverable in that tab; a reload is the reliable fix.
 */
function isDomInsertionError(err: Error): boolean {
  const msg = `${err.name} ${err.message}`.toLowerCase();
  return msg.includes('insertbefore') || msg.includes("not of type 'node'") || msg.includes('removechild');
}

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
  resetOnChange?: boolean;
  className?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  isExpanded: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      isExpanded: false,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    // Abort errors (DOMException name 'AbortError', message 'signal is
    // aborted without reason') are expected control flow — they fire when a
    // component unmounts or re-fetches and its AbortController.abort() runs.
    // They are NOT real errors and must never surface to the user. We still
    // enter the error state (React requires it), but render() will show a
    // benign empty fallback for aborts instead of the error UI. This is the
    // safety net: individual catch blocks should also swallow aborts, but
    // this guarantees no abort ever reaches the error fallback UI even if a
    // catch block forgets to check.
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    // Abort errors are expected control flow (unmount/refetch) — don't log
    // them as errors and don't set error state. getDerivedStateFromError
    // already filtered them, but this prevents the console.error noise and
    // the onError callback from firing for aborts.
    if (isAbortError(error)) {
      return;
    }
    this.setState({
      error,
      errorInfo,
    });

    // Call onError callback if provided
    this.props.onError?.(error, errorInfo);

    // Log error for debugging
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  componentDidUpdate(prevProps: Props): void {
    // Reset error state when children change (only when actively showing an error,
    // to avoid reset loops from inline-created React elements).
    if (this.props.resetOnChange && this.state.hasError && prevProps.children !== this.props.children) {
      this.setState({
        hasError: false,
        error: null,
        errorInfo: null,
      });
    }
  }

  handleReset = (): void => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      isExpanded: false,
    });
  };

  toggleDetails = (): void => {
    this.setState((prev) => ({
      isExpanded: !prev.isExpanded,
    }));
  };

  render(): ReactNode {
    const { hasError, error, errorInfo, isExpanded } = this.state;
    const { children, fallback } = this.props;

    if (hasError && error) {
      // Abort errors (signal is aborted without reason) are expected control
      // flow from unmount/refetch — render a benign empty fragment instead
      // of the error UI. This is the safety net; catch blocks should swallow
      // aborts first, but this guarantees no abort ever reaches the fallback.
      if (isAbortError(error)) {
        return null;
      }

      if (fallback) {
        return fallback;
      }

      // Stale-chunk-after-deploy is a common SPA failure that masquerades
      // as a generic crash. Render a dedicated "update available" view so
      // the user reloads instead of staring at a stack trace.
      if (isChunkLoadError(error)) {
        return <StaleChunkFallback />;
      }

      if (isDomInsertionError(error)) {
        return <StaleDomFallback />;
      }

      return (
        <ErrorFallback
          error={error}
          errorInfo={errorInfo}
          isExpanded={isExpanded}
          onReset={this.handleReset}
          onToggleDetails={this.toggleDetails}
        />
      );
    }

    return children;
  }
}

/**
 * Friendly view for a broken DOM reconciliation: the component tree cannot
 * recover in this tab, but a reload always rebuilds it cleanly.
 */
function StaleDomFallback(): JSX.Element {
  return (
    <div className="animate-fade-in-up w-full max-w-2xl mx-auto p-6 rounded-2xl bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700/40">
      <h3 className="text-lg font-bold text-amber-900 dark:text-amber-100 mb-2">This page needs a reload</h3>
      <p className="text-sm text-amber-800 dark:text-amber-200 mb-4">
        The page structure changed while it was rendering. Reloading rebuilds it cleanly; your data and filters are
        safe.
      </p>
      <button
        type="button"
        onClick={() => window.location.reload()}
        className="px-4 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-on-fill text-sm font-medium transition-colors inline-flex items-center gap-2 min-h-11"
      >
        <RefreshCw className="w-4 h-4" />
        Reload page
      </button>
    </div>
  );
}

/**
 * Friendly view for the stale-chunk case: a new deploy invalidated the
 * lazy chunk URLs this SPA shell was holding. A hard reload pulls the
 * new index.html (with the new chunk filenames) and the import succeeds.
 */
function StaleChunkFallback(): JSX.Element {
  return (
    <div className="animate-fade-in-up w-full max-w-2xl mx-auto p-6 rounded-2xl bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700/40">
      <div className="flex items-start gap-4">
        <div className="shrink-0">
          <div className="w-12 h-12 rounded-full bg-amber-100 dark:bg-amber-900/40 flex items-center justify-center">
            <Download className="w-6 h-6 text-amber-600 dark:text-amber-400" />
          </div>
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-lg font-bold text-amber-900 dark:text-amber-100 mb-1">Update available</h3>
          <p className="text-sm text-amber-800 dark:text-amber-200 mb-1">
            A new version of the site was deployed since you opened this tab. The browser is holding stale references to
            removed asset files.
          </p>
          <p className="text-xs font-mono text-amber-700/80 dark:text-amber-300/70 mb-4">
            Reload to fetch the latest version.
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="px-4 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-on-fill text-sm font-medium transition-colors inline-flex items-center gap-2"
            >
              <RefreshCw className="w-4 h-4" />
              Reload page
            </button>{' '}
            <a
              href="/"
              className="px-4 py-2 rounded-xl bg-track hover:bg-slate-300 dark:hover:bg-surface-300 text-body text-sm font-medium transition-colors inline-flex items-center gap-2 min-h-[44px]"
            >
              <Home className="w-4 h-4" />
              Go home
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

interface ErrorFallbackProps {
  error: Error;
  errorInfo: ErrorInfo | null;
  isExpanded: boolean;
  onReset: () => void;
  onToggleDetails: () => void;
}

function ErrorFallback({ error, errorInfo, isExpanded, onReset, onToggleDetails }: ErrorFallbackProps) {
  return (
    <div className="animate-fade-in-up w-full p-6 rounded-2xl bg-rose-50 dark:bg-rose-900/20 border border-rose-200 dark:border-rose-800/30">
      <div className="flex items-start gap-4">
        <div className="shrink-0">
          <div className="w-12 h-12 rounded-full bg-rose-100 dark:bg-rose-900/40 flex items-center justify-center">
            <AlertTriangle className="w-6 h-6 text-rose-600 dark:text-rose-400" />
          </div>
        </div>

        <div className="flex-1 min-w-0">
          <h3 className="text-lg font-bold text-rose-800 dark:text-rose-200 mb-1">Something went wrong</h3>
          <p className="text-sm text-rose-600 dark:text-rose-300 mb-4">
            {error.message || 'An unexpected error occurred. The error has been logged.'}
          </p>

          {/* Error Details (collapsible) */}
          <button
            onClick={onToggleDetails}
            className="flex items-center gap-2 text-xs text-rose-500 dark:text-rose-400 hover:text-rose-600 dark:hover:text-rose-300 transition-colors mb-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2"
          >
            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            {isExpanded ? 'Hide' : 'Show'} error details
          </button>

          {isExpanded && errorInfo && (
            <div className="animate-fade-in-up overflow-hidden">
              <div className="p-3 rounded-xl bg-surface-100 dark:bg-black/50 text-left">
                <div className="text-micro font-mono text-rose-300 mb-2 uppercase tracking-wider">Stack Trace</div>
                <pre className="text-micro font-mono text-inverted overflow-x-auto whitespace-pre-wrap break-all max-h-48">
                  {error.stack}
                </pre>
                {errorInfo.componentStack && (
                  <>
                    <div className="text-micro font-mono text-rose-300 mt-3 mb-2 uppercase tracking-wider">
                      Component Stack
                    </div>
                    <pre className="text-micro font-mono text-inverted overflow-x-auto whitespace-pre-wrap break-all max-h-32">
                      {errorInfo.componentStack}
                    </pre>
                  </>
                )}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex flex-wrap gap-2 mt-4">
            <button
              onClick={onReset}
              className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-on-fill text-sm font-medium transition-colors flex items-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2"
            >
              <RefreshCw className="w-4 h-4" />
              Try Again
            </button>
            <a
              href="/"
              className="px-4 py-2 rounded-xl bg-track hover:bg-slate-300 dark:hover:bg-surface-300 text-body text-sm font-medium transition-colors flex items-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 min-h-[44px]"
            >
              <Home className="w-4 h-4" />
              Go Home
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

// Hook to use error boundary functionality in function components
import { useState, useCallback } from 'react';

// eslint-disable-next-line react-refresh/only-export-components
export function useErrorBoundary() {
  const [error, setError] = useState<Error | null>(null);
  const [isExpanded, setIsExpanded] = useState(false);

  const resetError = useCallback(() => {
    setError(null);
    setIsExpanded(false);
  }, []);

  // Store the error in state so ErrorComponent can render the fallback UI.
  // Do NOT re-throw - throwError is called from callbacks / async code where
  // a thrown error would become an unhandled rejection and crash the app.
  const throwError = useCallback((err: Error) => {
    setError(err);
  }, []);

  const toggleDetails = useCallback(() => {
    setIsExpanded((v) => !v);
  }, []);

  const ErrorComponent = useCallback(
    ({ children }: { children: ReactNode }) => {
      if (error) {
        return (
          <ErrorFallback
            error={error}
            errorInfo={{ componentStack: '' }}
            isExpanded={isExpanded}
            onReset={resetError}
            onToggleDetails={toggleDetails}
          />
        );
      }
      return <>{children}</>;
    },
    [error, resetError, isExpanded, toggleDetails]
  );

  return {
    error,
    throwError,
    resetError,
    ErrorComponent,
  };
}

// Lazy loading wrapper with error boundary
// eslint-disable-next-line react-refresh/only-export-components
export function withErrorBoundary<P extends object>(WrappedComponent: React.ComponentType<P>, fallback?: ReactNode) {
  return function WithErrorBoundary(props: P) {
    return (
      <ErrorBoundary fallback={fallback}>
        <WrappedComponent {...props} />
      </ErrorBoundary>
    );
  };
}

// Section-specific error boundaries
export function SectionErrorBoundary({ sectionName, children }: { sectionName: string; children: ReactNode }) {
  const handleError = useCallback(
    (error: Error, errorInfo: ErrorInfo) => {
      // Log section-specific errors
      console.error(`Error in ${sectionName}:`, error, errorInfo);
    },
    [sectionName]
  );

  return (
    <ErrorBoundary
      onError={handleError}
      fallback={
        <div className="w-full p-8 rounded-2xl bg-surface-200/50 border border-line-1 dark:border-white/10 text-center">
          <AlertTriangle className="w-10 h-10 text-amber-500 mx-auto mb-3" />
          <h3 className="text-lg font-bold text-heading mb-2">{sectionName} Section</h3>
          <p className="text-sm text-muted mb-4">This section encountered an error and couldn't load.</p>
          <p className="text-xs text-muted">The rest of the page is still functional.</p>
        </div>
      }
    >
      {children}
    </ErrorBoundary>
  );
}
