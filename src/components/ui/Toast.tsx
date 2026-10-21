import { createContext, useContext, useState, useCallback, useMemo, useRef, type ReactNode } from 'react';
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react';

export type ToastVariant = 'success' | 'error' | 'warning' | 'info';

export interface Toast {
  id: string;
  message: string;
  variant: ToastVariant;
  duration?: number;
}

interface ToastContextValue {
  toasts: Toast[];
  toast: (message: string, variant?: ToastVariant, duration?: number) => void;
  success: (message: string, duration?: number) => void;
  error: (message: string, duration?: number) => void;
  warning: (message: string, duration?: number) => void;
  info: (message: string, duration?: number) => void;
  dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const ICON: Record<ToastVariant, ReactNode> = {
  success: <CheckCircle className="h-5 w-5 text-emerald-500" aria-hidden="true" />,
  error: <AlertCircle className="h-5 w-5 text-rose-500" aria-hidden="true" />,
  warning: <AlertTriangle className="h-5 w-5 text-amber-500" aria-hidden="true" />,
  info: <Info className="h-5 w-5 text-brand-500" aria-hidden="true" />,
};

const BORDER: Record<ToastVariant, string> = {
  success: 'border-l-emerald-500',
  error: 'border-l-rose-500',
  warning: 'border-l-amber-500',
  info: 'border-l-brand-500',
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    const timer = timers.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timers.current.delete(id);
    }
  }, []);

  const addToast = useCallback(
    (message: string, variant: ToastVariant = 'info', duration = 4000) => {
      const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
      setToasts((prev) => [...prev, { id, message, variant, duration }]);
      if (duration > 0) {
        timers.current.set(
          id,
          setTimeout(() => dismiss(id), duration)
        );
      }
      return id;
    },
    [dismiss]
  );

  const toast = useCallback(
    (message: string, variant: ToastVariant = 'info', duration?: number) => addToast(message, variant, duration),
    [addToast]
  );
  const success = useCallback(
    (message: string, duration?: number) => addToast(message, 'success', duration),
    [addToast]
  );
  const error = useCallback((message: string, duration?: number) => addToast(message, 'error', duration), [addToast]);
  const warning = useCallback(
    (message: string, duration?: number) => addToast(message, 'warning', duration),
    [addToast]
  );
  const info = useCallback((message: string, duration?: number) => addToast(message, 'info', duration), [addToast]);

  // Memoize the context value so it changes identity only when `toasts` does
  // (all the dispatch fns are useCallback-stable). Without this, every render
  // of the provider handed consumers a fresh object, re-rendering all of them.
  const value = useMemo(
    () => ({ toasts, toast, success, error, warning, info, dismiss }),
    [toasts, toast, success, error, warning, info, dismiss]
  );

  return (
    <ToastContext value={value}>
      {children}
      <div
        // `left-4 right-4` already sizes the container to the viewport with
        // a 16px gutter on each side. Adding `w-full` on top over-constrains
        // it (left + right + width), so CSS drops `right` and the element
        // becomes 100% of the viewport offset 16px from the left — 16px off
        // the right edge on every phone. `w-auto` lets left+right win.
        className="fixed bottom-4 right-4 left-4 sm:left-auto z-[70] flex w-auto sm:w-full sm:max-w-sm flex-col gap-2 pointer-events-none"
        aria-live="polite"
        aria-atomic="false"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            role="status"
            className={`pointer-events-auto flex items-start gap-3 rounded-xl border border-line-1/80 bg-surface-100 px-4 py-3 shadow-e3 ring-1 ring-black/5 backdrop-blur-sm transition-all dark:border-line-1 dark:bg-surface-200/95 animate-fade-in-up border-l-4 ${BORDER[t.variant]}`}
          >
            <span className="shrink-0 mt-0.5">{ICON[t.variant]}</span>
            <p className="flex-1 text-tool text-body">{t.message}</p>
            <button
              type="button"
              onClick={() => dismiss(t.id)}
              className="shrink-0 grid h-6 w-6 place-items-center rounded text-muted transition-colors hover:bg-surface-300 hover:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 dark:hover:bg-surface-300 dark:hover:text-inverted"
              aria-label="Dismiss"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    // SSR: entry-server.tsx renders without ToastProvider — return no-op so
    // prerender doesn't throw, but still throw in browser/jsdom where a missing
    // provider is a real bug (keeps src/components/__tests__/Toast.test.tsx green).
    if (typeof window === 'undefined') {
      return {
        toasts: [],
        toast: () => {},
        success: () => {},
        error: () => {},
        warning: () => {},
        info: () => {},
        dismiss: () => {},
      };
    }
    throw new Error('useToast must be used within a ToastProvider');
  }
  return ctx;
}
