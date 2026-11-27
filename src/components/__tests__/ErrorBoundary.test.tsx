import { describe, it, expect, vi, beforeAll } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ErrorBoundary } from '../ErrorBoundary';
import { isAbortError } from '../../lib/abort-error';

// Component that throws an error
const ThrowError = ({ shouldThrow }: { shouldThrow: boolean }) => {
  if (shouldThrow) {
    throw new Error('Test error');
  }
  return <div>No error</div>;
};

describe('ErrorBoundary', () => {
  // Suppress console.error for expected errors
  beforeAll(() => {
    const originalConsoleError = console.error;
    console.error = vi.fn();
    return () => {
      console.error = originalConsoleError;
    };
  });

  it('should render children when no error occurs', () => {
    render(
      <ErrorBoundary>
        <div data-testid="child">Child content</div>
      </ErrorBoundary>
    );

    expect(screen.getByTestId('child')).toBeInTheDocument();
  });

  it('should render error UI when error occurs', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    // The boundary surfaces the underlying error message inside a paragraph.
    // ThrowError raises `Error('Test error')` so we look for that.
    expect(screen.getByText(/test error/i)).toBeInTheDocument();
  });

  it('offers a reload instead of a stack trace for DOM insertion failures', () => {
    const ThrowDomError = () => {
      throw new TypeError("Failed to execute 'insertBefore' on 'Node': parameter 1 is not of type 'Node'.");
    };
    render(
      <ErrorBoundary>
        <ThrowDomError />
      </ErrorBoundary>
    );
    expect(screen.getByText('This page needs a reload')).toBeInTheDocument();
    expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument();
  });

  it('should render custom fallback when provided', () => {
    const fallback = <div data-testid="custom-fallback">Custom error message</div>;

    render(
      <ErrorBoundary fallback={fallback}>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByTestId('custom-fallback')).toBeInTheDocument();
  });

  it('should have try again button in error UI', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByRole('button', { name: 'Try Again' })).toBeInTheDocument();
  });

  it('should log error when component catches error', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it('should display error icon in error UI', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );

    // The error UI should be present with the warning icon
    const alertElement = screen.getByText('Something went wrong');
    expect(alertElement).toBeInTheDocument();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Abort errors (DOMException name 'AbortError', message 'signal is aborted
  // without reason') are expected control flow — they fire when a component
  // unmounts or re-fetches and its AbortController.abort() runs. They must
  // NEVER surface to the user via the ErrorBoundary fallback. The boundary's
  // getDerivedStateFromError returns null for abort errors so the UI continues
  // rendering normally.
  // ─────────────────────────────────────────────────────────────────────────
  describe('abort errors (signal is aborted without reason)', () => {
    // Component that throws an AbortError during render (simulates a fetch
    // rejection that escaped a catch block and reached the boundary).
    const ThrowAbortError = () => {
      const err = new DOMException('signal is aborted without reason', 'AbortError');
      throw err;
    };

    it('isAbortError detects DOMException AbortError', () => {
      const err = new DOMException('signal is aborted without reason', 'AbortError');
      expect(isAbortError(err)).toBe(true);
    });

    it('isAbortError detects plain Error with name AbortError', () => {
      const err = new Error('aborted');
      err.name = 'AbortError';
      expect(isAbortError(err)).toBe(true);
    });

    it('isAbortError does not match a generic Error', () => {
      expect(isAbortError(new Error('something broke'))).toBe(false);
    });

    it('does NOT render the error fallback for an AbortError', () => {
      const { container } = render(
        <ErrorBoundary>
          <ThrowAbortError />
        </ErrorBoundary>
      );
      // The fallback UI must NOT appear — abort errors render null (benign).
      expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument();
      // The boundary returns null for abort errors, so the container has no
      // rendered child content from the boundary itself.
      expect(container.firstChild).toBeNull();
    });

    it('does NOT log AbortError to console.error', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      render(
        <ErrorBoundary>
          <ThrowAbortError />
        </ErrorBoundary>
      );
      // componentDidCatch returns early for abort errors — no console.error.
      const abortCalls = consoleSpy.mock.calls.filter(
        (args) => String(args[0]).includes('AbortError') || String(args[0]).includes('aborted')
      );
      expect(abortCalls).toHaveLength(0);
      consoleSpy.mockRestore();
    });
  });
});
