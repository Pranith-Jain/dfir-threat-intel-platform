/**
 * Shared hook for API data fetching with loading, error, and retry.
 *
 * Replaces the pattern of:
 *   const [data, setData] = useState(null);
 *   const [loading, setLoading] = useState(true);
 *   const [error, setError] = useState(null);
 *   useEffect(() => { fetch(...).then(...).catch(...) }, []);
 *
 * With:
 *   const { data, loading, error, refetch } = useApiData('/api/v1/endpoint');
 *
 * Features:
 *   - Automatic loading/error state management
 *   - Stale-while-revalidate via useDataFetch
 *   - Consistent error messages from api client
 *   - Refetch on URL change
 *   - Optional polling interval
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { api, ApiError } from '../lib/api-client';
import { memoryCache } from '../infrastructure/cache/memory-cache';
import { isAbortError } from '../lib/abort-error';
import { errMessage } from '../lib/log';

export interface UseApiDataOptions<T> {
  /** Initial data while loading. */
  initial?: T;
  /** Polling interval in ms. 0 = disabled. */
  pollInterval?: number;
  /** Cache TTL in ms. Default 30s. */
  ttl?: number;
  /** Skip the fetch (e.g., when URL depends on user input). */
  enabled?: boolean;
  /** Transform the response before setting data. */
  transform?: (data: unknown) => T;
  /** Callback on error. */
  onError?: (err: Error) => void;
}

export interface UseApiDataResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
  /** Clear error and retry. */
  retry: () => void;
}

export function useApiData<T = unknown>(url: string | null, options: UseApiDataOptions<T> = {}): UseApiDataResult<T> {
  const { initial, pollInterval = 0, ttl = 30_000, enabled = true, transform, onError } = options;
  const [data, setData] = useState<T | null>(initial ?? null);
  const [loading, setLoading] = useState(!initial && !!url && enabled);
  const [error, setError] = useState<string | null>(null);
  const ctrlRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;
  const cacheKey = url && enabled ? url : null;

  const fetchData = useCallback(
    async (url: string, ttl: number, signal: AbortSignal) => {
      try {
        const result = await api.get<T>(url, { signal });
        if (!mountedRef.current || signal.aborted) return;
        memoryCache.set(url, result, ttl);
        const final = transform ? transform(result) : result;
        setData(final);
        setError(null);
        setLoading(false);
      } catch (err) {
        if (!mountedRef.current || signal.aborted) return;
        if (isAbortError(err)) return;
        const msg = err instanceof ApiError ? err.message : errMessage(err);
        setError(msg);
        setLoading(false);
        onErrorRef.current?.(err instanceof Error ? err : new Error(msg));
      }
    },
    [transform]
  );

  // Fetch on mount, URL/enabled change, or refetch.
  useEffect(() => {
    mountedRef.current = true;
    // Abort the previous url's in-flight request before any early return —
    // same race as useDataFetch (stale response overwriting fresh cache hit).
    if (ctrlRef.current) ctrlRef.current.abort();
    if (!cacheKey) return;

    const hit = memoryCache.get<T>(cacheKey);
    if (hit?.fresh) {
      setData(hit.data);
      setLoading(false);
      setError(null);
      return;
    }
    if (hit) {
      // SWR: show stale data while revalidating
      setData(hit.data);
      setLoading(false);
    } else {
      setLoading(true);
      setError(null);
    }

    const ctrl = new AbortController();
    ctrlRef.current = ctrl;

    fetchData(cacheKey, ttl, ctrl.signal);

    return () => {
      mountedRef.current = false;
      ctrl.abort();
    };
  }, [cacheKey, ttl, fetchData]);

  // Polling.
  useEffect(() => {
    if (!pollInterval || !url || !enabled) return;
    const interval = setInterval(() => {
      if (!url) return;
      memoryCache.delete(url);
      const ctrl = new AbortController();
      ctrlRef.current?.abort();
      ctrlRef.current = ctrl;
      fetchData(url, ttl, ctrl.signal);
    }, pollInterval);
    return () => clearInterval(interval);
  }, [pollInterval, url, enabled, ttl, fetchData]);

  const refetch = useCallback(() => {
    if (!cacheKey) return;
    memoryCache.delete(cacheKey);
    if (ctrlRef.current) ctrlRef.current.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    setLoading(true);
    fetchData(cacheKey, ttl, ctrl.signal);
  }, [cacheKey, ttl, fetchData]);

  const retry = useCallback(() => {
    setError(null);
    refetch();
  }, [refetch]);

  return { data, loading, error, refetch, retry };
}

/**
 * POST mutation hook with loading/error state.
 * For form submissions, button clicks, etc.
 */
export function useApiMutation<TInput, TOutput = void>(url: string) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<TOutput | null>(null);

  const mutate = useCallback(
    async (input: TInput): Promise<TOutput | null> => {
      setLoading(true);
      setError(null);
      try {
        const result = await api.post<TOutput>(url, input);
        setData(result);
        return result;
      } catch (err) {
        const msg = err instanceof ApiError ? err.message : errMessage(err);
        setError(msg);
        return null;
      } finally {
        setLoading(false);
      }
    },
    [url]
  );

  const reset = useCallback(() => {
    setError(null);
    setData(null);
  }, []);

  return { mutate, loading, error, data, reset };
}
