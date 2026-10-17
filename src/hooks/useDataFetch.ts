import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../lib/api-client';
import { memoryCache } from '../infrastructure/cache/memory-cache';
import { isAbortError } from '../lib/abort-error';
import { errMessage } from '../lib/log';

export interface UseDataFetchOptions<T> {
  url: string | null;
  ttl?: number;
  onError?: (err: Error) => void;
  staleWhileRevalidate?: boolean;
  initial?: T;
}

export interface UseDataFetchResult<T> {
  data: T | null;
  loading: boolean;
  stale: boolean;
  error: string | null;
  refetch: () => void;
}

async function fetchAndCache<T>(url: string, ttl: number, signal: AbortSignal): Promise<T> {
  const result = await api.get<T>(url, { signal });
  memoryCache.set(url, result, ttl);
  return result;
}

export function useDataFetch<T = unknown>({
  url,
  ttl = 30_000,
  onError,
  staleWhileRevalidate = true,
  initial,
}: UseDataFetchOptions<T>): UseDataFetchResult<T> {
  const [data, setData] = useState<T | null>(initial ?? null);
  const [loading, setLoading] = useState(!initial && !!url);
  const [stale, setStale] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ctrlRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;

  const doFetch = useCallback(async (url: string, ttl: number, signal: AbortSignal) => {
    try {
      const json = await fetchAndCache<T>(url, ttl, signal);
      if (!mountedRef.current || signal.aborted) return;
      setData(json);
      setError(null);
      setLoading(false);
      setStale(false);
    } catch (err) {
      if (!mountedRef.current || signal.aborted) return;
      if (isAbortError(err)) return;
      const msg = errMessage(err);
      setError(msg);
      setLoading(false);
      setStale(false);
      onErrorRef.current?.(err instanceof Error ? err : new Error(msg));
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    // Cancel any in-flight request from the previous url FIRST — even when
    // this run returns early via a fresh-cache hit, otherwise the stale
    // response can land after mount and overwrite the cached data.
    if (ctrlRef.current) ctrlRef.current.abort();
    if (!url) return;

    const hit = memoryCache.get<T>(url);

    if (hit?.fresh) {
      setData(hit.data);
      setLoading(false);
      setStale(false);
      return;
    }

    if (hit && staleWhileRevalidate) {
      setData(hit.data);
      setStale(true);
      setLoading(false);
    } else {
      setLoading(true);
      setStale(false);
    }

    const ctrl = new AbortController();
    ctrlRef.current = ctrl;

    doFetch(url, ttl, ctrl.signal);

    return () => {
      mountedRef.current = false;
      ctrl.abort();
    };
  }, [url, ttl, staleWhileRevalidate, doFetch]);

  const refetch = useCallback(() => {
    if (!url) return;
    memoryCache.delete(url);
    if (ctrlRef.current) ctrlRef.current.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;

    setError(null);
    setLoading(true);
    setStale(false);

    doFetch(url, ttl, ctrl.signal);
  }, [url, ttl, doFetch]);

  return { data, loading, stale, error, refetch };
}
