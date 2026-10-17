import { useEffect, useRef, useState } from 'react';
import { isAbortError } from '../lib/abort-error';
import { errMessage } from '../lib/log';

/**
 * useIntelBundle - fetch (or compute-on-miss) a STIX 2.1 intel bundle for a
 * source item, and surface its denormalized view to the card component.
 *
 * Behaviour:
 *   - First call hits GET /api/v1/intel-bundle?source=…&ref=….
 *   - 404 cache_miss → automatically retries with `title`/`body` query params
 *     so the route can extract+enrich+persist. The second call resolves to
 *     the freshly-built view; subsequent renders read D1 directly.
 *   - On HTTP/network error the hook surfaces an error string; the consumer
 *     should render the original (pre-card) row as fallback.
 */

export type IocType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'hash' | 'email' | 'unknown';
export type IocVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

export interface IntelViewProviderScore {
  source: string;
  score: number;
  verdict: IocVerdict;
  tags: string[];
}

export interface IntelViewIoc {
  type: IocType;
  value: string;
  confidence: number;
  riskScore: number;
  tags: string[];
  listedIn: string[];
  verdict: IocVerdict;
  /** Per-provider scores driving the composite verdict. Sorted by score desc.
   *  Optional for backwards compatibility with bundles persisted before the
   *  field was added. */
  providerScores?: IntelViewProviderScore[];
}

export interface IntelView {
  reportId: string;
  bundleId: string;
  title: string;
  source: { id: string; name: string; url?: string };
  publishedAt: string | null;
  summary: string;
  keywords: string[];
  threatActors: { name: string; aliases: string[]; mitreId?: string }[];
  malware: { name: string; aliases: string[]; mitreId?: string }[];
  cves: {
    id: string;
    /** Listed in CISA Known Exploited Vulnerabilities catalog. */
    kevListed?: boolean;
    kevDateAdded?: string;
    kevDueDate?: string;
    /** FIRST EPSS - probability of exploitation in next 30 days, 0.0–1.0. */
    epssScore?: number;
    /** EPSS percentile, 0.0–1.0. */
    epssPercentile?: number;
  }[];
  iocs: IntelViewIoc[];
  iocsOverflow: { type: IocType; value: string }[];
  attackPatterns: { name: string; mitreId: string }[];
  /** Ordered MITRE Attack-Flow steps (kill-chain or LLM order) mirroring the
   *  emitted attack-action chain. Optional for back-compat with pre-flow bundles. */
  flowSteps?: { techniqueId: string; name: string; tactic?: string }[];
  /** LLM-extracted sectors. Optional for back-compat with pre-LLM bundles. */
  sectors?: string[];
  /** LLM-extracted affected products. Optional for back-compat. */
  affectedProducts?: { vendor: string; product: string }[];
  /** LLM candidate actors - never promoted into threatActors. Optional for back-compat. */
  actorCandidates?: { name: string; rationale: string }[];
  /** LLM candidate malware - never promoted into malware. Optional for back-compat. */
  malwareCandidates?: { name: string; rationale: string }[];
  /** Provenance for the LLM enrichment call (or skipped). Optional for back-compat. */
  llmEnrichment?: { ran: boolean; partial: boolean; modelUsed?: string };
  tlp: 'WHITE' | 'AMBER';
  partial: boolean;
  generatedAt: string;
  extractedHash: string;
}

export interface IntelBundleResponse {
  bundle: { type: 'bundle'; id: string; objects: Array<Record<string, unknown>> };
  view: IntelView;
  cache: 'hit' | 'miss' | 'computed';
}

export interface UseIntelBundleOptions {
  sourceId: string;
  itemRef: string;
  /** Only required on cache miss. */
  title?: string;
  /** Only required on cache miss. */
  body?: string;
  publishedAt?: string | null;
  /** If `true`, the hook is enabled. Use to lazy-mount cards. */
  enabled?: boolean;
}

export interface UseIntelBundleResult {
  view: IntelView | null;
  bundle: IntelBundleResponse['bundle'] | null;
  status: 'idle' | 'loading' | 'enriching' | 'ready' | 'error';
  error: string | null;
  refresh: () => void;
}

function probeUrl(o: UseIntelBundleOptions): string {
  const u = new URL('/api/v1/intel-bundle', window.location.origin);
  u.searchParams.set('source', o.sourceId);
  u.searchParams.set('ref', o.itemRef);
  return u.toString();
}

export function useIntelBundle(options: UseIntelBundleOptions): UseIntelBundleResult {
  const { sourceId, itemRef, title, body, publishedAt, enabled = true } = options;
  const [view, setView] = useState<IntelView | null>(null);
  const [bundle, setBundle] = useState<IntelBundleResponse['bundle'] | null>(null);
  const [status, setStatus] = useState<UseIntelBundleResult['status']>('idle');
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  // Avoid duplicate fetches on rapid prop-update churn.
  const inflight = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!enabled || !sourceId || !itemRef) return;
    inflight.current?.abort();
    const ctrl = new AbortController();
    inflight.current = ctrl;
    setStatus('loading');
    setError(null);

    const opts: UseIntelBundleOptions = { sourceId, itemRef, title, body, publishedAt, enabled };

    (async () => {
      try {
        // Pass 1: D1-hit probe via GET. Cheap (URL only carries source + ref).
        let res = await fetch(probeUrl(opts), { signal: ctrl.signal });
        if (res.status === 404 && (title || body)) {
          setStatus('enriching');
          // Pass 2: cache_miss → POST so the body can be arbitrarily large
          // (aggregate cards routinely send 30–40 KB of pooled feed text,
          // which would blow Cloudflare's ~16 KB URL limit on a GET).
          res = await fetch('/api/v1/intel-bundle', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              source: opts.sourceId,
              ref: opts.itemRef,
              title: opts.title,
              body: opts.body,
              publishedAt: opts.publishedAt ?? null,
            }),
            signal: ctrl.signal,
          });
        }
        if (!res.ok) {
          const txt = await res.text().catch(() => res.statusText);
          throw new Error(`intel-bundle ${res.status}: ${txt.slice(0, 200)}`);
        }
        const json = (await res.json()) as IntelBundleResponse;
        setBundle(json.bundle);
        setView(json.view);
        setStatus('ready');
      } catch (err) {
        if (isAbortError(err)) return;
        setError(errMessage(err));
        setStatus('error');
      }
    })();

    return () => ctrl.abort();
  }, [enabled, sourceId, itemRef, title, body, publishedAt, tick]);

  return { view, bundle, status, error, refresh: () => setTick((n) => n + 1) };
}
