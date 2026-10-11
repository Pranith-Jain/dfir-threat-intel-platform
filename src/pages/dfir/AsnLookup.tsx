import { logCatch } from '../../lib/log';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { AlertTriangle, Network } from 'lucide-react';
const ASN_RE = /^(AS)?\d{1,10}$/i;

interface RirData {
  name?: string;
  description?: string;
}

interface AsnResult {
  asn: number;
  name?: string;
  description?: string;
  type?: string;
  is_announced?: boolean;
  abuse_contacts?: string[];
  rir?: RirData;
  prefixes_v4: number;
  prefixes_v6: number;
  sample_prefixes_v4?: string[];
  sample_prefixes_v6?: string[];
}

export default function AsnLookup(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  // Accept ?asn= or ?q=. Strip "AS" prefix and any trailing org suffix
  // (e.g. "AS15169 Google LLC" → "15169") so deep-links from IpGeo work.
  const raw = searchParams!.get('asn') ?? searchParams!.get('q') ?? '';
  const initialQuery = raw.trim().replace(/^AS/i, '').split(/\s+/)[0]!.replace(/^AS/i, '');
  const [input, setInput] = useState(initialQuery);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AsnResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const autoFetched = useRef(false);

  const valid = ASN_RE.test(input.trim());
  const canSubmit = valid && !loading;

  const lookupRef = useRef<AbortController | null>(null);

  const runLookup = async (q: string) => {
    if (!ASN_RE.test(q.trim())) return;
    lookupRef.current?.abort();
    const ctrl = new AbortController();
    lookupRef.current = ctrl;
    setLoading(true);
    setResult(null);
    setError(null);
    setSearchParams({ asn: q.trim() }, { replace: true });
    try {
      const r = await fetch(`/api/v1/asn/lookup?asn=${encodeURIComponent(q.trim())}`, {
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
      });
      if (ctrl.signal.aborted) return;
      if (!r.ok) {
        const body = (await r.json().catch(() => null)) as { message?: string } | null;
        throw new Error(body?.message ?? `HTTP ${r.status}`);
      }
      setResult((await r.json()) as AsnResult);
    } catch (err) {
      logCatch(err);
      if (ctrl.signal.aborted) return;
      setError(err instanceof Error ? err.message : 'lookup failed');
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  };

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      lookupRef.current?.abort();
    };
  }, []);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    void runLookup(input);
  };

  useEffect(() => {
    if (autoFetched.current) return;
    if (initialQuery && ASN_RE.test(initialQuery)) {
      autoFetched.current = true;
      void runLookup(initialQuery);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="max-w-6xl">
      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">ASN Lookup</h1>
        <p className="text-muted mb-8 max-w-2xl">Autonomous system ownership, announced prefixes, and abuse contacts for any ASN, IP, or CIDR.</p>
      </div>

      {/* Was DataPageLayout's `error` prop before this page became a hub
          tab. Keep it inline so a failed lookup is still surfaced. */}
      {error && (
        <div className="rounded-xl border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30 p-4 flex items-start gap-3 mb-6">
          <AlertTriangle size={16} className="text-rose-600 dark:text-rose-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-rose-700 dark:text-rose-300">Lookup failed</p>
            <p className="text-xs text-rose-600 dark:text-rose-400 mt-1 font-mono break-all">{error}</p>
          </div>
        </div>
      )}

      <form onSubmit={onSubmit} className="mb-10">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="AS15169 or 15169"
              className="w-full bg-input-200 border border-line-input rounded-control px-4 py-3 text-tool text-heading placeholder:text-muted focus:outline-none focus:border-accent-text transition-colors"
            />
          </div>
          <button
            type="submit"
            disabled={!canSubmit}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-control disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 transition-colors"
          >
            <Network size={16} className="inline mr-2" />
            Lookup
          </button>
        </div>
        {input && !valid && (
          <p className="mt-2 text-xs font-mono text-amber-600 dark:text-amber-400">
            Enter a valid ASN (e.g. AS15169 or 15169)
          </p>
        )}
      </form>

      {result && (
        <div className="space-y-6">
          {/* Header */}
          <section className="surface-card p-6">
            <div className="flex flex-wrap items-start gap-3 mb-3">
              <h2 className="font-display font-bold text-2xl font-mono">AS{result.asn}</h2>
              {result.name && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-sm font-bold font-mono bg-brand-100 text-brand-800 dark:bg-brand-900/30 dark:text-brand-300 border border-brand-300 dark:border-brand-700">
                  {result.name}
                </span>
              )}
              {result.type && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-surface-300 text-muted border border-line-2">
                  {result.type}
                </span>
              )}
            </div>
            {result.description && <p className="text-body mb-3">{result.description}</p>}
            <div className="flex flex-wrap gap-4 font-mono text-xs text-muted">
              {result.is_announced !== undefined && (
                <span>
                  Announced:{' '}
                  <span className={result.is_announced ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500'}>
                    {result.is_announced ? 'Yes' : 'No'}
                  </span>
                </span>
              )}
            </div>
          </section>

          {/* Contacts */}
          {result.abuse_contacts && result.abuse_contacts.length > 0 && (
            <section className="surface-card p-6">
              <h3 className="font-display font-semibold text-lg mb-3">Abuse Contacts</h3>
              <div className="flex flex-wrap gap-2">
                {result.abuse_contacts.map((email) => (
                  <a
                    key={email}
                    href={`mailto:${email}`}
                    className="text-sm font-mono text-brand-600 dark:text-brand-400 hover:underline transition-colors"
                  >
                    {email}
                  </a>
                ))}
              </div>
            </section>
          )}

          {/* RIR */}
          {result.rir && (result.rir.name || result.rir.description) && (
            <section className="surface-card p-6">
              <h3 className="font-display font-semibold text-lg mb-3">RIR / Registry</h3>
              <div className="grid sm:grid-cols-2 gap-4 font-mono text-sm">
                {result.rir.name && (
                  <div>
                    <div className="text-xs text-muted mb-1">Registry</div>
                    <div className="text-heading font-semibold">{result.rir.name}</div>
                  </div>
                )}
                {result.rir.description && (
                  <div>
                    <div className="text-xs text-muted mb-1">Description</div>
                    <div className="text-heading">{result.rir.description}</div>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Prefixes */}
          <section className="surface-card p-6">
            <h3 className="font-display font-semibold text-lg mb-4">Announced Prefixes</h3>
            <div className="grid sm:grid-cols-2 gap-6">
              <div>
                <div className="text-xs uppercase tracking-wider text-muted font-mono mb-2">
                  IPv4 ({result.prefixes_v4} total)
                </div>
                {result.sample_prefixes_v4 && result.sample_prefixes_v4.length > 0 ? (
                  <ul className="space-y-1">
                    {result.sample_prefixes_v4.map((p) => (
                      <li key={p} className="font-mono text-sm text-body bg-surface-200 px-2 py-1 rounded">
                        {p}
                      </li>
                    ))}
                    {result.prefixes_v4 > 5 && (
                      <li className="font-mono text-xs text-muted">… and {result.prefixes_v4 - 5} more</li>
                    )}
                  </ul>
                ) : (
                  <p className="font-mono text-sm text-muted">None announced</p>
                )}
              </div>
              <div>
                <div className="text-xs uppercase tracking-wider text-muted font-mono mb-2">
                  IPv6 ({result.prefixes_v6} total)
                </div>
                {result.sample_prefixes_v6 && result.sample_prefixes_v6.length > 0 ? (
                  <ul className="space-y-1">
                    {result.sample_prefixes_v6.map((p) => (
                      <li key={p} className="font-mono text-sm text-body bg-surface-200 px-2 py-1 rounded break-all">
                        {p}
                      </li>
                    ))}
                    {result.prefixes_v6 > 5 && (
                      <li className="font-mono text-xs text-muted">… and {result.prefixes_v6 - 5} more</li>
                    )}
                  </ul>
                ) : (
                  <p className="font-mono text-sm text-muted">None announced</p>
                )}
              </div>
            </div>
          </section>
        </div>
      )}
  </div>
  );
}
