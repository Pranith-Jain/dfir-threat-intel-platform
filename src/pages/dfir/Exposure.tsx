import { errMessage, logCatch } from '../../lib/log';
import { useState, useEffect, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Radar } from 'lucide-react';
import type { ExposureScanResponse } from '../../lib/dfir/types';
import { SubdomainTree } from '../../components/dfir/SubdomainTree';
import { recordHistory } from '../../lib/dfir/history';
import { BackLink } from '../../components/BackLink';
import { RelatedActors } from '../../components/dfir/RelatedActors';

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export default function Exposure(): JSX.Element {
  const [searchParams] = useSearchParams();
  const initialInput = searchParams.get('domain') ?? '';
  const [input, setInput] = useState(initialInput);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ExposureScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const valid = DOMAIN_RE.test(input.trim());

  // Auto-run when arriving from a search-results page or a deep link with
  // ?domain= or ?q=. Mirrors the pattern in DomainReputation.tsx so users
  // who navigate between DomainInvestigator tabs see consistent behaviour.
  useEffect(() => {
    if (initialInput && DOMAIN_RE.test(initialInput.trim()) && !result) {
      void onSubmit({ preventDefault: () => {} } as FormEvent);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialInput]);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const r = await fetch(`/api/v1/exposure/scan?domain=${encodeURIComponent(input.trim())}`);
      if (!r.ok) {
        const body = (await r.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? `${r.status}`);
      }
      const r2 = (await r.json()) as ExposureScanResponse;
      setResult(r2);
      recordHistory({ tool: 'exposure', indicator: r2.domain, verdict: r2.verdict, score: r2.score });
    } catch (err) {
      logCatch(err);
      setError(errMessage(err, 'scan failed'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink to="/dfir">back</BackLink>
      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">Exposure Scanner</h1>
        <p className="text-muted mb-8 max-w-2xl">
          Subdomains seen in Certificate Transparency logs, resolved to IPs, with optional Shodan host enrichment when
          available.
        </p>
      </div>

      <form onSubmit={onSubmit} className="mb-10">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="example.com"
            className="flex-1 px-4 py-3 bg-surface-100 border border-line-1 rounded-xl font-mono text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
          />
          <button
            type="submit"
            disabled={!valid || loading}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 transition-colors"
          >
            <Radar size={16} className="inline mr-2" /> Scan
          </button>
        </div>
      </form>

      {loading && <p className="font-mono text-muted">Scanning…</p>}
      {error && (
        <p role="alert" className="font-mono text-rose-600 dark:text-rose-400">
          error: {error}
        </p>
      )}

      {result && (
        <div className="space-y-6">
          <section className="surface-card p-6">
            <div className="flex items-baseline justify-between">
              <h2 className="font-display font-bold text-2xl">{result.domain}</h2>
              <span className="font-mono text-sm">
                exposure: <span className="text-heading">{result.score}/100</span>{' '}
                <span
                  className={
                    result.verdict === 'low'
                      ? 'text-emerald-600 dark:text-emerald-400'
                      : result.verdict === 'medium'
                        ? 'text-amber-600 dark:text-amber-400'
                        : 'text-rose-600 dark:text-rose-400'
                  }
                >
                  ({result.verdict})
                </span>
              </span>
            </div>
            <p className="mt-2 font-mono text-sm text-muted">
              {result.subdomains.length} of {result.total_subdomains_seen} subdomains shown · Shodan:{' '}
              {result.shodan_enabled ? 'enabled' : 'unavailable'}
            </p>
          </section>
          <section className="surface-card p-6">
            <h3 className="font-display font-bold text-lg mb-3">Subdomains seen in CT logs</h3>
            <SubdomainTree subdomains={result.subdomains} />
          </section>
          <RelatedActors
            hints={{
              free_text: result.subdomains.flatMap((s) => [
                ...(s.shodan?.tags ?? []),
                ...((s.shodan?.raw_summary as { org?: string })?.org
                  ? [(s.shodan!.raw_summary as { org?: string }).org!]
                  : []),
              ]),
              country:
                result.subdomains[0]?.shodan?.raw_summary &&
                (result.subdomains[0].shodan.raw_summary as { country?: string }).country,
            }}
          />
        </div>
      )}
    </div>
  );
}
