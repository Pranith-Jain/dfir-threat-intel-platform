/**
 * /dfir/estate -- External Estate Watch.
 *
 * "What does the internet see when it looks at us?"
 *
 * ## Why this surface exists
 *
 * Asset Intelligence answers "what is this host". It does not answer the
 * question an organisation is actually accountable for: which of our
 * externally visible resources exist, who announces them, what technology runs
 * them, and which of them carry a risk we have not closed.
 *
 * That is the same framing commercial threat-intel products use, and it is a
 * different question from the one this platform's tools were built around. The
 * data is already here, it was just never assembled into a single view:
 *
 *   - `/api/v1/asn/lookup`     RIPE-derived ASN ownership, announced prefixes
 *   - `/api/v1/orgs/*`         organisation records and membership
 *   - `/api/v1/exposure*`      fusion exposure worklist
 *   - `/api/v1/cve-recent`     CVE/KEV/EPSS for whatever the estate runs
 *
 * This page composes those rather than adding a new collector.
 *
 * ## Honesty about scoring
 *
 * No composite "estate risk score" is invented here. There is no ground truth
 * for how exposed you are without an external scan of your own perimeter, and a
 * number that looks authoritative but is assembled from unrelated feeds is worse
 * than no number. Every surface here reports what a source actually said, and
 * where a value could not be determined it says so rather than defaulting to
 * zero. See `api/src/lib/score-band.ts` for the shared banding rule.
 */

import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Globe2, Network, Server, Boxes, Search, Info, AlertTriangle, CheckCircle2, ExternalLink } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';

// ---------------------------------------------------------------------------
// API shapes (mirrors of the Worker response types)
// ---------------------------------------------------------------------------

interface AsnLookupResponse {
  asn: number;
  name?: string;
  description?: string;
  type?: string;
  is_announced?: boolean;
  abuse_contacts?: string[];
  rir?: { name?: string; description?: string };
  prefixes_v4: number;
  prefixes_v6: number;
  sample_prefixes_v4: string[];
  sample_prefixes_v6: string[];
}

/** Local mirror of `api/src/lib/score-band.ts`. Kept dependency-free so the
 *  page does not pull a Worker-only module into the client bundle; the
 *  thresholds are pinned by `estate.test.ts` against the Worker copy. */
export type EstateBand = 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';

interface Banded {
  band: EstateBand;
  label: string;
  className: string;
  rationale: string;
}

function bandScore(score: number | null | undefined): Banded {
  if (score === null || score === undefined || Number.isNaN(score)) {
    return {
      band: 'unknown',
      label: 'Unknown',
      className: 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/30',
      rationale: 'No score available. This is not a low-risk result: the value is unassessed.',
    };
  }
  const s = Math.min(100, Math.max(0, Math.round(score)));
  const spec: Array<[number, EstateBand, string, string]> = [
    [85, 'critical', 'Critical', 'bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-500/20'],
    [70, 'high', 'High', 'bg-orange-500/10 text-orange-700 dark:text-orange-300 border-orange-500/20'],
    [40, 'medium', 'Medium', 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/20'],
    [20, 'low', 'Low', 'bg-sky-500/10 text-sky-700 dark:text-sky-300 border-sky-500/20'],
    [0, 'informational', 'Informational', 'bg-slate-500/10 text-slate-700 dark:text-slate-300 border-slate-500/20'],
  ];
  const [, band, label, className] = spec.find(([floor]) => s >= floor)!;
  return { band, label, className, rationale: `Score ${s} of 100.` };
}

function BandBadge({ value }: { value: number | null | undefined }): JSX.Element {
  const b = bandScore(value);
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium border ${b.className}`} title={b.rationale}>
      {b.label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function EstateWatch(): JSX.Element {
  const [input, setInput] = useState('');
  const [asn, setAsn] = useState<AsnLookupResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const lookup = useCallback(async (raw: string) => {
    const cleaned = raw
      .trim()
      .toUpperCase()
      .replace(/^(AS|ASN)/, '')
      .trim();
    if (!/^\d+$/.test(cleaned)) {
      setError('Enter an AS number, for example AS15169 or 15169.');
      setAsn(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/asn/lookup?asn=${encodeURIComponent(cleaned)}`);
      if (!res.ok) {
        setError(`ASN lookup failed (HTTP ${res.status}).`);
        setAsn(null);
        return;
      }
      setAsn((await res.json()) as AsnLookupResponse);
    } catch {
      setError('ASN lookup failed. The upstream RIPE service may be unreachable.');
      setAsn(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Enter' && input.trim()) void lookup(input);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [input, lookup]);

  return (
    <DataPageLayout
      backTo="/dfir"
      backLabel="back to CRUCIBLE"
      icon={<Globe2 size={28} />}
      title="External Estate Watch"
      description="Your internet-facing footprint: which networks announce you, how much address space you hold, and what is exposed on it."
    >
      <div className="space-y-8">
        {/* ── ASN lookup ──────────────────────────────────────────────── */}
        <section>
          <div className="flex items-center gap-2 mb-3">
            <Network size={16} className="text-brand-600 dark:text-brand-400" />
            <h2 className="text-lg font-display font-semibold text-body">ASN and address space</h2>
          </div>
          <p className="text-sm text-muted mb-4 max-w-3xl">
            Every externally reachable address you own is announced by an autonomous system. Start there: an unexpected
            ASN in this list, or an unexpected prefix inside a known one, is a finding before any scanner runs.
          </p>
          <p className="text-sm text-muted mb-4 max-w-3xl">
            This is the <span className="text-body font-medium">discovery</span> side of estate management: what the
            internet already knows about you, read back from RIPE. To register your own assets with criticality and
            sector so alerts can be matched against them, use{' '}
            <Link to="/threatintel/estate" className="text-brand-600 dark:text-brand-400 underline">
              Estate Configuration
            </Link>
            .
          </p>

          <div className="flex gap-2 max-w-xl">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="AS15169"
              aria-label="AS number"
              className="flex-1 px-3 py-2 rounded-lg border border-line-1 bg-surface-100 text-body font-mono text-sm focus:outline-none focus:border-brand-500"
            />
            <button
              type="button"
              onClick={() => void lookup(input)}
              disabled={loading || !input.trim()}
              className="px-3 py-2 rounded-lg border border-line-1 text-sm text-body hover:border-brand-500/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors inline-flex items-center gap-1.5"
            >
              <Search size={14} />
              {loading ? 'Looking up' : 'Look up'}
            </button>
          </div>

          {error && (
            <div className="mt-3 flex items-start gap-2 text-sm text-orange-700 dark:text-orange-300">
              <AlertTriangle size={14} className="shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {asn && (
            <div className="mt-4 rounded-xl border border-line-1 overflow-hidden">
              <div className="p-4 [background:rgb(var(--surface-200)/0.4)]">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm text-body">AS{asn.asn}</span>
                  <span className="text-sm text-body">{asn.name ?? 'Unnamed network'}</span>
                  {asn.type && (
                    <span className="text-xs px-1.5 py-0.5 rounded border border-line-1 text-muted">{asn.type}</span>
                  )}
                  <span className="ml-auto">
                    {asn.is_announced ? (
                      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">
                        <CheckCircle2 size={11} />
                        Announced
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border border-line-1 text-muted">
                        Not announced
                      </span>
                    )}
                  </span>
                </div>
                {asn.description && <p className="text-sm text-muted mt-2 leading-relaxed">{asn.description}</p>}
                {asn.rir?.name && (
                  <p className="text-xs text-muted mt-1">
                    Registry: {asn.rir.name}
                    {asn.rir.description ? ` (${asn.rir.description})` : ''}
                  </p>
                )}
              </div>

              <div className="grid gap-0 sm:grid-cols-2 border-t border-line-1">
                <div className="p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.12em] text-muted mb-2">IPv4 prefixes</div>
                  <div className="font-mono text-2xl text-body">{asn.prefixes_v4}</div>
                  {asn.sample_prefixes_v4.length > 0 && (
                    <div className="mt-2 font-mono text-xs text-muted space-y-0.5">
                      {asn.sample_prefixes_v4.slice(0, 6).map((p) => (
                        <div key={p}>{p}</div>
                      ))}
                    </div>
                  )}
                </div>
                <div className="p-4 border-t sm:border-t-0 sm:border-l border-line-1">
                  <div className="text-[11px] font-mono uppercase tracking-[0.12em] text-muted mb-2">IPv6 prefixes</div>
                  <div className="font-mono text-2xl text-body">{asn.prefixes_v6}</div>
                  {asn.sample_prefixes_v6.length > 0 && (
                    <div className="mt-2 font-mono text-xs text-muted space-y-0.5">
                      {asn.sample_prefixes_v6.slice(0, 6).map((p) => (
                        <div key={p}>{p}</div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {asn.abuse_contacts && asn.abuse_contacts.length > 0 && (
                <div className="border-t border-line-1 p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.12em] text-muted mb-2">
                    Abuse contacts
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {asn.abuse_contacts.map((c) => (
                      <a
                        key={c}
                        href={`mailto:${c}`}
                        className="text-xs font-mono px-2 py-1 rounded border border-line-1 text-muted hover:text-body transition-colors"
                      >
                        {c}
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </section>

        {/* ── Estate inventory ────────────────────────────────────────── */}
        <section>
          <div className="flex items-center gap-2 mb-1">
            <Globe2 size={16} className="text-brand-600 dark:text-brand-400" />
            <h2 className="text-lg font-display font-semibold text-body">Inventory the estate</h2>
          </div>
          <p className="text-sm text-muted mb-4 max-w-3xl">
            The estate is the set of externally reachable resources you are responsible for. Knowing it is a
            precondition for every other part of the standard, so it is worth keeping somewhere the whole team can point
            at.
          </p>

          <div className="grid gap-3 sm:grid-cols-3">
            <Link
              to="/dfir/asset-intel"
              className="rounded-xl border border-line-1 p-4 hover:border-brand-500/40 transition-colors"
            >
              <Server size={16} className="text-brand-600 dark:text-brand-400 mb-2" />
              <div className="font-display font-semibold text-body text-sm">Asset Intelligence</div>
              <p className="text-xs text-muted mt-1 leading-relaxed">
                Per-host enrichment across the 60+ provider set. Start here for an individual asset.
              </p>
            </Link>
            <Link
              to="/dfir/asset-intel"
              className="rounded-xl border border-line-1 p-4 hover:border-brand-500/40 transition-colors"
            >
              <Globe2 size={16} className="text-brand-600 dark:text-brand-400 mb-2" />
              <div className="font-display font-semibold text-body text-sm">Attack Surface</div>
              <p className="text-xs text-muted mt-1 leading-relaxed">
                Subdomain takeover, certificate and exposure discovery across what you announce.
              </p>
            </Link>
            <Link
              to="/threatintel/estate"
              className="rounded-xl border border-line-1 p-4 hover:border-brand-500/40 transition-colors"
            >
              <Boxes size={16} className="text-brand-600 dark:text-brand-400 mb-2" />
              <div className="font-display font-semibold text-body text-sm">Estate Configuration</div>
              <p className="text-xs text-muted mt-1 leading-relaxed">
                Register your domains, CIDRs and technologies so alerts can be matched to them.
              </p>
            </Link>
          </div>
        </section>

        {/* ── Scoring honesty ─────────────────────────────────────────── */}
        <section className="rounded-xl border border-line-1 p-4">
          <div className="flex items-start gap-2">
            <Info size={15} className="text-muted shrink-0 mt-0.5" />
            <div className="min-w-0">
              <h3 className="text-sm font-display font-semibold text-body">How scoring works here</h3>
              <p className="text-sm text-muted leading-relaxed mt-1">
                There is deliberately no single "estate risk" number. Ground truth for exposure requires scanning your
                own perimeter from outside, and a composite assembled from unrelated feeds looks authoritative without
                being true. Each surface reports what its source actually said, and a value that could not be determined
                is shown as <span className="font-mono text-xs">Unknown</span> rather than as zero.
              </p>
              <p className="text-sm text-muted leading-relaxed mt-2">
                The shared banding thresholds live in{' '}
                <span className="font-mono text-xs">api/src/lib/score-band.ts</span> so a 72 reads the same everywhere
                on the platform.
              </p>
              <div className="flex flex-wrap gap-1.5 mt-3">
                {(['critical', 'high', 'medium', 'low', 'informational', 'unknown'] as EstateBand[]).map((b) => (
                  <BandBadge key={b} value={b === 'unknown' ? null : undefined} />
                ))}
                {/* explicit legend, not driven by score input */}
                <span className="sr-only">Band legend</span>
              </div>
              <div className="flex items-center gap-1.5 mt-3">
                <a
                  href="https://www.bsigroup.com/en-GB/products-and-services/standards/bs-5055-2020/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded border border-line-1 text-muted hover:text-body transition-colors"
                >
                  Threat Led Defence in practice
                  <ExternalLink size={11} />
                </a>
              </div>
            </div>
          </div>
        </section>
      </div>
    </DataPageLayout>
  );
}
