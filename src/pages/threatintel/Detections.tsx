import { logCatch } from '../../lib/log';
import { useEffect, useMemo, useState } from 'react';
import { relativeAgo } from '../../lib/relativeTime';
const shortRel = (iso?: string) => relativeAgo(iso, 'no timestamp');
import { Link } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { IocChip } from '../../components/dfir/IocChip';
import { ShieldAlert, RefreshCw, Search, FlaskConical, ChevronRight, Flame, FileDown, Loader2 } from 'lucide-react';
import { DataState } from '../../components/DataState';
import { SEVERITY_TONE } from '../../components/severity';
import { DetectionAiBriefing } from '../../components/threatintel/DetectionAiBriefing';

/**
 * Hand-authored interpretation per rule. The detections list shows what
 * fired; this map answers the question every analyst asks next: "so what
 * does it actually mean, and what should I do?" Pre-written rather than
 * LLM-improvised so the narrative is consistent across refreshes and
 * defensible if someone challenges the reasoning.
 *
 * Add a row when a new rule ships. Missing rule_ids fall through to a
 * generic severity-driven template in `narrativeFor()`, so the panel
 * never goes blank.
 */
interface RuleNarrative {
  /** What kind of activity this rule actually detects, plain English. */
  what: string;
  /** Why it matters operationally - not the textbook, the SOC read. */
  why: string;
  /** Concrete next action for the analyst seeing this on their dashboard. */
  action: string;
}
const RULE_NARRATIVES: Record<string, RuleNarrative> = {
  'cobalt-strike-c2': {
    what: 'Indicators match a tracked Cobalt Strike / generic C2 server profile aggregated from C2Intel, ThreatFox, and CriticalPathSecurity feeds.',
    why: 'These are commodity post-exploitation frameworks running on internet-reachable infrastructure right now. A beacon from your network to one of these is post-compromise traffic, not opportunistic scanning.',
    action:
      'Block the IPs at egress today and pull the last 24-72 hours of outbound flows for any host that resolved them.',
  },
  'c2-feed-ip': {
    what: 'An IP appears on a dedicated C2 tracking feed, separate from the Cobalt Strike enumeration.',
    why: 'Dedicated trackers exist because the C2 lifecycle is short. IPs rotate fast, so a current listing means the operator is staffed and the box is live this hour.',
    action: 'Push the IPs into your blocklist now; do not wait for the threat intel platform vendor to ingest them.',
  },
  'infostealer-malware': {
    what: 'An indicator is attributed to infostealer malware (Lumma, Vidar, RedLine, Stealc, RisePro, and the rest of the family).',
    why: "Infostealers grab once and leave. They do not generate ongoing C2 traffic. The signal here is that the URL, hash, or IP is currently running a stealer panel or distributing the payload, so the question isn't 'are we beaconing', it's 'has any user touched this URL in the last 72 hours'.",
    action:
      "Reverse-DNS your proxy logs against the indicators; for any hit, rotate that user's credentials and check session-cookie reuse.",
  },
  'hash-multi-source-consensus': {
    what: 'A file hash is independently confirmed as malicious across two or more upstream malware feeds (MalwareBazaar, ThreatFox, Hybrid Analysis, URLhaus).',
    why: 'This is the highest-confidence signal in the whole rule pack, even at small match counts. Single-feed flags can be vendor false alarms; cross-feed consensus is the rare overlap analysts actually trust.',
    action:
      'Treat these as immediate IR triggers, not enrichment. Pivot to your EDR with the hash and check execution events for the last 30 days.',
  },
  'phishing-brand-cluster': {
    what: 'Several phishing URLs target the same brand within the same window - campaign behaviour, not background radiation.',
    why: 'A single phishing URL is noise. A cluster targeting one brand means an operator has standing infrastructure and a current campaign. If the brand is yours, this is a takedown request; if it is a vendor your users authenticate against, awareness training matters this week.',
    action:
      "If the targeted brand is in your top-10 SSO providers, push a one-day awareness ping to users about that vendor's recent phishing pressure.",
  },
  'website-defacement': {
    what: 'A site is currently displaying defacement content (Zone-H / similar feed).',
    why: 'Defacement is the lowest-stakes detection here because it indicates past compromise of a public web property, not ongoing intrusion. Useful for asset mapping, not for IR triggers.',
    action:
      'Cross-reference the defaced hostnames against your external attack surface inventory. Low severity is correct unless one of your hostnames lands on the list.',
  },
};

function narrativeFor(d: Detection): RuleNarrative {
  const explicit = RULE_NARRATIVES[d.rule_id];
  if (explicit) return explicit;
  // Generic fallback so a freshly-added rule never blanks the panel.
  return {
    what: d.description ?? `Rule ${d.rule_name} matched ${d.match_count} indicators on the current snapshot.`,
    why:
      d.severity === 'critical' || d.severity === 'high'
        ? 'High-severity rules in this pack are tuned to fire on indicators with concrete attribution to malicious infrastructure or tooling. Treat any fire as worth a closer look.'
        : 'Medium and low rules are tuned to surface posture trends rather than individual IR triggers.',
    action:
      'Open the rule below to inspect the matching indicators, then pivot from there into the relevant IR or hardening workflow.',
  };
}

/**
 * Pick one rule fire to lead with, plus up to two supporting fires for the
 * "also firing" rail. The headline is what an analyst should *spend their
 * cognitive attention on right now* - so the ordering is severity-first,
 * then match volume, then recency. The hero deliberately can't be a low-
 * severity rule even if it dominates by volume; "defacement" rates count
 * but shouldn't ever be the top message.
 */
const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

function pickHeadlineFiring(detections: Detection[]): { hero: Detection | null; supporting: Detection[] } {
  if (detections.length === 0) return { hero: null, supporting: [] };
  const sorted = [...detections].sort((a, b) => {
    if (SEV_RANK[a.severity] !== SEV_RANK[b.severity]) return SEV_RANK[a.severity] - SEV_RANK[b.severity];
    if (a.match_count !== b.match_count) return b.match_count - a.match_count;
    const at = Date.parse(a.last_observed ?? '') || 0;
    const bt = Date.parse(b.last_observed ?? '') || 0;
    return bt - at;
  });
  const hero = sorted[0] ?? null;
  // Supporting list: skip identical rule_ids so we surface variety, not
  // five copies of the same rule that happened to fire on five clusters.
  const supporting: Detection[] = [];
  const seenRuleIds = new Set<string>([hero?.rule_id ?? '']);
  for (const d of sorted.slice(1)) {
    if (seenRuleIds.has(d.rule_id)) continue;
    seenRuleIds.add(d.rule_id);
    supporting.push(d);
    if (supporting.length >= 2) break;
  }
  return { hero, supporting };
}

type Severity = 'critical' | 'high' | 'medium' | 'low';

interface DetIndicator {
  value: string;
  kind: 'ip' | 'url' | 'domain' | 'hash';
  source: string;
  reporter?: string;
  context?: string;
  reference_url?: string;
  observed_at?: string;
}

interface Detection {
  rule_id: string;
  rule_name: string;
  severity: Severity;
  description?: string;
  match_count: number;
  group_key?: string;
  indicators: DetIndicator[];
  first_observed?: string;
  last_observed?: string;
}

interface DetectionsResponse {
  generated_at: string;
  source_total: number;
  rule_count: number;
  severity_counts: Record<string, number>;
  detections: Detection[];
  warnings: { rule_id: string; message: string }[];
}

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

const KIND_PILL: Record<DetIndicator['kind'], string> = {
  ip: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  url: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  domain: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  hash: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
};

function DetectionCard({ d }: { d: Detection }): JSX.Element {
  const [open, setOpen] = useState(false);
  return (
    <li className="surface-card">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left px-4 py-3 flex items-start gap-3"
        aria-expanded={open}
      >
        <span
          className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border shrink-0 mt-0.5 ${SEVERITY_TONE[d.severity]}`}
        >
          {d.severity}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2 flex-wrap">
            <span className="font-display font-semibold text-heading">{d.rule_name}</span>
            <span className="text-mini font-mono text-muted">×{d.match_count}</span>
          </div>
          {d.group_key && (
            <code className="text-mini font-mono text-rose-600 dark:text-rose-400 break-all">{d.group_key}</code>
          )}
          {d.description && <p className="text-meta text-muted mt-1 leading-relaxed">{d.description}</p>}
          <div className="text-mini font-mono text-muted mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
            <span className="text-muted">rule: {d.rule_id}</span>
            {d.last_observed && <span>last seen {shortRel(d.last_observed)}</span>}
            <span>
              {d.indicators.length} indicator{d.indicators.length === 1 ? '' : 's'} shown
            </span>
          </div>
        </div>
        <ChevronRight
          size={16}
          className={`shrink-0 mt-1 text-muted transition-transform ${open ? 'rotate-90' : ''}`}
        />
      </button>
      {open && (
        <ul className="border-t border-line-1 divide-y divide-line-1 dark:divide-slate-800/60">
          {d.indicators.map((it, i) => (
            <li key={`${it.source}:${it.value}:${i}`} className="px-4 py-2 flex items-center gap-3">
              <span
                className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border shrink-0 ${KIND_PILL[it.kind]}`}
              >
                {it.kind}
              </span>
              <div className="min-w-0 flex-1">
                <IocChip value={it.value} size="sm" bare truncate={56} className="min-w-0" />
                <div className="text-mini font-mono text-muted flex flex-wrap gap-x-2">
                  <span>{it.source}</span>
                  {it.context && (
                    <span className="text-muted italic truncate max-w-[44ch]" title={it.context}>
                      · {it.context}
                    </span>
                  )}
                </div>
              </div>
              <span className="shrink-0 text-mini font-mono text-muted" title={it.observed_at ?? ''}>
                {shortRel(it.observed_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export default function Detections(): JSX.Element {
  const [data, setData] = useState<DetectionsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [refreshKey, setRefreshKey] = useState(0);
  const [stixLoading, setStixLoading] = useState(false);
  const [stixBundleId, setStixBundleId] = useState<string | null>(null);
  const [stixError, setStixError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    fetch('/api/v1/detections', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => {
        if (!r.ok) throw new Error(`upstream ${r.status}`);
        return r.json() as Promise<DetectionsResponse>;
      })
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e: { name?: string; message?: string }) => {
        if (cancelled || e.name === 'AbortError') return;
        setError(e.message ?? 'failed');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey]);

  const buildStix = async () => {
    if (!data) return;
    const iocs = Array.from(new Set(data.detections.flatMap((d) => d.indicators.map((i) => i.value))));
    if (iocs.length === 0) return;
    setStixLoading(true);
    setStixBundleId(null);
    setStixError(null);
    try {
      const r = await fetch('/api/v1/intel-bundle/build', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ mode: 'iocs', input: iocs.join('\n') }),
      });
      if (!r.ok) throw new Error(r.statusText);
      const res = (await r.json()) as { bundle: { id: string } };
      setStixBundleId(res.bundle.id);
    } catch (e) {
      logCatch(e);
      setStixError(`STIX build failed: ${(e as Error).message}`);
    } finally {
      setStixLoading(false);
    }
  };

  const filtered = useMemo(() => {
    if (!data) return [] as Detection[];
    const q = query.trim().toLowerCase();
    return data.detections.filter((d) => {
      if (sevFilter.size > 0 && !sevFilter.has(d.severity)) return false;
      if (!q) return true;
      return (
        d.rule_name.toLowerCase().includes(q) ||
        d.rule_id.toLowerCase().includes(q) ||
        (d.group_key ?? '').toLowerCase().includes(q) ||
        d.indicators.some((it) => it.value.toLowerCase().includes(q))
      );
    });
  }, [data, query, sevFilter]);

  // Headline picker reads the *unfiltered* list. The narrative panel is
  // about "what should an analyst pay attention to today" regardless of
  // whether the user happens to have a sev filter applied below.
  const { hero, supporting } = useMemo(() => pickHeadlineFiring(data?.detections ?? []), [data]);

  const toggleSev = (s: Severity) =>
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<ShieldAlert size={28} />}
      title="Detections"
      description={
        <>
          A curated detection-rule pack evaluated hourly against the unified live-IOC stream. Each card is a rule that
          fired - cross-feed consensus, C2 / ransomware / infostealer tagging, and campaign clustering - with the
          indicators that triggered it.
        </>
      }
      loading={loading}
      error={error}
      onRetry={() => setRefreshKey((k) => k + 1)}
      headerExtra={
        <p className="text-xs text-muted font-mono">
          Want to write your own?{' '}
          <Link
            to="/dfir/rule-converter"
            className="text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-1"
          >
            <FlaskConical size={11} /> Detection Lab
          </Link>{' '}
          runs the same engine against the live feed in your browser.
        </p>
      }
    >
      {/* Headline read: one rule fire promoted to narrative form. Each rule
          has a hand-authored "what / why / action" map; the picker takes the
          highest-severity, highest-volume rule fire and renders that as the
          lead. Two more rules surface as a supporting rail, deduped by
          rule_id so the panel shows variety rather than five clusters of
          the same rule. */}
      {hero &&
        (() => {
          const n = narrativeFor(hero);
          const indicatorPreview = hero.indicators.slice(0, 3);
          const remaining = Math.max(0, hero.indicators.length - indicatorPreview.length);
          return (
            <section className="rounded-xl border border-rose-500/30 bg-gradient-to-br from-rose-50/40 to-transparent dark:from-rose-900/20 dark:to-transparent p-5 sm:p-6 mb-6">
              <div className="flex items-baseline gap-3 mb-4 flex-wrap">
                <Flame size={18} className="text-rose-600 dark:text-rose-400" />
                <h2 className="font-display font-bold text-lg text-heading">Today's lead: {hero.rule_name}</h2>
                <span
                  className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${SEVERITY_TONE[hero.severity]}`}
                >
                  {hero.severity}
                </span>
                <span className="text-mini font-mono text-muted">
                  {hero.match_count} matches · last seen {shortRel(hero.last_observed)}
                </span>
              </div>
              <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
                <div className="space-y-3">
                  <div>
                    <div className="text-mini font-mono uppercase tracking-[0.18em] text-muted mb-1">what fired</div>
                    <p className="text-sm text-heading leading-relaxed">{n.what}</p>
                  </div>
                  <div>
                    <div className="text-mini font-mono uppercase tracking-[0.18em] text-muted mb-1">
                      why it matters
                    </div>
                    <p className="text-sm text-body leading-relaxed">{n.why}</p>
                  </div>
                  <div className="rounded border-l-2 border-rose-500 pl-3 py-1 bg-rose-50/50 dark:bg-rose-900/10">
                    <div className="text-mini font-mono uppercase tracking-[0.18em] text-rose-700 dark:text-rose-300 mb-1">
                      do this
                    </div>
                    <p className="text-sm text-heading leading-relaxed">{n.action}</p>
                  </div>
                </div>
                <div>
                  <div className="text-mini font-mono uppercase tracking-[0.18em] text-muted mb-2">
                    triggering indicators
                  </div>
                  <ul className="space-y-1.5">
                    {indicatorPreview.map((it, i) => (
                      <li
                        key={`${it.source}:${it.value}:${i}`}
                        className="rounded border border-line-1 bg-surface-100/60 dark:bg-surface-200/40 px-2.5 py-1.5"
                      >
                        <div className="flex items-center gap-2 mb-0.5">
                          <span
                            className={`text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded border ${KIND_PILL[it.kind]}`}
                          >
                            {it.kind}
                          </span>
                          <span className="text-micro font-mono text-muted">{it.source}</span>
                        </div>
                        <IocChip value={it.value} size="sm" bare truncate={64} className="min-w-0 max-w-full" />
                      </li>
                    ))}
                  </ul>
                  {remaining > 0 && (
                    <p className="text-mini font-mono text-muted mt-2">+ {remaining} more on the rule card below</p>
                  )}
                </div>
              </div>
              {supporting.length > 0 && (
                <div className="mt-5 pt-4 border-t border-line-1/60">
                  <div className="text-mini font-mono uppercase tracking-[0.18em] text-muted mb-2">
                    also firing right now
                  </div>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {supporting.map((d) => {
                      const sn = narrativeFor(d);
                      return (
                        <div
                          key={`${d.rule_id}:${d.group_key ?? ''}`}
                          className="rounded border border-line-1 bg-surface-100/60 dark:bg-surface-200/40 px-3 py-2"
                        >
                          <div className="flex items-baseline gap-2 mb-1 flex-wrap">
                            <span
                              className={`text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded border ${SEVERITY_TONE[d.severity]}`}
                            >
                              {d.severity}
                            </span>
                            <span className="font-display font-semibold text-tool text-heading">{d.rule_name}</span>
                            <span className="text-micro font-mono text-muted">×{d.match_count}</span>
                          </div>
                          <p className="text-meta text-muted leading-relaxed">{sn.what}</p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </section>
          );
        })()}

      <DetectionAiBriefing
        surface="Detection Rules"
        source="detections"
        label="rule fires"
        dayKey={data?.generated_at?.slice(0, 10)}
        items={filtered.map((d) => ({
          title: d.rule_name,
          body: `${d.severity} · ${d.match_count} matches · ${d.description ?? narrativeFor(d).what}`,
          source: d.rule_id,
        }))}
      />

      <section className="surface-card p-4 mb-4">
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter by rule, group key, or indicator…"
              className="w-full pl-9 pr-4 py-2 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
              aria-label="Filter detections"
            />
          </div>
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border border-line-1 hover:border-rose-500/40"
          >
            <RefreshCw size={12} /> refresh
          </button>
          {stixBundleId ? (
            <a
              href={`/api/v1/intel-bundle/${stixBundleId}/export.stix.json`}
              download={`${stixBundleId}.stix.json`}
              className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/10 transition-colors"
            >
              <FileDown size={12} /> STIX
            </a>
          ) : (
            <button
              type="button"
              onClick={() => void buildStix()}
              disabled={stixLoading || !data}
              className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 rounded border border-line-1 hover:border-rose-500/40 disabled:opacity-40"
            >
              {stixLoading ? <Loader2 size={12} className="animate-spin" /> : <FileDown size={12} />}
              {stixLoading ? 'building…' : 'STIX'}
            </button>
          )}
          {stixError && (
            <span role="alert" className="text-mini font-mono text-rose-700 dark:text-rose-300">
              {stixError}
            </span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-1.5 mt-3">
          <span className="text-mini font-mono text-muted mr-1">severity:</span>
          {SEV_ORDER.map((s) => {
            const active = sevFilter.has(s);
            const n = data?.severity_counts[s] ?? 0;
            return (
              <button
                key={s}
                type="button"
                onClick={() => toggleSev(s)}
                className={`text-mini font-mono px-2 py-1 rounded border ${
                  active ? SEVERITY_TONE[s] : 'border-slate-300 dark:border-line-1 text-slate-500'
                }`}
              >
                {s} <span className="opacity-70">· {n}</span>
              </button>
            );
          })}
          {sevFilter.size > 0 && (
            <button
              type="button"
              onClick={() => setSevFilter(new Set())}
              className="text-mini font-mono text-rose-600 dark:text-rose-400 hover:underline ml-2"
            >
              clear
            </button>
          )}
        </div>
        {data && (
          <p className="text-mini font-mono text-muted mt-3">
            Showing <span className="text-body">{filtered.length}</span> of{' '}
            <span className="text-body">{data.detections.length}</span> detections ·{' '}
            <span className="text-body">{data.rule_count}</span> rules ·{' '}
            <span className="text-body">{data.source_total}</span> indicators evaluated · snapshot{' '}
            <span className="text-body">{shortRel(data.generated_at)}</span>
          </p>
        )}
      </section>

      <DataState
        loading={loading}
        error={error}
        empty={filtered.length === 0}
        emptyLabel={
          query || sevFilter.size > 0
            ? 'No detections match the current filter.'
            : 'No rules fired on the current snapshot - the feeds are quiet or the rule pack is conservative.'
        }
        onRetry={() => setRefreshKey((k) => k + 1)}
        rows={6}
      >
        <ul className="space-y-2">
          {filtered.map((d) => (
            <DetectionCard key={`${d.rule_id}:${d.group_key ?? ''}`} d={d} />
          ))}
        </ul>
      </DataState>
    </DataPageLayout>
  );
}
