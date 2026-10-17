import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, Crosshair, Shield, Bug, Hash, Copy, Check, Layers, RefreshCw, ExternalLink } from 'lucide-react';
import { DataState } from '../../components/DataState';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { errMessage } from '../../lib/log';

/** Build a deep link for an entity label so the analyst can pivot
 *  straight into the platform / MITRE rather than re-typing the ID. */
function entityHref(kind: PulseEntity['kind'], label: string): { href: string; external: boolean } | null {
  switch (kind) {
    case 'cve':
      return { href: `/dfir/cve?id=${encodeURIComponent(label)}`, external: false };
    case 'technique':
      // MITRE uses T1234/001 not T1234.001 in URL paths.
      return {
        href: `https://attack.mitre.org/techniques/${label.replace('.', '/')}`,
        external: true,
      };
    case 'actor':
      // The slug already matches the ActorDetail route param.
      return { href: `/threatintel/actors/${encodeURIComponent(label)}`, external: false };
    case 'malware':
      return null;
  }
}

interface PulseEntity {
  label: string;
  kind: 'cve' | 'actor' | 'technique' | 'malware';
  source_count: number;
  sources: string[];
}

interface PulseResponse {
  generated_at: string;
  entities: PulseEntity[];
}

const KIND_ICONS = {
  cve: Hash,
  actor: Shield,
  technique: Crosshair,
  malware: Bug,
} as const;

const KIND_LABEL = {
  cve: 'CVE',
  actor: 'Actor',
  technique: 'Technique',
  malware: 'Malware',
} as const;

/**
 * Per-kind pill colour. Sourced from Tailwind defaults so dark mode works
 * without any custom token mapping - every class lists an explicit
 * `dark:` variant.
 */
const KIND_COLOR = {
  cve: 'border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-400',
  actor: 'border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/30 text-rose-700 dark:text-rose-400',
  technique: 'border-rose-300 dark:border-rose-500/40 bg-rose-50 dark:bg-rose-950/30 text-rose-700 dark:text-rose-400',
  malware:
    'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-400',
} as const;

const SURFACE_LABEL: Record<string, string> = {
  writeups: 'CTI Writeups',
  cybercrime: 'Cyber Crime',
};

function surfaceLabel(s: string): string {
  if (s.startsWith('reddit:')) return `Reddit r/${s.slice(7)}`;
  if (s.startsWith('bsky:')) return `Bluesky @${s.slice(5)}`;
  if (s.startsWith('mastodon:')) return `Mastodon @${s.slice(9)}`;
  if (s.startsWith('tg:')) return `Telegram @${s.slice(3)}`;
  if (s.startsWith('x:')) return `X @${s.slice(2)}`;
  return SURFACE_LABEL[s] ?? s;
}

/**
 * Coarse platform-type taxonomy: which surface family does each source
 * identifier belong to? An entity that shows up across multiple distinct
 * platform types is a stronger signal than the same count of mentions all
 * inside one platform (e.g. 3 Reddit subs == one community echoing itself;
 * 1 Reddit + 1 Telegram + 1 writeup == genuine cross-platform corroboration).
 */
function platformType(s: string): string {
  if (s.startsWith('reddit:')) return 'reddit';
  if (s.startsWith('bsky:')) return 'bluesky';
  if (s.startsWith('mastodon:')) return 'mastodon';
  if (s.startsWith('tg:')) return 'telegram';
  if (s.startsWith('x:')) return 'x';
  return s; // 'writeups', 'cybercrime' etc are already platform-type level.
}

export default function ThreatPulse(): JSX.Element {
  const [data, setData] = useState<PulseResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [kindFilter, setKindFilter] = useState<string | null>(null);
  const [minSources, setMinSources] = useState(2);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const r = await fetch('/api/v1/threat-pulse', {
          signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const j = (await r.json()) as PulseResponse;
        if (!cancelled) setData(j);
      } catch (e) {
        console.error('ThreatPulse failed:', errMessage(e));
        if (!cancelled && (e as { name?: string }).name !== 'AbortError') setError((e as Error).message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!data) return [];
    return data.entities
      .filter((e) => e.source_count >= minSources)
      .filter((e) => !kindFilter || e.kind === kindFilter)
      .sort((a, b) => b.source_count - a.source_count);
  }, [data, minSources, kindFilter]);

  const kindCounts = useMemo(() => {
    if (!data) return {};
    const counts: Record<string, number> = {};
    for (const e of data.entities) {
      counts[e.kind] = (counts[e.kind] ?? 0) + 1;
    }
    return counts;
  }, [data]);

  // Highest threshold that still yields at least one entity under the current
  // kind filter - used to power the "lower the threshold for me" recovery
  // button in the empty state instead of dead-ending the analyst on a
  // "try lowering it yourself" instruction.
  const recovery = useMemo(() => {
    if (!data) return null;
    const eligible = kindFilter ? data.entities.filter((e) => e.kind === kindFilter) : data.entities;
    if (eligible.length === 0) return null;
    const bestThreshold = Math.max(...eligible.map((e) => e.source_count));
    if (bestThreshold >= minSources) return null;
    const matchCount = eligible.filter((e) => e.source_count >= bestThreshold).length;
    return { threshold: bestThreshold, count: matchCount };
  }, [data, kindFilter, minSources]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Activity size={28} className="text-rose-600 dark:text-rose-400" />}
      title="Cross-source threat pulse"
      description={
        <>
          Entities mentioned across multiple independent intelligence surfaces simultaneously. Higher cross-source count
          = higher confidence that this is a real, active threat. Scans Reddit (16 subs), Bluesky (16 researchers),
          Mastodon (infosec.exchange - 8 accounts), Telegram (curated cybersec channels), X (cookie-auth firehose for 5
          CTI handles + TweetFeed × fxtwitter), CTI writeups (35+ blogs), and cybercrime news in real time. IOC feeds
          include Phishing.Database, ViriBack C2, Threatview IP/Domain blocklists, and 12+ other live threat sources.
        </>
      }
      headerExtra={
        <button
          type="button"
          onClick={() => setRefreshKey((k) => k + 1)}
          className="text-mini font-mono px-2.5 py-1.5 rounded border border-line-2 hover:border-rose-500/40 inline-flex items-center gap-1 mt-1"
          aria-label="Refresh threat pulse"
        >
          <RefreshCw size={11} /> refresh
        </button>
      }
      loading={loading}
      error={error}
      empty={!loading && !error && data !== null && data.entities.length === 0}
      emptyMessage="No entities found."
    >
      {/* Kind summary - at-a-glance counts before the filter row.
          Computed off the entire entities array so the numbers reflect the
          full snapshot regardless of active filter / threshold. */}
      {data && data.entities.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          {(['cve', 'actor', 'technique', 'malware'] as const).map((k) => {
            const Icon = KIND_ICONS[k];
            const n = kindCounts[k] ?? 0;
            return (
              <button
                key={k}
                type="button"
                onClick={() => setKindFilter(kindFilter === k ? null : k)}
                aria-pressed={kindFilter === k}
                className={`flex items-center gap-3 rounded-xl border p-3 text-left transition-colors ${
                  kindFilter === k
                    ? 'border-rose-500/60 bg-rose-500/10'
                    : 'border-line-1 bg-white dark:bg-surface-200 hover:border-rose-500/40'
                }`}
              >
                <Icon size={18} className="shrink-0 text-rose-600 dark:text-rose-400" />
                <div className="min-w-0">
                  <div className="text-micro font-mono uppercase tracking-wider text-muted">{KIND_LABEL[k]}s</div>
                  <div className="text-xl font-display font-bold tabular-nums">{n.toLocaleString()}</div>
                </div>
              </button>
            );
          })}
        </div>
      )}

      {data && data.entities.length > 0 && (
        <>
          <PostAnalysisButton
            title="Threat Pulse Digest"
            description="AI-powered threat analysis of the current feed."
            source="threatpulse"
          />
          <AiSummaryCard
            surface="Threat Pulse"
            items={data.entities.slice(0, 30).map((e) => ({
              title: `${e.label} (${e.kind}) - seen in ${e.source_count} source${e.source_count > 1 ? 's' : ''}`,
              body: `Sources: ${e.sources.join(', ')}`,
            }))}
            requireAdmin={false}
          />
        </>
      )}

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-4 mb-6">
        <div className="flex flex-wrap gap-2">
          {[
            { id: null, label: 'All' },
            { id: 'cve', label: 'CVEs' },
            { id: 'actor', label: 'Actors' },
            { id: 'technique', label: 'Techniques' },
            { id: 'malware', label: 'Malware' },
          ].map((f) => (
            <button
              key={f.label}
              type="button"
              onClick={() => setKindFilter(f.id)}
              className={`px-3 py-1 text-xs font-mono uppercase tracking-wider border transition-colors ${
                kindFilter === f.id
                  ? 'bg-rose-50 dark:bg-rose-950/30 text-rose-700 dark:text-rose-300 border-rose-300 dark:border-rose-500/40'
                  : 'bg-white dark:bg-surface-200 text-muted border-line-1 hover:border-rose-500/40'
              }`}
            >
              {f.label}
              {f.id && kindCounts[f.id] !== undefined && <span className="ml-1 opacity-60">({kindCounts[f.id]})</span>}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 ml-auto">
          <label htmlFor="pulse-min-sources" className="text-micro font-mono uppercase tracking-wider text-muted">
            Min. sources
          </label>
          <select
            id="pulse-min-sources"
            value={minSources}
            onChange={(e) => setMinSources(Number(e.target.value))}
            className="border border-line-1 bg-surface-100 px-2 py-1 text-xs font-mono text-heading focus:outline-none focus:border-rose-500/60"
          >
            {[1, 2, 3, 4].map((n) => (
              <option key={n} value={n}>
                {n}+
              </option>
            ))}
          </select>
        </div>
      </div>

      {data && filtered.length === 0 && (
        <div className="border border-dashed border-line-2 p-10 text-center rounded-xl">
          <Activity size={32} className="mx-auto mb-3 text-muted" />
          <p className="font-mono text-sm text-muted">
            No entities at ≥{minSources} source{minSources > 1 ? 's' : ''}
            {kindFilter ? ` in ${KIND_LABEL[kindFilter as keyof typeof KIND_LABEL]}` : ''}.
          </p>
          {data.entities.length > 0 && (
            <p className="text-xs font-mono text-muted mt-1.5">
              {data.entities.length} total entit{data.entities.length === 1 ? 'y' : 'ies'} across all surfaces.
            </p>
          )}
          {(recovery || kindFilter) && (
            <div className="mt-5 flex flex-wrap gap-2 justify-center">
              {recovery && (
                <button
                  type="button"
                  onClick={() => setMinSources(recovery.threshold)}
                  className="inline-flex items-center gap-1.5 border border-rose-500 bg-rose-500/10 px-3 py-1.5 font-mono text-mini uppercase tracking-wider text-rose-700 dark:text-rose-400 transition-colors hover:bg-rose-500 hover:text-white rounded"
                >
                  Show {recovery.count} at ≥{recovery.threshold} source{recovery.threshold > 1 ? 's' : ''}
                </button>
              )}
              {kindFilter && (
                <button
                  type="button"
                  onClick={() => setKindFilter(null)}
                  className="inline-flex items-center gap-1.5 border border-line-1 px-3 py-1.5 font-mono text-mini uppercase tracking-wider text-muted transition-colors hover:border-line-3 hover:text-heading dark:hover:text-slate-100 rounded"
                >
                  Clear {KIND_LABEL[kindFilter as keyof typeof KIND_LABEL]} filter
                </button>
              )}
            </div>
          )}
        </div>
      )}

      <DataState loading={loading} error={error} rows={8}>
        {filtered.length > 0 && (
          <div className="space-y-2">
            {filtered.map((entity) => {
              const Icon = KIND_ICONS[entity.kind];
              const platformCount = new Set(entity.sources.map(platformType)).size;
              const isCrossPlatform = platformCount >= 2;
              return (
                <div
                  key={`${entity.kind}:${entity.label}`}
                  className="border border-line-1 bg-surface-100 p-4 hover:border-rose-500/40 dark:hover:border-rose-400/40 transition-colors rounded-xl"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <Icon size={18} className="shrink-0 text-rose-600 dark:text-rose-400" />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-baseline gap-2 flex-wrap">
                          {(() => {
                            const link = entityHref(entity.kind, entity.label);
                            if (!link) {
                              return (
                                <span className="font-display font-semibold text-base text-heading break-all">
                                  {entity.label}
                                </span>
                              );
                            }
                            const className =
                              'font-display font-semibold text-base text-heading break-all hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-1';
                            return link.external ? (
                              <a
                                href={sanitizeUrl(link.href)}
                                target="_blank"
                                rel="noopener noreferrer"
                                className={className}
                              >
                                {entity.label}
                                <ExternalLink size={11} className="shrink-0 opacity-70" />
                              </a>
                            ) : (
                              <Link to={link.href} className={className}>
                                {entity.label}
                              </Link>
                            );
                          })()}
                          <span
                            className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${KIND_COLOR[entity.kind]}`}
                          >
                            {KIND_LABEL[entity.kind]}
                          </span>
                          {/* Platform-diversity badge - same source_count means
                            different things when all from one platform vs
                            spread across many. The badge separates the two
                            without needing more screen space than a pill. */}
                          {isCrossPlatform ? (
                            <span
                              className="inline-flex items-center gap-1 text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                              title={`${platformCount} distinct platform types - cross-platform corroboration, stronger signal than same-platform mentions`}
                            >
                              <Layers size={9} aria-hidden="true" />
                              {platformCount} platforms
                            </span>
                          ) : entity.source_count > 1 ? (
                            <span
                              className="inline-flex items-center gap-1 text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-line-2 text-muted"
                              title="All mentions on a single platform - same-platform corroboration, weaker signal than cross-platform"
                            >
                              same-platform
                            </span>
                          ) : null}
                          <CopyEntityButton entity={entity} />
                        </div>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {entity.sources.map((s) => (
                            <span
                              key={s}
                              className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-1 bg-surface-200 text-muted"
                            >
                              {surfaceLabel(s)}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                    <div
                      className={`shrink-0 px-3 py-1.5 text-center rounded ${
                        entity.source_count >= 3
                          ? 'bg-rose-500/15 text-rose-700 dark:text-rose-400'
                          : entity.source_count === 2
                            ? 'bg-amber-500/15 text-amber-700 dark:text-amber-400'
                            : 'bg-rose-500/10 text-rose-700 dark:text-rose-400'
                      }`}
                    >
                      <span className="text-lg font-bold">{entity.source_count}</span>
                      <p className="text-micro uppercase tracking-wider font-mono">sources</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </DataState>

      {data && (
        <p className="mt-6 text-mini font-mono text-muted text-center">
          Generated {data.generated_at.slice(0, 16).replace('T', ' ')} UTC · {data.entities.length} total entities
        </p>
      )}
    </DataPageLayout>
  );
}

/**
 * Inline copy-to-clipboard for an entity. Formats as
 *   "<kind>: <label> [<sources>]"
 * so the analyst can paste straight into a ticket / Slack with full
 * context. Uses the standard transient-check feedback pattern.
 */
function CopyEntityButton({ entity }: { entity: PulseEntity }): JSX.Element {
  const [done, setDone] = useState(false);
  const onClick = async () => {
    const line = `${KIND_LABEL[entity.kind]}: ${entity.label} [${entity.sources.map(surfaceLabel).join(', ')}]`;
    try {
      await navigator.clipboard.writeText(line);
      setDone(true);
      setTimeout(() => setDone(false), 1200);
    } catch (_catchErr) {
      console.error('CopyEntityButton failed:', errMessage(_catchErr));
      /* clipboard blocked - silent */
    }
  };
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={`Copy ${entity.label} with sources`}
      title="Copy entity + sources for tickets / Slack"
      className="inline-flex items-center justify-center min-h-[44px] min-w-[44px] sm:min-h-[22px] sm:min-w-[22px] rounded text-muted hover:text-rose-500 transition-colors"
    >
      {done ? <Check size={12} /> : <Copy size={12} />}
    </button>
  );
}
