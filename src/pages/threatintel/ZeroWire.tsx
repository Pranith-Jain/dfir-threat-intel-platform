import { useMemo, useState } from 'react';
import { ChevronDown, ExternalLink, Rss, Search, ShieldAlert, Wifi } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';
import { sanitizeUrl } from '../../lib/sanitize-url';

/**
 * Replication of the two Cloudflare Radar Zero Wire JSON feeds:
 *   /zero-wire/feed       — analyst briefings (13 items, full text + action steps)
 *   /zero-wire/cves/feed  — the 100 most recently published CVEs with CVSS
 *
 * REA's browser scenario on https://radar.cloudflare.com/zero-wire confirmed
 * the page is server-rendered and advertises JSON Feed 1.1 variants of both.
 * scripts/sync-zero-wire.mjs mirrors those feeds verbatim into
 * public/data/zero-wire/index.json; this page is the reader.
 */

interface FeedLink {
  label?: string;
  text?: string;
  url: string;
}

interface BriefingExt {
  about?: string;
  slug?: string;
  main_action?: string;
  last_reviewed?: string;
  summary?: string;
  cves?: string[];
  recommended_action_steps?: Array<{ text: string; links?: FeedLink[] }>;
  product_coverage?: string;
  product_mitigations?: {
    waf?: { rules?: Array<{ name: string; plans?: string[]; cves?: string[]; default_action?: string }> };
  };
  assessment_prompt?: string;
  updates?: Array<{ date?: string; text?: string; links?: FeedLink[] }>;
  sources?: Array<{ title?: string; description?: string; links?: FeedLink[] }>;
  service_status?: string;
}

interface ZeroItem {
  id: string;
  url: string;
  title: string;
  summary: string;
  contentText: string;
  published: string | null;
  modified: string | null;
  tags: string[];
  image: string | null;
  ext: BriefingExt;
  cveId?: string;
  severity?: string;
  score?: number | null;
  cvssVersion?: string;
}

interface ZeroIndex {
  generatedAt: string;
  upstream: {
    site: string;
    cvesPage: string;
    briefingsFeed: string;
    cvesFeed: string;
    briefingsRss: string;
    cvesRss: string;
    schema: string;
  };
  feedTitles: { briefings: string; cves: string };
  stats: { briefings: number; cves: number; bySeverity: Record<string, number> };
  briefings: ZeroItem[];
  cves: ZeroItem[];
}

const SEVERITY_TONE: Record<string, string> = {
  CRITICAL: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  HIGH: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  MEDIUM: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  LOW: 'border-slate-400/40 bg-slate-400/10 text-slate-600 dark:text-slate-300',
  UNKNOWN: 'border-line-2 text-muted',
};

const ACTION_TONE: Record<string, string> = {
  patch: 'bg-rose-500/10 text-rose-700 dark:text-rose-300',
  monitor: 'bg-sky-500/10 text-sky-700 dark:text-sky-300',
  investigate: 'bg-amber-500/10 text-amber-700 dark:text-amber-300',
};

function day(iso?: string | null): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' }).format(
    t
  );
}

function ExtLink({ href, children }: { href: string; children: React.ReactNode }): JSX.Element {
  const url = sanitizeUrl(href);
  return (
    <a href={url || '#'} target="_blank" rel="noopener noreferrer" className="text-accent-text hover:underline">
      {children} <ExternalLink size={11} className="inline align-baseline" aria-hidden="true" />
    </a>
  );
}

function LinkList({ links }: { links?: FeedLink[] }): JSX.Element | null {
  if (!links?.length) return null;
  return (
    <ul className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs">
      {links.map((l, i) => (
        <li key={`${l.url}-${i}`}>
          <ExtLink href={l.url}>{l.label || l.text || l.url}</ExtLink>
        </li>
      ))}
    </ul>
  );
}

/** Full text of a JSON Feed item: already-structured prose, rendered as text. */
function ContentText({ text }: { text: string }): JSX.Element | null {
  if (!text) return null;
  return (
    <div className="mt-3 space-y-2 border-t border-line-1 pt-3">
      {text.split(/\n{2,}/).map((para, i) => (
        <div key={i}>
          {para.split('\n').map((line, j) => (
            <p key={j} className="whitespace-pre-wrap text-sm leading-relaxed text-body">
              {line}
            </p>
          ))}
        </div>
      ))}
    </div>
  );
}

function BriefingCard({ item }: { item: ZeroItem }): JSX.Element {
  const [open, setOpen] = useState(false);
  const ext = item.ext ?? {};
  const tags = item.tags.filter((t) => !/^(critical|high|medium|low)$/i.test(t));
  return (
    <article className="rounded-lg border border-line-1 bg-surface-100 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
            <span>Last reviewed {day(ext.last_reviewed) || day(item.modified) || day(item.published)}</span>
            {ext.main_action && (
              <span
                className={`rounded px-1.5 py-0.5 font-mono uppercase ${ACTION_TONE[ext.main_action] ?? 'bg-wash text-muted'}`}
              >
                {ext.main_action}
              </span>
            )}
          </div>
          <h3 className="mt-1 text-base font-semibold text-heading">
            <a
              href={sanitizeUrl(item.url) || '#'}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-accent-text hover:underline"
            >
              {item.title}
            </a>
          </h3>
        </div>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          className="inline-flex items-center gap-1 rounded border border-line-1 px-2 py-1 font-mono text-xs text-muted hover:bg-wash hover:text-heading"
        >
          {open ? 'Less' : 'Details'}
          <ChevronDown
            size={13}
            className={open ? 'rotate-180 transition-transform' : 'transition-transform'}
            aria-hidden="true"
          />
        </button>
      </div>

      <p className="mt-2 text-sm leading-relaxed text-body">{ext.summary || item.summary}</p>

      {(ext.cves?.length ?? 0) > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          {ext.cves?.map((cve) => (
            <a
              key={cve}
              href={sanitizeUrl(`https://radar.cloudflare.com/zero-wire/cves/${encodeURIComponent(cve)}`) || '#'}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded border border-line-2 bg-wash px-1.5 py-0.5 font-mono text-[11px] text-accent-text hover:underline"
            >
              {cve}
            </a>
          ))}
        </div>
      )}

      {tags.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {tags.map((tag) => (
            <span key={tag} className="rounded border border-line-2 px-1.5 py-0.5 font-mono text-[11px] text-muted">
              {tag}
            </span>
          ))}
        </div>
      )}

      {open && (
        <div className="mt-3 border-t border-line-1 pt-3">
          <ContentText text={item.contentText} />

          {!!ext.updates?.length && (
            <section className="mt-4">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">Updates</h4>
              <ul className="mt-2 space-y-2">
                {ext.updates.map((u, i) => (
                  <li key={i} className="text-sm text-body">
                    <span className="font-mono text-xs text-muted">{day(u.date)} </span>
                    {u.text}
                    <LinkList links={u.links} />
                  </li>
                ))}
              </ul>
            </section>
          )}

          {!!ext.recommended_action_steps?.length && (
            <section className="mt-4">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">Recommended actions</h4>
              <ol className="mt-2 list-decimal space-y-3 pl-5 text-sm text-body">
                {ext.recommended_action_steps.map((s, i) => (
                  <li key={i}>
                    {s.text}
                    <LinkList links={s.links} />
                  </li>
                ))}
              </ol>
            </section>
          )}

          {ext.product_coverage && (
            <section className="mt-4">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">Cloudflare product coverage</h4>
              <p className="mt-1 whitespace-pre-wrap text-sm text-body">{ext.product_coverage}</p>
            </section>
          )}

          {!!ext.product_mitigations?.waf?.rules?.length && (
            <section className="mt-4">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">WAF rules</h4>
              <ul className="mt-2 space-y-1 text-sm text-body">
                {ext.product_mitigations.waf.rules.map((r, i) => (
                  <li key={i}>
                    <span className="font-mono text-xs">{r.default_action?.toUpperCase()}</span> — {r.name}{' '}
                    <span className="text-muted">({(r.plans ?? []).join(', ')})</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {ext.assessment_prompt && (
            <section className="mt-4">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">Assessment prompt</h4>
              <p className="mt-1 whitespace-pre-wrap text-sm text-body">{ext.assessment_prompt}</p>
            </section>
          )}

          {!!ext.sources?.length && (
            <section className="mt-4">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">Sources</h4>
              <ul className="mt-2 space-y-2">
                {ext.sources.map((s, i) => (
                  <li key={i} className="text-sm text-body">
                    <span className="font-semibold text-heading">{s.title}</span>
                    {s.description && <span className="text-muted"> — {s.description}</span>}
                    <LinkList links={s.links} />
                  </li>
                ))}
              </ul>
            </section>
          )}

          {ext.service_status && (
            <section className="mt-4 rounded border border-line-1 bg-wash p-3">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">Cloudflare service status</h4>
              <p className="mt-1 whitespace-pre-wrap text-sm text-body">{ext.service_status}</p>
            </section>
          )}
        </div>
      )}
    </article>
  );
}

function CveRow({ item }: { item: ZeroItem }): JSX.Element {
  const [open, setOpen] = useState(false);
  const tone = SEVERITY_TONE[item.severity ?? 'UNKNOWN'] ?? SEVERITY_TONE.UNKNOWN;
  return (
    <article className="rounded-lg border border-line-1 bg-surface-100 p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <a
              href={sanitizeUrl(item.url) || '#'}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-sm font-semibold text-accent-text hover:underline"
            >
              {item.cveId || item.title}
            </a>
            <span className={`rounded border px-1.5 py-0.5 font-mono text-[11px] uppercase ${tone}`}>
              {item.severity}
            </span>
            {item.score != null && (
              <span className="font-mono text-xs text-muted">
                CVSS {item.cvssVersion || '—'} · {item.score}
              </span>
            )}
            <span className="font-mono text-xs text-muted">{day(item.published)}</span>
          </div>
          {item.title !== item.cveId && <p className="mt-1 text-sm text-heading">{item.title}</p>}
          <p className="mt-1 line-clamp-3 text-sm text-body">{item.summary}</p>
        </div>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          className="inline-flex items-center gap-1 rounded border border-line-1 px-2 py-1 font-mono text-xs text-muted hover:bg-wash hover:text-heading"
        >
          {open ? 'Less' : 'More'}
          <ChevronDown
            size={13}
            className={open ? 'rotate-180 transition-transform' : 'transition-transform'}
            aria-hidden="true"
          />
        </button>
      </div>
      {open && <ContentText text={item.contentText} />}
    </article>
  );
}

export default function ZeroWire({ bare = false }: { bare?: boolean }): JSX.Element {
  const data = useDataFetch<ZeroIndex>({ url: '/data/zero-wire/index.json', ttl: 600_000 });
  const [view, setView] = useState<'briefings' | 'cves'>('briefings');
  const [query, setQuery] = useState('');
  const [tag, setTag] = useState('all');
  const [severity, setSeverity] = useState('all');

  const tags = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const b of data.data?.briefings ?? []) {
      for (const t of b.tags) if (!/^(critical|high|medium|low)$/i.test(t)) counts[t] = (counts[t] ?? 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }, [data.data]);

  const briefings = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (data.data?.briefings ?? []).filter((b) => {
      if (tag !== 'all' && !b.tags.includes(tag)) return false;
      if (!needle) return true;
      return `${b.title} ${b.summary} ${b.contentText} ${(b.ext?.cves ?? []).join(' ')}`.toLowerCase().includes(needle);
    });
  }, [data.data, query, tag]);

  const cves = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (data.data?.cves ?? []).filter((c) => {
      if (severity !== 'all' && c.severity !== severity) return false;
      if (!needle) return true;
      return `${c.cveId ?? ''} ${c.title} ${c.summary}`.toLowerCase().includes(needle);
    });
  }, [data.data, query, severity]);

  const body = (
    <>
      <div
        className="mb-4 flex flex-wrap items-center gap-2 border-b border-line-1 pb-2"
        role="tablist"
        aria-label="Zero Wire feeds"
      >
        {(
          [
            ['briefings', `Briefings (${data.data?.stats?.briefings ?? 0})`],
            ['cves', `CVEs (${data.data?.stats?.cves ?? 0})`],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={view === id}
            onClick={() => {
              setView(id);
              setQuery('');
            }}
            className={`border-b-2 px-3 py-2 font-mono text-sm font-semibold transition-colors ${
              view === id
                ? 'border-sky-500 text-sky-600 dark:text-sky-300'
                : 'border-transparent text-muted hover:text-heading'
            }`}
          >
            {label}
          </button>
        ))}
        <a
          href={
            sanitizeUrl(view === 'briefings' ? data.data?.upstream.briefingsRss : data.data?.upstream.cvesRss) || '#'
          }
          target="_blank"
          rel="noopener noreferrer"
          className="ml-auto inline-flex items-center gap-1 font-mono text-xs text-muted hover:text-accent-text"
        >
          <Rss size={13} aria-hidden="true" /> RSS feed
        </a>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <label className="relative flex-1 min-w-[220px]">
          <Search size={15} className="absolute left-2.5 top-2.5 text-muted" aria-hidden="true" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={view === 'briefings' ? 'Search briefings, CVEs, actions…' : 'Search CVE ID or summary…'}
            aria-label="Search feed"
            className="w-full rounded border border-line-input bg-input-200 py-2 pl-8 pr-3 text-sm text-heading placeholder:text-muted"
          />
        </label>
        {view === 'briefings' ? (
          <select
            value={tag}
            onChange={(e) => setTag(e.target.value)}
            aria-label="Filter by tag"
            className="rounded border border-line-input bg-input-200 px-2 py-2 text-sm text-heading"
          >
            <option value="all">All tags</option>
            {tags.map(([t, n]) => (
              <option key={t} value={t}>
                {t} ({n})
              </option>
            ))}
          </select>
        ) : (
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            aria-label="Filter by severity"
            className="rounded border border-line-input bg-input-200 px-2 py-2 text-sm text-heading"
          >
            <option value="all">All severities</option>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
              <option key={s} value={s}>
                {s} ({data.data?.stats?.bySeverity?.[s] ?? 0})
              </option>
            ))}
          </select>
        )}
      </div>

      {view === 'briefings' ? (
        <section aria-label="Zero Wire briefings" className="space-y-3">
          <p className="text-xs font-mono text-muted">
            {briefings.length} of {data.data?.stats?.briefings ?? 0} briefings · mirrored{' '}
            {relativeAgo(data.data?.generatedAt)} ·{' '}
            <ExtLink href={data.data?.upstream.site ?? 'https://radar.cloudflare.com/zero-wire'}>upstream</ExtLink>
          </p>
          {briefings.map((b) => (
            <BriefingCard key={b.id} item={b} />
          ))}
          {data.data && briefings.length === 0 && (
            <p className="py-8 text-center text-sm text-muted">No briefings match these filters.</p>
          )}
        </section>
      ) : (
        <section aria-label="Zero Wire CVEs" className="space-y-2">
          <p className="text-xs font-mono text-muted">
            {cves.length} of {data.data?.stats?.cves ?? 0} recently published CVEs · CVSS scores are upstream values ·{' '}
            <ExtLink href={data.data?.upstream.cvesPage ?? 'https://radar.cloudflare.com/zero-wire/cves'}>
              upstream
            </ExtLink>
          </p>
          {cves.map((c) => (
            <CveRow key={c.id} item={c} />
          ))}
          {data.data && cves.length === 0 && (
            <p className="py-8 text-center text-sm text-muted">No CVEs match these filters.</p>
          )}
        </section>
      )}
    </>
  );

  if (bare) return body;

  return (
    <DataPageLayout
      backTo="/threatintel/cves/cves"
      icon={<Wifi size={28} />}
      title="Zero Wire — Cloudflare Radar"
      description="Replication of Cloudflare Radar's two Zero Wire JSON feeds: analyst security briefings with patch actions and WAF coverage, plus the 100 most recently published CVEs with CVSS severity."
      loading={data.loading}
      error={data.error}
      onRetry={data.refetch}
      maxWidthClass="max-w-6xl"
    >
      <p className="mb-4 flex items-center gap-2 text-xs text-muted">
        <ShieldAlert size={14} aria-hidden="true" />
        Data mirrored from radar.cloudflare.com/zero-wire · {day(data.data?.generatedAt)}
      </p>
      {body}
    </DataPageLayout>
  );
}
