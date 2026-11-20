import { useMemo, useState, type ReactNode } from 'react';
import { ChevronDown, Rss, Search, ShieldAlert, Wifi } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';
import { Badge, Empty, OutLink, Section } from './cyberview/shared-ui';
import { asArray, fmtDayFull, matches, text, topCounts } from './cyberview/shared-utils';

// Reader for the mirrored Cloudflare Radar Zero Wire feeds synced by scripts/sync-zero-wire.mjs.
// prettier-ignore
interface FeedLink { label?: string; text?: string; url: string }
// prettier-ignore
interface BriefingExt {
  main_action?: string; last_reviewed?: string; summary?: string; cves?: string[];
  recommended_action_steps?: Array<{ text: string; links?: FeedLink[] }>;
  product_coverage?: string;
  product_mitigations?: { waf?: { rules?: Array<{ name: string; plans?: string[]; cves?: string[]; default_action?: string }> } };
  assessment_prompt?: string;
  updates?: Array<{ date?: string; text?: string; links?: FeedLink[] }>;
  sources?: Array<{ title?: string; description?: string; links?: FeedLink[] }>;
  service_status?: string;
}
// prettier-ignore
interface ZeroItem {
  id: string; url: string; title: string; summary: string; contentText: string;
  published: string | null; modified: string | null; tags: string[]; ext: BriefingExt;
  cveId?: string; severity?: string; score?: number | null; cvssVersion?: string;
}
// prettier-ignore
interface ZeroIndex {
  generatedAt: string;
  upstream: { site: string; cvesPage: string; briefingsRss: string; cvesRss: string };
  stats: { briefings: number; cves: number; bySeverity: Record<string, number> };
  briefings: ZeroItem[]; cves: ZeroItem[];
}

const SEVERITY_TONE: Record<string, string> = { CRITICAL: 'high', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };
const ACTION_TONE: Record<string, string> = { patch: 'high', monitor: 'low', investigate: 'medium' };

// prettier-ignore
function LinkList({ links }: { links?: FeedLink[] }): JSX.Element | null {
  const list = asArray(links);
  if (!list.length) return null;
  return (
    <ul className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs">
      {list.map((l, i) => (
        <li key={`${l.url}-${i}`}><OutLink href={l.url}>{text(l.label || l.text || l.url)}</OutLink></li>
      ))}
    </ul>
  );
}

// prettier-ignore
function ContentText({ text: body }: { text: string }): JSX.Element | null {
  if (!body) return null;
  return (
    <div className="mt-3 space-y-2 border-t border-line-1 pt-3">
      {body.split(/\n{2,}/).map((para, i) => (
        <div key={i}>
          {para.split('\n').map((line, j) => (
            <p key={j} className="whitespace-pre-wrap text-sm leading-relaxed text-body">{line}</p>
          ))}
        </div>
      ))}
    </div>
  );
}

// prettier-ignore
function Field({ title, children, box = false }: { title: string; children: ReactNode; box?: boolean }): JSX.Element {
  return (
    <section className={`mt-4 ${box ? 'rounded border border-line-1 bg-wash p-3' : ''}`}>
      <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">{title}</h4>
      {children}
    </section>
  );
}

// prettier-ignore
function Toggle({ open, onClick, label }: { open: boolean; onClick: () => void; label: string }): JSX.Element {
  return (
    <button type="button" onClick={onClick} aria-expanded={open}
      className="inline-flex items-center gap-1 rounded border border-line-1 px-2 py-1 font-mono text-xs text-muted hover:bg-wash hover:text-heading">
      {open ? 'Less' : label}
      <ChevronDown size={13} className={open ? 'rotate-180 transition-transform' : 'transition-transform'} aria-hidden="true" />
    </button>
  );
}

// prettier-ignore
function BriefingCard({ item }: { item: ZeroItem }): JSX.Element {
  const [open, setOpen] = useState(false);
  const ext = item.ext ?? {};
  const wafRules = asArray(ext.product_mitigations?.waf?.rules);
  const tags = item.tags.filter((t) => !/^(critical|high|medium|low)$/i.test(t));
  return (
    <article className="rounded-lg border border-line-1 bg-surface-100 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
            <span>Last reviewed {fmtDayFull(ext.last_reviewed) || fmtDayFull(item.modified) || fmtDayFull(item.published)}</span>
            {ext.main_action && <Badge tone={ACTION_TONE[ext.main_action]} className="uppercase">{ext.main_action}</Badge>}
          </div>
          <h3 className="mt-1 text-base font-semibold text-heading">
            <OutLink href={item.url} className="hover:text-accent-text hover:underline">{item.title}</OutLink>
          </h3>
        </div>
        <Toggle open={open} onClick={() => setOpen((v) => !v)} label="Details" />
      </div>
      <p className="mt-2 text-sm leading-relaxed text-body">{text(ext.summary || item.summary)}</p>
      {!!ext.cves?.length && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          {asArray(ext.cves).map((cve) => (
            <OutLink key={cve} href={`https://radar.cloudflare.com/zero-wire/cves/${encodeURIComponent(cve)}`}
              className="rounded border border-line-2 bg-wash px-1.5 py-0.5 font-mono text-[11px] text-accent-text hover:underline">
              {cve}
            </OutLink>
          ))}
        </div>
      )}
      {tags.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">{tags.map((tag) => <Badge key={tag}>{tag}</Badge>)}</div>
      )}
      {open && (
        <div className="mt-3 border-t border-line-1 pt-3">
          <ContentText text={item.contentText} />
          {!!ext.updates?.length && (
            <Field title="Updates">
              <ul className="mt-2 space-y-2">
                {asArray(ext.updates).map((u, i) => (
                  <li key={i} className="text-sm text-body">
                    <span className="font-mono text-xs text-muted">{fmtDayFull(u.date)} </span>{text(u.text)}
                    <LinkList links={u.links} />
                  </li>
                ))}
              </ul>
            </Field>
          )}
          {!!ext.recommended_action_steps?.length && (
            <Field title="Recommended actions">
              <ol className="mt-2 list-decimal space-y-3 pl-5 text-sm text-body">
                {asArray(ext.recommended_action_steps).map((s, i) => (
                  <li key={i}>{text(s.text)}<LinkList links={s.links} /></li>
                ))}
              </ol>
            </Field>
          )}
          {wafRules.length > 0 && (
            <Field title="WAF rules">
              <ul className="mt-2 space-y-1 text-sm text-body">
                {wafRules.map((r, i) => (
                  <li key={i}>
                    <span className="font-mono text-xs">{text(r.default_action).toUpperCase()}</span> — {text(r.name)}{' '}
                    <span className="text-muted">({asArray(r.plans).join(', ')})</span>
                  </li>
                ))}
              </ul>
            </Field>
          )}
          {([
            ['Cloudflare product coverage', ext.product_coverage, false],
            ['Assessment prompt', ext.assessment_prompt, false],
            ['Cloudflare service status', ext.service_status, true],
          ] as const).map(([title, value, box]) => value && (
            <Field key={title} title={title} box={box}>
              <p className="mt-1 whitespace-pre-wrap text-sm text-body">{value}</p>
            </Field>
          ))}
          {!!ext.sources?.length && (
            <Field title="Sources">
              <ul className="mt-2 space-y-2">
                {asArray(ext.sources).map((s, i) => (
                  <li key={i} className="text-sm text-body">
                    <span className="font-semibold text-heading">{text(s.title)}</span>
                    {s.description && <span className="text-muted"> — {text(s.description)}</span>}
                    <LinkList links={s.links} />
                  </li>
                ))}
              </ul>
            </Field>
          )}
        </div>
      )}
    </article>
  );
}

// prettier-ignore
function CveRow({ item }: { item: ZeroItem }): JSX.Element {
  const [open, setOpen] = useState(false);
  return (
    <article className="rounded-lg border border-line-1 bg-surface-100 p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <OutLink href={item.url} className="font-mono text-sm font-semibold text-accent-text hover:underline">
              {text(item.cveId || item.title)}
            </OutLink>
            <Badge tone={SEVERITY_TONE[item.severity ?? ''] ?? 'neutral'}>{item.severity}</Badge>
            {item.score != null && (
              <span className="font-mono text-xs text-muted">CVSS {text(item.cvssVersion) || '—'} · {item.score}</span>
            )}
            <span className="font-mono text-xs text-muted">{fmtDayFull(item.published)}</span>
          </div>
          {item.title !== item.cveId && <p className="mt-1 text-sm text-heading">{item.title}</p>}
          <p className="mt-1 line-clamp-3 text-sm text-body">{item.summary}</p>
        </div>
        <Toggle open={open} onClick={() => setOpen((v) => !v)} label="More" />
      </div>
      {open && <ContentText text={item.contentText} />}
    </article>
  );
}

// prettier-ignore
export default function ZeroWire({ bare = false }: { bare?: boolean }): JSX.Element {
  const data = useDataFetch<ZeroIndex>({ url: '/data/zero-wire/index.json', ttl: 600_000 });
  const [view, setView] = useState<'briefings' | 'cves'>('briefings');
  const [query, setQuery] = useState('');
  const [tag, setTag] = useState('all');
  const [severity, setSeverity] = useState('all');
  const index = data.data;
  const isBriefings = view === 'briefings';

  const tags = useMemo(
    () => topCounts(asArray(index?.briefings).flatMap((b) => asArray(b.tags).filter((t) => !/^(critical|high|medium|low)$/i.test(t))), 1000),
    [index]
  );
  const shownBriefings = useMemo(() => {
    const needle = query.trim();
    return asArray(index?.briefings).filter((b) =>
      (tag === 'all' || b.tags.includes(tag)) &&
      (!needle || matches(`${b.title} ${b.summary} ${b.contentText} ${asArray(b.ext?.cves).join(' ')}`, needle))
    );
  }, [index, query, tag]);
  const shownCves = useMemo(() => {
    const needle = query.trim();
    return asArray(index?.cves).filter((c) =>
      (severity === 'all' || c.severity === severity) &&
      (!needle || matches(`${text(c.cveId)} ${c.title} ${c.summary}`, needle))
    );
  }, [index, query, severity]);

  const visible = isBriefings ? shownBriefings : shownCves;
  const total = isBriefings ? index?.stats?.briefings ?? 0 : index?.stats?.cves ?? 0;
  const meta = isBriefings
    ? `${visible.length} of ${total} briefings · mirrored ${relativeAgo(index?.generatedAt)}`
    : `${visible.length} of ${total} recently published CVEs · CVSS scores are upstream values`;
  const rss = text(isBriefings ? index?.upstream?.briefingsRss : index?.upstream?.cvesRss) || '#';
  const upstreamUrl = text(isBriefings ? index?.upstream?.site : index?.upstream?.cvesPage) ||
    (isBriefings ? 'https://radar.cloudflare.com/zero-wire' : 'https://radar.cloudflare.com/zero-wire/cves');

  const body = (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-2 border-b border-line-1 pb-2" role="tablist" aria-label="Zero Wire feeds">
        {([
          ['briefings', `Briefings (${index?.stats?.briefings ?? 0})`],
          ['cves', `CVEs (${index?.stats?.cves ?? 0})`],
        ] as const).map(([id, label]) => (
          <button key={id} type="button" role="tab" aria-selected={view === id}
            onClick={() => { setView(id); setQuery(''); }}
            className={`border-b-2 px-3 py-2 font-mono text-sm font-semibold transition-colors ${
              view === id ? 'border-sky-500 text-sky-600 dark:text-sky-300' : 'border-transparent text-muted hover:text-heading'
            }`}>
            {label}
          </button>
        ))}
        <OutLink href={rss} className="ml-auto inline-flex items-center gap-1 font-mono text-xs text-muted hover:text-accent-text">
          <Rss size={13} aria-hidden="true" /> RSS feed
        </OutLink>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <label className="relative flex-1 min-w-[220px]">
          <Search size={15} className="absolute left-2.5 top-2.5 text-muted" aria-hidden="true" />
          <input type="search" value={query} onChange={(e) => setQuery(e.target.value)}
            placeholder={isBriefings ? 'Search briefings, CVEs, actions…' : 'Search CVE ID or summary…'}
            aria-label="Search feed"
            className="w-full rounded border border-line-input bg-input-200 py-2 pl-8 pr-3 text-sm text-heading placeholder:text-muted" />
        </label>
        <select value={isBriefings ? tag : severity}
          onChange={(e) => isBriefings ? setTag(e.target.value) : setSeverity(e.target.value)}
          aria-label={isBriefings ? 'Filter by tag' : 'Filter by severity'}
          className="rounded border border-line-input bg-input-200 px-2 py-2 text-sm text-heading">
          {isBriefings ? (
            <>
              <option value="all">All tags</option>
              {tags.map(([t, n]) => <option key={t} value={t}>{t} ({n})</option>)}
            </>
          ) : (
            <>
              <option value="all">All severities</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
                <option key={s} value={s}>{s} ({index?.stats?.bySeverity?.[s] ?? 0})</option>
              ))}
            </>
          )}
        </select>
      </div>

      <Section title={isBriefings ? 'Briefings' : 'CVEs'}>
        <p className="mb-3 text-xs font-mono text-muted">
          {meta} · <OutLink href={upstreamUrl}>upstream</OutLink>
        </p>
        <div className={isBriefings ? 'space-y-3' : 'space-y-2'}>
          {visible.map((item) => isBriefings
            ? <BriefingCard key={item.id} item={item} />
            : <CveRow key={item.id} item={item} />)}
        </div>
        {index && visible.length === 0 && (
          <Empty>No {isBriefings ? 'briefings' : 'CVEs'} match these filters.</Empty>
        )}
      </Section>
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
        Data mirrored from radar.cloudflare.com/zero-wire · {fmtDayFull(index?.generatedAt)}
      </p>
      {body}
    </DataPageLayout>
  );
}
