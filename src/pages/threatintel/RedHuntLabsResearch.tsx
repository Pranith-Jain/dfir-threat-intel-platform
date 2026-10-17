import { useEffect, useState } from 'react';
import {
  Search,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  FolderTree,
  Info,
  Wrench,
  FlaskConical,
  Database,
  Building2,
  Github,
  Twitter,
  Linkedin,
  Mail,
} from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';
import {
  SECTIONS,
  TOOLS,
  RESEARCH_ITEMS,
  DATASETS,
  ABOUT,
  COUNTS,
  type RedHuntCategory,
  type RedHuntTool,
  type RedHuntResearchItem,
  type RedHuntDataset,
} from '../../data/threatintel/redhunt-labs-research';

type TabId = RedHuntCategory;

const TABS: { id: TabId; label: string; icon: typeof Wrench; count: number }[] = [
  { id: 'tools', label: 'Tools', icon: Wrench, count: COUNTS.tools },
  { id: 'research', label: 'Research', icon: FlaskConical, count: COUNTS.research },
  { id: 'datasets', label: 'Datasets', icon: Database, count: COUNTS.datasets },
  { id: 'about', label: 'About', icon: Building2, count: 0 },
];

// Pill palette for tool tags / conferences. Tones: docker, k8s, ML/LLM,
// recon / osint, vulnerability scanner, and conference.
const TAG_PILL: Record<string, string> = {
  docker: 'border-sky-300 dark:border-sky-800 bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300',
  k8s: 'border-brand-300 dark:border-blue-800 bg-blue-50 dark:bg-blue-950/40 text-brand-700 dark:text-brand-300',
  firebase:
    'border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300',
  aws: 'border-orange-300 dark:border-orange-800 bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300',
  gcp: 'border-cyan-300 dark:border-cyan-800 bg-cyan-50 dark:bg-cyan-950/40 text-sky-700 dark:text-sky-300',
  'digital-ocean':
    'border-indigo-300 dark:border-indigo-800 bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-300',
  ML: 'border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300',
  LLM: 'border-purple-300 dark:border-purple-800 bg-purple-50 dark:bg-purple-950/40 text-purple-700 dark:text-purple-300',
  'PII-scanner': 'border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300',
  'vulnerability-scanner':
    'border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300',
  recon:
    'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300',
  osint: 'border-teal-300 dark:border-teal-800 bg-teal-50 dark:bg-teal-950/40 text-teal-700 dark:text-teal-300',
  burpsuite:
    'border-orange-300 dark:border-orange-800 bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300',
  'awesome-list':
    'border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300',
  os: 'border-slate-300 dark:border-line-1 bg-slate-50 dark:bg-surface-200 text-body',
};

function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch (_catchErr) {
    console.error('hostnameOf failed:', errMessage(_catchErr));
    return url;
  }
}

function matchesText(haystack: string, q: string): boolean {
  return haystack.toLowerCase().includes(q.toLowerCase());
}

function ToolRow({
  tool,
  query,
  defaultOpen,
  depth,
}: {
  tool: RedHuntTool;
  query: string;
  defaultOpen: boolean;
  depth: number;
}): JSX.Element {
  const [open, setOpen] = useState(defaultOpen);
  const haystack = `${tool.name} ${tool.description} ${tool.tags.join(' ')} ${tool.conferences.join(' ')} ${tool.authors.map((a) => a.name).join(' ')}`;
  const visible = !query || matchesText(haystack, query);
  if (!visible) return <></>;
  return (
    <div className="border-b border-line-1 last:border-b-0">
      <div
        className="flex items-start gap-3 px-3 py-3 hover:bg-surface-200 dark:hover:bg-surface-200/50 transition-colors"
        style={{ paddingLeft: `${depth * 16 + 12}px` }}
      >
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded text-muted hover:bg-track/60 dark:hover:bg-surface-300/60"
          aria-label={open ? 'Collapse' : 'Expand'}
        >
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-2">
            <a
              href={tool.url}
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium text-heading hover:text-rose-600 dark:hover:text-rose-400 hover:underline transition-colors"
            >
              {tool.name}
            </a>
            <span className="text-xs text-muted">by {tool.authors.map((a) => a.name).join(', ')}</span>
            {tool.tags.map((t) => (
              <span
                key={t}
                className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${
                  TAG_PILL[t] ?? 'border-slate-300 dark:border-line-1 bg-slate-50 dark:bg-surface-200 text-muted'
                }`}
              >
                {t}
              </span>
            ))}
            {tool.conferences.length > 0 && (
              <span className="text-micro font-mono rounded border border-violet-300 dark:border-violet-800 bg-violet-50 dark:bg-violet-950/40 px-1.5 py-0.5 text-violet-700 dark:text-violet-300">
                {tool.conferences.length} conf
              </span>
            )}
            <a
              href={tool.url}
              target="_blank"
              rel="noopener noreferrer"
              className="ml-auto text-muted hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
              aria-label="Open on GitHub"
            >
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </div>
          {open && (
            <>
              <p className="mt-1 text-sm text-muted leading-relaxed">{tool.description}</p>
              {tool.conferences.length > 0 && (
                <p className="mt-1 text-xs text-muted">Showcased at: {tool.conferences.join(' · ')}</p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function ResearchCard({ item, query }: { item: RedHuntResearchItem; query: string }): JSX.Element | null {
  const haystack = `${item.title} ${item.summary} ${item.details ?? ''}`;
  if (query && !matchesText(haystack, query)) return null;
  return (
    <a
      href={item.url}
      target="_blank"
      rel="noopener noreferrer"
      className="block rounded-xl border border-line-1 bg-surface-100 p-4 hover:border-rose-500/60 hover:shadow-e2 transition-all"
    >
      <div className="flex items-start gap-2">
        <FlaskConical className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
        <div className="min-w-0 flex-1">
          <h3 className="text-base font-medium text-heading">{item.title}</h3>
          <p className="mt-1 text-sm text-muted leading-relaxed">{item.summary}</p>
          {item.details && <p className="mt-2 text-xs text-muted leading-relaxed line-clamp-3">{item.details}</p>}
          <p className="mt-2 inline-flex items-center gap-1 text-xs text-rose-600 dark:text-rose-400">
            {hostnameOf(item.url)}
            <ExternalLink className="h-3 w-3" />
          </p>
        </div>
      </div>
    </a>
  );
}

function DatasetCard({ ds, query }: { ds: RedHuntDataset; query: string }): JSX.Element | null {
  const haystack = `${ds.title} ${ds.description} ${ds.wave}`;
  if (query && !matchesText(haystack, query)) return null;
  const statusTone =
    ds.releaseStatus === 'available'
      ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300'
      : ds.releaseStatus === 'pending'
        ? 'border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300'
        : 'border-slate-300 dark:border-line-1 bg-slate-50 dark:bg-surface-200 text-muted';
  return (
    <a
      href={ds.url}
      target="_blank"
      rel="noopener noreferrer"
      className="block rounded-xl border border-line-1 bg-surface-100 p-4 hover:border-rose-500/60 hover:shadow-e2 transition-all"
    >
      <div className="flex items-start gap-2">
        <Database className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-2">
            <h3 className="text-base font-medium text-heading">{ds.title}</h3>
            <span className="text-micro font-mono rounded border border-line-2 px-1.5 py-0.5 text-muted">
              {ds.wave}
            </span>
            <span className={`text-micro font-mono rounded border px-1.5 py-0.5 ${statusTone}`}>
              {ds.releaseStatus}
            </span>
          </div>
          <p className="mt-1 text-sm text-muted leading-relaxed">{ds.description}</p>
        </div>
      </div>
    </a>
  );
}

function socialIcon(label: string): typeof Github {
  if (label === 'GitHub') return Github;
  if (label === 'Twitter') return Twitter;
  if (label === 'LinkedIn') return Linkedin;
  return Mail;
}

/**
 * RedHunt Labs Research - curated mirror of https://research.redhuntlabs.com/
 *
 * RedHunt Labs is an ASM (Attack Surface Management) and exposures
 * shop. Their research arm publishes ~11 open-source security tools
 * (most presented at Black Hat conferences) and runs Project Resonance,
 * an internet-wide security research initiative that ships
 * downloadable datasets one Wave at a time.
 *
 * This page is the in-platform landing for the catalog entry
 * `redhunt-labs-research` in /threatintel/external-resources. It uses
 * the same tabbed shell as /owasp-ai-landscape and /curated-toolbox
 * so the navigation pattern is consistent across curated research
 * mirrors.
 *
 * Data is bundled (no API fetch) because the upstream research site is
 * a client-rendered Next.js app and scraping it reliably is out of
 * scope for a static mirror. Each tool links directly to the upstream
 * GitHub repo so the page never goes stale when RedHunt updates a
 * README.
 *
 * Mirrored: 2026-06-13.
 */
export default function RedHuntLabsResearch(): JSX.Element {
  const [tab, setTab] = useState<TabId>('tools');
  const [query, setQuery] = useState('');

  // Persist last-open tab in localStorage so a returning visitor picks
  // up where they left off. Defaults to 'tools' on first visit.
  useEffect(() => {
    try {
      const stored = localStorage.getItem('redhunt.tab.v1');
      if (stored && SECTIONS.some((s) => s.id === stored)) {
        setTab(stored as TabId);
      }
    } catch (_catchErr) {
      console.error('RedHuntLabsResearch failed:', errMessage(_catchErr));
      /* localStorage may be disabled (private mode, sandbox) - fall back to default. */
    }
  }, []);
  useEffect(() => {
    try {
      localStorage.setItem('redhunt.tab.v1', tab);
    } catch (_catchErr) {
      console.error('RedHuntLabsResearch failed:', errMessage(_catchErr));
      /* no-op */
    }
  }, [tab]);

  const section = SECTIONS.find((s) => s.id === tab) ?? SECTIONS[0]!;

  const filteredTools = TOOLS;
  const filteredResearch = RESEARCH_ITEMS;
  const filteredDatasets = DATASETS;

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="back to threat intel"
      icon={<FlaskConical className="h-6 w-6" />}
      title="RedHunt Labs Research"
      description={
        <span>
          Curated mirror of{' '}
          <a
            href="https://research.redhuntlabs.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            research.redhuntlabs.com
          </a>{' '}
          - ASM and Exposure research, open-source security tools, Project Resonance waves, and downloadable datasets.
          Pairs with the catalog entry at /threatintel/external-resources.
        </span>
      }
      headerExtra={
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
          <span className="rounded border border-line-2 px-2 py-1 text-muted font-mono">
            mirrored <span className="text-body">2026-06-13</span>
          </span>
          <span className="rounded border border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 px-2 py-1 text-emerald-700 dark:text-emerald-300 font-mono">
            static seed
          </span>
        </div>
      }
      maxWidthClass="max-w-6xl"
    >
      {/* Tabs */}
      <div className="mb-4 flex flex-wrap items-center gap-1.5 surface-card p-2">
        {TABS.map((t) => {
          const Icon = t.icon;
          const active = t.id === tab;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              className={`inline-flex items-center gap-1.5 rounded px-3 py-1.5 text-sm font-medium transition-colors ${
                active
                  ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-300/60 dark:border-rose-500/40/60'
                  : 'border border-transparent text-muted hover:bg-slate-100 dark:hover:bg-surface-300/50'
              }`}
            >
              <Icon className="h-4 w-4" />
              {t.label}
              {t.count > 0 && (
                <span className="rounded-full border border-line-2 bg-surface-100 px-1.5 py-0.5 text-micro font-mono">
                  {t.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Section intro card */}
      <div className="mb-3 flex items-start gap-2 rounded-xl border border-sky-200 dark:border-sky-900 bg-sky-50 dark:bg-sky-950/30 p-3 text-sm text-body">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-600 dark:text-sky-400" />
        <span>{section.intro}</span>
      </div>

      {/* Toolbar (only on list tabs) */}
      {tab !== 'about' && (
        <section className="mb-4 surface-card p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={
                  tab === 'tools'
                    ? `Search ${TOOLS.length} tools by name, tag, conference, or author…`
                    : tab === 'research'
                      ? `Search ${RESEARCH_ITEMS.length} research projects…`
                      : `Search ${DATASETS.length} datasets…`
                }
                className="w-full rounded-xl border border-line-2 bg-surface-100 py-2 pl-9 pr-3 text-sm text-heading placeholder:text-muted focus:border-rose-500/60 focus:outline-none"
              />
            </div>
            {query && (
              <button
                type="button"
                onClick={() => setQuery('')}
                className="text-mini font-mono rounded border border-line-2 px-2.5 py-1 text-muted hover:text-body dark:hover:text-inverted"
              >
                clear
              </button>
            )}
          </div>
        </section>
      )}

      {/* Header cards */}
      <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label="Tools" value={COUNTS.tools} />
        <Stat label="Research" value={COUNTS.research} />
        <Stat label="Datasets" value={COUNTS.datasets} />
        <Stat
          label="Source"
          value={
            <a
              href="https://research.redhuntlabs.com/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-rose-600 dark:text-rose-400 hover:underline truncate transition-colors"
            >
              research.redhuntlabs.com
            </a>
          }
        />
      </div>

      {/* Tab content */}
      {tab === 'tools' && (
        <div className="overflow-hidden rounded-xl border border-line-1 bg-surface-100">
          {filteredTools.length === 0 ? (
            <div className="p-8 text-center text-sm text-muted">
              <FolderTree className="mx-auto mb-2 h-8 w-8 text-muted" />
              No tools match &quot;{query}&quot;.
            </div>
          ) : (
            filteredTools.map((t) => <ToolRow key={t.id} tool={t} query={query} defaultOpen={!query} depth={0} />)
          )}
        </div>
      )}

      {tab === 'research' && (
        <div className="grid gap-2 sm:grid-cols-2">
          {filteredResearch.length === 0 ||
          filteredResearch.every((r) => {
            const haystack = `${r.title} ${r.summary} ${r.details ?? ''}`;
            return query && !matchesText(haystack, query);
          }) ? (
            <div className="col-span-full rounded-xl border border-line-1 bg-surface-200 p-8 text-center text-sm text-muted">
              <Search className="mx-auto mb-2 h-8 w-8 text-muted" />
              No research projects match &quot;{query}&quot;.
            </div>
          ) : (
            filteredResearch.map((r) => <ResearchCard key={r.id} item={r} query={query} />)
          )}
        </div>
      )}

      {tab === 'datasets' && (
        <div className="grid gap-2 sm:grid-cols-2">
          {filteredDatasets.length === 0 ||
          filteredDatasets.every((d) => {
            const haystack = `${d.title} ${d.description} ${d.wave}`;
            return query && !matchesText(haystack, query);
          }) ? (
            <div className="col-span-full rounded-xl border border-line-1 bg-surface-200 p-8 text-center text-sm text-muted">
              <Search className="mx-auto mb-2 h-8 w-8 text-muted" />
              No datasets match &quot;{query}&quot;.
            </div>
          ) : (
            filteredDatasets.map((d) => <DatasetCard key={d.id} ds={d} query={query} />)
          )}
        </div>
      )}

      {tab === 'about' && (
        <div className="space-y-4">
          {/* Mission */}
          <div className="surface-card p-5">
            <h2 className="text-lg font-semibold text-heading">Our Mission</h2>
            <p className="mt-2 text-sm text-body leading-relaxed">{ABOUT.mission}</p>
          </div>

          {/* Principles */}
          <div>
            <h2 className="mb-2 text-lg font-semibold text-heading">Join Hands in our Research</h2>
            <div className="grid gap-2 sm:grid-cols-3">
              {ABOUT.principles.map((p) => (
                <div key={p.title} className="rounded-xl border border-line-1 bg-surface-100 p-4">
                  <h3 className="text-sm font-medium text-heading">{p.title}</h3>
                  <p className="mt-1 text-xs text-muted leading-relaxed">{p.body}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Contact + Socials */}
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="surface-card p-4">
              <h3 className="text-sm font-medium text-heading">Contact</h3>
              <ul className="mt-2 space-y-1 text-sm">
                {ABOUT.contact.map((c) => (
                  <li key={c.label}>
                    <a
                      href={c.href}
                      className="inline-flex items-center gap-1.5 text-rose-600 dark:text-rose-400 hover:underline transition-colors"
                    >
                      <Mail className="h-3.5 w-3.5" />
                      {c.value}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
            <div className="surface-card p-4">
              <h3 className="text-sm font-medium text-heading">Social</h3>
              <ul className="mt-2 space-y-1 text-sm">
                {ABOUT.socials.map((s) => {
                  const Icon = socialIcon(s.label);
                  return (
                    <li key={s.label}>
                      <a
                        href={s.href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 text-rose-600 dark:text-rose-400 hover:underline transition-colors"
                      >
                        <Icon className="h-3.5 w-3.5" />
                        {s.label}
                      </a>
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>

          <p className="text-center text-xs text-muted">
            Built with passion by the RedHunt Labs Research Team - Fueling research and innovation for the community.
          </p>
        </div>
      )}
    </DataPageLayout>
  );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }): JSX.Element {
  return (
    <div className="surface-card px-3 py-2">
      <div className="text-micro font-mono uppercase tracking-wider text-muted">{label}</div>
      <div className="text-lg font-semibold text-heading truncate">{value}</div>
    </div>
  );
}
