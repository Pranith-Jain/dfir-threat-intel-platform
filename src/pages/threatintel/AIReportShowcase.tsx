import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  Beaker,
  BookOpen,
  Bug,
  Calendar,
  CircleDot,
  Diamond,
  ExternalLink,
  Eye,
  FileText,
  Globe2,
  Link2,
  LinkIcon,
  Loader2,
  Network,
  RefreshCw,
  Search,
  Sparkles,
  Target,
  TrendingUp,
  Users,
} from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { McpStatusBanner } from '../../components/ti-mindmap-mcp/McpStatusBanner';
import { SAMPLE_REPORTS, type SampleReport } from '../../data/threatintel/sample-reports';
import { DataTable, type DataTableColumn } from '../../components/ui/DataTable';
import {
  getStoredApiKey,
  probeConnection,
  searchIoc,
  searchCve,
  listReports,
  McpError,
  type IocSearchResult,
  type CveSearchResult,
  type ListReportsResult,
  type TiReportSummary,
} from '../../lib/ti-mindmap-mcp';

// Mirror of api/src/lib/report-analyzer.ts types (kept in sync - this page
// is a read-only consumer; if the API shape changes, this needs an update).
type IocKind = 'ip' | 'url' | 'domain' | 'hash' | 'cve' | 'email';
interface ExtractedIoc {
  value: string;
  kind: IocKind;
  confidence: number;
  confidence_band: 'high' | 'medium' | 'low';
  evidence: string;
  source: 'report-text' | 'image-ocr';
}
interface TtpHit {
  id: string;
  name: string;
  tactic: string;
  confidence: 'high' | 'medium' | 'low';
  evidence: string;
}
interface ExtractedCve {
  id: string;
  context: string;
}
interface FiveW {
  who: string;
  what: string;
  when: string;
  where: string;
  why: string;
  attribution_basis?: string;
  confidence: number;
}
interface MindmapNode {
  id: string;
  label: string;
  kind: 'actor' | 'malware' | 'ttp' | 'ioc' | 'cve' | 'finding';
}
interface MindmapEdge {
  source: string;
  target: string;
  label: string;
}
interface DiamondModel {
  adversary: string[];
  capability: { id: string; name: string; tactic: string; evidence: string }[];
  infrastructure: string[];
  victim: { sector: string; geography: string; asset: string };
}
interface AttackFlowPhase {
  phase: string;
  techniques: { id: string; name: string; evidence: string }[];
}
interface AnalyzerOutput {
  title: string;
  source?: string;
  textLength: number;
  generatedAt: string;
  summary: { text: string; model: string } | null;
  fiveW: FiveW | null;
  iocs: ExtractedIoc[];
  ttp: TtpHit[];
  cves: ExtractedCve[];
  mindmap: { nodes: MindmapNode[]; edges: MindmapEdge[] };
  diamond: DiamondModel | null;
  attackFlow: AttackFlowPhase[];
  stix: { bundle: { type: string; id: string; objects: unknown[] }; view: unknown } | null;
  errors: { branch: string; message: string }[];
  elapsed_ms: number;
}

// ── Tab IDs (PDF section IDs mirrored from the upstream report) ────────
type TabId = 'summary' | 'mindmap' | 'stix' | 'diamond' | 'iocs' | 'ttps' | 'attackflow' | '5w';

const TABS: { id: TabId; label: string; icon: typeof FileText }[] = [
  { id: 'summary', label: 'AI Summary', icon: FileText },
  { id: 'mindmap', label: 'Mindmap', icon: Network },
  { id: 'stix', label: 'STIX 2.1', icon: Globe2 },
  { id: 'diamond', label: 'Diamond Model', icon: Diamond },
  { id: 'iocs', label: 'IOCs', icon: Link2 },
  { id: 'ttps', label: 'TTP Catalog', icon: Bug },
  { id: 'attackflow', label: 'Attack Flow', icon: TrendingUp },
  { id: '5w', label: '5W Analysis', icon: Users },
];

// ── Formatting helpers ────────────────────────────────────────────────
function fmtTime(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function fmtConfidence(n: number): string {
  return `${Math.round(n * 100)}%`;
}

const CONFIDENCE_PILL: Record<'high' | 'medium' | 'low', string> = {
  high: 'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800',
  medium: 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800',
  low: 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
};

const IOC_PILL: Record<IocKind, string> = {
  ip: 'text-sky-700 dark:text-sky-300 bg-cyan-50 dark:bg-cyan-950/40 border-cyan-300 dark:border-cyan-800',
  url: 'text-purple-700 dark:text-purple-300 bg-purple-50 dark:bg-purple-950/40 border-purple-300 dark:border-purple-800',
  domain: 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800',
  hash: 'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800',
  cve: 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
  email: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
};

// ── Tab bodies (mirror the ReportAnalyzer styles, no React Flow needed
//    for the showcase - we use a CSS-only mindmap rendering so the page
//    loads without the 250KB xyflow bundle) ───────────────────────────

function SummaryTab({ data, sample }: { data: AnalyzerOutput; sample: SampleReport }): JSX.Element {
  return (
    <div className="surface-card p-5 space-y-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-line-1 pb-3">
        <div>
          <p className="text-micro font-mono uppercase tracking-wider text-rose-600 dark:text-rose-400">
            AI-Generated Summary · {data.summary?.model ?? 'unknown model'}
          </p>
          <h2 className="text-xl sm:text-2xl font-display font-bold text-heading mt-1">{data.title || sample.title}</h2>
        </div>
        <div className="text-right text-xs text-muted font-mono">
          <p>elapsed: {fmtTime(data.elapsed_ms)}</p>
          <p>chars: {data.textLength.toLocaleString()}</p>
        </div>
      </div>
      {data.summary?.text ? (
        <div className="prose prose-slate dark:prose-invert max-w-none text-sm leading-relaxed text-body whitespace-pre-wrap">
          {data.summary.text}
        </div>
      ) : (
        <p className="text-sm text-muted italic">No AI summary was generated.</p>
      )}
    </div>
  );
}

function MindmapSimpleTab({ mindmap }: { mindmap: { nodes: MindmapNode[]; edges: MindmapEdge[] } }): JSX.Element {
  // CSS-only rendering: a central "finding" card with each connected node
  // listed under a kind label. We trade the interactive force-layout of the
  // /dfir/report-analyzer page for a lighter, SEO-friendly version that
  // works without lazy-loading xyflow.
  if (mindmap.nodes.length === 0) {
    return <EmptyTab msg="No mindmap nodes were generated for this report." />;
  }
  const finding = mindmap.nodes.find((n) => n.kind === 'finding');
  const byKind: Record<string, MindmapNode[]> = {};
  for (const n of mindmap.nodes) {
    if (n.id === finding?.id) continue;
    (byKind[n.kind] ??= []).push(n);
  }
  const KIND_ORDER: Array<{ kind: string; label: string; tone: string }> = [
    {
      kind: 'actor',
      label: 'Actors',
      tone: 'border-rose-300 dark:border-rose-800 bg-rose-50/40 dark:bg-rose-950/20 text-rose-700 dark:text-rose-300',
    },
    {
      kind: 'malware',
      label: 'Malware / Tools',
      tone: 'border-violet-300 dark:border-violet-800 bg-violet-50/40 dark:bg-violet-950/20 text-violet-700 dark:text-violet-300',
    },
    {
      kind: 'ttp',
      label: 'TTPs',
      tone: 'border-indigo-300 dark:border-indigo-800 bg-indigo-50/40 dark:bg-indigo-950/20 text-indigo-700 dark:text-indigo-300',
    },
    {
      kind: 'cve',
      label: 'CVEs',
      tone: 'border-amber-300 dark:border-amber-800 bg-amber-50/40 dark:bg-amber-950/20 text-amber-700 dark:text-amber-300',
    },
    {
      kind: 'ioc',
      label: 'IOCs',
      tone: 'border-sky-300 dark:border-sky-800 bg-sky-50/40 dark:bg-sky-950/20 text-sky-700 dark:text-sky-300',
    },
  ];
  return (
    <div className="space-y-3">
      {finding && (
        <div className="rounded-xl border-2 border-rose-400 dark:border-rose-600 bg-rose-50 dark:bg-rose-950/30 p-4 text-center shadow-e1">
          <p className="text-micro font-mono uppercase tracking-wider text-rose-600 dark:text-rose-400">
            Central Finding
          </p>
          <h3 className="mt-1 text-base font-semibold text-heading">{finding.label}</h3>
        </div>
      )}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {KIND_ORDER.map(({ kind, label, tone }) => {
          const items = byKind[kind] ?? [];
          if (items.length === 0) return null;
          return (
            <div key={kind} className={`rounded-xl border ${tone} p-4 shadow-e1`}>
              <p className="text-micro font-mono uppercase tracking-wider opacity-80 mb-2">
                {label} · {items.length}
              </p>
              <ul className="space-y-1">
                {items.slice(0, 10).map((n) => (
                  <li key={n.id} className="text-xs font-mono truncate text-body" title={n.label}>
                    {n.label}
                  </li>
                ))}
                {items.length > 10 && <li className="text-xs text-muted">+{items.length - 10} more</li>}
              </ul>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function StixTab({ data }: { data: AnalyzerOutput }): JSX.Element {
  if (!data.stix) return <EmptyTab msg="No STIX 2.1 bundle was generated." />;
  const objects = Array.isArray((data.stix.bundle as { objects?: unknown[] }).objects)
    ? (data.stix.bundle as { objects: unknown[] }).objects
    : [];
  // Count object types for a summary
  const typeCounts: Record<string, number> = {};
  for (const o of objects) {
    if (typeof o === 'object' && o !== null) {
      const t = (o as { type?: string }).type ?? 'unknown';
      typeCounts[t] = (typeCounts[t] ?? 0) + 1;
    }
  }
  return (
    <div className="surface-card p-5 space-y-4">
      <div className="flex items-baseline justify-between">
        <p className="text-micro font-mono uppercase tracking-wider text-rose-600 dark:text-rose-400">
          STIX 2.1 Bundle · {objects.length} objects
        </p>
        <details className="text-xs">
          <summary className="cursor-pointer text-muted hover:text-body dark:hover:text-inverted font-mono">
            show raw JSON
          </summary>
          <pre className="mt-2 max-h-96 overflow-auto rounded border border-line-1 bg-surface-200 p-3 text-mini text-body">
            {JSON.stringify(data.stix.bundle, null, 2)}
          </pre>
        </details>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {Object.entries(typeCounts).map(([type, n]) => (
          <div key={type} className="rounded border border-line-1 bg-surface-200 p-3 text-center">
            <p className="text-2xl font-display font-bold text-heading">{n}</p>
            <p className="text-micro font-mono uppercase tracking-wider text-muted mt-1">{type}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function DiamondTabView({ diamond }: { diamond: DiamondModel | null }): JSX.Element {
  if (!diamond) return <EmptyTab msg="No Diamond Model could be derived from this report." />;
  const pillars = [
    {
      key: 'adversary',
      title: 'Adversary',
      items: diamond.adversary,
      tone: 'border-rose-300 dark:border-rose-800 bg-rose-50/40 dark:bg-rose-950/20 text-rose-700 dark:text-rose-300',
    },
    {
      key: 'capability',
      title: 'Capability',
      items: diamond.capability.map((c) => c.id),
      tone: 'border-violet-300 dark:border-violet-800 bg-violet-50/40 dark:bg-violet-950/20 text-violet-700 dark:text-violet-300',
    },
    {
      key: 'infrastructure',
      title: 'Infrastructure',
      items: diamond.infrastructure,
      tone: 'border-sky-300 dark:border-sky-800 bg-sky-50/40 dark:bg-sky-950/20 text-sky-700 dark:text-sky-300',
    },
    {
      key: 'victim',
      title: 'Victim',
      items: [`${diamond.victim.sector} · ${diamond.victim.geography}`],
      tone: 'border-emerald-300 dark:border-emerald-800 bg-emerald-50/40 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-300',
    },
  ] as const;
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {pillars.map((p) => (
        <div key={p.key} className={`rounded-xl border ${p.tone} p-4 shadow-e1`}>
          <div className="flex items-center gap-2 mb-2">
            <Diamond className="h-4 w-4 opacity-70" />
            <h3 className="text-sm font-semibold">{p.title}</h3>
            <span className="ml-auto text-micro font-mono uppercase opacity-70">
              {p.items.length} item{p.items.length === 1 ? '' : 's'}
            </span>
          </div>
          {p.items.length === 0 ? (
            <p className="text-xs opacity-60 italic">none</p>
          ) : (
            <ul className="space-y-1">
              {p.items.slice(0, 8).map((i, idx) => (
                <li key={idx} className="text-xs font-mono truncate" title={i}>
                  {i}
                </li>
              ))}
              {p.items.length > 8 && <li className="text-xs opacity-70">+{p.items.length - 8} more</li>}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

interface IocEnrichmentRow {
  ioc: ExtractedIoc;
  hit: IocSearchResult | null;
  loading: boolean;
  error?: string;
}

function IocsTab(props: { iocs: ExtractedIoc[]; apiKey: string; mcpStatus: McpStatus }): JSX.Element {
  const { iocs, apiKey, mcpStatus } = props;
  const [enrichments, setEnrichments] = useState<Record<string, IocEnrichmentRow>>({});
  const [enriching, setEnriching] = useState(false);

  if (iocs.length === 0) return <EmptyTab msg="No IOCs were extracted." />;

  const enrichable = iocs.filter(
    (i) =>
      i.confidence_band !== 'low' && (i.kind === 'ip' || i.kind === 'domain' || i.kind === 'hash' || i.kind === 'url')
  );
  const canEnrich = mcpStatus === 'connected' && !!apiKey;

  async function runEnrichment(): Promise<void> {
    if (!canEnrich || enrichable.length === 0) return;
    setEnriching(true);
    // Cap at 8 to keep latency + rate limit polite.
    const targets = enrichable.slice(0, 8);
    // Optimistic loading rows.
    const initRows: Record<string, IocEnrichmentRow> = {};
    for (const i of targets) {
      initRows[i.value] = { ioc: i, hit: null, loading: true };
    }
    setEnrichments(initRows);
    // Fan out the lookups in parallel.
    await Promise.all(
      targets.map(async (i) => {
        try {
          const r = await searchIoc(apiKey, i.value);
          setEnrichments((prev) => ({ ...prev, [i.value]: { ioc: i, hit: r, loading: false } }));
        } catch (e) {
          console.error('runEnrichment failed:', errMessage(e));
          const msg = e instanceof McpError ? e.message : errMessage(e);
          setEnrichments((prev) => ({ ...prev, [i.value]: { ioc: i, hit: null, loading: false, error: msg } }));
        }
      })
    );
    setEnriching(false);
  }

  return (
    <div className="surface-card overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 px-4 py-2.5 border-b border-line-1 bg-surface-200">
        <Link2 className="h-4 w-4 text-rose-600 dark:text-rose-400" />
        <p className="text-sm font-semibold text-heading">
          {iocs.length} IOC{iocs.length === 1 ? '' : 's'} extracted
        </p>
        <span className="text-micro font-mono uppercase text-muted">{enrichable.length} cross-checkable</span>
        <button
          type="button"
          onClick={() => void runEnrichment()}
          disabled={!canEnrich || enriching || enrichable.length === 0}
          className="ml-auto inline-flex items-center gap-1.5 rounded border border-rose-300 dark:border-rose-500/40 bg-rose-50 dark:bg-rose-950/40 px-2.5 py-1 text-xs font-medium text-rose-700 dark:text-rose-300 hover:bg-rose-100 disabled:opacity-50"
          title={
            canEnrich ? `Cross-check up to 8 IOCs against TI-Mindmap-Hub` : 'Configure your MCP API key above to enable'
          }
        >
          {enriching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
          cross-check on TI-Mindmap-Hub
        </button>
      </div>
      <div className="overflow-x-auto">
        <DataTable
          columns={
            [
              {
                key: 'value',
                header: 'Value',
                sortValue: (i: (typeof iocs)[number]) => i.value,
                render: (i) => (
                  <span className="font-mono text-xs text-body truncate max-w-md" title={i.value}>
                    {i.value}
                  </span>
                ),
              },
              {
                key: 'type',
                header: 'Type',
                sortValue: (i: (typeof iocs)[number]) => i.kind,
                render: (i) => (
                  <span
                    className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${IOC_PILL[i.kind]}`}
                  >
                    {i.kind}
                  </span>
                ),
              },
              {
                key: 'confidence',
                header: 'Confidence',
                sortValue: (i: (typeof iocs)[number]) => i.confidence,
                render: (i) => (
                  <span
                    className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${CONFIDENCE_PILL[i.confidence_band]}`}
                  >
                    {i.confidence_band} · {fmtConfidence(i.confidence)}
                  </span>
                ),
              },
              {
                key: 'source',
                header: 'Source',
                sortValue: (i: (typeof iocs)[number]) => i.source,
                render: (i) => <span className="text-xs text-muted font-mono">{i.source}</span>,
              },
              {
                key: 'hub',
                header: 'TI-Mindmap-Hub',
                render: (i) => <span className="text-xs">{enrichments[i.value] ? '✓' : '-'}</span>,
              },
            ] as DataTableColumn<(typeof iocs)[number]>[]
          }
          rows={iocs.slice(0, 50)}
          rowKey={(i, idx) => `${i.value}-${idx}`}
          rowClassName={() => 'hover:bg-slate-50 dark:hover:bg-surface-200/50'}
        />
      </div>
      {iocs.length > 50 && (
        <p className="px-4 py-2 text-xs text-muted border-t border-line-1 bg-surface-200">
          Showing first 50 of {iocs.length} indicators.
        </p>
      )}
    </div>
  );
}

function TtpsTab({ ttp }: { ttp: TtpHit[] }): JSX.Element {
  if (ttp.length === 0) return <EmptyTab msg="No MITRE ATT&CK techniques were extracted." />;
  return (
    <div className="surface-card overflow-hidden">
      <div className="overflow-x-auto">
        <DataTable
          columns={
            [
              {
                key: 'name',
                header: 'Technique',
                sortValue: (t: (typeof ttp)[number]) => t.name,
                render: (t) => <span className="text-heading font-medium">{t.name}</span>,
              },
              {
                key: 'id',
                header: 'ID',
                sortValue: (t: (typeof ttp)[number]) => t.id,
                render: (t) => (
                  <a
                    href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-xs text-rose-600 dark:text-rose-400 hover:underline transition-colors"
                  >
                    {t.id}
                  </a>
                ),
              },
              {
                key: 'tactic',
                header: 'Tactic',
                sortValue: (t: (typeof ttp)[number]) => t.tactic,
                render: (t) => <span className="text-xs text-muted">{t.tactic}</span>,
              },
              {
                key: 'confidence',
                header: 'Confidence',
                sortValue: (t: (typeof ttp)[number]) => t.confidence,
                render: (t) => (
                  <span
                    className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${CONFIDENCE_PILL[t.confidence]}`}
                  >
                    {t.confidence}
                  </span>
                ),
              },
              {
                key: 'evidence',
                header: 'Evidence',
                render: (t) => (
                  <span className="text-xs text-muted max-w-md truncate" title={t.evidence}>
                    {t.evidence}
                  </span>
                ),
              },
            ] as DataTableColumn<(typeof ttp)[number]>[]
          }
          rows={ttp}
          rowKey={(t, idx) => `${t.id}-${idx}`}
          rowClassName={() => 'hover:bg-slate-50 dark:hover:bg-surface-200/50'}
        />
      </div>
    </div>
  );
}

function AttackFlowTabView({ phases }: { phases: AttackFlowPhase[] }): JSX.Element {
  if (phases.length === 0) return <EmptyTab msg="No kill-chain phases to render." />;
  return (
    <div className="space-y-2">
      {phases.map((p) => (
        <div key={p.phase} className="rounded-xl border border-line-1 bg-surface-100 shadow-e1 overflow-hidden">
          <div className="flex items-center gap-2 border-b border-line-1 bg-surface-200 px-4 py-2">
            <TrendingUp className="h-4 w-4 text-rose-600 dark:text-rose-400" />
            <h3 className="text-sm font-semibold text-heading">{p.phase}</h3>
            <span className="ml-auto text-micro font-mono uppercase text-muted">
              {p.techniques.length} technique{p.techniques.length === 1 ? '' : 's'}
            </span>
          </div>
          <ul className="divide-y divide-line-1 dark:divide-slate-800/60">
            {p.techniques.map((t) => (
              <li key={t.id} className="flex items-start gap-3 px-4 py-2.5">
                <span className="mt-0.5 inline-flex h-5 items-center rounded border border-violet-300 dark:border-violet-800 bg-violet-50 dark:bg-violet-950/40 px-1.5 text-micro font-mono uppercase tracking-wider text-violet-700 dark:text-violet-300">
                  {t.id}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-heading">{t.name}</p>
                  {t.evidence && <p className="mt-0.5 text-xs text-muted line-clamp-2">{t.evidence}</p>}
                </div>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

function FiveWTab({ fiveW }: { fiveW: FiveW | null }): JSX.Element {
  if (!fiveW) return <EmptyTab msg="No 5W analysis was generated." />;
  const questions: Array<{ q: string; a: string; icon: typeof Users }> = [
    { q: 'Who', a: fiveW.who, icon: Users },
    { q: 'What', a: fiveW.what, icon: Target },
    { q: 'When', a: fiveW.when, icon: Calendar },
    { q: 'Where', a: fiveW.where, icon: Globe2 },
    { q: 'Why', a: fiveW.why, icon: Eye },
  ];
  return (
    <div className="surface-card p-5 space-y-3">
      <p className="text-micro font-mono uppercase tracking-wider text-rose-600 dark:text-rose-400">
        5W Analysis · AI confidence {fmtConfidence(fiveW.confidence)}
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {questions.map(({ q, a, icon: Icon }) => (
          <div key={q} className="rounded border border-line-1 bg-surface-200 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Icon className="h-3.5 w-3.5 text-muted" />
              <p className="text-micro font-mono uppercase tracking-wider text-muted">{q}</p>
            </div>
            <p className="text-sm text-heading">{a || '-'}</p>
          </div>
        ))}
      </div>
      {fiveW.attribution_basis && (
        <div className="rounded border border-line-1 bg-surface-200 p-3">
          <p className="text-micro font-mono uppercase tracking-wider text-muted mb-1">Attribution basis</p>
          <p className="text-sm text-body">{fiveW.attribution_basis}</p>
        </div>
      )}
    </div>
  );
}

function EmptyTab({ msg }: { msg: string }): JSX.Element {
  return <div className="rounded-xl border border-line-1 bg-surface-200 p-8 text-center text-sm text-muted">{msg}</div>;
}

// ── TI-Mindmap-Hub MCP integration ────────────────────────────
// Browser-side client for https://mcp.ti-mindmap-hub.com/mcp (JSON-RPC over
// HTTPS + SSE). The API key is stored in localStorage and never reaches our
// backend - the MCP server validates it directly. Components below:
//   - McpStatusBanner : read-only status, key editing lives in the global TopBar
//   - McpSearchPanel  : free-text search across reports / IOCs / CVEs
//   - IocEnrichment   : per-IOC lookup result chip rendered next to each row

type McpMode = 'report' | 'ioc' | 'cve';
type McpStatus = 'idle' | 'probing' | 'connected' | 'error' | 'unconfigured';

interface McpSearchHit {
  ioc?: IocSearchResult;
  cve?: CveSearchResult;
  reports?: ListReportsResult;
}

function McpSearchPanel(props: { apiKey: string; status: McpStatus }): JSX.Element {
  const [mode, setMode] = useState<McpMode>('ioc');
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);
  const [hit, setHit] = useState<McpSearchHit | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const disabled = !props.apiKey || props.status !== 'connected' || !q.trim() || busy;

  async function run(): Promise<void> {
    if (disabled) return;
    setBusy(true);
    setErr(null);
    setHit(null);
    try {
      if (mode === 'ioc') {
        const r = await searchIoc(props.apiKey, q.trim());
        setHit({ ioc: r });
      } else if (mode === 'cve') {
        const r = await searchCve(props.apiKey, q.trim().toUpperCase());
        setHit({ cve: r });
      } else {
        const r = await listReports(props.apiKey, { search: q.trim(), limit: 8 });
        setHit({ reports: r });
      }
    } catch (e) {
      console.error('run failed:', errMessage(e));
      const msg = e instanceof McpError ? e.message : errMessage(e);
      setErr(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-3 surface-card p-4">
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <Search className="h-4 w-4 text-rose-600 dark:text-rose-400" />
        <h3 className="text-sm font-semibold text-heading">Cross-Source Search</h3>
        <span className="ml-auto text-micro font-mono uppercase text-muted">via TI-Mindmap-Hub MCP · 25 tools</span>
      </div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run();
        }}
        className="flex flex-wrap items-center gap-2"
      >
        <div className="flex rounded border border-line-2 overflow-hidden text-xs font-mono">
          {(['ioc', 'cve', 'report'] as McpMode[]).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className={`px-2.5 py-1.5 ${mode === m ? 'bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300' : 'bg-white dark:bg-surface-200 text-body hover:bg-slate-50 dark:hover:bg-surface-300'}`}
            >
              {m}
            </button>
          ))}
        </div>
        <input
          type="text"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={
            mode === 'ioc'
              ? '8.8.8.8 · evil.com · sha256…'
              : mode === 'cve'
                ? 'CVE-2025-55182'
                : 'ransomware · lazarus · apt29'
          }
          className="flex-1 min-w-[12rem] rounded border border-line-2 bg-surface-100 px-2.5 py-1.5 font-mono text-sm text-heading"
          autoComplete="off"
          spellCheck={false}
        />
        <button
          type="submit"
          disabled={disabled}
          className="inline-flex items-center gap-1.5 rounded border border-rose-300 dark:border-rose-500/40 bg-rose-600 dark:bg-rose-500 px-3 py-1.5 text-sm font-medium text-on-fill hover:bg-rose-700 disabled:opacity-50 transition-colors"
        >
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
          search
        </button>
      </form>

      {!props.apiKey && (
        <p className="mt-3 text-xs text-muted">
          Add your TI-Mindmap-Hub API key above to enable cross-source lookups. Keys stay in your browser (localStorage)
          - they are never sent to our backend.
        </p>
      )}

      {err && (
        <div className="mt-3 rounded border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/40 p-2.5 text-xs text-rose-700 dark:text-rose-300">
          <AlertTriangle className="inline h-3.5 w-3.5 mr-1" /> {err}
        </div>
      )}

      {hit && (
        <div className="mt-3 space-y-2">
          {hit.ioc && <IocHitCard hit={hit.ioc} />}
          {hit.cve && <CveHitCard hit={hit.cve} />}
          {hit.reports && <ReportsHitCard hit={hit.reports} />}
        </div>
      )}
    </div>
  );
}

function IocHitCard({ hit }: { hit: IocSearchResult }): JSX.Element {
  const reports = hit.reports ?? [];
  return (
    <div className="rounded border border-line-1 bg-surface-200 p-3">
      <p className="text-micro font-mono uppercase tracking-wider text-muted mb-1">
        IOC search · <span className="text-heading">{hit.ioc_value}</span>
        {hit.ioc_type && <span className="ml-2 rounded border border-line-2 px-1.5 py-0.5">{hit.ioc_type}</span>}
        {typeof hit.total_reports === 'number' && (
          <span className="ml-2 text-emerald-600 dark:text-emerald-400">
            {hit.total_reports} report{hit.total_reports === 1 ? '' : 's'}
          </span>
        )}
      </p>
      {reports.length === 0 ? (
        <p className="text-xs text-muted">No reports mention this indicator.</p>
      ) : (
        <ul className="space-y-1.5">
          {reports.slice(0, 5).map((r) => (
            <ReportRow key={r.report_id} r={r} />
          ))}
          {reports.length > 5 && <li className="text-xs text-muted">+ {reports.length - 5} more reports</li>}
        </ul>
      )}
    </div>
  );
}

function CveHitCard({ hit }: { hit: CveSearchResult }): JSX.Element {
  return (
    <div className="rounded border border-line-1 bg-surface-200 p-3">
      <p className="text-micro font-mono uppercase tracking-wider text-muted mb-1">
        CVE · <span className="text-heading">{hit.cve_id}</span>
        {hit.severity && (
          <span className="ml-2 rounded border border-amber-300 dark:border-amber-700 px-1.5 py-0.5 text-amber-700 dark:text-amber-300">
            {hit.severity}
          </span>
        )}
        {typeof hit.cvss_score === 'number' && <span className="ml-2 font-mono">CVSS {hit.cvss_score.toFixed(1)}</span>}
        {typeof hit.epss_score === 'number' && (
          <span className="ml-2 font-mono">EPSS {(hit.epss_score * 100).toFixed(1)}%</span>
        )}
        {hit.exploited && (
          <span className="ml-2 rounded border border-rose-300 dark:border-rose-700 px-1.5 py-0.5 text-rose-700 dark:text-rose-300">
            KEV
          </span>
        )}
      </p>
      {hit.description && <p className="text-xs text-body line-clamp-3">{hit.description}</p>}
      {hit.references && hit.references.length > 0 && (
        <ul className="mt-2 space-y-0.5">
          {hit.references.slice(0, 3).map((ref, i) => (
            <li key={i} className="text-micro text-muted truncate font-mono">
              <LinkIcon className="inline h-2.5 w-2.5 mr-1" />
              {ref}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ReportsHitCard({ hit }: { hit: ListReportsResult }): JSX.Element {
  const reports = hit.reports ?? [];
  return (
    <div className="rounded border border-line-1 bg-surface-200 p-3">
      <p className="text-micro font-mono uppercase tracking-wider text-muted mb-1">
        Reports · {reports.length} match{reports.length === 1 ? '' : 'es'}
        {typeof hit.total === 'number' && hit.total !== reports.length && (
          <span className="ml-1 text-muted">(of {hit.total} total)</span>
        )}
      </p>
      {reports.length === 0 ? (
        <p className="text-xs text-muted">No matching reports.</p>
      ) : (
        <ul className="space-y-1.5">
          {reports.slice(0, 6).map((r) => (
            <ReportRow key={r.report_id} r={r} />
          ))}
        </ul>
      )}
    </div>
  );
}

function ReportRow({ r }: { r: TiReportSummary }): JSX.Element {
  return (
    <li className="rounded border border-line-1 bg-surface-100 px-2.5 py-1.5">
      <p className="text-xs font-medium text-heading line-clamp-2">{r.title ?? r.report_id}</p>
      <p className="mt-0.5 text-micro font-mono uppercase text-muted">
        {r.source ?? 'unknown'} {r.published_at ? `· ${r.published_at}` : ''}
        {r.actor && <span className="ml-2 text-rose-600 dark:text-rose-400">actor: {r.actor}</span>}
        {r.cves && r.cves.length > 0 && (
          <span className="ml-2 text-amber-600 dark:text-amber-400">
            cve: {r.cves.slice(0, 2).join(', ')}
            {r.cves.length > 2 ? '…' : ''}
          </span>
        )}
      </p>
      {r.summary && <p className="mt-1 text-mini text-muted line-clamp-2">{r.summary}</p>}
    </li>
  );
}

// ── Page ─────────────────────────────────────────────────────────────
export default function AIReportShowcase(): JSX.Element {
  const [selectedId, setSelectedId] = useState<string>(SAMPLE_REPORTS[0]?.id ?? '');
  const [data, setData] = useState<AnalyzerOutput | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<TabId>('summary');
  const [startedAt, setStartedAt] = useState<number | null>(null);

  // ── TI-Mindmap-Hub MCP state ──────────────────────────────────────
  const [apiKey, setApiKey] = useState<string>('');
  const [mcpStatus, setMcpStatus] = useState<McpStatus>('idle');

  // On mount, hydrate the key from localStorage and probe the connection.
  useEffect(() => {
    const k = getStoredApiKey();
    setApiKey(k);
    if (k) void doProbe(k);
  }, []);

  const sample = SAMPLE_REPORTS.find((r) => r.id === selectedId) ?? SAMPLE_REPORTS[0]!;

  const runAnalyzer = useMemo(() => {
    return async (report: SampleReport) => {
      setLoading(true);
      setError(null);
      setStartedAt(Date.now());
      const t0 = Date.now();
      try {
        const r = await fetch('/api/v1/report-analyzer', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ text: report.text, source: report.source, title: report.title }),
        });
        if (!r.ok) {
          const body = await r.text();
          throw new Error(`HTTP ${r.status}: ${body.slice(0, 200)}`);
        }
        const d = (await r.json()) as AnalyzerOutput;
        setData(d);
      } catch (e) {
        logCatch(e);
        const message = errMessage(e);
        setError(message || 'analysis failed');
      } finally {
        setLoading(false);
        void t0;
      }
    };
  }, []);

  // Auto-run on first mount with the default sample.
  useEffect(() => {
    if (selectedId && !data) {
      void runAnalyzer(sample);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Re-run when the user picks a different sample.
  function handleSelect(id: string) {
    setSelectedId(id);
    setData(null);
    void runAnalyzer(SAMPLE_REPORTS.find((r) => r.id === id)!);
  }

  async function doProbe(key: string): Promise<void> {
    if (!key) {
      setMcpStatus('unconfigured');
      return;
    }
    setMcpStatus('probing');
    const r = await probeConnection(key);
    if (r.ok) {
      setMcpStatus('connected');
    } else {
      setMcpStatus('error');
    }
  }

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="back to threat intel"
      icon={<Sparkles className="h-6 w-6" />}
      title="AI Report Showcase"
      description={
        <span>
          A live, in-browser demonstration of the{' '}
          <Link to="/dfir/report-analyzer" className="text-rose-600 dark:text-rose-400 hover:underline">
            Report Analyzer
          </Link>{' '}
          pipeline. Pick a sample report (or paste your own at{' '}
          <Link to="/dfir/report-analyzer" className="text-rose-600 dark:text-rose-400 hover:underline">
            /dfir/report-analyzer
          </Link>
          ) - the page runs the eight-branch AI extraction (summary, IOCs, MITRE ATT&CK TTPs, 5W, CVEs, mindmap, Diamond
          Model, STIX 2.1) and renders all 9 PDF-quality sections below.
        </span>
      }
      headerExtra={
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
          {data && !loading && (
            <span className="rounded border border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 px-2 py-1 text-emerald-700 dark:text-emerald-300 font-mono">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse mr-1.5" />
              analyzed in {fmtTime(data.elapsed_ms)}
            </span>
          )}
          {data && data.errors.length > 0 && (
            <span
              className="rounded border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-950/40 px-2 py-1 font-mono text-amber-700 dark:text-amber-300"
              title={data.errors.map((e) => `${e.branch}: ${e.message}`).join('\n')}
            >
              {data.errors.length} branch{data.errors.length > 1 ? 'es' : ''} degraded
            </span>
          )}
          {startedAt && loading && (
            <span className="rounded border border-line-2 px-2 py-1 font-mono inline-flex items-center gap-1.5">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              analyzing…
            </span>
          )}
        </div>
      }
      loading={loading && !data}
      error={error}
      onRetry={() => void runAnalyzer(sample)}
      maxWidthClass="max-w-7xl"
    >
      {/* ── Sample picker ───────────────────────────────────────────── */}
      <div className="mb-4 surface-card p-4">
        <div className="flex items-center gap-2 mb-3">
          <Beaker className="h-4 w-4 text-rose-600 dark:text-rose-400" />
          <h3 className="text-sm font-semibold text-heading">Pick a sample report</h3>
          <span className="ml-auto text-micro font-mono uppercase text-muted">
            {SAMPLE_REPORTS.length} curated samples
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {SAMPLE_REPORTS.map((r) => {
            const active = r.id === selectedId;
            return (
              <button
                key={r.id}
                type="button"
                onClick={() => handleSelect(r.id)}
                className={`text-left rounded-xl border p-3 transition-all ${
                  active
                    ? 'border-rose-500 bg-rose-50 dark:bg-rose-950/30 shadow-e2'
                    : 'border-line-1 bg-slate-50 dark:bg-input-200 hover:border-rose-400/60'
                }`}
              >
                <div className="flex items-baseline justify-between gap-2 mb-1">
                  <p className="text-sm font-medium text-heading line-clamp-2">{r.title}</p>
                  {active && <CircleDot className="h-3 w-3 text-rose-500 shrink-0" />}
                </div>
                <p className="text-micro font-mono uppercase tracking-wider text-muted mb-1">
                  {r.source} · {r.publishedAt}
                </p>
                <p className="text-xs text-muted line-clamp-2">{r.tags.slice(0, 4).join(' · ')}</p>
              </button>
            );
          })}
        </div>
        <div className="mt-3 flex items-center gap-2 text-xs text-muted">
          <span>Source:</span>
          <a
            href={sample.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline inline-flex items-center gap-1 transition-colors"
          >
            {sample.url}
            <ExternalLink className="h-3 w-3" />
          </a>
          <span className="ml-auto">
            {sample.text.length.toLocaleString()} chars · ~{Math.ceil(sample.text.length / 4).toLocaleString()} tokens
          </span>
        </div>
      </div>

      {/* ── MCP status banner (read-only; key editing lives in the TopBar) ── */}
      <div className="mb-4 space-y-3">
        <McpStatusBanner />
        <McpSearchPanel apiKey={apiKey} status={mcpStatus} />
      </div>

      {/* ── Tabs ──────────────────────────────────────────────────────── */}
      {data && (
        <>
          <div className="mb-3 flex flex-wrap gap-1.5">
            {TABS.map((t) => {
              const Icon = t.icon;
              const count =
                t.id === 'iocs'
                  ? data.iocs.length
                  : t.id === 'ttps'
                    ? data.ttp.length
                    : t.id === 'mindmap'
                      ? data.mindmap.nodes.length
                      : t.id === 'stix'
                        ? Array.isArray((data.stix?.bundle as { objects?: unknown[] })?.objects)
                          ? (data.stix?.bundle as { objects: unknown[] }).objects.length
                          : 0
                        : t.id === 'diamond'
                          ? data.diamond
                            ? data.diamond.adversary.length +
                              data.diamond.capability.length +
                              data.diamond.infrastructure.length
                            : 0
                          : t.id === 'attackflow'
                            ? data.attackFlow.length
                            : null;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setTab(t.id)}
                  className={`inline-flex items-center gap-1.5 text-mini font-mono rounded-full border px-2.5 py-1 transition-colors ${
                    tab === t.id
                      ? 'border-rose-500 bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300'
                      : 'border-slate-300 dark:border-line-1 text-muted hover:border-slate-400 dark:hover:border-slate-500'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" /> {t.label}
                  {count != null && count > 0 && <span className="opacity-60">· {count}</span>}
                </button>
              );
            })}
            <button
              type="button"
              onClick={() => void runAnalyzer(sample)}
              disabled={loading}
              className="ml-auto inline-flex items-center gap-1.5 text-mini font-mono rounded-full border border-line-2 px-2.5 py-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
              re-run
            </button>
          </div>

          {/* Tab body */}
          {tab === 'summary' && <SummaryTab data={data} sample={sample} />}
          {tab === 'mindmap' && <MindmapSimpleTab mindmap={data.mindmap} />}
          {tab === 'stix' && <StixTab data={data} />}
          {tab === 'diamond' && <DiamondTabView diamond={data.diamond} />}
          {tab === 'iocs' && <IocsTab iocs={data.iocs} apiKey={apiKey} mcpStatus={mcpStatus} />}
          {tab === 'ttps' && <TtpsTab ttp={data.ttp} />}
          {tab === 'attackflow' && <AttackFlowTabView phases={data.attackFlow} />}
          {tab === '5w' && <FiveWTab fiveW={data.fiveW} />}
        </>
      )}

      {!data && !loading && !error && (
        <div className="rounded-xl border border-line-1 bg-surface-200 p-12 text-center">
          <BookOpen className="mx-auto h-10 w-10 text-muted mb-3" />
          <p className="text-sm text-muted">Pick a sample above to begin.</p>
        </div>
      )}
    </DataPageLayout>
  );
}
