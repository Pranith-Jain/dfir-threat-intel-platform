import { errMessage, logCatch } from '../../lib/log';
import { useMemo, useState, useRef, useEffect } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  ReactFlowProvider,
  type Node,
  type Edge,
  type NodeTypes,
} from '@xyflow/react';
import dagre from 'dagre';
import '@xyflow/react/dist/style.css';
import {
  Link2,
  RefreshCw,
  FileText,
  Search,
  ExternalLink,
  AlertTriangle,
  Network,
  Bug,
  Users,
  Diamond,
  GitBranch,
  Globe2,
  Download,
  Shield,
  CheckCircle,
  Terminal,
} from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { exportAnalyzerPdf, downloadBlob, pdfFilename } from '../../lib/dfir/report-analyzer/export-pdf';
import type {
  IocKind,
  ExtractedIoc,
  TtpHit,
  ExtractedCve,
  FiveW,
  MindmapNode,
  MindmapEdge,
  DiamondModel,
  AttackFlowPhase,
  AnalyzerOutput,
} from './report-analyzer-types';
import { downloadCsv, exportIocsCsv, exportDetectionCsv } from './report-analyzer-csv';
import { turnstileHeaders } from '../../lib/turnstile';

// ── Helpers ──────────────────────────────────────────────────────────

function slug(s: string): string {
  return s.replace(/[^a-z0-9]/gi, '_').slice(0, 60) || 'report';
}

// ── Mindmap renderer (light-mode + dark: tokens, in-page xyflow) ─────

const NODE_STYLES: Record<MindmapNode['kind'], { light: string; dark: string; ring: string }> = {
  finding: {
    light: 'border-slate-400 bg-slate-50 text-slate-900',
    dark: 'dark:border-line-2 dark:bg-surface-200 dark:text-slate-100',
    ring: '#64748b',
  },
  actor: {
    light: 'border-rose-300 bg-rose-50 text-rose-900',
    dark: 'dark:border-rose-700 dark:bg-rose-950/50 dark:text-rose-100',
    ring: '#e11d48',
  },
  malware: {
    light: 'border-orange-300 bg-orange-50 text-orange-900',
    dark: 'dark:border-orange-700 dark:bg-orange-950/50 dark:text-orange-100',
    ring: '#ea580c',
  },
  ttp: {
    light: 'border-violet-300 bg-violet-50 text-violet-900',
    dark: 'dark:border-violet-700 dark:bg-violet-950/50 dark:text-violet-100',
    ring: '#7c3aed',
  },
  ioc: {
    light: 'border-sky-300 bg-sky-50 text-sky-900',
    dark: 'dark:border-sky-700 dark:bg-sky-950/50 dark:text-sky-100',
    ring: '#0284c7',
  },
  cve: {
    light: 'border-amber-300 bg-amber-50 text-amber-900',
    dark: 'dark:border-amber-700 dark:bg-amber-950/50 dark:text-amber-100',
    ring: '#d97706',
  },
};

function MindmapNode({ data }: { data: { label: string; kind: MindmapNode['kind']; subtitle?: string } }) {
  const s = NODE_STYLES[data.kind] ?? NODE_STYLES.finding;
  return (
    <div
      className={`rounded-xl border-2 px-2.5 py-1.5 text-xs font-mono shadow-e1 bg-surface-100 ${s.light} ${s.dark}`}
      style={{ minWidth: 100, maxWidth: 220 }}
    >
      <Handle type="target" position={Position.Top} style={{ background: s.ring, width: 6, height: 6 }} />
      <div className="font-semibold leading-tight">{data.label}</div>
      {data.subtitle && <div className="text-micro opacity-70 mt-0.5">{data.subtitle}</div>}
      <Handle type="source" position={Position.Bottom} style={{ background: s.ring, width: 6, height: 6 }} />
    </div>
  );
}

const NODE_TYPES: NodeTypes = { mindmap: MindmapNode };

function layoutNodes(rawNodes: MindmapNode[], rawEdges: MindmapEdge[]): { nodes: Node[]; edges: Edge[] } {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: 'LR', nodesep: 30, ranksep: 60 });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of rawNodes) g.setNode(n.id, { width: 180, height: 36 });
  for (const e of rawEdges) g.setEdge(e.source, e.target);
  dagre.layout(g);
  const nodes: Node[] = rawNodes.map((n) => {
    const pos = g.node(n.id);
    return {
      id: n.id,
      type: 'mindmap',
      position: { x: pos.x - 90, y: pos.y - 18 },
      data: { label: n.label, kind: n.kind, subtitle: n.kind === 'ttp' ? '' : n.kind },
    };
  });
  const edges: Edge[] = rawEdges.map((e, i) => ({
    id: `e-${i}`,
    source: e.source,
    target: e.target,
    label: e.label,
    type: 'smoothstep',
    style: { stroke: '#94a3b8', strokeWidth: 1.5 },
    labelStyle: { fontSize: 10, fontFamily: 'monospace' },
  }));
  return { nodes, edges };
}

// ── Page ──────────────────────────────────────────────────────────────

const TABS = [
  'summary',
  'detection',
  'conclusion',
  'iocs',
  'ttps',
  'cves',
  '5w',
  'diamond',
  'attackflow',
  'heatmap',
  'mindmap',
  'stix',
  'source',
  'timeline',
] as const;
type Tab = (typeof TABS)[number];

const TAB_META: Record<Tab, { label: string; icon: React.ReactNode }> = {
  summary: { label: 'Summary', icon: <FileText className="h-3.5 w-3.5" /> },
  detection: { label: 'Detection', icon: <Shield className="h-3.5 w-3.5" /> },
  conclusion: { label: 'Conclusion', icon: <CheckCircle className="h-3.5 w-3.5" /> },
  iocs: { label: 'IOCs', icon: <Link2 className="h-3.5 w-3.5" /> },
  ttps: { label: 'TTPs', icon: <Bug className="h-3.5 w-3.5" /> },
  cves: { label: 'CVEs', icon: <AlertTriangle className="h-3.5 w-3.5" /> },
  '5w': { label: '5W', icon: <Users className="h-3.5 w-3.5" /> },
  mindmap: { label: 'Mindmap', icon: <Network className="h-3.5 w-3.5" /> },
  stix: { label: 'STIX', icon: <Globe2 className="h-3.5 w-3.5" /> },
  diamond: { label: 'Diamond', icon: <Diamond className="h-3.5 w-3.5" /> },
  attackflow: { label: 'Attack Flow', icon: <GitBranch className="h-3.5 w-3.5" /> },
  heatmap: { label: 'ATT&CK Heatmap', icon: <Search className="h-3.5 w-3.5" /> },
  source: { label: 'Source', icon: <Terminal className="h-3.5 w-3.5" /> },
  timeline: { label: 'Timeline', icon: <GitBranch className="h-3.5 w-3.5" /> },
};

const IOC_PILL: Record<IocKind, string> = {
  ip: 'text-sky-700 dark:text-sky-300 bg-cyan-50 dark:bg-cyan-950/40 border-cyan-300 dark:border-cyan-800',
  ipv6: 'text-teal-700 dark:text-teal-300 bg-teal-50 dark:bg-teal-950/40 border-teal-300 dark:border-teal-800',
  url: 'text-purple-700 dark:text-purple-300 bg-purple-50 dark:bg-purple-950/40 border-purple-300 dark:border-purple-800',
  domain: 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800',
  hash: 'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800',
  cve: 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
  email: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
  'file-path':
    'text-indigo-700 dark:text-indigo-300 bg-indigo-50 dark:bg-indigo-950/40 border-indigo-300 dark:border-indigo-800',
  directory:
    'text-fuchsia-700 dark:text-fuchsia-300 bg-fuchsia-50 dark:bg-fuchsia-950/40 border-fuchsia-300 dark:border-fuchsia-800',
};
const CONFIDENCE_PILL: Record<'high' | 'medium' | 'low', string> = {
  high: 'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800',
  medium: 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800',
  low: 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
};

/**
 * Report Analyzer - paste a URL or text, get a unified per-report
 * analysis: AI summary, IOCs (with allowlist filtering + confidence),
 * MITRE ATT&CK TTPs (LLM + keyword merged), CVEs, 5W context, an
 * auto-generated mindmap, and a STIX 2.1 bundle.
 *
 * Single round-trip to /api/v1/report-analyzer, which fans out the
 * four LLM branches in parallel and applies the same ioc-normalize
 * pipeline as the live feeds.
 */
export default function ReportAnalyzer(): JSX.Element {
  const [inputText, setInputText] = useState('');
  const [inputUrl, setInputUrl] = useState('');
  const [imageUrls, setImageUrls] = useState('');
  const [includeStix, setIncludeStix] = useState(false);
  const [data, setData] = useState<AnalyzerOutput | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<Tab>('summary');
  const [filter, setFilter] = useState('');
  const [correlations, setCorrelations] = useState<Record<
    string,
    { count: number; reports: Array<{ id: string; title: string; created_at: string }> }
  > | null>(null);
  const [correlating, setCorrelating] = useState(false);
  const [pdfExporting, setPdfExporting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const run = async () => {
    if (!inputText.trim() && !inputUrl.trim()) {
      setError('Provide a URL or paste text.');
      return;
    }
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    setData(null);
    try {
      const body: Record<string, unknown> = {};
      if (inputText.trim()) body.text = inputText;
      if (inputUrl.trim()) body.url = inputUrl;
      const imgs = imageUrls
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (imgs.length > 0) body.imageUrls = imgs;
      if (includeStix) body.includeStix = true;
      const res = await fetch('/api/v1/report-analyzer', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.any([ac.signal, AbortSignal.timeout(60_000)]),
      });
      if (!res.ok) {
        const j = (await res.json().catch(() => ({}))) as { message?: string };
        throw new Error(j.message ?? `HTTP ${res.status}`);
      }
      setData((await res.json()) as AnalyzerOutput);
    } catch (e) {
      logCatch(e);
      // A superseded run (re-click while in-flight) or unmount aborts this
      // controller — expected control flow, never surface it as an error.
      if (ac.signal.aborted) return;
      setError(errMessage(e));
    } finally {
      if (!ac.signal.aborted) setLoading(false);
    }
  };

  const exportPdf = async () => {
    if (!data) return;
    setPdfExporting(true);
    try {
      const blob = await exportAnalyzerPdf(data);
      downloadBlob(blob, pdfFilename(data));
    } catch (e) {
      logCatch(e);
      setError(errMessage(e));
    } finally {
      setPdfExporting(false);
    }
  };

  const exportMarkdown = async () => {
    if (!data) return;
    try {
      const res = await fetch('/api/v1/report-analyzer/render', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ output: data }),
        signal: AbortSignal.timeout(60_000),
      });
      if (!res.ok) throw new Error(`render failed: ${res.status}`);
      const json = (await res.json()) as { markdown?: string };
      if (!json.markdown) throw new Error('render returned no markdown');
      downloadBlob(new Blob([json.markdown], { type: 'text/markdown' }), `${slug(data.title)}.md`);
    } catch (e) {
      logCatch(e);
      setError(errMessage(e));
    }
  };

  const saveReportHandler = async () => {
    if (!data) return;
    setSaving(true);
    setSavedMsg(null);
    try {
      const res = await fetch('/api/v1/saved-reports', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(await turnstileHeaders('save-report')) },
        body: JSON.stringify({
          title: data.title,
          sourceUrl: inputUrl || undefined,
          sourceText: data.sourceText || undefined,
          reportJson: JSON.stringify(data),
        }),
        signal: AbortSignal.timeout(60_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const j = (await res.json()) as { id: string };
      setSavedMsg(`Saved as ${j.id.slice(0, 8)}…`);
    } catch (e) {
      logCatch(e);
      setError(errMessage(e));
    } finally {
      setSaving(false);
    }
  };

  const checkCorrelations = async () => {
    if (!data || data.iocs.length === 0) return;
    setCorrelating(true);
    try {
      const iocValues = data.iocs.map((i) => i.value).slice(0, 20);
      const res = await fetch('/api/v1/saved-reports/correlate', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(await turnstileHeaders('correlate-report')) },
        body: JSON.stringify({ iocs: iocValues }),
        signal: AbortSignal.timeout(60_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const j = (await res.json()) as {
        correlations: Record<
          string,
          { count: number; reports: Array<{ id: string; title: string; created_at: string }> }
        >;
      };
      setCorrelations(Object.keys(j.correlations).length > 0 ? j.correlations : null);
    } catch (_catchErr) {
      logCatch(_catchErr);
      // Silently fail - correlation is best-effort
    } finally {
      setCorrelating(false);
    }
  };

  return (
    <DataPageLayout
      backTo="/dfir"
      backLabel="back to threat intel"
      icon={<FileText className="h-6 w-6" />}
      title="Report Analyzer"
      description="Paste a report URL or text. The analyzer runs AI summary, IOC extraction, MITRE ATT&CK TTP mapping, 5W context, CVE extraction, image-OCR, detection opportunities, conclusion with recommendations, and a STIX 2.1 bundle - in a single round-trip."
      maxWidthClass="max-w-6xl"
    >
      {/* Input card */}
      <section className="surface-card p-4 mb-4">
        <div className="grid gap-3 md:grid-cols-3">
          <div className="md:col-span-2">
            <label
              htmlFor="report-analyzer-text"
              className="text-micro font-mono uppercase tracking-wider text-muted block mb-1"
            >
              Paste report text
            </label>
            <textarea
              id="report-analyzer-text"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Paste the report here. Plain text or markdown. Up to 80KB."
              className="w-full h-40 rounded border border-line-2 bg-surface-200 p-2 text-sm font-mono text-heading placeholder:text-muted focus:border-brand-500/60 focus:outline-none"
            />
          </div>
          <div>
            <label
              htmlFor="report-analyzer-url"
              className="text-micro font-mono uppercase tracking-wider text-muted block mb-1"
            >
              …or fetch from URL
            </label>
            <input
              id="report-analyzer-url"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              placeholder="https://example.com/report"
              className="w-full rounded border border-line-2 bg-surface-200 p-2 text-sm font-mono text-heading placeholder:text-muted focus:border-brand-500/60 focus:outline-none"
            />
            <p className="mt-1 text-mini text-muted leading-snug">
              Works best with server-rendered pages (Arctic Wolf, vendor blogs). JS-rendered sites (CISA, Mandiant,
              CrowdStrike) may return minimal content - paste the text directly for best results.
            </p>
            <label
              htmlFor="report-analyzer-images"
              className="text-micro font-mono uppercase tracking-wider text-muted block mb-1 mt-3"
            >
              Image URLs to OCR (one per line, optional)
            </label>
            <textarea
              id="report-analyzer-images"
              value={imageUrls}
              onChange={(e) => setImageUrls(e.target.value)}
              placeholder="https://example.com/screenshot1.png"
              className="w-full h-20 rounded border border-line-2 bg-surface-200 p-2 text-xs font-mono text-heading placeholder:text-muted focus:border-brand-500/60 focus:outline-none"
            />
            <div className="mt-3 flex items-start gap-2 text-xs text-muted">
              <input
                id="report-analyzer-stix"
                type="checkbox"
                checked={includeStix}
                onChange={(e) => setIncludeStix(e.target.checked)}
                className="mt-0.5 h-3.5 w-3.5 rounded border-line-2 text-brand-500 focus:ring-brand-500"
                aria-label="Include STIX bundle"
              />
              <label htmlFor="report-analyzer-stix" className="cursor-pointer">
                <span className="font-mono uppercase tracking-wider text-muted block">Include STIX bundle</span>
                <span className="block mt-0.5 normal-case">
                  Off by default - STIX enrichment (Maltiverse / RDAP / NVD) can exceed the free-plan subrequest budget
                  on larger reports. Turn on for short / high-value reports where you specifically need the STIX tab
                  populated.
                </span>
              </label>
            </div>
            <button
              type="button"
              onClick={run}
              disabled={loading}
              className="mt-3 w-full inline-flex items-center justify-center gap-2 rounded-xl border border-brand-500 bg-brand-500 text-on-fill px-3 py-2 text-sm font-medium hover:bg-brand-600 transition-colors disabled:opacity-50"
            >
              {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              {loading ? 'Analyzing…' : 'Run analyzer'}
            </button>
          </div>
        </div>
        {error && (
          <div className="mt-3 flex items-start gap-2 rounded border border-rose-300 dark:border-rose-700 bg-rose-50 dark:bg-rose-950/30 p-2 text-sm text-rose-700 dark:text-rose-200">
            <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </section>

      {/* Results */}
      {data && (
        <>
          {/* Status bar */}
          <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-muted">
            <span className="rounded border border-line-2 px-2 py-1 font-mono">
              title <span className="text-body">{data.title}</span>
            </span>
            <span className="rounded border border-line-2 px-2 py-1 font-mono">
              {data.textLength.toLocaleString()} chars
            </span>
            <span className="rounded border border-line-2 px-2 py-1 font-mono">{data.elapsed_ms} ms</span>
            {data.errors.length > 0 && (
              <span
                className="rounded border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-950/40 px-2 py-1 font-mono text-amber-700 dark:text-amber-300"
                title={data.errors.map((e) => `${e.branch}: ${e.message}`).join('\n')}
              >
                {data.errors.length} branch{data.errors.length > 1 ? 'es' : ''} degraded
              </span>
            )}
            <button
              type="button"
              onClick={exportPdf}
              disabled={pdfExporting}
              className="ml-auto inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1 font-mono text-xs text-muted hover:border-brand-500/50 hover:text-brand-600 dark:hover:text-brand-400 transition-colors disabled:opacity-50"
            >
              {pdfExporting ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
              {pdfExporting ? 'exporting…' : 'export PDF'}
            </button>
            <button
              type="button"
              onClick={exportMarkdown}
              className="shrink-0 inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1 font-mono text-xs text-muted hover:border-brand-500/50 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
            >
              <Download className="h-3 w-3" /> MD
            </button>
            <button
              type="button"
              onClick={saveReportHandler}
              disabled={saving}
              className="shrink-0 inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1 font-mono text-xs text-muted hover:border-brand-500/50 hover:text-brand-600 dark:hover:text-brand-400 transition-colors disabled:opacity-50"
            >
              {saving ? <RefreshCw className="h-3 w-3 animate-spin" /> : <CheckCircle className="h-3 w-3" />}
              {saving ? 'saving…' : (savedMsg ?? 'save')}
            </button>
            <button
              type="button"
              onClick={checkCorrelations}
              disabled={correlating}
              className="shrink-0 inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1 font-mono text-xs text-muted hover:border-brand-500/50 hover:text-brand-600 dark:hover:text-brand-400 transition-colors disabled:opacity-50"
            >
              {correlating ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Network className="h-3 w-3" />}
              {correlating ? 'checking…' : 'correlate'}
            </button>
          </div>

          {/* Correlation results */}
          {correlations && (
            <div className="mb-3 rounded-xl border border-amber-200 dark:border-amber-900/60 bg-amber-50/40 dark:bg-amber-950/20 p-3">
              <div className="flex items-center gap-2 mb-2">
                <Network className="h-4 w-4 text-amber-600 dark:text-amber-400" />
                <span className="text-sm font-semibold text-amber-800 dark:text-amber-200">
                  Cross-Report Correlations
                </span>
                <span className="text-xs text-amber-600 dark:text-amber-400">
                  {Object.keys(correlations).length} IOC{Object.keys(correlations).length !== 1 ? 's' : ''} found in
                  multiple reports
                </span>
              </div>
              <div className="space-y-2">
                {Object.entries(correlations).map(([ioc, corr]) => (
                  <div
                    key={ioc}
                    className="rounded border border-amber-200 dark:border-amber-800 bg-surface-100 dark:bg-amber-950/30 p-2"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <code className="font-mono text-sm font-semibold text-amber-900 dark:text-amber-100">{ioc}</code>
                      <span className="text-xs text-amber-600 dark:text-amber-400">
                        appeared in {corr.count} reports
                      </span>
                    </div>
                    <div className="text-xs text-amber-700 dark:text-amber-300">
                      {corr.reports.map((r) => r.title).join(' · ')}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tabs */}
          <div className="mb-3 flex flex-wrap gap-1.5">
            {TABS.map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTab(t)}
                className={`inline-flex items-center gap-1.5 text-mini font-mono rounded-full border px-2.5 py-1 transition-colors ${
                  tab === t
                    ? 'border-brand-500 bg-brand-50 dark:bg-brand-950/40 text-brand-700 dark:text-brand-300'
                    : 'border-slate-300 dark:border-line-1 text-muted hover:border-slate-400 dark:hover:border-slate-500'
                }`}
              >
                {TAB_META[t].icon} {TAB_META[t].label}
                {t === 'iocs' && data.iocs.length > 0 && <span className="opacity-60">· {data.iocs.length}</span>}
                {t === 'ttps' && data.ttp.length > 0 && <span className="opacity-60">· {data.ttp.length}</span>}
                {t === 'cves' && data.cves.length > 0 && <span className="opacity-60">· {data.cves.length}</span>}
                {t === 'detection' && data.detection && data.detection.siemRules.length > 0 && (
                  <span className="opacity-60">· {data.detection.siemRules.length}</span>
                )}
                {t === 'conclusion' && data.conclusion && data.conclusion.recommendedActions.length > 0 && (
                  <span className="opacity-60">· {data.conclusion.recommendedActions.length}</span>
                )}
                {t === 'mindmap' && data.mindmap.nodes.length > 0 && (
                  <span className="opacity-60">· {data.mindmap.nodes.length}</span>
                )}
                {t === 'stix' && data.stix && (
                  <span className="opacity-60">
                    ·{' '}
                    {Array.isArray((data.stix.bundle as { objects?: unknown[] }).objects)
                      ? (data.stix.bundle as { objects: unknown[] }).objects.length
                      : 0}
                  </span>
                )}
                {t === 'heatmap' && data.ttp.length > 0 && <span className="opacity-60">· {data.ttp.length}</span>}
              </button>
            ))}
          </div>

          {/* Tab body */}
          {tab === 'summary' && <SummaryTab data={data} />}
          {tab === 'detection' && <DetectionTab detection={data.detection} />}
          {tab === 'conclusion' && <ConclusionTab conclusion={data.conclusion} />}
          {tab === 'iocs' && <IocsTab iocs={data.iocs} filter={filter} setFilter={setFilter} />}
          {tab === 'ttps' && <TtpsTab ttp={data.ttp} filter={filter} setFilter={setFilter} />}
          {tab === 'cves' && <CvesTab cves={data.cves} filter={filter} setFilter={setFilter} />}
          {tab === '5w' && <FiveWTab fiveW={data.fiveW} />}
          {tab === 'mindmap' && <MindmapTab mindmap={data.mindmap} />}
          {tab === 'stix' && <StixTab data={data} />}
          {tab === 'diamond' && <DiamondTab diamond={data.diamond} />}
          {tab === 'attackflow' && <AttackFlowTab phases={data.attackFlow} />}
          {tab === 'heatmap' && <HeatmapTab ttp={data.ttp} />}
          {tab === 'source' && <SourceTab url={inputUrl} data={data} />}
          {tab === 'timeline' && <TimelineTab />}
        </>
      )}
    </DataPageLayout>
  );
}

// ── Tab bodies ────────────────────────────────────────────────────────

function FilterInput({
  value,
  setValue,
  placeholder,
}: {
  value: string;
  setValue: (v: string) => void;
  placeholder: string;
}) {
  return (
    <div className="relative mb-3">
      <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded border border-line-2 bg-surface-100 py-1.5 pl-9 pr-3 text-sm text-heading placeholder:text-muted focus:border-brand-500/60 focus:outline-none"
      />
    </div>
  );
}

function SummaryTab({ data }: { data: AnalyzerOutput }) {
  if (!data.summary) {
    return <EmptyState message="Summary branch failed. Check the degraded-branches badge for details." />;
  }
  return (
    <section className="surface-card p-4">
      <div className="text-micro font-mono uppercase tracking-wider text-muted mb-2">
        model <span className="text-body">{data.summary.model}</span>
      </div>
      <p className="text-sm text-body leading-relaxed whitespace-pre-wrap">{data.summary.text}</p>
    </section>
  );
}

function IocsTab({
  iocs,
  filter,
  setFilter,
}: {
  iocs: ExtractedIoc[];
  filter: string;
  setFilter: (v: string) => void;
}) {
  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return iocs;
    return iocs.filter((i) => `${i.value} ${i.kind} ${i.evidence}`.toLowerCase().includes(q));
  }, [iocs, filter]);
  if (iocs.length === 0) return <EmptyState message="No indicators survived allowlist filtering." />;
  return (
    <section className="surface-card p-4">
      <div className="flex items-start gap-2">
        <div className="flex-1">
          <FilterInput value={filter} setValue={setFilter} placeholder={`Filter ${iocs.length} IOCs…`} />
        </div>
        <button
          type="button"
          onClick={() => downloadCsv('iocs.csv', exportIocsCsv(iocs))}
          className="shrink-0 mt-0.5 inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1.5 text-xs font-mono text-muted hover:border-brand-500/50 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
        >
          <Download className="h-3 w-3" /> CSV
        </button>
        <button
          type="button"
          onClick={() =>
            downloadBlob(new Blob([JSON.stringify(iocs, null, 2)], { type: 'application/json' }), 'iocs.json')
          }
          className="shrink-0 mt-0.5 inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1.5 text-xs font-mono text-muted hover:border-brand-500/50 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
        >
          <Download className="h-3 w-3" /> JSON
        </button>
      </div>
      <ul className="space-y-1.5">
        {filtered.map((i, idx) => (
          <li
            key={`${i.kind}-${i.value}-${idx}`}
            className="flex flex-wrap items-center gap-2 border-b border-line-1/60 pb-1.5 last:border-b-0"
          >
            <span
              className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${IOC_PILL[i.kind]}`}
            >
              {i.kind}
            </span>
            <span
              className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${CONFIDENCE_PILL[i.confidence_band]}`}
            >
              {Math.round(i.confidence * 100)}%
            </span>
            {i.maltiverse && (
              <span
                className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${
                  i.maltiverse.verdict === 'malicious'
                    ? 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800'
                    : i.maltiverse.verdict === 'suspicious'
                      ? 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800'
                      : 'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800'
                }`}
                title={i.maltiverse.classification ? `classification: ${i.maltiverse.classification}` : ''}
              >
                {i.maltiverse.verdict} {i.maltiverse.score > 0 ? `(${i.maltiverse.score})` : ''}
              </span>
            )}
            {i.source === 'image-ocr' && (
              <span className="text-micro font-mono rounded border border-line-2 px-1.5 py-0.5 text-muted">ocr</span>
            )}
            <code className="font-mono text-sm text-heading break-all">{i.value}</code>
            {i.evidence && <span className="ml-auto text-xs text-muted truncate max-w-[40%]">{i.evidence}</span>}
          </li>
        ))}
      </ul>
    </section>
  );
}

function TtpsTab({ ttp, filter, setFilter }: { ttp: TtpHit[]; filter: string; setFilter: (v: string) => void }) {
  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return ttp;
    return ttp.filter((t) => `${t.id} ${t.name} ${t.tactic} ${t.evidence}`.toLowerCase().includes(q));
  }, [ttp, filter]);
  // Group by tactic for nicer reading.
  const grouped = useMemo(() => {
    const m = new Map<string, TtpHit[]>();
    for (const t of filtered) {
      if (!m.has(t.tactic)) m.set(t.tactic, []);
      m.get(t.tactic)!.push(t);
    }
    return Array.from(m.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  }, [filtered]);
  if (ttp.length === 0) return <EmptyState message="No MITRE ATT&CK techniques identified." />;
  return (
    <section className="surface-card p-4">
      <FilterInput value={filter} setValue={setFilter} placeholder={`Filter ${ttp.length} techniques…`} />
      <div className="space-y-3">
        {grouped.map(([tactic, hits]) => (
          <div key={tactic}>
            <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">{tactic}</div>
            <ul className="space-y-1.5">
              {hits.map((t) => (
                <li key={t.id} className="flex flex-col gap-1 border-b border-line-1/60 pb-2 last:border-b-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <a
                      href={`https://attack.mitre.org/techniques/${t.id}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-sm text-brand-600 dark:text-brand-400 hover:underline transition-colors"
                    >
                      {t.id}
                    </a>
                    <span className="text-sm text-body">{t.name}</span>
                    <span
                      className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${CONFIDENCE_PILL[t.confidence]}`}
                    >
                      {t.confidence}
                    </span>
                  </div>
                  {t.evidence && <p className="text-xs text-muted ml-6 line-clamp-2">{t.evidence}</p>}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}

function CvesTab({
  cves,
  filter,
  setFilter,
}: {
  cves: ExtractedCve[];
  filter: string;
  setFilter: (v: string) => void;
}) {
  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return cves;
    return cves.filter((c) =>
      `${c.id} ${c.context} ${c.description ?? ''} ${(c.products ?? []).join(' ')}`.toLowerCase().includes(q)
    );
  }, [cves, filter]);

  const severityColor = (s?: string) => {
    if (!s) return '';
    const v = s.toUpperCase();
    if (v === 'CRITICAL')
      return 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800';
    if (v === 'HIGH')
      return 'text-orange-700 dark:text-orange-300 bg-orange-50 dark:bg-orange-950/40 border-orange-300 dark:border-orange-800';
    if (v === 'MEDIUM')
      return 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800';
    return 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800';
  };

  if (cves.length === 0) return <EmptyState message="No CVEs mentioned in the report." />;
  return (
    <section className="surface-card p-4">
      <FilterInput value={filter} setValue={setFilter} placeholder={`Filter ${cves.length} CVEs…`} />
      <div className="space-y-3">
        {filtered.map((c) => (
          <div key={c.id} className="rounded border border-line-1 bg-surface-200 p-3">
            <div className="flex flex-wrap items-center gap-2 mb-1.5">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${c.id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="font-mono text-sm font-semibold text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
              >
                {c.id} <ExternalLink className="h-3 w-3" />
              </a>
              {c.cvss_severity && (
                <span
                  className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${severityColor(c.cvss_severity)}`}
                >
                  {c.cvss_severity} {c.cvss_v3 != null ? c.cvss_v3.toFixed(1) : ''}
                </span>
              )}
              {c.in_kev && (
                <span className="text-micro font-mono rounded border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/40 px-1.5 py-0.5 text-rose-700 dark:text-rose-300">
                  KEV
                </span>
              )}
              {c.epss != null && (
                <span
                  className="text-micro font-mono rounded border border-line-2 px-1.5 py-0.5 text-body"
                  title={`EPSS percentile: ${c.epss_percentile != null ? (c.epss_percentile * 100).toFixed(1) : '?'}%`}
                >
                  EPSS {(c.epss * 100).toFixed(1)}%
                </span>
              )}
              {c.exploited_in_wild && (
                <span className="text-micro font-mono rounded border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-1.5 py-0.5 text-amber-700 dark:text-amber-300">
                  exploited
                </span>
              )}
            </div>
            {c.description && <p className="text-xs text-body mb-1.5 line-clamp-2">{c.description}</p>}
            {c.products && c.products.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-1.5">
                {c.products.map((p) => (
                  <span key={p} className="text-micro font-mono rounded border border-line-1 px-1.5 py-0.5 text-muted">
                    {p}
                  </span>
                ))}
              </div>
            )}
            <p className="text-xs text-muted line-clamp-2">{c.context}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function FiveWTab({ fiveW }: { fiveW: FiveW | null }) {
  if (!fiveW) return <EmptyState message="5W extraction failed." />;
  const rows: Array<{ label: string; value: string; wide?: boolean }> = [
    { label: 'Who', value: fiveW.who },
    { label: 'What', value: fiveW.what },
    { label: 'When', value: fiveW.when },
    { label: 'Where', value: fiveW.where },
    { label: 'Why', value: fiveW.why },
  ];
  const extraRows: Array<{ label: string; value: string }> = [];
  if (fiveW.how) extraRows.push({ label: 'How', value: fiveW.how });
  if (fiveW.so_what) extraRows.push({ label: 'So What', value: fiveW.so_what });
  if (fiveW.what_next) extraRows.push({ label: 'What Next', value: fiveW.what_next });
  return (
    <section className="surface-card p-4">
      <div className="text-micro font-mono uppercase tracking-wider text-muted mb-2">
        confidence <span className="text-body">{Math.round(fiveW.confidence * 100)}%</span>
      </div>
      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-3">
        {rows.map((r) => (
          <div key={r.label} className="rounded border border-line-1 bg-surface-200 p-2.5">
            <dt className="text-micro font-mono uppercase tracking-wider text-muted">{r.label}</dt>
            <dd className="mt-0.5 text-sm text-heading break-words">{r.value || '-'}</dd>
          </div>
        ))}
      </dl>
      {extraRows.length > 0 && (
        <div className="space-y-2">
          {extraRows.map((r) => (
            <div key={r.label} className="rounded border border-line-1 bg-surface-200 p-2.5">
              <dt className="text-micro font-mono uppercase tracking-wider text-muted">{r.label}</dt>
              <dd className="mt-0.5 text-sm text-body leading-relaxed break-words">{r.value}</dd>
            </div>
          ))}
        </div>
      )}
      {fiveW.attribution_basis && (
        <div className="mt-3 text-xs text-muted">
          <span className="font-mono uppercase tracking-wider text-muted mr-1">attribution basis:</span>
          {fiveW.attribution_basis}
        </div>
      )}
    </section>
  );
}

function DiamondTab({ diamond }: { diamond: DiamondModel | null }): JSX.Element {
  if (!diamond) {
    return (
      <div className="rounded-xl border border-line-1 bg-surface-200 p-8 text-center text-sm text-muted">
        <Diamond className="mx-auto mb-2 h-8 w-8 text-muted" />
        No adversary/capability/infrastructure/victim signal could be derived from this report.
      </div>
    );
  }
  const facets: Array<{
    pillar: 'adversary' | 'capability' | 'infrastructure' | 'victim';
    title: string;
    tone: string;
    ring: string;
    items: JSX.Element[];
  }> = [
    {
      pillar: 'adversary',
      title: 'Adversary',
      tone: 'border-rose-200 dark:border-rose-900/60 bg-rose-50/40 dark:bg-rose-950/20',
      ring: 'ring-rose-400/40',
      items:
        diamond.adversary.length === 0
          ? [
              <span key="none" className="text-xs text-muted">
                not identified in the report
              </span>,
            ]
          : diamond.adversary.map((a) => (
              <span
                key={a}
                className="inline-flex items-center rounded border border-rose-300 dark:border-rose-800 bg-surface-100 dark:bg-rose-950/40 px-2 py-0.5 text-xs font-mono text-rose-700 dark:text-rose-300"
              >
                {a}
              </span>
            )),
    },
    {
      pillar: 'capability',
      title: 'Capability',
      tone: 'border-violet-200 dark:border-violet-900/60 bg-violet-50/40 dark:bg-violet-950/20',
      ring: 'ring-violet-400/40',
      items:
        diamond.capability.length === 0
          ? [
              <span key="none" className="text-xs text-muted">
                none extracted
              </span>,
            ]
          : diamond.capability.slice(0, 8).map((c) => (
              <span
                key={c.id}
                className="inline-flex items-center gap-1 rounded border border-violet-300 dark:border-violet-800 bg-surface-100 dark:bg-violet-950/40 px-2 py-0.5 text-xs font-mono text-violet-700 dark:text-violet-300"
                title={c.tactic}
              >
                {c.id.startsWith('T') && /^T\d{4}(\.\d{3})?$/.test(c.id) ? (
                  <span className="text-micro text-muted">{c.id}</span>
                ) : null}
                <span className="truncate max-w-[180px]">{c.name}</span>
              </span>
            )),
    },
    {
      pillar: 'infrastructure',
      title: 'Infrastructure',
      tone: 'border-sky-200 dark:border-sky-900/60 bg-sky-50/40 dark:bg-sky-950/20',
      ring: 'ring-sky-400/40',
      items:
        diamond.infrastructure.length === 0
          ? [
              <span key="none" className="text-xs text-muted">
                no network IOCs
              </span>,
            ]
          : diamond.infrastructure.slice(0, 8).map((i) => (
              <span
                key={i}
                className="inline-flex items-center rounded border border-sky-300 dark:border-sky-800 bg-surface-100 dark:bg-sky-950/40 px-2 py-0.5 text-xs font-mono text-sky-700 dark:text-sky-300 truncate max-w-[200px]"
              >
                {i}
              </span>
            )),
    },
    {
      pillar: 'victim',
      title: 'Victim',
      tone: 'border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/40 dark:bg-emerald-950/20',
      ring: 'ring-emerald-400/40',
      items: [
        <div key="v" className="space-y-1 text-xs">
          <p>
            <span className="text-micro font-mono uppercase text-muted">sector</span> ·{' '}
            <span className="font-mono text-body">{diamond.victim.sector}</span>
          </p>
          <p>
            <span className="text-micro font-mono uppercase text-muted">geography</span> ·{' '}
            <span className="font-mono text-body">{diamond.victim.geography}</span>
          </p>
          <p>
            <span className="text-micro font-mono uppercase text-muted">asset</span> ·{' '}
            <span className="font-mono text-body">{diamond.victim.asset}</span>
          </p>
        </div>,
      ],
    },
  ];
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {facets.map((f) => (
        <div key={f.pillar} className={`rounded-xl border ${f.tone} p-4 shadow-e1`}>
          <div className="mb-2 flex items-center gap-2">
            <Diamond className="h-4 w-4 text-body" />
            <h3 className="text-sm font-semibold text-heading">{f.title}</h3>
            <span className="ml-auto text-micro font-mono uppercase text-muted">{f.pillar}</span>
          </div>
          <div className="flex flex-wrap gap-1.5">{f.items}</div>
        </div>
      ))}
    </div>
  );
}

function AttackFlowTab({ phases }: { phases: AttackFlowPhase[] }): JSX.Element {
  if (phases.length === 0) {
    return (
      <div className="rounded-xl border border-line-1 bg-surface-200 p-8 text-center text-sm text-muted">
        <GitBranch className="mx-auto mb-2 h-8 w-8 text-muted" />
        No TTP signal to render as a kill chain.
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {phases.map((p) => (
        <div key={p.phase} className="rounded-xl border border-line-1 bg-surface-100 shadow-e1 overflow-hidden">
          <div className="flex items-center gap-2 border-b border-line-1 bg-surface-200 px-4 py-2">
            <GitBranch className="h-4 w-4 text-brand-600 dark:text-brand-400" />
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

function MindmapTab({ mindmap }: { mindmap: { nodes: MindmapNode[]; edges: MindmapEdge[] } }) {
  const { nodes, edges } = useMemo(() => layoutNodes(mindmap.nodes, mindmap.edges), [mindmap]);
  if (mindmap.nodes.length === 0) return <EmptyState message="Mindmap is empty (no entities extracted)." />;
  return (
    <section className="surface-card" style={{ height: 540 }}>
      <ReactFlowProvider>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={NODE_TYPES}
          fitView
          proOptions={{ hideAttribution: true }}
          minZoom={0.2}
          maxZoom={2}
        >
          <Background gap={16} />
          <Controls position="bottom-right" />
          <MiniMap pannable zoomable />
        </ReactFlow>
      </ReactFlowProvider>
    </section>
  );
}

function StixTab({ data }: { data: AnalyzerOutput }) {
  const bundle = data.stix
    ? (data.stix.bundle as { type: string; id: string; objects: Array<{ type: string; id: string; name?: string }> })
    : null;
  const byType = useMemo(() => {
    if (!bundle) return [] as Array<[string, number]>;
    const m = new Map<string, number>();
    for (const o of bundle.objects) m.set(o.type, (m.get(o.type) ?? 0) + 1);
    return Array.from(m.entries()).sort((a, b) => b[1] - a[1]);
  }, [bundle]);
  if (!bundle) return <EmptyState message="STIX bundle generation failed." />;
  const downloadHref = `data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(bundle, null, 2))}`;
  return (
    <section className="surface-card p-4">
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <span className="text-micro font-mono uppercase tracking-wider text-muted">
          STIX 2.1 bundle · {bundle.objects.length} objects
        </span>
        <a
          href={downloadHref}
          download={`stix-${data.title
            .replace(/[^a-z0-9]+/gi, '-')
            .toLowerCase()
            .slice(0, 50)}.json`}
          className="ml-auto inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1 text-xs text-muted hover:border-brand-500/50 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
        >
          <Download className="h-3.5 w-3.5" /> download
        </a>
      </div>
      <div className="grid grid-cols-2 gap-2 mb-3 sm:grid-cols-3 md:grid-cols-4">
        {byType.map(([type, n]) => (
          <div key={type} className="rounded border border-line-1 bg-surface-200 px-2 py-1.5">
            <div className="text-micro font-mono uppercase tracking-wider text-muted">{type}</div>
            <div className="text-sm font-semibold text-heading">{n}</div>
          </div>
        ))}
      </div>
      <details className="rounded border border-line-1 bg-surface-200 p-2">
        <summary className="cursor-pointer text-micro font-mono uppercase tracking-wider text-muted">
          view raw JSON
        </summary>
        <pre className="mt-2 max-h-96 overflow-auto text-xs font-mono text-heading">
          {JSON.stringify(bundle, null, 2)}
        </pre>
      </details>
    </section>
  );
}

function DetectionTab({ detection }: { detection: AnalyzerOutput['detection'] }) {
  if (
    !detection ||
    (detection.siemRules.length === 0 &&
      detection.monitoringGuidance.length === 0 &&
      detection.cliCommands.length === 0)
  ) {
    return <EmptyState message="Detection opportunities extraction failed or no rules generated." />;
  }

  const severityColor: Record<string, string> = {
    critical: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
    high: 'text-orange-700 dark:text-orange-300 bg-orange-50 dark:bg-orange-950/40 border-orange-300 dark:border-orange-800',
    medium:
      'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
    low: 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800',
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <button
          type="button"
          onClick={() => downloadCsv('detection.csv', exportDetectionCsv(detection))}
          className="inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1 text-xs font-mono text-muted hover:border-brand-500/50 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
        >
          <Download className="h-3 w-3" /> export CSV
        </button>
      </div>
      {/* SIEM Rules */}
      {detection.siemRules.length > 0 && (
        <section className="surface-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="h-4 w-4 text-brand-600 dark:text-brand-400" />
            <h3 className="text-sm font-semibold text-heading">SIEM Detection Rules</h3>
            <span className="ml-auto text-micro font-mono uppercase text-muted">
              {detection.siemRules.length} rules
            </span>
          </div>
          <div className="space-y-3">
            {detection.siemRules.map((rule, i) => (
              <div key={i} className="rounded border border-line-1 bg-surface-200 p-3">
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <span className="text-sm font-medium text-heading">{rule.title}</span>
                  <span
                    className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${severityColor[rule.severity] ?? severityColor.medium}`}
                  >
                    {rule.severity}
                  </span>
                  {rule.mitreId && (
                    <span className="text-micro font-mono text-violet-600 dark:text-violet-400">{rule.mitreId}</span>
                  )}
                  {rule.platform && <span className="text-micro font-mono text-muted">{rule.platform}</span>}
                </div>
                <p className="text-xs text-body mb-2">{rule.description}</p>
                {rule.query && (
                  <pre className="text-xs font-mono text-heading bg-surface-300 rounded p-2 overflow-x-auto">
                    {rule.query}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Monitoring Guidance */}
      {detection.monitoringGuidance.length > 0 && (
        <section className="surface-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Network className="h-4 w-4 text-brand-600 dark:text-brand-400" />
            <h3 className="text-sm font-semibold text-heading">Monitoring Guidance</h3>
          </div>
          <div className="space-y-3">
            {detection.monitoringGuidance.map((cat, i) => (
              <div key={i}>
                <div className="text-micro font-mono uppercase tracking-wider text-muted mb-1">{cat.category}</div>
                <ul className="space-y-1">
                  {cat.items.map((item, j) => (
                    <li key={j} className="flex items-start gap-2 text-xs text-body">
                      <span className="mt-1 h-1.5 w-1.5 rounded-full bg-brand-500 shrink-0" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* CLI Commands */}
      {detection.cliCommands.length > 0 && (
        <section className="surface-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Terminal className="h-4 w-4 text-brand-600 dark:text-brand-400" />
            <h3 className="text-sm font-semibold text-heading">CLI Verification Commands</h3>
          </div>
          <div className="space-y-2">
            {detection.cliCommands.map((cmd, i) => (
              <div key={i} className="rounded border border-line-1 bg-surface-200 p-2">
                <div className="text-xs text-body mb-1">{cmd.purpose}</div>
                <pre className="text-xs font-mono text-heading bg-surface-300 rounded p-2 overflow-x-auto">
                  {cmd.command}
                </pre>
                {cmd.platform && <div className="mt-1 text-micro font-mono text-muted">{cmd.platform}</div>}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Detection Limitations */}
      {detection.detectionLimitations.length > 0 && (
        <section className="rounded-xl border border-amber-200 dark:border-amber-900/60 bg-amber-50/40 dark:bg-amber-950/20 shadow-e1 p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400" />
            <h3 className="text-sm font-semibold text-amber-800 dark:text-amber-200">Detection Limitations</h3>
          </div>
          <ul className="space-y-1">
            {detection.detectionLimitations.map((lim, i) => (
              <li key={i} className="text-xs text-amber-700 dark:text-amber-300">
                {lim}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

function ConclusionTab({ conclusion }: { conclusion: AnalyzerOutput['conclusion'] }) {
  if (!conclusion || (conclusion.keyTakeaways.length === 0 && conclusion.recommendedActions.length === 0)) {
    return <EmptyState message="Conclusion extraction failed." />;
  }

  const priorityColor: Record<string, string> = {
    immediate: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
    'short-term':
      'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
    'long-term': 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800',
  };

  return (
    <div className="space-y-4">
      {/* Risk Assessment */}
      {conclusion.riskAssessment && (
        <section className="rounded-xl border border-rose-200 dark:border-rose-900/60 bg-rose-50/40 dark:bg-rose-950/20 shadow-e1 p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-4 w-4 text-rose-600 dark:text-rose-400" />
            <h3 className="text-sm font-semibold text-rose-800 dark:text-rose-200">Risk Assessment</h3>
          </div>
          <p className="text-sm text-rose-700 dark:text-rose-200 leading-relaxed">{conclusion.riskAssessment}</p>
        </section>
      )}

      {/* Key Takeaways */}
      {conclusion.keyTakeaways.length > 0 && (
        <section className="surface-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <CheckCircle className="h-4 w-4 text-brand-600 dark:text-brand-400" />
            <h3 className="text-sm font-semibold text-heading">Key Takeaways</h3>
          </div>
          <ul className="space-y-2">
            {conclusion.keyTakeaways.map((t, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-body">
                <span className="mt-1 h-1.5 w-1.5 rounded-full bg-brand-500 shrink-0" />
                {t}
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Recommended Actions */}
      {conclusion.recommendedActions.length > 0 && (
        <section className="surface-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <Shield className="h-4 w-4 text-brand-600 dark:text-brand-400" />
            <h3 className="text-sm font-semibold text-heading">Recommended Actions</h3>
          </div>
          <div className="space-y-2">
            {conclusion.recommendedActions.map((action, i) => (
              <div key={i} className="rounded border border-line-1 bg-surface-200 p-3">
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <span
                    className={`text-micro font-mono uppercase tracking-wider rounded border px-1.5 py-0.5 ${priorityColor[action.priority] ?? priorityColor['long-term']}`}
                  >
                    {action.priority}
                  </span>
                </div>
                <p className="text-sm text-heading">{action.action}</p>
                {action.rationale && <p className="mt-1 text-xs text-muted">{action.rationale}</p>}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

const MITRE_TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
] as const;

const CONFIDENCE_BG: Record<'high' | 'medium' | 'low', string> = {
  high: 'bg-rose-200 dark:bg-rose-800/60 border-rose-400 dark:border-rose-600',
  medium: 'bg-amber-100 dark:bg-amber-800/40 border-amber-300 dark:border-amber-700',
  low: 'bg-sky-100 dark:bg-sky-800/30 border-sky-300 dark:border-sky-700',
};

function HeatmapTab({ ttp }: { ttp: TtpHit[] }) {
  const grouped = useMemo(() => {
    const m = new Map<string, TtpHit[]>();
    for (const t of ttp) {
      const tactic = t.tactic || 'Other';
      if (!m.has(tactic)) m.set(tactic, []);
      m.get(tactic)!.push(t);
    }
    return m;
  }, [ttp]);

  // Count total unique techniques (including sub-techniques).
  const uniqueTechniques = useMemo(() => {
    const ids = new Set(ttp.map((t) => t.id.split('.')[0]));
    return ids.size;
  }, [ttp]);

  if (ttp.length === 0) return <EmptyState message="No techniques detected - heatmap is empty." />;

  // Sort tactics by canonical ATT&CK order.
  const activeTactics = MITRE_TACTICS.filter((t) => grouped.has(t));
  const otherTactics = Array.from(grouped.keys()).filter(
    (t) => !MITRE_TACTICS.includes(t as (typeof MITRE_TACTICS)[number])
  );

  return (
    <section className="surface-card p-4 overflow-x-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="text-micro font-mono uppercase tracking-wider text-muted">MITRE ATT&CK Heatmap</div>
        <div className="flex items-center gap-2 text-xs">
          <span className="rounded bg-surface-300 px-2 py-0.5 font-mono text-body">{uniqueTechniques} techniques</span>
          <span className="rounded bg-surface-300 px-2 py-0.5 font-mono text-body">
            {activeTactics.length + otherTactics.length} tactics
          </span>
          <span className="rounded bg-surface-300 px-2 py-0.5 font-mono text-body">{ttp.length} mappings</span>
        </div>
      </div>

      {/* Confidence legend */}
      <div className="flex items-center gap-3 mb-4 text-micro font-mono">
        <span className="text-muted">Confidence:</span>
        <span className="flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded bg-rose-400" /> high
        </span>
        <span className="flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded bg-amber-400" /> medium
        </span>
        <span className="flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded bg-sky-400" /> low
        </span>
      </div>

      {/* Matrix grid */}
      <div
        className="grid gap-1.5"
        style={{
          gridTemplateColumns: `repeat(${Math.min(activeTactics.length + otherTactics.length, 7)}, minmax(130px, 1fr))`,
        }}
      >
        {[...activeTactics, ...otherTactics].map((tactic) => {
          const hits = grouped.get(tactic)!;
          const density = Math.min(hits.length / 5, 1); // 0-1 scale
          return (
            <div
              key={tactic}
              className="rounded border border-line-1 overflow-hidden"
              style={{
                background: `rgba(59, 130, 246, ${0.03 + density * 0.08})`,
              }}
            >
              <div className="px-2 py-1.5 bg-surface-300/60 border-b border-line-1">
                <div className="text-micro font-mono font-semibold uppercase tracking-wider text-body truncate">
                  {tactic}
                </div>
                <div className="text-micro font-mono text-muted">
                  {hits.length} technique{hits.length !== 1 ? 's' : ''}
                </div>
              </div>
              <div className="p-1 space-y-0.5 max-h-64 overflow-y-auto">
                {hits.map((t) => {
                  const isSub = t.id.includes('.');
                  return (
                    <div
                      key={t.id}
                      title={`${t.id}: ${t.name}\n${t.evidence || ''}`}
                      className={`rounded border px-1.5 py-0.5 text-micro font-mono leading-tight cursor-default transition-opacity hover:opacity-80 ${CONFIDENCE_BG[t.confidence]} ${isSub ? 'ml-2 border-l-2' : ''}`}
                    >
                      <span className="font-semibold">{t.id}</span>
                      <span className="ml-1 opacity-70 truncate">{t.name}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* Technique density bar chart */}
      <div className="mt-4 pt-3 border-t border-line-1">
        <div className="text-micro font-mono text-muted mb-2">Technique Density by Tactic</div>
        <div className="space-y-1">
          {[...activeTactics, ...otherTactics].map((tactic) => {
            const hits = grouped.get(tactic)!;
            const maxHits = Math.max(...Array.from(grouped.values()).map((v) => v.length));
            const pct = maxHits > 0 ? (hits.length / maxHits) * 100 : 0;
            return (
              <div key={tactic} className="flex items-center gap-2 text-micro">
                <span className="w-24 truncate font-mono text-muted">{tactic}</span>
                <div className="flex-1 h-2 bg-surface-300 rounded overflow-hidden">
                  <div
                    className="h-full bg-brand-500 dark:bg-brand-400 rounded transition-all"
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="w-6 text-right font-mono text-body">{hits.length}</span>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

function SourceTab({ url, data }: { url: string; data: AnalyzerOutput }) {
  const displayText = data.sourceText || '';
  return (
    <section className="surface-card p-4">
      <div className="flex flex-wrap items-center gap-2 mb-3 text-xs text-muted">
        <span className="rounded border border-line-2 px-2 py-1 font-mono">
          {data.textLength.toLocaleString()} chars
        </span>
        {url && (
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded border border-line-2 px-2 py-1 font-mono text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            <ExternalLink className="h-3 w-3" /> {url}
          </a>
        )}
      </div>
      {displayText ? (
        <pre className="max-h-[600px] overflow-auto rounded border border-line-1 bg-surface-200 p-3 text-xs font-mono text-heading whitespace-pre-wrap break-words">
          {displayText}
        </pre>
      ) : (
        <EmptyState message="No source text captured." />
      )}
    </section>
  );
}

interface TimelineReport {
  id: string;
  title: string;
  source_url: string | null;
  created_at: string;
  ioc_count: number;
  ttp_count: number;
  cve_count: number;
  iocs: Array<{ value: string; kind: string }>;
  ttps: Array<{ id: string; name: string; tactic: string }>;
  cves: Array<{ id: string }>;
}

function TimelineTab() {
  const [timeline, setTimeline] = useState<TimelineReport[]>([]);
  const [sharedIocs, setSharedIocs] = useState<Array<{ value: string; reportIds: string[] }>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('/api/v1/saved-reports/timeline');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = (await res.json()) as {
          timeline: TimelineReport[];
          sharedIocs: Array<{ value: string; reportIds: string[] }>;
        };
        setTimeline(d.timeline);
        setSharedIocs(d.sharedIocs);
      } catch (e) {
        console.error('TimelineTab failed:', errMessage(e));
        setError(errMessage(e));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) {
    return (
      <section className="surface-card p-8 text-center">
        <RefreshCw className="h-6 w-6 animate-spin text-muted mx-auto mb-2" />
        <span className="text-sm text-muted">Loading timeline…</span>
      </section>
    );
  }

  if (error) return <EmptyState message={`Failed to load timeline: ${error}`} />;
  if (timeline.length === 0) return <EmptyState message="No saved reports yet. Save reports to see the timeline." />;

  // Group shared IOCs by value for quick lookup.
  const sharedIocSet = new Set(sharedIocs.map((s) => s.value.toLowerCase()));

  return (
    <section className="surface-card p-4">
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="text-micro font-mono uppercase tracking-wider text-muted">Report Timeline</div>
        <div className="flex items-center gap-2 text-xs">
          <span className="rounded bg-surface-300 px-2 py-0.5 font-mono text-body">{timeline.length} reports</span>
          <span className="rounded bg-amber-100 dark:bg-amber-900/40 px-2 py-0.5 font-mono text-amber-700 dark:text-amber-300">
            {sharedIocs.length} shared IOCs
          </span>
        </div>
      </div>

      {/* Shared IOCs summary */}
      {sharedIocs.length > 0 && (
        <div className="mb-4 p-3 rounded-xl border border-amber-200 dark:border-amber-900/60 bg-amber-50/40 dark:bg-amber-950/20">
          <div className="text-xs font-semibold text-amber-800 dark:text-amber-200 mb-2">
            Cross-Report IOCs (appear in multiple reports)
          </div>
          <div className="flex flex-wrap gap-1.5">
            {sharedIocs.map((s) => (
              <span
                key={s.value}
                className="inline-flex items-center gap-1 rounded border border-amber-300 dark:border-amber-700 bg-amber-100 dark:bg-amber-900/40 px-2 py-0.5 text-xs font-mono text-amber-800 dark:text-amber-200"
                title={`Appears in ${s.reportIds.length} reports`}
              >
                {s.value}
                <span className="text-amber-500 dark:text-amber-400">·{s.reportIds.length}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Timeline visualization */}
      <div className="relative">
        {/* Vertical line */}
        <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-track" />

        <div className="space-y-4">
          {timeline.map((report) => {
            const date = new Date(report.created_at);
            const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            const timeStr = date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
            const sharedInReport = report.iocs.filter((i) => sharedIocSet.has(i.value.toLowerCase()));

            return (
              <div key={report.id} className="relative pl-10">
                {/* Timeline dot */}
                <div
                  className={`absolute left-2.5 top-2 w-3 h-3 rounded-full border-2 ${
                    sharedInReport.length > 0
                      ? 'border-amber-500 bg-amber-100 dark:bg-amber-900/40'
                      : 'border-slate-300 dark:border-line-2 bg-white dark:bg-surface-200'
                  }`}
                />

                {/* Report card */}
                <div className="rounded-xl border border-line-1 bg-surface-200 p-3">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <span className="text-sm font-semibold text-heading">{report.title}</span>
                    <span className="text-xs text-muted font-mono">
                      {dateStr} {timeStr}
                    </span>
                  </div>

                  {/* Stats */}
                  <div className="flex flex-wrap gap-1.5 mb-2 text-micro font-mono">
                    <span className="rounded bg-sky-100 dark:bg-sky-900/40 px-1.5 py-0.5 text-sky-700 dark:text-sky-300">
                      {report.ioc_count} IOCs
                    </span>
                    <span className="rounded bg-violet-100 dark:bg-violet-900/40 px-1.5 py-0.5 text-violet-700 dark:text-violet-300">
                      {report.ttp_count} TTPs
                    </span>
                    <span className="rounded bg-amber-100 dark:bg-amber-900/40 px-1.5 py-0.5 text-amber-700 dark:text-amber-300">
                      {report.cve_count} CVEs
                    </span>
                    {sharedInReport.length > 0 && (
                      <span className="rounded bg-rose-100 dark:bg-rose-900/40 px-1.5 py-0.5 text-rose-700 dark:text-rose-300">
                        {sharedInReport.length} shared
                      </span>
                    )}
                  </div>

                  {/* Top IOCs (highlight shared ones) */}
                  {report.iocs.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {report.iocs.slice(0, 8).map((ioc) => {
                        const isShared = sharedIocSet.has(ioc.value.toLowerCase());
                        return (
                          <span
                            key={ioc.value}
                            className={`inline-flex items-center rounded px-1.5 py-0.5 text-micro font-mono ${
                              isShared
                                ? 'border border-amber-400 dark:border-amber-600 bg-amber-100 dark:bg-amber-900/40 text-amber-800 dark:text-amber-200 font-semibold'
                                : 'border border-line-1 bg-white dark:bg-surface-200 text-muted'
                            }`}
                            title={isShared ? 'Shared across reports' : ioc.kind}
                          >
                            {ioc.value.length > 25 ? ioc.value.slice(0, 25) + '…' : ioc.value}
                          </span>
                        );
                      })}
                      {report.iocs.length > 8 && (
                        <span className="text-micro text-muted self-center">+{report.iocs.length - 8} more</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <section className="rounded-xl border border-line-1 bg-surface-200 p-8 text-center text-sm text-muted">
      {message}
    </section>
  );
}
