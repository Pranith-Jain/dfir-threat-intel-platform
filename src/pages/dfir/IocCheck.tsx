import { logCatch } from '../../lib/log';
import { useEffect, useState, useRef, useCallback, useMemo, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ToolDocs } from '../../components/dfir/ToolDocs';
import { BackLink } from '../../components/BackLink';
import { IocChip } from '../../components/dfir/IocChip';
import {
  ArrowRight,
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertCircle,
  ExternalLink,
  FileDown,
  FileCode,
  Copy,
  Check,
  ChevronDown,
  Layers,
  Loader2,
} from 'lucide-react';
import { detectType, detectHashSubtype, refang } from '../../lib/dfir/indicator-client';
import { detectIoc, getIocPivots, IOC_TYPE_LABEL } from '../../lib/dfir/ioc-detect';
import { streamIoc } from '../../lib/dfir/api';
import type { ProviderResultWire, DoneEvent, ProviderId } from '../../lib/dfir/types';
import { IocResultRow } from '../../components/dfir/IocResultRow';
import { VerdictChip } from '../../components/dfir/VerdictChip';
import { recordHistory } from '../../lib/dfir/history';
import { RelatedActors } from '../../components/dfir/RelatedActors';
import { RelatedWikiArticles } from '../../components/dfir/RelatedWikiArticles';
import { PivotMatrix } from '../../components/dfir/PivotMatrix';
import { AdmiraltyBadge } from '../../components/dfir/AdmiraltyBadge';
import { PivotsTab } from '../../components/dfir/PivotsTab';
import { Textarea } from '../../components/ui/Input';
import { downloadBlob } from '../../lib/download';

type BulkVerdict = 'clean' | 'suspicious' | 'malicious' | 'unknown';

/** One row in the bulk table - assembled from each indicator's `done` event. */
interface BulkRow {
  indicator: string;
  type: string;
  status: 'pending' | 'running' | 'done' | 'error';
  verdict?: BulkVerdict;
  score?: number;
  confidence?: string;
  contributing?: number;
  total?: number;
  /** Provider ids that flagged this IOC as malicious or suspicious. */
  flagged?: string[];
  error?: string;
}

type BulkSortKey = 'indicator' | 'type' | 'verdict' | 'score' | 'sources';

/** Severity rank for sorting verdicts (worst first by default). */
const VERDICT_RANK: Record<BulkVerdict, number> = { malicious: 3, suspicious: 2, unknown: 1, clean: 0 };

/** Bulk runner - streams each indicator, with a concurrency cap so a paste
 *  of 30 IOCs doesn't open 30 EventSources at once. Uses the same per-IOC
 *  `streamIoc` the single-mode path uses, just promisified. */
async function runBulk(
  indicators: string[],
  onRowUpdate: (i: number, patch: Partial<BulkRow>) => void,
  concurrency = 3
): Promise<void> {
  let next = 0;
  async function worker() {
    while (next < indicators.length) {
      const idx = next++;
      const ind = indicators[idx]!;
      onRowUpdate(idx, { status: 'running' });
      await new Promise<void>((resolve) => {
        const collected: ProviderResultWire[] = [];
        let metaEligible: ProviderId[] = [];
        streamIoc(ind, {
          onMeta: (m) => {
            metaEligible = m.providers;
          },
          onResult: (r) => collected.push(r),
          onDone: (s) => {
            const flagged = collected
              .filter((r) => r.verdict === 'malicious' || r.verdict === 'suspicious')
              .map((r) => r.source);
            onRowUpdate(idx, {
              status: 'done',
              verdict: s.verdict as 'clean' | 'suspicious' | 'malicious' | 'unknown',
              score: s.score,
              confidence: s.confidence,
              contributing: s.contributing,
              total: metaEligible.length,
              flagged,
            });
            resolve();
          },
          onError: (e) => {
            onRowUpdate(idx, { status: 'error', error: e });
            resolve();
          },
        });
      });
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, indicators.length) }, worker));
}

/** Split a paste blob into clean unique IOC tokens. Whitespace, commas,
 *  semicolons, and pipes all separate. */
function parseBulkInput(raw: string, max: number): string[] {
  const tokens = raw
    .split(/[\s,;|]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return Array.from(new Set(tokens)).slice(0, max);
}

const BULK_MAX = 30;

function downloadFile(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  downloadBlob(blob, filename);
}

function rowsToCsv(rows: BulkRow[]): string {
  const header = [
    'indicator',
    'type',
    'status',
    'verdict',
    'score',
    'confidence',
    'contributing',
    'total',
    'flagged_sources',
    'error',
  ];
  const escape = (v: unknown): string => {
    if (v === undefined || v === null) return '';
    const s = String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [
    header.join(','),
    ...rows.map((r) =>
      [
        r.indicator,
        r.type,
        r.status,
        r.verdict ?? '',
        r.score ?? '',
        r.confidence ?? '',
        r.contributing ?? '',
        r.total ?? '',
        (r.flagged ?? []).join('|'),
        r.error ?? '',
      ]
        .map(escape)
        .join(',')
    ),
  ].join('\n');
}

interface NextStep {
  tone: 'malicious' | 'suspicious' | 'clean';
  title: string;
  steps: string[];
}

function buildNextSteps(verdict: string, type: string): NextStep {
  if (verdict === 'malicious') {
    const steps = [
      'Block at the perimeter (firewall, DNS sinkhole, mail-gateway, or proxy ACL) immediately.',
      'Search SIEM and proxy logs for the last 30 days of matches; pivot on any source IPs that touched it.',
      'Scope the blast radius: which hosts, which users, which sessions resolved or connected to it?',
    ];
    if (type === 'url' || type === 'domain') {
      steps.push('Submit the URL to URLhaus or PhishTank to help other defenders.');
      steps.push('Check if your DMARC policy is set to reject - phishing campaigns abuse weak SPF/DMARC.');
    }
    if (type === 'ipv4' || type === 'ipv6') {
      steps.push('Add to your perimeter blocklist; consider rate-limiting the entire ASN if abuse is widespread.');
    }
    if (type === 'hash' || type === 'md5' || type === 'sha1' || type === 'sha256') {
      steps.push('Hunt the hash across EDR. Quarantine endpoints if matches found.');
      steps.push('Pull a sample to a sandbox (Hybrid Analysis, ANY.RUN) for behavioural confirmation.');
    }
    return { tone: 'malicious', title: 'Confirmed malicious - recommended actions', steps };
  }
  if (verdict === 'suspicious') {
    return {
      tone: 'suspicious',
      title: 'Mixed signals - recommended actions',
      steps: [
        "Treat as untrusted until cleared. Don't auto-allow if it appears in user-reported phishing or alerts.",
        'Cross-check with other tools: Domain Lookup for registration age, Subdomain Takeover for dangling pointers, URL Preview for content inspection.',
        'Search your logs for prior interactions; one signal in isolation is rarely enough to act on.',
        'Re-run in 24h - providers update their feeds frequently and a "suspicious" verdict often hardens or clears within a day.',
      ],
    };
  }
  return {
    tone: 'clean',
    title: 'No active threat signal - operational notes',
    steps: [
      'Clean now does not mean clean tomorrow. Re-check periodically if this indicator stays in scope.',
      'A clean verdict on a freshly-registered domain or recently-rotated IP is weaker evidence than for a long-established asset.',
      'If you reached this tool because of an alert, document the false-positive context so future analysts have the trail.',
    ],
  };
}

export default function IocCheck(): JSX.Element {
  const [searchParams] = useSearchParams();
  const initialInput = searchParams.get('indicator') ?? '';
  const [input, setInput] = useState(initialInput);
  const [streaming, setStreaming] = useState(false);
  const [results, setResults] = useState<ProviderResultWire[]>([]);
  const [summary, setSummary] = useState<DoneEvent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [eligible, setEligible] = useState<ProviderId[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const summaryRef = useRef<HTMLHeadingElement>(null);
  const streamCleanupRef = useRef<(() => void) | null>(null);
  const detectedType = input ? detectType(input) : 'unknown';
  const canSubmit = !!input.trim() && detectedType !== 'unknown' && !streaming;
  // The Checker only enriches network indicators + hashes (detectType's domain).
  // When the input is a recognized IOC of another kind (CVE / MITRE / ASN / BTC),
  // don't dead-end with "unrecognized" - `detectIoc` is the richer detector and
  // `getIocPivots` gives the canonical tool to route to instead.
  const richIoc = input.trim() && detectedType === 'unknown' ? detectIoc(refang(input.trim())) : null;
  const redirectPivot = richIoc ? (getIocPivots(richIoc)[0] ?? null) : null;

  // ── Bulk mode ──────────────────────────────────────────────────────────
  // Toggle to a multi-line textarea; pool 3 streamIoc() calls; collect
  // each indicator's `done` event into a table row. Single-mode behaviour
  // is untouched - the two modes live side-by-side on the same page.
  const [mode, setMode] = useState<'single' | 'bulk'>('single');
  const [bulkInput, setBulkInput] = useState('');
  const [bulkRows, setBulkRows] = useState<BulkRow[]>([]);
  const [bulkRunning, setBulkRunning] = useState(false);
  const [bulkSort, setBulkSort] = useState<{ key: BulkSortKey; dir: 'asc' | 'desc' } | null>(null);

  const sortedBulkRows = useMemo(() => {
    if (!bulkSort) return bulkRows;
    const { key, dir } = bulkSort;
    const mult = dir === 'asc' ? 1 : -1;
    return [...bulkRows].sort((a, b) => {
      let cmp = 0;
      if (key === 'indicator') cmp = a.indicator.localeCompare(b.indicator);
      else if (key === 'type') cmp = a.type.localeCompare(b.type);
      else if (key === 'verdict')
        cmp = (VERDICT_RANK[a.verdict ?? 'unknown'] ?? 0) - (VERDICT_RANK[b.verdict ?? 'unknown'] ?? 0);
      else if (key === 'score') cmp = (a.score ?? -1) - (b.score ?? -1);
      else if (key === 'sources') cmp = (a.contributing ?? -1) - (b.contributing ?? -1);
      return cmp * mult;
    });
  }, [bulkRows, bulkSort]);

  // Cycle: none -> desc -> asc -> none (desc first: worst/highest at top).
  const toggleBulkSort = (key: BulkSortKey) =>
    setBulkSort((prev) =>
      prev?.key === key ? (prev.dir === 'desc' ? { key, dir: 'asc' } : null) : { key, dir: 'desc' }
    );
  const [stixLoading, setStixLoading] = useState(false);
  const [stixBundleId, setStixBundleId] = useState<string | null>(null);
  const [stixError, setStixError] = useState<string | null>(null);

  const [explainText, setExplainText] = useState<string | null>(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [ruleText, setRuleText] = useState<string | null>(null);
  const [ruleName, setRuleName] = useState<string | null>(null);
  const [ruleLoading, setRuleLoading] = useState(false);
  const [ruleFormat, setRuleFormat] = useState<'kql' | 'sigma' | 'yara'>('kql');
  const [copied, setCopied] = useState<'explain' | 'rule' | null>(null);

  const explainVerdict = useCallback(async () => {
    const raw = refang(input.trim());
    if (!raw || !summary) return;
    setExplainLoading(true);
    setExplainText(null);
    try {
      const res = await fetch('/api/v1/ioc/explain', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ indicator: raw }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as { explanation: string; generated_at: string };
      setExplainText(data.explanation);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* ignore */
    } finally {
      setExplainLoading(false);
    }
  }, [input, summary]);

  const generateRule = useCallback(async () => {
    const raw = refang(input.trim());
    if (!raw) return;
    setRuleLoading(true);
    setRuleText(null);
    setRuleName(null);
    try {
      const res = await fetch('/api/v1/ioc/rule', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ indicator: raw, format: ruleFormat }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as { rule_name: string; rule_text: string };
      setRuleName(data.rule_name);
      setRuleText(data.rule_text);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* ignore */
    } finally {
      setRuleLoading(false);
    }
  }, [input, ruleFormat]);

  const bulkIndicators = parseBulkInput(bulkInput, BULK_MAX);

  const runBulkScan = useCallback(async () => {
    if (bulkIndicators.length === 0 || bulkRunning) return;
    setBulkRunning(true);
    const initial: BulkRow[] = bulkIndicators.map((ind) => ({
      indicator: ind,
      type: detectType(ind),
      status: 'pending',
    }));
    setBulkRows(initial);
    await runBulk(bulkIndicators, (i, patch) =>
      setBulkRows((prev) => prev.map((row, idx) => (idx === i ? { ...row, ...patch } : row)))
    );
    setBulkRunning(false);
  }, [bulkIndicators, bulkRunning]);

  const bulkVerdictCounts = bulkRows.reduce<Record<string, number>>((acc, r) => {
    if (r.verdict) acc[r.verdict] = (acc[r.verdict] ?? 0) + 1;
    return acc;
  }, {});

  const exportBulkCsv = () => {
    if (bulkRows.length === 0) return;
    downloadFile(`ioc-check-${new Date().toISOString().slice(0, 10)}.csv`, rowsToCsv(bulkRows), 'text/csv');
  };
  const exportBulkJson = () => {
    if (bulkRows.length === 0) return;
    downloadFile(
      `ioc-check-${new Date().toISOString().slice(0, 10)}.json`,
      JSON.stringify(bulkRows, null, 2),
      'application/json'
    );
  };

  const buildStix = async () => {
    const iocs = bulkRows.filter((r) => r.status === 'done').map((r) => r.indicator);
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
      if (!r.ok) {
        const body = await r.text().catch(() => '');
        throw new Error(body ? `${r.status}: ${body.slice(0, 100)}` : r.statusText);
      }
      const ct = r.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON response');
      const data = (await r.json()) as { bundle: { id: string } };
      setStixBundleId(data.bundle.id);
    } catch (e) {
      logCatch(e);
      setStixError(`STIX build failed: ${(e as Error).message}. The intel-bundle endpoint may be down.`);
    } finally {
      setStixLoading(false);
    }
  };

  const runCheck = (override?: string) => {
    const value = (override ?? input).trim();
    if (!value || detectType(value) === 'unknown' || streaming) return;
    streamCleanupRef.current?.();
    setStreaming(true);
    setInput(value);
    setResults([]);
    setSummary(null);
    setError(null);
    setEligible([]);

    const cleanup = streamIoc(value, {
      onMeta: (m) => setEligible(m.providers),
      onResult: (r) => setResults((prev) => [...prev, r]),
      onDone: (s) => {
        setSummary(s);
        setStreaming(false);
        streamCleanupRef.current = null;
        recordHistory({ tool: 'ioc', indicator: value, verdict: s.verdict, score: s.score });
        setTimeout(() => summaryRef.current?.focus(), 0);
      },
      onError: (e) => {
        setError(e);
        setStreaming(false);
        streamCleanupRef.current = null;
        setTimeout(() => inputRef.current?.focus(), 0);
      },
    });
    streamCleanupRef.current = cleanup;
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    runCheck();
  };

  // Auto-run on deep-link: /dfir/ioc-check?indicator=8.8.8.8 should kick
  // off the check, not just pre-fill the input. The pivot links from the
  // IOC Extractor and other tools rely on this. Single-shot via a ref
  // guard so subsequent state changes don't retrigger.
  const lastRunRef = useRef<string>('');
  useEffect(() => {
    if (!initialInput) return;
    if (lastRunRef.current === initialInput) return;
    if (detectType(initialInput) === 'unknown') return;
    lastRunRef.current = initialInput;
    runCheck(initialInput);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialInput]);

  useEffect(() => () => streamCleanupRef.current?.(), []);

  const resultMap = useMemo(() => new Map(results.map((r) => [r.source, r])), [results]);

  const relatedTags = useMemo(() => results.flatMap((r) => r.tags), [results]);
  const relatedFreeText = useMemo(
    () => results.flatMap((r) => Object.values(r.raw_summary).filter((v) => typeof v === 'string') as string[]),
    [results]
  );

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <div className="animate-fade-in-up">
        <BackLink to="/dfir" />
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">IOC Checker</h1>
        <p className="text-muted mb-8 max-w-2xl">
          Checks IPs, domains, URLs, and file hashes against 60+ threat-intel sources in parallel. Streamed per-source
          verdicts with a weighted composite score; tags surface when a provider reports them.
        </p>
      </div>

      <ToolDocs path="/dfir/ioc-check" />

      {/* Mode toggle - single is the default, faithful to the existing
          single-IOC streaming experience. Bulk swaps to a paste-many UI
          with a table of per-IOC verdicts + CSV/JSON export. */}
      <div className="mb-4 inline-flex rounded border border-line-1 overflow-hidden">
        <button
          type="button"
          onClick={() => setMode('single')}
          aria-pressed={mode === 'single'}
          className={
            'text-xs font-mono uppercase tracking-wider px-3 py-1.5 min-h-[44px] sm:min-h-0 inline-flex items-center justify-center ' +
            (mode === 'single'
              ? 'bg-brand-500/15 text-brand-700 dark:text-brand-300'
              : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300')
          }
        >
          Single
        </button>
        <button
          type="button"
          onClick={() => setMode('bulk')}
          aria-pressed={mode === 'bulk'}
          className={
            'text-xs font-mono uppercase tracking-wider px-3 py-1.5 min-h-[44px] sm:min-h-0 inline-flex items-center justify-center gap-1 ' +
            (mode === 'bulk'
              ? 'bg-brand-500/15 text-brand-700 dark:text-brand-300'
              : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300')
          }
        >
          <Layers size={11} aria-hidden="true" /> Bulk
        </button>
      </div>

      {mode === 'bulk' ? (
        <section className="mb-10">
          <label htmlFor="ioc-bulk-input" className="sr-only">
            Bulk IOCs
          </label>
          <Textarea
            id="ioc-bulk-input"
            value={bulkInput}
            onChange={(e) => setBulkInput(e.target.value)}
            rows={5}
            spellCheck={false}
            placeholder={`Paste up to ${BULK_MAX} IPs / domains / URLs / hashes. Separators: newline / comma / space / pipe.`}
          />
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void runBulkScan()}
              disabled={bulkRunning || bulkIndicators.length === 0}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono text-sm font-semibold rounded-xl disabled:opacity-40 hover:bg-brand-700 dark:hover:bg-brand-400"
            >
              {bulkRunning && <Loader2 size={14} className="animate-spin" />}
              {bulkRunning
                ? `scanning ${bulkRows.filter((r) => r.status === 'done').length}/${bulkRows.length}…`
                : `check ${bulkIndicators.length} indicator${bulkIndicators.length === 1 ? '' : 's'}`}
            </button>
            {bulkRows.length > 0 && (
              <>
                <button
                  type="button"
                  onClick={exportBulkCsv}
                  disabled={bulkRunning}
                  className="text-mini font-mono px-2 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 disabled:opacity-40 inline-flex items-center gap-1 transition-colors"
                >
                  <FileDown size={11} /> CSV
                </button>
                <button
                  type="button"
                  onClick={exportBulkJson}
                  disabled={bulkRunning}
                  className="text-mini font-mono px-2 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 disabled:opacity-40 inline-flex items-center gap-1 transition-colors"
                >
                  <FileDown size={11} /> JSON
                </button>
                {stixBundleId ? (
                  <a
                    href={`/api/v1/intel-bundle/${stixBundleId}/export.stix.json`}
                    download={`${stixBundleId}.stix.json`}
                    className="text-mini font-mono px-2 py-1 rounded border border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/10 inline-flex items-center gap-1 transition-colors"
                  >
                    <FileDown size={11} /> STIX
                  </a>
                ) : (
                  <button
                    type="button"
                    onClick={() => void buildStix()}
                    disabled={stixLoading || bulkRunning}
                    className="text-mini font-mono px-2 py-1 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 disabled:opacity-40 inline-flex items-center gap-1"
                  >
                    <FileDown size={11} /> {stixLoading ? 'building…' : 'STIX'}
                  </button>
                )}
                {stixError && (
                  <span role="alert" className="text-mini font-mono text-rose-700 dark:text-rose-300">
                    {stixError}
                  </span>
                )}
              </>
            )}
            {bulkIndicators.length > 0 && (
              <span className="text-mini font-mono text-muted">
                detected {bulkIndicators.length} unique indicator{bulkIndicators.length === 1 ? '' : 's'}
                {bulkInput.split(/[\s,;|]+/).filter(Boolean).length > BULK_MAX && ` (capped at ${BULK_MAX})`}
              </span>
            )}
          </div>

          {bulkRows.length > 0 && (
            <>
              {/* Verdict summary */}
              <div className="mt-4 flex flex-wrap items-center gap-2 text-sm">
                {Object.entries(bulkVerdictCounts).map(([v, count]) => (
                  <span key={v} className="inline-flex items-center gap-1.5">
                    <span className="text-meta font-mono text-body tabular-nums">{count}</span>
                    <VerdictChip verdict={v as 'clean' | 'suspicious' | 'malicious' | 'unknown'} />
                  </span>
                ))}
              </div>

              {/* Results table */}
              <div className="mt-4 overflow-x-auto rounded-xl border border-line-1">
                <table className="w-full text-sm">
                  <thead className="text-left text-micro font-mono uppercase tracking-wider text-muted bg-surface-200/60">
                    <tr>
                      {(
                        [
                          ['indicator', 'Indicator', 'text-left'],
                          ['type', 'Type', 'text-left'],
                          ['verdict', 'Verdict', 'text-left'],
                          ['score', 'Score', 'text-right'],
                          ['sources', 'Sources', 'text-left'],
                        ] as Array<[BulkSortKey, string, string]>
                      ).map(([key, label, align]) => {
                        const active = bulkSort?.key === key;
                        return (
                          <th
                            key={key}
                            scope="col"
                            aria-sort={active ? (bulkSort?.dir === 'asc' ? 'ascending' : 'descending') : 'none'}
                            className={`px-3 py-2 ${align}`}
                          >
                            <button
                              type="button"
                              onClick={() => toggleBulkSort(key)}
                              className="inline-flex items-center gap-1 uppercase hover:text-heading dark:hover:text-inverted transition-colors"
                            >
                              {label}
                              <span
                                aria-hidden
                                className={`text-micro ${active ? 'text-brand-600 dark:text-brand-400' : 'text-slate-400/60'}`}
                              >
                                {active ? (bulkSort?.dir === 'asc' ? '▲' : '▼') : '↕'}
                              </span>
                            </button>
                          </th>
                        );
                      })}
                      <th scope="col" className="px-3 py-2">
                        Flagged by
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedBulkRows.map((r, i) => (
                      <tr key={`${r.indicator}-${i}`} className="border-t border-line-1/70 align-top">
                        <td className="px-3 py-2 max-w-[18rem]">
                          <IocChip
                            value={r.indicator}
                            bare
                            size="sm"
                            pivots={false}
                            truncate={48}
                            className="min-w-0"
                          />
                        </td>
                        <td className="px-3 py-2 text-mini font-mono uppercase text-muted">
                          {r.type === 'unknown' ? '?' : r.type}
                        </td>
                        <td className="px-3 py-2">
                          {r.status === 'pending' && <span className="text-mini font-mono text-muted">queued</span>}
                          {r.status === 'running' && (
                            <span className="inline-flex items-center gap-1 text-mini font-mono text-muted">
                              <Loader2 size={11} className="animate-spin" /> running
                            </span>
                          )}
                          {r.status === 'error' && (
                            <span className="text-mini font-mono text-rose-600 dark:text-rose-400">error</span>
                          )}
                          {r.status === 'done' && r.verdict && <VerdictChip verdict={r.verdict} />}
                        </td>
                        <td className="px-3 py-2 text-right font-mono tabular-nums">
                          {r.score !== undefined ? `${r.score}/100` : '-'}
                        </td>
                        <td className="px-3 py-2 text-meta font-mono text-muted">
                          {r.contributing !== undefined && r.total !== undefined ? `${r.contributing}/${r.total}` : '-'}
                        </td>
                        <td className="px-3 py-2 text-meta font-mono text-body">
                          {r.flagged && r.flagged.length > 0 ? r.flagged.join(', ') : '-'}
                          {r.error && <span className="text-rose-500"> ({r.error})</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </section>
      ) : (
        <form onSubmit={onSubmit} className="mb-10">
          <label htmlFor="ioc-input" className="sr-only">
            Indicator of compromise (IP, domain, URL, or hash)
          </label>
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <input
                id="ioc-input"
                ref={inputRef}
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="paste an IP, domain, URL, or hash"
                className="w-full bg-input-200 border border-line-input rounded-control px-4 py-3 text-tool text-heading placeholder:text-muted focus:outline-none focus:border-accent-text transition-colors"
                aria-label="Indicator of compromise"
              />
              {input && detectedType !== 'unknown' && (
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs font-mono text-brand-600 dark:text-brand-400 uppercase">
                  {detectedType === 'hash'
                    ? (() => {
                        const sub = detectHashSubtype(input);
                        if (sub === 'md5') return 'MD5';
                        if (sub === 'sha1') return 'SHA-1';
                        if (sub === 'sha256') return 'SHA-256';
                        return 'HASH';
                      })()
                    : detectedType}
                </span>
              )}
            </div>
            <button
              type="submit"
              disabled={!canSubmit}
              className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-control disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 transition-colors"
            >
              <Search size={16} className="inline mr-2" />
              Check
            </button>
          </div>
          {input && redirectPivot && richIoc ? (
            <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-xl border border-brand-500/30 bg-brand-500/5 px-3 py-2 text-xs font-mono">
              <span className="text-body">
                <code className="font-semibold text-heading">{richIoc.value}</code> is a {IOC_TYPE_LABEL[richIoc.type]}{' '}
                - the IOC Checker enriches network indicators &amp; hashes. Open it in:
              </span>
              {redirectPivot.external ? (
                <a
                  href={redirectPivot.path}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 font-semibold text-brand-600 dark:text-brand-400 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 rounded transition-colors"
                >
                  {redirectPivot.label} <ExternalLink size={12} aria-hidden="true" />
                </a>
              ) : (
                <Link
                  to={redirectPivot.path}
                  className="inline-flex items-center gap-1 font-semibold text-brand-600 dark:text-brand-400 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 rounded"
                >
                  {redirectPivot.label} <ArrowRight size={12} aria-hidden="true" />
                </Link>
              )}
            </div>
          ) : input && detectedType === 'unknown' ? (
            <p className="mt-2 text-xs font-mono text-amber-600 dark:text-amber-400">
              Unrecognized format. Accepted: IPv4 (e.g. <code className="font-semibold">1.1.1.1</code>), IPv6, domain
              (e.g. <code className="font-semibold">example.com</code>), URL (with scheme), or file hash (MD5 / SHA-1 /
              SHA-256).
            </p>
          ) : null}
        </form>
      )}

      {mode === 'single' &&
        summary &&
        (() => {
          const next = buildNextSteps(summary.verdict, detectedType);
          const toneStyles =
            next.tone === 'malicious'
              ? 'border-rose-300 bg-rose-50/50 dark:border-rose-800 dark:bg-rose-900/15 text-rose-900 dark:text-rose-200'
              : next.tone === 'suspicious'
                ? 'border-amber-300 bg-amber-50/50 dark:border-amber-800 dark:bg-amber-900/15 text-amber-900 dark:text-amber-200'
                : 'border-emerald-300 bg-emerald-50/50 dark:border-emerald-800 dark:bg-emerald-900/15 text-emerald-900 dark:text-emerald-200';
          const Icon = next.tone === 'malicious' ? ShieldAlert : next.tone === 'suspicious' ? AlertCircle : ShieldCheck;
          return (
            <>
              <section className="mb-4 surface-card p-6">
                <div className="flex items-baseline justify-between mb-2">
                  <h2 ref={summaryRef} tabIndex={-1} className="font-display font-bold text-2xl focus:outline-none">
                    Composite verdict
                  </h2>
                  <div className="flex items-center gap-2">
                    {summary.admiralty && <AdmiraltyBadge admiralty={summary.admiralty} />}
                    <VerdictChip
                      verdict={summary.verdict}
                      contributing={summary.contributing}
                      total={summary.total}
                      confidence={summary.confidence as 'high' | 'medium' | 'low' | undefined}
                    />
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-sm text-muted">
                  <span>
                    score: <span className="font-semibold text-heading">{summary.score}</span> / 100
                  </span>
                  <span>
                    confidence: <span className="font-semibold text-heading">{summary.confidence}</span>
                  </span>
                  <span>
                    {summary.contributing} of {eligible.length} responding
                  </span>
                </div>
              </section>
              {summary.admiralty && (
                <section className="mb-4 surface-card p-5">
                  <h3 className="font-display font-semibold text-sm mb-2">NATO Admiralty Code</h3>
                  <p className="text-sm font-mono text-muted leading-relaxed">
                    <span className="font-bold">{summary.admiralty.label}</span>
                    {' - '}
                    Reliability <strong>{summary.admiralty.reliability}</strong> (source ceiling), Credibility{' '}
                    <strong>{summary.admiralty.credibility}</strong> (IOC type baseline). IP-based IOCs cap at D because
                    addresses rotate fast; hashes and CVEs score higher as persistent artifacts.
                  </p>
                </section>
              )}
              <section className="mb-8 flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={explainVerdict}
                  disabled={explainLoading}
                  className="inline-flex items-center gap-1.5 px-4 py-2 surface-card/40 shadow-e1 text-sm font-medium text-body hover:border-brand-500/40 transition-colors disabled:opacity-50"
                >
                  {explainLoading ? <Loader2 size={14} className="animate-spin" /> : <ChevronDown size={14} />}
                  AI explain verdict
                </button>

                <div className="flex items-center gap-1.5">
                  {(['kql', 'sigma', 'yara'] as const).map((f) => (
                    <button
                      key={f}
                      type="button"
                      onClick={() => setRuleFormat(f)}
                      aria-pressed={ruleFormat === f}
                      className={`px-3 py-2 rounded-xl text-xs font-mono border transition-colors ${
                        ruleFormat === f
                          ? 'border-brand-500/60 bg-brand-500/10 text-brand-700 dark:text-brand-300'
                          : 'border-line-1 text-muted hover:border-slate-300 dark:hover:border-line-1'
                      }`}
                    >
                      {f.toUpperCase()}
                    </button>
                  ))}
                  <button
                    type="button"
                    onClick={generateRule}
                    disabled={ruleLoading}
                    className="inline-flex items-center gap-1.5 px-4 py-2 surface-card/40 shadow-e1 text-sm font-medium text-body hover:border-brand-500/40 transition-colors disabled:opacity-50"
                  >
                    {ruleLoading ? <Loader2 size={14} className="animate-spin" /> : <FileCode size={14} />}
                    Generate rule
                  </button>
                </div>
              </section>

              {explainText && (
                <section className="mb-8 surface-card p-4 animate-fade-in-up">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-muted">
                      AI Verdict Explanation
                    </h3>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(explainText);
                        setCopied('explain');
                        setTimeout(() => setCopied(null), 2000);
                      }}
                      className="text-xs font-mono text-muted hover:text-muted dark:hover:text-inverted"
                    >
                      {copied === 'explain' ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                    </button>
                  </div>
                  <p className="text-sm text-body leading-relaxed whitespace-pre-line">{explainText}</p>
                </section>
              )}

              {ruleText && (
                <section className="mb-8 surface-card animate-fade-in-up">
                  <div className="flex items-center justify-between p-3 border-b border-line-1">
                    <div className="flex items-center gap-2">
                      <FileCode size={14} className="text-brand-600 dark:text-brand-400" />
                      <span className="text-sm font-mono font-semibold text-body">{ruleName}</span>
                      <span className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-muted">
                        {ruleFormat.toUpperCase()}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(ruleText);
                        setCopied('rule');
                        setTimeout(() => setCopied(null), 2000);
                      }}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-mono text-muted hover:bg-surface-300 dark:hover:bg-surface-300 transition-colors"
                    >
                      {copied === 'rule' ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                      {copied === 'rule' ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre className="p-4 overflow-x-auto text-xs font-mono text-heading leading-relaxed whitespace-pre max-h-96 overflow-y-auto">
                    {ruleText}
                  </pre>
                </section>
              )}
              <PivotMatrix type={detectedType} value={input.trim()} verdict={summary.verdict} />
              <section className={`mb-8 rounded-xl border p-5 ${toneStyles}`}>
                <h3 className="font-display font-semibold text-base mb-3 inline-flex items-center gap-2">
                  <Icon size={16} aria-hidden="true" /> {next.title}
                </h3>
                <ul className="space-y-1.5 text-sm leading-relaxed">
                  {next.steps.map((s) => (
                    <li key={s} className="flex gap-2">
                      <span className="opacity-50 select-none">→</span>
                      <span>{s}</span>
                    </li>
                  ))}
                </ul>
              </section>
            </>
          );
        })()}

      {mode === 'single' && (streaming || results.length > 0) && (
        <section aria-busy={streaming && eligible.length === 0} aria-live="polite" aria-atomic="true">
          <h3 className="font-display font-semibold mb-4 text-lg">Per-source</h3>
          {streaming && eligible.length === 0 ? (
            <p className="text-xs font-mono text-muted animate-pulse">
              opening stream - waiting for eligible providers…
            </p>
          ) : (
            <div className="grid sm:grid-cols-2 gap-3">
              {eligible
                .filter((p) => {
                  const r = resultMap.get(p);
                  // Show if: still loading, flagged (malicious/suspicious), or has an error
                  if (!r) return true;
                  return r.verdict === 'malicious' || r.verdict === 'suspicious' || r.status === 'error';
                })
                .map((p) => {
                  const r = resultMap.get(p);
                  if (r) return <IocResultRow key={p} r={r} />;
                  return (
                    <div key={p} className="surface-card p-4 animate-pulse">
                      <span className="font-display capitalize text-muted">{p}</span>
                      <span className="block mt-2 text-xs font-mono text-muted">querying…</span>
                    </div>
                  );
                })}
            </div>
          )}
          {results.length > 0 && (
            <p className="mt-3 text-xs font-mono text-muted">
              {results.filter((r) => r.verdict === 'clean' || r.status !== 'ok').length} clean / errored sources hidden
            </p>
          )}
        </section>
      )}

      {mode === 'single' && error && (
        <div
          role="alert"
          className="mt-6 rounded-xl border border-rose-300 dark:border-rose-800 bg-rose-50/50 dark:bg-rose-900/15 p-4 flex items-start justify-between gap-3"
        >
          <div className="text-sm font-mono text-rose-700 dark:text-rose-300">
            <span className="font-semibold">stream error:</span> {error}
          </div>
          <button
            type="button"
            onClick={() => runCheck()}
            className="shrink-0 text-xs font-mono px-3 py-1.5 rounded border border-rose-400/60 text-rose-700 dark:text-rose-300 hover:bg-rose-500/10 transition-colors"
          >
            retry
          </button>
        </div>
      )}

      {mode === 'single' && summary && results.length > 0 && (
        <div className="mt-6">
          <PivotsTab results={results} indicatorValue={input.trim()} />
        </div>
      )}

      {mode === 'single' && summary && (
        <div className="mt-6">
          <RelatedActors
            hints={{
              tags: relatedTags,
              free_text: relatedFreeText,
            }}
          />
        </div>
      )}

      {mode === 'single' && summary && (
        <section className="mt-6 surface-card p-5">
          <h3 className="font-display font-semibold text-sm mb-3 inline-flex items-center gap-2">
            <Search size={14} /> External Enrichment
          </h3>
          <p className="text-xs font-mono text-muted mb-3">
            Query additional free threat intel APIs for deeper context.
          </p>
          <div className="flex flex-wrap gap-2">
            <a
              href={`/threatintel/ioc-enrichment?q=${encodeURIComponent(input.trim())}`}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono rounded-xl border border-line-1 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
            >
              <Search size={12} /> Open in IOC Enrichment
            </a>
            <a
              href={`https://socradar.io/free-tools/ioc-radar`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-mono rounded-xl border border-line-1 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
            >
              <ExternalLink size={12} /> SOCRadar IOC Radar
            </a>
          </div>
        </section>
      )}
      <RelatedWikiArticles />
    </div>
  );
}
