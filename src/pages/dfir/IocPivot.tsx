import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { Search, Loader2, FileSearch, FileDown, AlertCircle } from 'lucide-react';
import { streamIoc } from '../../lib/dfir/api';
import { detectType } from '../../lib/dfir/indicator-client';
import type { ProviderResultWire, DoneEvent } from '../../lib/dfir/types';
import { errMessage } from '../../lib/log';

/**
 * IOC Pivot Graph - enrich one indicator across the 60+ source checker
 * (reuses /api/v1/ioc/check SSE), then render a radial relationship graph:
 * indicator → sources (verdict-coloured) → derived pivot indicators
 * (IPs / domains / hashes / ASNs / CVEs found in the evidence). Every
 * pivot node is clickable to re-centre the graph on it - the core CTI
 * pivoting workflow. Nothing is stored; analysis is per-request.
 */

const VERDICT_COLOR: Record<string, string> = {
  malicious: '#e11d48', // rose-600
  suspicious: '#d97706', // amber-600
  clean: '#059669', // emerald-600
  unknown: '#64748b', // slate-500
};

// Pivot extraction over result tags + stringy raw_summary values.
const RE_IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const RE_DOMAIN = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;
const RE_HASH = /\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi;
const RE_ASN = /\bAS\d{2,6}\b/gi;
const RE_CVE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const refang = (s: string) =>
  s
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\[dot\]/gi, '.')
    .replace(/h(?:xx|tt)ps?:\/\//gi, '');

interface Pivot {
  value: string;
  kind: 'ipv4' | 'domain' | 'hash' | 'asn' | 'cve';
}

function extractPivots(results: ProviderResultWire[], center: string): Pivot[] {
  const c = center.toLowerCase();
  const seen = new Set<string>();
  const out: Pivot[] = [];
  const add = (value: string, kind: Pivot['kind']) => {
    const v = value.trim();
    const key = `${kind}:${v.toLowerCase()}`;
    if (!v || v.toLowerCase() === c || seen.has(key)) return;
    seen.add(key);
    out.push({ value: v, kind });
  };
  for (const r of results) {
    const blobs = [
      ...r.tags,
      ...Object.values(r.raw_summary)
        .filter((v) => typeof v === 'string')
        .map((v) => v as string),
    ];
    for (const raw of blobs) {
      const b = refang(raw);
      for (const m of b.match(RE_CVE) ?? []) add(m.toUpperCase(), 'cve');
      for (const m of b.match(RE_ASN) ?? []) add(m.toUpperCase(), 'asn');
      for (const m of b.match(RE_HASH) ?? []) add(m.toLowerCase(), 'hash');
      for (const m of b.match(RE_IPV4) ?? []) if (!/^0\.|^255\.|\.0$/.test(m)) add(m, 'ipv4');
      for (const m of b.match(RE_DOMAIN) ?? [])
        if (!/\.(png|jpg|svg|css|js|json|html?)$/i.test(m)) add(m.toLowerCase(), 'domain');
    }
  }
  return out.slice(0, 28);
}

const PIVOT_FILL: Record<Pivot['kind'], string> = {
  ipv4: '#0ea5e9',
  domain: '#8b5cf6',
  hash: '#0d9488',
  asn: '#f59e0b',
  cve: '#e11d48',
};

export default function IocPivot(): JSX.Element {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [input, setInput] = useState(params.get('q') ?? '');
  const [active, setActive] = useState(params.get('q')?.trim() ?? '');
  const [results, setResults] = useState<ProviderResultWire[]>([]);
  const [summary, setSummary] = useState<DoneEvent | null>(null);
  const [streaming, setStreaming] = useState(false);
  const stopRef = useRef<(() => void) | null>(null);
  // STIX export state - built lazily on first click, then the bundleId is
  // remembered so the user can re-trigger the download without rebuilding.
  // `stixBuilding` is a separate flag from `streaming` (the live enrichment)
  // so the buttons can show independent spinners.
  const [stixBundleId, setStixBundleId] = useState<string | null>(null);
  const [stixBuilding, setStixBuilding] = useState(false);
  const [stixError, setStixError] = useState<string | null>(null);

  useEffect(() => {
    if (!active) return;
    setResults([]);
    setSummary(null);
    setStreaming(true);
    stopRef.current?.();
    const stop = streamIoc(active, {
      onMeta: () => {},
      onResult: (r) => setResults((p) => [...p, r]),
      onDone: (s) => {
        setSummary(s);
        setStreaming(false);
      },
      onError: () => setStreaming(false),
    });
    stopRef.current = stop;
    return () => stop();
  }, [active]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = input.trim();
    if (!v) return;
    setParams({ q: v }, { replace: false });
    setActive(v);
  };
  const pivotTo = (v: string) => {
    // Ignore pivot clicks while the previous stream is still open - two
    // concurrent EventSources would race their results into the same state.
    // The submit button is already disabled during `streaming`, but the
    // graph node clicks aren't, so they need their own guard.
    if (streaming) return;
    setInput(v);
    setParams({ q: v }, { replace: false });
    setActive(v);
  };

  const centerType = active ? detectType(active) : 'unknown';
  // Sources that actually returned a signal (drop pure unknown/no-data noise).
  const sources = results.filter((r) => r.verdict !== 'unknown' || r.score > 0);
  const pivots = extractPivots(results, active);

  function pipeToExtractor() {
    const text = [active, ...pivots.map((p) => p.value)].join('\n');
    sessionStorage.setItem('ioc-extractor-pipe', text);
    navigate('/dfir/extract?from=pivot');
  }

  /**
   * Compose the current pivot session (center + all discovered pivots +
   * per-source verdicts) into a STIX 2.1 bundle via the existing
   * /api/v1/intel-bundle/build endpoint (mode='iocs'). The endpoint
   * normalises the input into a synthetic body, runs it through the same
   * extractor as the manual STIX builder, and persists the resulting
   * bundle. The returned bundleId links to the canonical server export
   * endpoint, which serves the strict `application/stix+json; version=2.1`
   * media type that MISP / OpenCTI / TAXII collectors expect.
   */
  async function buildPivotStix(): Promise<void> {
    if (stixBuilding || streaming) return;
    if (!active) return;
    setStixBuilding(true);
    setStixError(null);
    try {
      // mode='iocs' takes a newline-separated indicator list. The build
      // endpoint classifies each line via detectType() before assembly, so
      // the bundle emits one indicator object per pivot even though the
      // source input is bare text with no context.
      const input = [active, ...pivots.map((p) => p.value)].join('\n');
      const res = await fetch('/api/v1/intel-bundle/build', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          mode: 'iocs',
          input,
          sourceName: `IOC pivot session: ${active}`,
          tlp: 'AMBER',
        }),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => res.statusText);
        throw new Error(`build failed (${res.status}): ${text.slice(0, 200)}`);
      }
      const data = (await res.json()) as { bundle?: { id?: string } };
      const id = data.bundle?.id;
      if (!id) throw new Error('build response missing bundle.id');
      setStixBundleId(id);
    } catch (err) {
      console.error('buildPivotStix failed:', errMessage(err));
      setStixError(errMessage(err));
    } finally {
      setStixBuilding(false);
    }
  }

  // Radial layout.
  const W = 820;
  const cx = W / 2;
  const cy = W / 2;
  const r1 = 190; // sources ring
  const r2 = 350; // pivots ring
  const pt = (radius: number, i: number, n: number) => {
    const a = (i / Math.max(1, n)) * 2 * Math.PI - Math.PI / 2;
    return { x: cx + radius * Math.cos(a), y: cy + radius * Math.sin(a) };
  };

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">IOC Pivot Graph</h1>
        <p className="text-muted mb-6 max-w-2xl">
          Enrich an indicator across 60+ sources and graph what it touches - verdict-coloured sources plus derived IPs /
          domains / hashes / ASNs / CVEs. Click any derived node to re-centre the graph on it. Nothing is stored.
        </p>
      </div>

      <form onSubmit={submit} className="flex flex-wrap gap-2 mb-6">
        <div className="relative flex-1 min-w-[240px]">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="IP · domain · URL · file hash"
            aria-label="Indicator"
            className="w-full pl-9 pr-3 py-2.5 bg-surface-100 border border-line-1 rounded-xl text-sm font-mono text-heading placeholder:text-muted focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
          />
        </div>
        <button
          type="submit"
          disabled={streaming || !input.trim()}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono text-sm font-semibold rounded-xl disabled:opacity-40 hover:bg-brand-700 dark:hover:bg-brand-400 transition-colors"
        >
          {streaming && <Loader2 size={14} className="animate-spin" />}
          {streaming ? 'enriching…' : 'pivot'}
        </button>
      </form>

      {active && (
        <>
          <div className="surface-card p-3 mb-4">
            <svg viewBox={`0 0 ${W} ${W}`} className="w-full h-auto" role="img" aria-label="IOC pivot graph">
              {/* edges: centre → sources */}
              {sources.map((s, i) => {
                const p = pt(r1, i, sources.length);
                return (
                  <line
                    key={`es-${s.source}`}
                    x1={cx}
                    y1={cy}
                    x2={p.x}
                    y2={p.y}
                    stroke={VERDICT_COLOR[s.verdict] ?? VERDICT_COLOR.unknown}
                    strokeOpacity="0.35"
                    strokeWidth="1.5"
                  />
                );
              })}
              {/* edges: centre → pivots */}
              {pivots.map((pv, i) => {
                const p = pt(r2, i, pivots.length);
                return (
                  <line
                    key={`ep-${pv.kind}-${pv.value}`}
                    x1={cx}
                    y1={cy}
                    x2={p.x}
                    y2={p.y}
                    stroke="#94a3b8"
                    strokeOpacity="0.18"
                    strokeWidth="1"
                  />
                );
              })}
              {/* pivot nodes (clickable) */}
              {pivots.map((pv, i) => {
                const p = pt(r2, i, pivots.length);
                return (
                  <g key={`pn-${pv.kind}-${pv.value}`} className="cursor-pointer" onClick={() => pivotTo(pv.value)}>
                    <circle cx={p.x} cy={p.y} r="7" fill={PIVOT_FILL[pv.kind]} />
                    <text
                      x={p.x}
                      y={p.y - 12}
                      textAnchor="middle"
                      className="fill-slate-600 dark:fill-slate-300"
                      fontSize="12"
                      fontFamily="monospace"
                    >
                      {pv.value.length > 28 ? pv.value.slice(0, 26) + '…' : pv.value}
                    </text>
                  </g>
                );
              })}
              {/* source nodes */}
              {sources.map((s, i) => {
                const p = pt(r1, i, sources.length);
                return (
                  <g key={`sn-${s.source}`}>
                    <circle cx={p.x} cy={p.y} r="9" fill={VERDICT_COLOR[s.verdict] ?? VERDICT_COLOR.unknown} />
                    <text
                      x={p.x}
                      y={p.y + 24}
                      textAnchor="middle"
                      className="fill-slate-500"
                      fontSize="11"
                      fontFamily="monospace"
                    >
                      {s.source}
                    </text>
                  </g>
                );
              })}
              {/* centre */}
              <circle cx={cx} cy={cy} r="16" className="fill-brand-600 dark:fill-brand-500" />
              <text
                x={cx}
                y={cy + 38}
                textAnchor="middle"
                className="fill-slate-900 dark:fill-slate-100"
                fontSize="14"
                fontFamily="monospace"
                fontWeight="bold"
              >
                {active.length > 34 ? active.slice(0, 32) + '…' : active}
              </text>
              <text
                x={cx}
                y={cy + 56}
                textAnchor="middle"
                className="fill-slate-500"
                fontSize="11"
                fontFamily="monospace"
              >
                {centerType}
              </text>
            </svg>
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-mini font-mono text-muted px-2 pb-1">
              <span>
                <span style={{ color: VERDICT_COLOR.malicious }}>●</span> malicious
              </span>
              <span>
                <span style={{ color: VERDICT_COLOR.suspicious }}>●</span> suspicious
              </span>
              <span>
                <span style={{ color: VERDICT_COLOR.clean }}>●</span> clean
              </span>
              <span className="ml-auto">
                {sources.length} sources · {pivots.length} pivots
                {streaming ? ' · streaming…' : summary ? ` · verdict ${summary.verdict}` : ''}
              </span>
            </div>
          </div>

          {pivots.length > 0 && (
            <section className="surface-card p-4">
              <div className="flex items-center justify-between mb-2 gap-2 flex-wrap">
                <h3 className="text-mini font-mono uppercase tracking-wider text-muted">
                  Pivot indicators ({pivots.length})
                </h3>
                <div className="flex items-center gap-2 flex-wrap">
                  {stixBundleId ? (
                    <a
                      href={`/api/v1/intel-bundle/${encodeURIComponent(stixBundleId)}/export.stix.json`}
                      download={`${stixBundleId}.stix.json`}
                      className="text-mini font-mono px-2 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/10 inline-flex items-center gap-1 transition-colors"
                    >
                      <FileDown size={11} /> STIX
                    </a>
                  ) : (
                    <button
                      type="button"
                      onClick={() => void buildPivotStix()}
                      disabled={stixBuilding || streaming}
                      className="text-mini font-mono px-2 py-0.5 rounded border border-line-1 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 disabled:opacity-40 inline-flex items-center gap-1"
                    >
                      {stixBuilding ? (
                        <Loader2 size={11} className="animate-spin" />
                      ) : stixError ? (
                        <AlertCircle size={11} className="text-rose-500" />
                      ) : (
                        <FileDown size={11} />
                      )}
                      {stixBuilding ? 'building…' : stixError ? 'retry STIX' : 'STIX'}
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={pipeToExtractor}
                    className="text-mini font-mono px-2 py-0.5 rounded border border-line-1 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1 transition-colors"
                  >
                    <FileSearch size={11} /> Extract IOCs →
                  </button>
                </div>
                {stixError && (
                  <span role="alert" className="basis-full text-micro font-mono text-rose-700 dark:text-rose-300 mt-1">
                    {stixError}
                  </span>
                )}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {pivots.map((pv) => (
                  <button
                    key={`pl-${pv.kind}-${pv.value}`}
                    type="button"
                    onClick={() => pivotTo(pv.value)}
                    title={`Pivot to ${pv.value}`}
                    className="text-mini font-mono px-2 py-0.5 rounded border border-line-1 bg-surface-200 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400"
                  >
                    <span style={{ color: PIVOT_FILL[pv.kind] }}>●</span> {pv.value}{' '}
                    <span className="text-muted">{pv.kind}</span>
                  </button>
                ))}
              </div>
            </section>
          )}
        </>
      )}
    </div>
  );
}
