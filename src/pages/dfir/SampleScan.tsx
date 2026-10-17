import { errMessage, logCatch } from '../../lib/log';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { useNoindex } from '../../lib/use-noindex';
import {
  AlertTriangle,
  Bug,
  CheckCircle2,
  ExternalLink,
  FileSearch,
  Fingerprint,
  Key,
  Loader2,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Tag,
  Upload,
  XCircle,
} from 'lucide-react';
import { VerdictChip } from '../../components/dfir/VerdictChip';
import { CopyChip } from '../../components/dfir/CopyButton';
import { analyseFile, type FileAnalysis } from '../../lib/dfir/file-analysis';
import { useFeatures } from '../../lib/features';
import type { Verdict } from '../../lib/dfir/types';

type ProviderResultWire = {
  source: string;
  status: 'ok' | 'error' | 'unsupported';
  score: number;
  verdict: Verdict;
  raw_summary: Record<string, unknown>;
  tags: string[];
  error?: string;
  error_code?:
    | 'rate_limited'
    | 'upstream_5xx'
    | 'upstream_4xx'
    | 'unauthorized'
    | 'forbidden'
    | 'not_found'
    | 'timeout'
    | 'network'
    | 'parse'
    | 'unsupported_indicator'
    | 'no_api_key'
    | 'unknown';
  error_status?: number;
  error_tags?: string[];
  fetched_at: string;
  cached: boolean;
};

type MetaEvent = {
  hash: string;
  hash_type: 'md5' | 'sha1' | 'sha256';
  providers: string[];
};

type DoneEvent = {
  hash: string;
  hash_type: 'md5' | 'sha1' | 'sha256';
  score: number;
  verdict: Verdict;
  confidence: 'low' | 'medium' | 'high';
  contributing: number;
  public_sandboxes: Array<{ name: string; description: string; requires_key: boolean; url: string }>;
  signatures: string[];
  families: string[];
};

type Phase = 'idle' | 'hashing' | 'streaming' | 'done' | 'error';

const CARD = 'surface-card p-4';
const H2 = 'text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono inline-flex items-center gap-2';

const VERDICT_ICON: Record<Verdict, typeof ShieldAlert> = {
  malicious: ShieldAlert,
  suspicious: AlertTriangle,
  clean: ShieldCheck,
  unknown: ShieldCheck,
};

const VERDICT_BAR: Record<Verdict, string> = {
  malicious: 'bg-rose-500',
  suspicious: 'bg-amber-500',
  clean: 'bg-emerald-500',
  unknown: 'bg-slate-400',
};

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

interface StreamHandle {
  close: () => void;
}

function streamSampleScan(
  hash: string,
  onMeta: (m: MetaEvent) => void,
  onResult: (r: ProviderResultWire) => void,
  onDone: (d: DoneEvent) => void,
  onError: (err: string) => void
): StreamHandle {
  const url = `/api/v1/sample/scan`;
  const controller = new AbortController();
  fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ hash }),
    signal: controller.signal,
  })
    .then(async (res) => {
      if (!res.ok || !res.body) {
        onError(`HTTP ${res.status}`);
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      let currentEvent: string | null = null;
      let currentData = '';
      const dispatch = (): void => {
        if (!currentEvent || !currentData) {
          currentEvent = null;
          currentData = '';
          return;
        }
        try {
          const data = JSON.parse(currentData);
          if (currentEvent === 'meta') onMeta(data as MetaEvent);
          else if (currentEvent === 'result') onResult(data as ProviderResultWire);
          else if (currentEvent === 'done') onDone(data as DoneEvent);
        } catch (e) {
          logCatch(e);
          onError(`malformed ${currentEvent} frame`);
        }
        currentEvent = null;
        currentData = '';
      };
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let nl: number;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          if (line === '') {
            dispatch();
          } else if (line.startsWith('event:')) {
            currentEvent = line.slice(6).trim();
          } else if (line.startsWith('data:')) {
            currentData += line.slice(5).trim();
          }
        }
      }
    })
    .catch((e) => {
      if ((e as { name?: string }).name !== 'AbortError') onError(errMessage(e));
    });
  return { close: () => controller.abort() };
}

function FamilyTag({ name }: { name: string }): JSX.Element {
  return (
    <span className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/10 px-2 py-0.5 font-mono text-mini text-rose-700 dark:text-rose-300">
      <Bug size={10} />
      {name}
    </span>
  );
}

function SignatureTag({ tag }: { tag: string }): JSX.Element {
  return (
    <span className="inline-flex items-center gap-1 rounded border border-line-2 bg-surface-300 px-2 py-0.5 font-mono text-mini text-body">
      <Tag size={10} />
      {tag}
    </span>
  );
}

function ProviderRow({ r }: { r: ProviderResultWire }): JSX.Element {
  const Icon = VERDICT_ICON[r.verdict] ?? ShieldCheck;
  const dot =
    r.status === 'ok'
      ? r.score >= 70
        ? 'bg-rose-500'
        : r.score >= 40
          ? 'bg-amber-500'
          : 'bg-emerald-500'
      : 'bg-slate-400';
  return (
    <li className="flex items-center justify-between gap-2 rounded bg-surface-200 px-2 py-1.5 font-mono text-meta">
      <span className="flex items-center gap-2 truncate">
        <span className={`inline-block size-1.5 shrink-0 rounded-full ${dot}`} />
        <span className="truncate text-body">{r.source}</span>
      </span>
      <span className="flex items-center gap-2 text-muted">
        {r.status === 'ok' ? (
          <>
            <Icon
              size={11}
              className={
                r.verdict === 'malicious'
                  ? 'text-rose-500'
                  : r.verdict === 'suspicious'
                    ? 'text-amber-500'
                    : 'text-emerald-500'
              }
            />
            <span>{r.verdict}</span>
            <span className="tabular-nums">{r.score}/100</span>
          </>
        ) : r.status === 'error' ? (
          <span
            className="text-rose-500"
            title={`${r.error ?? ''}${r.error_code ? ` (${r.error_code}${r.error_status ? ` · ${r.error_status}` : ''})` : ''}`}
          >
            {r.error_code ?? 'err'}
            {r.error_status ? ` · ${r.error_status}` : ''}
          </span>
        ) : (
          <span className="text-muted">skipped</span>
        )}
      </span>
    </li>
  );
}

export default function SampleScan(): JSX.Element {
  useNoindex();
  const { samples, loaded } = useFeatures();
  const [, setFile] = useState<File | null>(null);
  const [hashInput, setHashInput] = useState('');
  const [analysis, setAnalysis] = useState<FileAnalysis | null>(null);
  const [phase, setPhase] = useState<Phase>('idle');
  const [meta, setMeta] = useState<MetaEvent | null>(null);
  const [results, setResults] = useState<ProviderResultWire[]>([]);
  const [done, setDone] = useState<DoneEvent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const streamRef = useRef<StreamHandle | null>(null);

  const cancelStream = useCallback(() => {
    streamRef.current?.close();
    streamRef.current = null;
  }, []);

  useEffect(() => () => cancelStream(), [cancelStream]);

  const startScan = useCallback(
    (hash: string) => {
      cancelStream();
      setMeta(null);
      setResults([]);
      setDone(null);
      setError(null);
      setPhase('streaming');
      streamRef.current = streamSampleScan(
        hash,
        (m) => setMeta(m),
        (r) => setResults((prev) => [...prev, r]),
        (d) => {
          setDone(d);
          setPhase('done');
          streamRef.current = null;
        },
        (e) => {
          setError(e);
          setPhase('error');
          streamRef.current = null;
        }
      );
    },
    [cancelStream]
  );

  const onFile = useCallback(
    async (f: File) => {
      setFile(f);
      setError(null);
      setPhase('hashing');
      try {
        const a = await analyseFile(f);
        setAnalysis(a);
        setHashInput(a.sha256);
        startScan(a.sha256);
      } catch (e) {
        logCatch(e);
        setError(errMessage(e, 'analysis failed'));
        setPhase('error');
      }
    },
    [startScan]
  );

  const onHashSubmit = useCallback(() => {
    const h = hashInput.trim().toLowerCase();
    if (!/^[a-f0-9]{32}$/.test(h) && !/^[a-f0-9]{40}$/.test(h) && !/^[a-f0-9]{64}$/.test(h)) {
      setError('expected MD5 / SHA-1 / SHA-256 hex');
      return;
    }
    setFile(null);
    setAnalysis(null);
    startScan(h);
  }, [hashInput, startScan]);

  if (loaded && !samples) return <Navigate to="/dfir" replace />;

  const busy = phase === 'hashing' || phase === 'streaming';

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <header className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <ScanSearch size={28} className="text-brand-600 dark:text-brand-400" /> Sample Scan
        </h1>
        <p className="text-muted mb-8 max-w-2xl">
          Drop a sample (or paste a hash) → static analysis (SHA-256 / SHA-1 / MD5, magic-byte family, entropy,
          suspicious strings) → 9-engine free public reputation fan-out (VirusTotal, MalwareBazaar, YARAify, Hybrid
          Analysis, OTX, ThreatFox, Malshare, Hashlookup, Kaspersky) → composite verdict + one-click deep links to 12
          free public sandboxes for deeper detonation.
        </p>
        <p className="mt-2 max-w-prose text-xs text-muted">
          <strong className="text-body">Free, no secrets required.</strong> Cloudflare Workers Free caps server CPU at
          10ms, so the SHA-256 is computed client-side (your file never leaves the browser until the hash is
          dispatched). The hash fan-out is on the same /api/v1/ read-rate-limit as the rest of the toolkit.
        </p>
      </header>

      {/* Input */}
      <section className={`${CARD} mb-6`}>
        <h2 className={H2}>
          <Upload size={12} /> submit
        </h2>
        <div
          onDrop={(e) => {
            e.preventDefault();
            const f = e.dataTransfer.files?.[0];
            if (f) void onFile(f);
          }}
          onDragOver={(e) => e.preventDefault()}
          onClick={() => document.getElementById('sample-scan-file')?.click()}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              document.getElementById('sample-scan-file')?.click();
            }
          }}
          role="button"
          tabIndex={0}
          aria-label="Drop a file here or click to choose"
          className="mt-3 cursor-pointer rounded border-2 border-dashed border-line-2 p-6 text-center hover:border-brand-500/40 focus-visible:border-brand-500 focus-visible:outline-none"
        >
          <FileSearch size={28} className="mx-auto mb-2 text-muted" />
          <p className="font-mono text-sm text-body">Drop a file here, or click to choose</p>
          <p className="mt-1 font-mono text-mini text-muted">8 MB hard cap (in-browser analysis limit)</p>
          <input
            id="sample-scan-file"
            type="file"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void onFile(f);
            }}
          />
        </div>

        <div className="mt-4 flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="flex-1">
            <label htmlFor="sample-scan-hash" className="font-mono text-mini uppercase tracking-wider text-muted">
              …or paste a hash
            </label>
            <input
              id="sample-scan-hash"
              type="text"
              value={hashInput}
              onChange={(e) => setHashInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') onHashSubmit();
              }}
              placeholder="MD5 / SHA-1 / SHA-256 hex"
              spellCheck={false}
              autoComplete="off"
              className="mt-1 w-full rounded border border-line-1 bg-surface-200 px-3 py-2 font-mono text-meta focus:border-brand-500 focus:outline-none"
            />
          </div>
          <button
            type="button"
            disabled={!hashInput.trim() || busy}
            onClick={onHashSubmit}
            className="inline-flex items-center gap-2 rounded bg-brand-600 px-4 py-2 font-mono text-meta font-semibold text-on-fill hover:bg-brand-700 disabled:opacity-30 dark:bg-brand-500 transition-colors"
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Fingerprint size={14} />}
            {phase === 'hashing' ? 'Hashing…' : phase === 'streaming' ? 'Scanning…' : 'Scan hash'}
          </button>
        </div>
      </section>

      {error && (
        <div className="mb-6 flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 p-4 dark:border-rose-900 dark:bg-rose-950/30">
          <XCircle size={16} className="shrink-0 text-rose-600 dark:text-rose-400" />
          <p className="font-mono text-meta text-rose-700 dark:text-rose-300">{error}</p>
        </div>
      )}

      {/* Static analysis */}
      {analysis && (
        <section className={`${CARD} mb-6`}>
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 className={H2}>
              <FileSearch size={12} /> static analysis
            </h2>
            <span className="font-mono text-mini text-muted">
              {analysis.filename} · {fmtBytes(analysis.size)}
              {analysis.truncated ? ' (truncated)' : ''}
            </span>
          </div>
          <dl className="mt-3 grid grid-cols-[140px_1fr] gap-x-4 gap-y-1 font-mono text-meta">
            <dt className="text-muted">Type</dt>
            <dd className="text-heading">
              {analysis.fileType} · family <span className="text-brand-600 dark:text-brand-400">{analysis.family}</span>
            </dd>
            <dt className="text-muted">Entropy</dt>
            <dd className="text-heading">
              {analysis.entropy.toFixed(3)} / 8.000
              {analysis.entropy > 7.5 ? ' · ! likely packed/encrypted' : analysis.entropy > 7.0 ? ' · elevated' : ''}
            </dd>
          </dl>
          <ul className="mt-3 space-y-1 font-mono text-mini">
            <li className="flex items-center justify-between gap-2">
              <span className="w-16 text-muted">SHA-256</span>
              <span className="flex-1 truncate text-heading">{analysis.sha256}</span>
              <CopyChip value={analysis.sha256} label="copy" />
            </li>
            <li className="flex items-center justify-between gap-2">
              <span className="w-16 text-muted">SHA-1</span>
              <span className="flex-1 truncate text-heading">{analysis.sha1}</span>
              <CopyChip value={analysis.sha1} label="copy" />
            </li>
            <li className="flex items-center justify-between gap-2">
              <span className="w-16 text-muted">MD5</span>
              <span className="flex-1 truncate text-heading">{analysis.md5}</span>
              <CopyChip value={analysis.md5} label="copy" />
            </li>
          </ul>
          {analysis.tags.length > 0 && (
            <div className="mt-3">
              <h3 className="mb-1 font-mono text-mini font-semibold uppercase tracking-wider text-rose-700 dark:text-rose-300">
                Heuristic tags
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {analysis.tags.map((t) => (
                  <SignatureTag key={t} tag={t} />
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* Verdict */}
      {done && (
        <section className={`${CARD} mb-6`}>
          <div className="flex flex-wrap items-center gap-3">
            <h2 className={H2}>
              <Sparkles size={12} /> composite verdict
            </h2>
            <VerdictChip verdict={done.verdict} />
            <span className="font-mono text-meta text-muted">
              {done.score}/100 · {done.confidence} confidence · {done.contributing}/{meta?.providers.length ?? 0}{' '}
              providers
            </span>
          </div>
          <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-track">
            <div
              className={`h-full ${VERDICT_BAR[done.verdict]} transition-all`}
              style={{ width: `${Math.max(2, done.score)}%` }}
            />
          </div>
          <dl className="mt-3 grid grid-cols-[140px_1fr] gap-x-4 gap-y-1 font-mono text-meta">
            <dt className="text-muted">Hash</dt>
            <dd className="break-all text-heading">
              {done.hash} <span className="text-muted">({done.hash_type})</span>
            </dd>
          </dl>
          {done.families.length > 0 && (
            <div className="mt-3">
              <h3 className="mb-1 font-mono text-mini font-semibold uppercase tracking-wider text-muted">
                Families ({done.families.length})
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {done.families.map((f) => (
                  <FamilyTag key={f} name={f} />
                ))}
              </div>
            </div>
          )}
          {done.signatures.length > 0 && (
            <div className="mt-3">
              <h3 className="mb-1 font-mono text-mini font-semibold uppercase tracking-wider text-muted">
                Signatures / tags ({done.signatures.length})
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {done.signatures.slice(0, 30).map((s) => (
                  <SignatureTag key={s} tag={s} />
                ))}
                {done.signatures.length > 30 && (
                  <span className="font-mono text-mini text-muted">+{done.signatures.length - 30} more</span>
                )}
              </div>
            </div>
          )}
        </section>
      )}

      {/* Provider results */}
      {results.length > 0 && (
        <section className={`${CARD} mb-6`}>
          <h2 className={H2}>
            <ShieldAlert size={12} /> provider results ({results.length})
          </h2>
          <ul className="mt-3 space-y-1">
            {results.map((r) => (
              <ProviderRow key={r.source} r={r} />
            ))}
          </ul>
          {done && (
            <p className="mt-3 font-mono text-mini text-muted">
              Streaming as each engine responds - finished in {meta ? 'one round-trip' : '?'} of the SSE feed. Verdict
              biased toward malicious when ≥2 weighted providers agree.
            </p>
          )}
        </section>
      )}

      {/* Public sandbox deep links */}
      {done && done.public_sandboxes.length > 0 && (
        <section className={`${CARD} mb-6`}>
          <h2 className={H2}>
            <ExternalLink size={12} /> detonate in a free public sandbox
          </h2>
          <p className="mt-2 font-mono text-mini text-muted">
            One-click deep links to {done.public_sandboxes.length} free public sandboxes / lookup engines. Most are
            click-through only; a few require a free community API key for full results.
          </p>
          <ul className="mt-3 grid gap-2 sm:grid-cols-2">
            {done.public_sandboxes.map((s) => (
              <li
                key={s.name}
                className="flex items-start justify-between gap-2 rounded border border-line-1 bg-surface-200 p-2"
              >
                <div className="min-w-0 flex-1">
                  <a
                    href={s.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-meta font-semibold text-brand-600 hover:underline dark:text-brand-400 transition-colors"
                  >
                    {s.name}
                    <ExternalLink size={10} />
                  </a>
                  <p className="mt-0.5 font-mono text-mini text-muted">{s.description}</p>
                </div>
                {s.requires_key && (
                  <span className="inline-flex shrink-0 items-center gap-0.5 rounded border border-amber-300 bg-amber-50 px-1.5 py-0.5 font-mono text-micro text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-300">
                    <Key size={9} /> key
                  </span>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      {!done && !busy && (
        <p className="font-mono text-meta text-muted">
          <CheckCircle2 size={12} className="mr-1 inline-block text-emerald-500" />
          Nothing scanned yet. Drop a file or paste a hash to start.
        </p>
      )}

      {busy && !done && (
        <p className="inline-flex items-center gap-2 font-mono text-meta text-muted">
          <Loader2 size={12} className="animate-spin" />
          {phase === 'hashing' ? 'hashing in your browser…' : 'streaming from 10 free public engines…'}
        </p>
      )}

      <p className="mt-6 font-mono text-mini text-muted">
        Pairs with{' '}
        <Link to="/dfir/ioc-investigate" className="text-brand-600 hover:underline dark:text-brand-400">
          IOC checker
        </Link>{' '}
        (per-indicator provider lookups),{' '}
        <Link to="/dfir/malware-analyzer" className="text-brand-600 hover:underline dark:text-brand-400">
          malware-scan
        </Link>{' '}
        (the older hash-only surface).
      </p>
    </div>
  );
}
