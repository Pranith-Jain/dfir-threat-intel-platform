import { useState, useCallback } from 'react';
import { Upload, X, Loader2, AlertTriangle, Check } from 'lucide-react';
import { Textarea } from '../ui/Input';
import { adminAuthHeaders } from '../../lib/admin-token';
import { errMessage } from '../../lib/log';

interface ParsedIoc {
  value: string;
  type: 'ip' | 'domain' | 'hash' | 'cve' | 'url' | 'email' | 'unknown';
}

const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/i;
const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\b/;
const HASH_RE = /\b[a-fA-F0-9]{32,64}\b/;
const DOMAIN_RE =
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|io|co|ru|cn|onion|dev|app|gov|edu|info|biz)\b/;
const URL_RE = /\bhttps?:\/\/[^\s<>"']+/i;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;

function parseIocs(text: string): ParsedIoc[] {
  const seen = new Set<string>();
  const iocs: ParsedIoc[] = [];
  const tokens = text.split(/[\s,;]+/).filter(Boolean);
  for (const token of tokens) {
    const t = token.replace(/[.,;:!?]+$/, '').trim();
    if (!t || seen.has(t.toLowerCase())) continue;
    seen.add(t.toLowerCase());
    if (CVE_RE.test(t)) {
      iocs.push({ value: t.toUpperCase(), type: 'cve' });
    } else if (IP_RE.test(t)) {
      iocs.push({ value: t, type: 'ip' });
    } else if (HASH_RE.test(t)) {
      iocs.push({ value: t, type: 'hash' });
    } else if (EMAIL_RE.test(t)) {
      iocs.push({ value: t, type: 'email' });
    } else if (URL_RE.test(t)) {
      iocs.push({ value: t, type: 'url' });
    } else if (DOMAIN_RE.test(t)) {
      iocs.push({ value: t.toLowerCase(), type: 'domain' });
    } else {
      iocs.push({ value: t, type: 'unknown' });
    }
  }
  return iocs;
}

interface BulkIocResult {
  value: string;
  type: string;
  verdict: string;
  score: number;
  tags: string[];
  source: string;
  summary?: string;
  error?: string;
}

interface BulkIocInputProps {
  onSubmit: (query: string) => void;
}

export function BulkIocInput({ onSubmit }: BulkIocInputProps) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState('');
  const [parsed, setParsed] = useState<ParsedIoc[]>([]);
  const [enriching, setEnriching] = useState(false);
  const [enrichResults, setEnrichResults] = useState<BulkIocResult[] | null>(null);

  const handleParse = useCallback(() => {
    const iocs = parseIocs(text);
    setParsed(iocs);
  }, [text]);

  const handleInvestigate = useCallback(() => {
    if (parsed.length === 0) return;

    const byType: Record<string, string[]> = {};
    for (const ioc of parsed) {
      if (!byType[ioc.type]) byType[ioc.type] = [];
      byType[ioc.type]!.push(ioc.value);
    }

    const parts: string[] = [];
    for (const [type, values] of Object.entries(byType)) {
      if (values.length <= 3) {
        parts.push(`${type.toUpperCase()}: ${values.join(', ')}`);
      } else {
        parts.push(
          `${type.toUpperCase()} (${values.length} total): ${values.slice(0, 3).join(', ')} and ${values.length - 3} more`
        );
      }
    }

    const query = `Bulk IOC investigation\n\nIOCs to investigate:\n${parts.join('\n')}\n\nFor each IOC, tell me: the type, reputation/verdict, associated threat actor or malware, any related CVEs, and a priority score (Critical/High/Medium/Low). Group by IOC type and highlight the most dangerous ones first.`;

    onSubmit(query);
    setOpen(false);
    setText('');
    setParsed([]);
    setEnrichResults(null);
  }, [parsed, onSubmit]);

  const handleEnrich = useCallback(async () => {
    if (parsed.length === 0) return;
    setEnriching(true);
    setEnrichResults(null);
    try {
      const res = await fetch('/api/v1/copilot/bulk-ioc', {
        method: 'POST',
        headers: { ...adminAuthHeaders(), 'content-type': 'application/json' },
        body: JSON.stringify({ iocs: parsed.map((i) => i.value) }),
        signal: AbortSignal.timeout(30_000),
      });
      if (!res.ok) throw new Error('Enrichment failed');
      const data = (await res.json()) as { results: BulkIocResult[] };
      setEnrichResults(data.results ?? []);
    } catch (e) {
      setEnrichResults([
        {
          value: '',
          type: 'error',
          verdict: 'error',
          score: 0,
          tags: [],
          source: '',
          error: errMessage(e, 'Enrichment failed'),
        },
      ]);
    } finally {
      setEnriching(false);
    }
  }, [parsed]);

  return (
    <>
      <button
        onClick={() => {
          setOpen(!open);
          if (!open) setEnrichResults(null);
        }}
        className="inline-flex items-center gap-1.5 rounded-full border border-line-1 px-3 py-1.5 font-mono text-xs text-muted transition-colors hover:border-brand-400 hover:text-brand-600 dark:hover:border-brand-400 dark:hover:text-brand-400"
      >
        <Upload size={12} />
        Bulk IOC
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm" onClick={() => setOpen(false)} />
          <div className="fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-xl border border-line-1 bg-surface-100 p-5 shadow-xl">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-body">Bulk IOC Investigation</h3>
              <button onClick={() => setOpen(false)} className="text-muted hover:text-muted">
                <X size={16} />
              </button>
            </div>
            <p className="mb-3 text-xs text-muted">
              Paste IPs, domains, hashes, CVEs, emails, or URLs - one per line or comma-separated.
            </p>
            <Textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              onInput={handleParse}
              placeholder={`8.8.8.8\n1.1.1.1\nCVE-2024-1709\nevil.com\ncafebabedeadbeef...`}
              className="h-28 w-full resize-none"
              spellCheck={false}
            />
            {parsed.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {(() => {
                  const counts: Record<string, { count: number; color: string }> = {};
                  const typeColors: Record<string, string> = {
                    ip: 'bg-blue-100 text-brand-700 dark:bg-blue-900/30 dark:text-brand-300',
                    domain: 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300',
                    hash: 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300',
                    cve: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
                    url: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',
                    email: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
                    unknown: 'bg-slate-100 text-slate-700 dark:bg-surface-300 dark:text-slate-300',
                  };
                  for (const ioc of parsed) {
                    if (!counts[ioc.type])
                      counts[ioc.type] = {
                        count: 0,
                        color:
                          typeColors[ioc.type] || 'bg-slate-100 text-slate-700 dark:bg-surface-300 dark:text-slate-300',
                      };
                    const entry = counts[ioc.type]!;
                    entry.count++;
                  }
                  return Object.entries(counts).map(([type, { count, color }]) => (
                    <span
                      key={type}
                      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-micro font-semibold ${color}`}
                    >
                      {type} <span className="opacity-70">({count})</span>
                    </span>
                  ));
                })()}
              </div>
            )}
            {enriching && (
              <div className="mt-2 flex items-center gap-2 rounded-xl bg-surface-200 p-2">
                <Loader2 size={12} className="animate-spin text-brand-500" />
                <span className="font-mono text-xs text-muted">Enriching across providers…</span>
              </div>
            )}
            {enrichResults && enrichResults.length > 0 && (
              <div className="mt-2 max-h-40 overflow-y-auto space-y-1">
                {enrichResults[0]?.type === 'error' ? (
                  <div className="flex items-center gap-1.5 rounded bg-rose-50 p-2 text-xs text-rose-600 dark:bg-rose-950/20 dark:text-rose-400">
                    <AlertTriangle size={11} />
                    {enrichResults[0].error}
                  </div>
                ) : (
                  enrichResults.slice(0, 20).map((r, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 rounded border border-line-1 bg-surface-200/50 px-2 py-1 text-xs dark:bg-surface-200/30"
                    >
                      <span
                        className={`inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full text-micro font-bold text-white ${
                          r.verdict === 'malicious'
                            ? 'bg-rose-500'
                            : r.verdict === 'suspicious'
                              ? 'bg-amber-500'
                              : r.verdict === 'clean'
                                ? 'bg-emerald-500'
                                : 'bg-slate-400'
                        }`}
                      >
                        {r.verdict === 'malicious' ? '!' : r.verdict === 'clean' ? <Check size={8} /> : '?'}
                      </span>
                      <span className="font-mono text-body">{r.value}</span>
                      <span className="text-muted">({r.score})</span>
                      {r.tags.length > 0 && (
                        <span className="truncate text-muted">{r.tags.slice(0, 2).join(', ')}</span>
                      )}
                    </div>
                  ))
                )}
              </div>
            )}
            <div className="mt-3 flex justify-end gap-2">
              <button
                onClick={() => {
                  setOpen(false);
                  setText('');
                  setParsed([]);
                  setEnrichResults(null);
                }}
                className="rounded-xl border border-line-1 px-3 py-1.5 font-mono text-xs text-muted hover:bg-surface-200"
              >
                Cancel
              </button>
              <button
                onClick={handleEnrich}
                disabled={parsed.length === 0 || enriching}
                className="rounded-xl border border-line-1 px-3 py-1.5 font-mono text-xs text-muted hover:border-brand-400 hover:text-brand-600 disabled:opacity-50 transition-colors"
              >
                {enriching ? <Loader2 size={11} className="animate-spin" /> : 'Enrich'}
              </button>
              <button
                onClick={handleInvestigate}
                disabled={parsed.length === 0 || enriching}
                className="rounded-xl bg-brand-600 px-3 py-1.5 font-mono text-xs text-on-fill hover:bg-brand-700 disabled:opacity-50 transition-colors"
              >
                Investigate {parsed.length > 0 ? `(${parsed.length} IOCs)` : ''}
              </button>
            </div>
          </div>
        </>
      )}
    </>
  );
}
