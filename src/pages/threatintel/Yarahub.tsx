import { errMessage, logCatch } from '../../lib/log';
import { useState, useEffect, useCallback, useRef, type FormEvent } from 'react';
import { Input } from '../../components/ui/Input';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Search, Loader2, ExternalLink, FileDown, X, FileCode } from 'lucide-react';
import { downloadBlob } from '../../lib/download';

interface YaraRuleEntry {
  rule_name: string;
  author?: string;
  description?: string;
  malware?: string;
  yarahub_uuid?: string;
  date?: string;
  matches?: number;
  last_matched?: string;
}

interface YaraifyListResponse {
  query_status: string;
  data?: YaraRuleEntry[] | string;
}

export default function Yarahub(): JSX.Element {
  const [rules, setRules] = useState<YaraRuleEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [ruleContent, setRuleContent] = useState<string | null>(null);
  const [contentLoading, setContentLoading] = useState(false);
  const [contentName, setContentName] = useState<string | null>(null);
  const [contentError, setContentError] = useState<string | null>(null);
  const latestRuleReq = useRef(0);

  const fetchCtrlRef = useRef<AbortController | null>(null);
  const fetchRules = useCallback(async () => {
    fetchCtrlRef.current?.abort();
    const ctrl = new AbortController();
    fetchCtrlRef.current = ctrl;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/yara-hub?max=150', {
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15000)]),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(((body as Record<string, unknown>)?.error as string) ?? `HTTP ${res.status}`);
      }
      const json = (await res.json()) as YaraifyListResponse;
      if (json.query_status !== 'ok') {
        throw new Error(`YARAify API: ${json.query_status}${typeof json.data === 'string' ? ` - ${json.data}` : ''}`);
      }
      if (!ctrl.signal.aborted) setRules(Array.isArray(json.data) ? json.data : []);
    } catch (e) {
      logCatch(e);
      if ((e as Error).name === 'AbortError') return;
      setError(errMessage(e, 'Failed to fetch YARA rules'));
      if (!ctrl.signal.aborted) setRules([]);
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const ctrl = new AbortController();
    fetchCtrlRef.current = ctrl;
    void fetchRules();
    return () => ctrl.abort();
  }, [fetchRules]);

  const q = search.trim().toLowerCase();
  const filtered = q
    ? rules.filter(
        (r) =>
          r.rule_name.toLowerCase().includes(q) ||
          (r.author ?? '').toLowerCase().includes(q) ||
          (r.malware ?? '').toLowerCase().includes(q) ||
          (r.description ?? '').toLowerCase().includes(q)
      )
    : rules;

  const handleSearch = (e: FormEvent) => {
    e.preventDefault();
  };

  const viewRule = async (uuid: string, ruleName?: string) => {
    const reqId = ++latestRuleReq.current;
    const ctrl = new AbortController();
    setContentName(ruleName ?? uuid);
    setContentLoading(true);
    setRuleContent(null);
    setContentError(null);
    try {
      const res = await fetch(`/api/v1/yara-hub/rule/${encodeURIComponent(uuid)}`, {
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15000)]),
      });
      if (latestRuleReq.current !== reqId) return;
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        if (latestRuleReq.current !== reqId) return;
        throw new Error(((body as Record<string, unknown>)?.error as string) ?? `HTTP ${res.status}`);
      }
      const ct = res.headers.get('content-type') ?? '';
      if (ct.includes('json')) {
        const json = (await res.json()) as Record<string, unknown>;
        if (latestRuleReq.current !== reqId) return;
        if (json.rule_content) {
          setRuleContent(json.rule_content as string);
        } else if (json.data && typeof json.data === 'object' && (json.data as Record<string, unknown>).rule_content) {
          setRuleContent((json.data as Record<string, unknown>).rule_content as string);
        } else if (typeof json.data === 'string') {
          setContentError(json.data as string);
        } else if (json.query_status === 'error') {
          setContentError(typeof json.data === 'string' ? json.data : 'YARAify API returned an error');
        } else {
          setRuleContent(JSON.stringify(json, null, 2));
          setContentError('Unexpected response format - showing raw JSON');
        }
      } else {
        const text = await res.text();
        if (latestRuleReq.current !== reqId) return;
        setRuleContent(text);
      }
    } catch (e) {
      logCatch(e);
      if (latestRuleReq.current !== reqId) return;
      setContentError(errMessage(e, 'Unknown error'));
      setRuleContent(null);
    } finally {
      if (latestRuleReq.current === reqId) setContentLoading(false);
    }
  };

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<FileCode size={28} />}
      title="YARA Rule Hub"
      maxWidthClass="max-w-6xl"
      description={
        <span className="text-sm font-mono">
          Browse and search YARA rules from{' '}
          <a
            href="https://yaraify.abuse.ch/yarahub/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            YARAhub
          </a>{' '}
          by abuse.ch. Over 1,200 community-contributed rules with search by family, author, or rule name.
        </span>
      }
      headerExtra={
        <form onSubmit={handleSearch}>
          <label htmlFor="yara-search" className="sr-only">
            Search YARA rules
          </label>
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <Input
                id="yara-search"
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by rule name, family, or author (e.g. MALWARE_Win_Neshta, emotet, trickbot)"
                className="focus:border-rose-500 dark:focus:border-rose-400"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-3 bg-rose-600 dark:bg-rose-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-rose-700 dark:hover:bg-rose-400 inline-flex items-center gap-2 transition-colors"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
              Search
            </button>
          </div>
        </form>
      }
      error={error}
      onRetry={() => void fetchRules()}
    >
      {loading && !error && (
        <div className="surface-card p-8 text-center">
          <Loader2 size={20} className="animate-spin mx-auto text-muted mb-2" />
          <p className="text-xs font-mono text-muted">Fetching YARA rules from YARAhub…</p>
        </div>
      )}

      {!loading && !error && filtered.length === 0 && (
        <div className="surface-card p-12 text-center">
          <Search size={32} className="mx-auto text-inverted mb-3" />
          <p className="text-sm font-mono text-muted">{search ? 'No matching rules' : 'No YARA rules loaded'}</p>
          <p className="text-xs font-mono text-muted mt-1">
            {search ? 'Try a different search term' : 'The YARAhub API may be unavailable'}
          </p>
        </div>
      )}

      {filtered.length > 0 && (
        <>
          {search && (
            <p className="text-mini font-mono text-muted mb-2">
              {filtered.length} of {rules.length} rule{rules.length === 1 ? '' : 's'} match &quot;{search}&quot;
              {filtered.length < rules.length && (
                <button
                  type="button"
                  onClick={() => setSearch('')}
                  className="ml-2 text-rose-600 dark:text-rose-400 hover:underline"
                >
                  clear filter
                </button>
              )}
            </p>
          )}
          <div className="grid gap-2">
            {filtered.map((rule) => (
              <div
                key={rule.yarahub_uuid ?? rule.rule_name}
                className="surface-card hover:border-rose-500/40 transition-colors"
              >
                <div className="flex items-start justify-between p-4">
                  <div className="flex-1 min-w-0">
                    <button
                      type="button"
                      onClick={() => void viewRule(rule.yarahub_uuid ?? rule.rule_name, rule.rule_name)}
                      className="text-left font-display font-semibold text-sm text-rose-600 dark:text-rose-400 hover:underline break-all"
                    >
                      {rule.rule_name}
                    </button>
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1 text-meta font-mono text-muted">
                      {rule.author && <span>by {rule.author}</span>}
                      {rule.malware && (
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20 text-micro">
                          {rule.malware}
                        </span>
                      )}
                      {rule.date && <span>{rule.date}</span>}
                      {rule.matches !== undefined && (
                        <span>
                          {rule.matches.toLocaleString()} match{rule.matches === 1 ? '' : 'es'}
                        </span>
                      )}
                      {rule.last_matched && <span>last: {new Date(rule.last_matched).toLocaleDateString()}</span>}
                    </div>
                    {rule.description && (
                      <p className="mt-1 text-meta font-mono text-muted line-clamp-2">{rule.description}</p>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => void viewRule(rule.yarahub_uuid ?? rule.rule_name, rule.rule_name)}
                    className="shrink-0 ml-3 text-mini font-mono px-2.5 py-1 rounded border border-line-1 hover:border-rose-500/40 text-muted hover:text-rose-600 dark:hover:text-rose-400"
                  >
                    View rule
                  </button>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {contentLoading && (
        <div className="mt-6 surface-card p-8 text-center">
          <Loader2 size={20} className="animate-spin mx-auto text-muted mb-2" />
          <p className="text-xs font-mono text-muted">Downloading rule content…</p>
        </div>
      )}

      {ruleContent && !contentLoading && (
        <div className="mt-6 surface-card overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-line-1 bg-surface-200/60">
            <h3 className="font-display font-semibold text-sm truncate">{contentName}</h3>
            <div className="flex items-center gap-2">
              <a
                href={`https://yaraify.abuse.ch/yarahub/#${contentName}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-mini font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-1 transition-colors"
              >
                <ExternalLink size={11} /> YARAhub
              </a>
              <button
                type="button"
                onClick={() => {
                  const blob = new Blob([ruleContent], { type: 'text/plain' });
                  downloadBlob(blob, `${contentName}.yar`);
                }}
                className="text-mini font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-1"
              >
                <FileDown size={11} /> Download
              </button>
              <button
                type="button"
                onClick={() => {
                  setRuleContent(null);
                  setContentName(null);
                }}
                className="text-muted hover:text-muted dark:hover:text-inverted"
              >
                <X size={14} />
              </button>
            </div>
          </div>
          <pre className="p-4 overflow-auto max-h-[70vh] text-meta font-mono text-heading leading-relaxed whitespace-pre-wrap break-all">
            {ruleContent}
          </pre>
        </div>
      )}

      {contentError && (
        <div className="mt-4 rounded-xl border border-amber-200 dark:border-amber-900 bg-amber-50 dark:bg-amber-950/30 p-3">
          <p className="text-meta font-mono text-amber-700 dark:text-amber-300">{contentError}</p>
        </div>
      )}

      {!loading && filtered.length > 0 && (
        <p className="mt-4 text-mini font-mono text-muted text-center">
          {rules.length} rule{rules.length === 1 ? '' : 's'} loaded from YARAhub (abuse.ch){' '}
          <a
            href="https://yaraify.abuse.ch/yarahub/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            View on YARAhub <ExternalLink size={10} className="inline" />
          </a>
        </p>
      )}
    </DataPageLayout>
  );
}
