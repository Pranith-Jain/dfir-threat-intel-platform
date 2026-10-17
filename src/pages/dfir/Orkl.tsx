import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback, useRef } from 'react';
import { BookOpen, Calendar, FileText, Globe, Loader2, Search, User, Hash } from 'lucide-react';
import { BackLink } from '../../components/BackLink';
import { DataState } from '../../components/DataState';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';

interface ThreatActor {
  main_name: string;
  aliases?: string[];
  id: string;
}

interface ReportFiles {
  pdf?: string;
  img?: string;
  text?: string;
}

interface LibraryEntry {
  id: string;
  sha1_hash: string;
  title: string;
  llm_title?: string;
  authors?: string;
  created_at: string;
  updated_at: string;
  file_creation_date?: string;
  file_modification_date?: string;
  file_size?: number;
  language?: string;
  extraction_quality?: number;
  plain_text?: string;
  report_names?: string[];
  references?: string[];
  sources?: string[];
  threat_actors?: ThreatActor[];
  files?: ReportFiles;
}

interface SearchResponse {
  status: string;
  data: LibraryEntry[];
}

interface InfoResponse {
  status: string;
  data: {
    library_entries: number;
    library_version: number;
    library_last_update: string;
    source_entries: number;
    threat_actor_entries: number;
  };
}

function formatDate(iso: string): string {
  if (!iso) return '-';
  try {
    return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  } catch (_catchErr) {
    console.error('formatDate failed:', errMessage(_catchErr));
    return iso.slice(0, 10);
  }
}

function formatBytes(b?: number): string {
  if (!b) return '';
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / (1024 * 1024)).toFixed(1)} MB`;
}

export default function Orkl(): JSX.Element {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<LibraryEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<LibraryEntry | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [info, setInfo] = useState<InfoResponse['data'] | null>(null);
  const [showInfo, setShowInfo] = useState(false);

  const searchRef = useRef<AbortController | null>(null);

  const search = useCallback(async (q: string) => {
    if (!q.trim()) return;
    searchRef.current?.abort();
    const ctrl = new AbortController();
    searchRef.current = ctrl;
    setLoading(true);
    setError(null);
    setResults(null);
    setSelected(null);
    try {
      const r = await fetch(`/api/v1/orkl/search?query=${encodeURIComponent(q.trim())}&limit=25&full=false`, {
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
      });
      if (ctrl.signal.aborted) return;
      if (!r.ok) {
        const j = (await r.json().catch(() => ({}))) as { error?: string };
        throw new Error(j.error ?? `search failed (${r.status})`);
      }
      const body = (await r.json()) as SearchResponse;
      if (body.status !== 'success') throw new Error(body.status ?? 'orkl error');
      setResults(body.data ?? []);
    } catch (e) {
      logCatch(e);
      if (ctrl.signal.aborted) return;
      setError(errMessage(e));
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  }, []);

  const detailRef = useRef<AbortController | null>(null);

  const openDetail = async (entry: LibraryEntry) => {
    setSelected(entry);
    if (entry.plain_text) return;
    detailRef.current?.abort();
    const ctrl = new AbortController();
    detailRef.current = ctrl;
    setDetailLoading(true);
    try {
      const r = await fetch(`/api/v1/orkl/entry/${encodeURIComponent(entry.id)}?full=true`, {
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
      });
      if (ctrl.signal.aborted) return;
      if (!r.ok) throw new Error(`detail failed (${r.status})`);
      const body = (await r.json()) as { status: string; data: LibraryEntry };
      if (body.status === 'success' && body.data) {
        setSelected(body.data);
      }
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* keep the basic entry */
    } finally {
      if (!ctrl.signal.aborted) setDetailLoading(false);
    }
  };

  const loadInfo = async () => {
    if (info) {
      setShowInfo(!showInfo);
      return;
    }
    const ctrl = new AbortController();
    try {
      const r = await fetch('/api/v1/orkl/info', {
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]),
      });
      if (ctrl.signal.aborted) return;
      if (!r.ok) return;
      const body = (await r.json()) as InfoResponse;
      if (body.status === 'success' && body.data) {
        setInfo(body.data);
      }
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* ignore */
    }
    setShowInfo(true);
  };

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <BookOpen size={28} className="text-brand-600 dark:text-brand-400" /> ORKL Library
        </h1>
        <p className="text-muted mb-6 max-w-2xl leading-relaxed">
          Search the{' '}
          <a
            href="https://orkl.eu"
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
          >
            ORKL
          </a>{' '}
          open-source threat intelligence library - security reports, threat actor profiles, and vulnerability analyses
          aggregated from hundreds of sources. Click any entry to view full details.
        </p>
      </div>

      <button
        onClick={loadInfo}
        className="mb-6 text-xs font-mono text-muted hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
      >
        {showInfo && info ? 'hide' : 'show'} library stats
      </button>

      {showInfo && info && (
        <div className="surface-card p-4 mb-6 grid grid-cols-2 sm:grid-cols-5 gap-4 text-center">
          {[
            { label: 'Reports', value: info.library_entries.toLocaleString() },
            { label: 'Sources', value: info.source_entries.toLocaleString() },
            { label: 'Threat Actors', value: info.threat_actor_entries.toLocaleString() },
            { label: 'Version', value: `v${info.library_version}` },
            { label: 'Last Update', value: formatDate(info.library_last_update) },
          ].map((s) => (
            <div key={s.label}>
              <div className="text-2xl font-bold text-heading">{s.value}</div>
              <div className="text-micro font-mono uppercase tracking-wider text-muted mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          search(query);
        }}
        className="flex flex-col sm:flex-row gap-3 mb-6"
      >
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search threat reports, actors, CVEs…"
          className="flex-1 px-3 py-2 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
          aria-label="Search ORKL library"
        />
        <button
          type="submit"
          disabled={loading || !query.trim()}
          className="inline-flex items-center justify-center gap-1.5 text-xs font-mono px-4 py-2 rounded border border-brand-500/40 bg-brand-500/10 text-brand-700 dark:text-brand-300 hover:border-brand-500/70 disabled:opacity-50 transition-colors"
        >
          {loading ? <Loader2 size={13} className="animate-spin" /> : <Search size={13} />} search
        </button>
      </form>

      <DataState loading={loading} error={error} empty={false} rows={4}>
        {results !== null && results.length === 0 && !loading && (
          <p className="font-mono text-sm text-muted py-8 text-center">No results for &ldquo;{query}&rdquo;</p>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Results list */}
          {results !== null && results.length > 0 && (
            <div className={`space-y-2 ${selected ? 'lg:col-span-1' : 'lg:col-span-3'}`}>
              {/* AI summary of the visible ORKL search results. Public surface
                  so every visitor sees the analyst take on the matched reports. */}
              <AiSummaryCard
                surface="ORKL threat-intel reports"
                items={results.slice(0, 30).map((e) => ({
                  title: e.llm_title || e.title || 'Untitled',
                  body: `${e.authors ?? ''} · ${(e.threat_actors ?? []).map((ta) => ta.main_name).join(', ') || 'no actors'} · ${(e.report_names ?? []).join(', ') || 'no reports'}`,
                  source: e.authors ?? 'ORKL',
                }))}
                requireAdmin={false}
              />
              <div className="text-micro font-mono font-semibold uppercase tracking-wider text-muted mb-2">
                {results.length} result{results.length !== 1 ? 's' : ''}
              </div>
              {results.map((entry) => (
                <button
                  key={entry.id}
                  onClick={() => openDetail(entry)}
                  className={`w-full text-left rounded-xl border p-3 transition-colors ${
                    selected?.id === entry.id
                      ? 'border-brand-500/50 bg-brand-500/10'
                      : 'border-line-1 bg-white dark:bg-surface-200 hover:border-slate-300 dark:hover:border-slate-600'
                  }`}
                >
                  <div className="text-sm font-semibold text-heading leading-snug line-clamp-2">
                    {entry.llm_title || entry.title || 'Untitled'}
                  </div>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 mt-1.5 text-mini font-mono text-muted">
                    {entry.authors && (
                      <span className="inline-flex items-center gap-1">
                        <User size={10} /> {entry.authors}
                      </span>
                    )}
                    <span className="inline-flex items-center gap-1">
                      <Calendar size={10} /> {formatDate(entry.file_creation_date || entry.created_at)}
                    </span>
                    {entry.sources && entry.sources[0] && (
                      <span className="inline-flex items-center gap-1">
                        <Globe size={10} /> {entry.sources[0]}
                      </span>
                    )}
                  </div>
                </button>
              ))}
            </div>
          )}

          {/* Detail panel */}
          {selected && (
            <div className="lg:col-span-2 space-y-4">
              <div className="surface-card p-4">
                <h2 className="text-lg font-bold text-heading mb-2">
                  {selected.llm_title || selected.title || 'Untitled'}
                </h2>

                {selected.sha1_hash && (
                  <div className="flex items-center gap-1.5 text-mini font-mono text-muted mb-2">
                    <Hash size={10} /> {selected.sha1_hash}
                  </div>
                )}

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-4 text-mini font-mono">
                  {selected.authors && (
                    <div>
                      <span className="text-muted">Authors</span>
                      <div className="text-body">{selected.authors}</div>
                    </div>
                  )}
                  {selected.file_creation_date && (
                    <div>
                      <span className="text-muted">Published</span>
                      <div className="text-body">{formatDate(selected.file_creation_date)}</div>
                    </div>
                  )}
                  {selected.language && (
                    <div>
                      <span className="text-muted">Language</span>
                      <div className="text-body uppercase">{selected.language}</div>
                    </div>
                  )}
                  {selected.file_size != null && (
                    <div>
                      <span className="text-muted">File Size</span>
                      <div className="text-body">{formatBytes(selected.file_size)}</div>
                    </div>
                  )}
                  {selected.extraction_quality != null && (
                    <div>
                      <span className="text-muted">Extraction</span>
                      <div className="text-body">{Math.round(selected.extraction_quality * 100)}%</div>
                    </div>
                  )}
                  {selected.sources && selected.sources.length > 0 && (
                    <div>
                      <span className="text-muted">Sources</span>
                      <div className="text-body truncate" title={selected.sources.join(', ')}>
                        {selected.sources.join(', ')}
                      </div>
                    </div>
                  )}
                </div>

                {/* Threat actors */}
                {selected.threat_actors && selected.threat_actors.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mb-3">
                    {selected.threat_actors.map((ta) => (
                      <span
                        key={ta.id}
                        className="text-micro font-mono px-1.5 py-0.5 rounded border border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300"
                      >
                        {ta.main_name}
                      </span>
                    ))}
                  </div>
                )}

                {/* External links */}
                <div className="flex flex-wrap gap-2">
                  {selected.files?.pdf && (
                    <a
                      href={selected.files.pdf}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs font-mono px-2.5 py-1 rounded border border-line-1 text-muted hover:border-brand-500/40 transition-colors"
                    >
                      <FileText size={11} /> PDF
                    </a>
                  )}
                  {selected.references && selected.references.length > 0 && (
                    <a
                      href={selected.references[0]}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs font-mono px-2.5 py-1 rounded border border-line-1 text-muted hover:border-brand-500/40 transition-colors"
                    >
                      <Globe size={11} /> Source
                    </a>
                  )}
                </div>
              </div>

              {/* Plain text */}
              <div className="surface-card p-4">
                <h3 className="text-micro font-mono font-semibold uppercase tracking-wider text-muted mb-3">
                  Full Text
                </h3>
                {detailLoading ? (
                  <div className="flex items-center gap-2 text-sm text-muted">
                    <Loader2 size={14} className="animate-spin" /> Loading…
                  </div>
                ) : selected.plain_text ? (
                  <div className="text-sm text-body whitespace-pre-wrap leading-relaxed max-h-[600px] overflow-y-auto">
                    {selected.plain_text}
                  </div>
                ) : (
                  <p className="text-sm text-muted">No plain-text content available.</p>
                )}
              </div>
            </div>
          )}
        </div>
      </DataState>
    </div>
  );
}
