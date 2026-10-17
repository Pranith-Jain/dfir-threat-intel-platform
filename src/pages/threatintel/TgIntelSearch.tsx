/**
 * /threatintel/tools/tg-intel-search -- Telegram Intelligence Search
 *
 * Boolean AND/OR/NOT search across indexed Telegram messages with
 * field qualifiers, IOC auto-extraction, timeline, saved searches.
 */

import { logCatch } from '../../lib/log';
import { turnstileHeaders } from '../../lib/turnstile';
import { useEffect, useState, useCallback, useRef, type FormEvent } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import {
  Search,
  Trash2,
  Bookmark,
  X,
  ChevronDown,
  Copy,
  Check,
  ExternalLink,
  Filter,
  BarChart3,
  Loader2,
  AlertTriangle,
  Eye,
  Star,
  ChevronUp,
  Shield,
  Globe,
  Mail,
  Hash,
  Link2,
  Server,
} from 'lucide-react';

interface LeakEntry {
  id: number;
  channel_handle: string;
  message_link: string;
  message_text: string;
  leak_type: string;
  credential_count: number;
  file_name: string;
  domains_found: string;
  severity: string;
  discovered_at: string;
}

interface TimelinePoint {
  day: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}
interface SavedSearch {
  id: string;
  name: string;
  query: string;
  mode: string;
  sort_order: string;
  created_at: string;
}
interface ParsedIOC {
  type: string;
  value: string;
}

// ── IOC Extraction ──
const IOC_PATTERNS: Array<{ type: string; regex: RegExp }> = [
  { type: 'ipv4', regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g },
  {
    type: 'domain',
    regex: /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|ir|onion|top|xyz|cc|pw|su|biz|info|me)\b/gi,
  },
  { type: 'email', regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g },
  { type: 'sha256', regex: /\b[A-Fa-f0-9]{64}\b/g },
  { type: 'md5', regex: /\b[A-Fa-f0-9]{32}\b/g },
  { type: 'cve', regex: /CVE-\d{4}-\d{4,}/gi },
  { type: 'url', regex: /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi },
  { type: 'btc', regex: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g },
  { type: 'eth', regex: /\b0x[a-fA-F0-9]{40}\b/g },
  { type: 'onion', regex: /\b[a-z2-7]{16,56}\.onion\b/gi },
];

function extractIOCs(text: string): ParsedIOC[] {
  const seen = new Set<string>();
  const out: ParsedIOC[] = [];
  for (const { type, regex } of IOC_PATTERNS) {
    for (const m of text.match(regex) || []) {
      const k = `${type}:${m.toLowerCase()}`;
      if (!seen.has(k)) {
        seen.add(k);
        out.push({ type, value: m });
      }
    }
  }
  return out;
}

const IOC_CLR: Record<string, string> = {
  ipv4: 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300',
  domain: 'bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300',
  email: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300',
  sha256: 'bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300',
  md5: 'bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300',
  cve: 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300',
  url: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300',
  btc: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300',
  eth: 'bg-blue-100 dark:bg-blue-900/30 text-brand-700 dark:text-brand-300',
  onion: 'bg-slate-100 dark:bg-surface-200 text-body',
};

const IOC_ICO: Record<string, typeof Server> = {
  ipv4: Server,
  domain: Globe,
  email: Mail,
  sha256: Hash,
  md5: Hash,
  cve: Shield,
  url: Link2,
  btc: Globe,
  eth: Globe,
  onion: Globe,
};

const SEV: Record<string, string> = {
  critical: 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-800',
  high: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800',
  medium: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800',
  low: 'bg-slate-100 dark:bg-surface-300 text-muted border-line-1',
};

const LEAK_CLR: Record<string, string> = {
  credential: 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300',
  paste_link: 'bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300',
  file_link: 'bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300',
  keyword: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300',
  ioc: 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300',
  cve: 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300',
  unknown: 'bg-slate-100 dark:bg-surface-300 text-muted',
};

function TgIntelSearch() {
  const [query, setQuery] = useState('');
  const [mode, setMode] = useState<'boolean' | 'general'>('boolean');
  const [results, setResults] = useState<LeakEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const limit = 50;
  const [filterChannel, setFilterChannel] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterFrom, setFilterFrom] = useState('');
  const [filterTo, setFilterTo] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [topChannels, setTopChannels] = useState<Array<{ channel_handle: string; count: number }>>([]);
  const [timelineDays, setTimelineDays] = useState(30);
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>([]);
  const [showSaved, setShowSaved] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [showSaveForm, setShowSaveForm] = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [copiedIOC, setCopiedIOC] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const api = '/api/v1';

  const doSearch = useCallback(
    async (q: string, offset = 0) => {
      setLoading(true);
      setError(null);
      try {
        const p = new URLSearchParams({ q, mode, limit: String(limit), offset: String(offset), sort: 'newest' });
        if (filterChannel) p.set('channel', filterChannel);
        if (filterSeverity) p.set('severity', filterSeverity);
        if (filterFrom) p.set('from', filterFrom);
        if (filterTo) p.set('to', filterTo);
        const [s, t] = await Promise.all([
          fetch(`${api}/tg-search?${p}`).then((r) => r.json()),
          fetch(
            `${api}/tg-timeline?q=${encodeURIComponent(q)}&days=${timelineDays}${filterChannel ? `&channel=${filterChannel}` : ''}`
          ).then((r) => r.json()),
        ]);
        setResults(s.results || []);
        setTotal(s.total || 0);
        setPage(Math.floor(offset / limit));
        setTimeline(t.timeline || []);
        setTopChannels(t.topChannels || []);
      } catch (_catchErr) {
        logCatch(_catchErr);
        setError('Search failed');
      }
      setLoading(false);
    },
    [mode, filterChannel, filterSeverity, filterFrom, filterTo, timelineDays]
  );

  const handleSearch = (e: FormEvent) => {
    e.preventDefault();
    if (query.trim()) doSearch(query, 0);
  };
  const handleTimelineClick = (day: string) => {
    setFilterFrom(day);
    setFilterTo(day);
    doSearch(query, 0);
  };

  const fetchSaved = useCallback(async () => {
    try {
      const r = await fetch(`${api}/tg-saved-searches`);
      setSavedSearches((await r.json()).searches || []);
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* */
    }
  }, []);
  useEffect(() => {
    fetchSaved();
  }, [fetchSaved]);

  const handleSave = async () => {
    if (!saveName.trim() || !query.trim()) return;
    await fetch(`${api}/tg-saved-searches`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(await turnstileHeaders('tg-saved-search-save')) },
      body: JSON.stringify({ name: saveName, query, mode, sort_order: 'newest' }),
    });
    setSaveName('');
    setShowSaveForm(false);
    fetchSaved();
  };
  const handleDeleteSaved = async (id: string) => {
    await fetch(`${api}/tg-saved-searches/${id}`, {
      method: 'DELETE',
      headers: await turnstileHeaders('tg-saved-search-delete', 'DELETE'),
    });
    fetchSaved();
  };
  const loadSaved = (s: SavedSearch) => {
    setQuery(s.query);
    setMode(s.mode as 'boolean' | 'general');
    setShowSaved(false);
    doSearch(s.query, 0);
  };

  const toggleExpand = (id: number) => setExpandedId(expandedId === id ? null : id);
  const copyIOC = (v: string) => {
    navigator.clipboard.writeText(v);
    setCopiedIOC(v);
    setTimeout(() => setCopiedIOC(null), 1500);
  };

  const maxCount = Math.max(...timeline.map((t) => t.count), 1);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Search size={28} />}
      title="Telegram Intelligence Search"
      description="Boolean AND/OR/NOT search across indexed Telegram messages. Field qualifiers, IOC auto-extraction, timeline visualization."
      headerExtra={
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowSaved(!showSaved)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-mini font-mono font-semibold rounded border border-line-1 bg-surface-100 hover:border-rose-300 dark:hover:border-rose-500/40 transition-colors"
          >
            <Bookmark size={10} /> Saved ({savedSearches.length})
          </button>
          <button
            type="button"
            onClick={() => setShowFilters(!showFilters)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-mini font-mono font-semibold rounded border border-line-1 bg-surface-100 hover:border-rose-300 dark:hover:border-rose-500/40 transition-colors"
          >
            <Filter size={10} /> Filters
          </button>
        </div>
      }
    >
      {/* Saved Searches */}
      {showSaved && (
        <div className="mb-4 surface-card p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-display font-semibold text-sm">Saved Searches</h3>
            <button
              type="button"
              onClick={() => setShowSaved(false)}
              className="text-muted hover:text-heading dark:hover:text-slate-100"
            >
              <X size={14} />
            </button>
          </div>
          {savedSearches.length === 0 ? (
            <p className="text-meta font-mono text-muted">No saved searches yet.</p>
          ) : (
            <div className="space-y-1.5">
              {savedSearches.map((s) => (
                <div key={s.id} className="flex items-center justify-between p-2 rounded bg-surface-200">
                  <button type="button" onClick={() => loadSaved(s)} className="text-left flex-1 min-w-0">
                    <p className="text-tool font-semibold truncate">{s.name}</p>
                    <p className="text-meta font-mono text-muted truncate">{s.query}</p>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDeleteSaved(s.id)}
                    className="p-1 text-inverted dark:text-muted hover:text-rose-500 ml-2"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Search Bar */}
      <form onSubmit={handleSearch} className="mb-4">
        <div className="flex gap-2">
          <div className="flex items-center surface-card overflow-hidden flex-1">
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as 'boolean' | 'general')}
              className="px-2.5 py-2 bg-surface-200 border-r border-line-1 text-mini font-mono font-semibold text-muted focus:outline-none"
            >
              <option value="boolean">Boolean</option>
              <option value="general">General</option>
            </select>
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={
                mode === 'boolean' ? 'ransomware AND channel.title:TeamPCP NOT tutorial' : 'search keywords...'
              }
              className="flex-1 px-3 py-2 bg-transparent font-mono text-tool text-heading placeholder:text-muted focus:outline-none"
            />
            {query && (
              <button
                type="button"
                onClick={() => {
                  setQuery('');
                  setResults([]);
                  setTotal(0);
                  setTimeline([]);
                }}
                className="px-2 text-muted hover:text-heading dark:hover:text-slate-100"
              >
                <X size={14} />
              </button>
            )}
          </div>
          <button
            aria-label="Search"
            type="submit"
            className="px-4 py-2 bg-rose-600 dark:bg-rose-500 text-on-fill font-mono text-sm font-semibold rounded-xl hover:bg-rose-700 dark:hover:bg-rose-400 transition-colors"
          >
            <Search size={14} />
          </button>
          {query && (
            <button
              type="button"
              onClick={() => setShowSaveForm(true)}
              className="px-2.5 py-2 border border-line-1 rounded-xl font-mono text-muted hover:text-heading dark:hover:text-slate-100 hover:border-rose-300 transition-colors"
            >
              <Star size={14} />
            </button>
          )}
        </div>
      </form>

      {showSaveForm && (
        <div className="mb-4 flex gap-2 items-center">
          <input
            value={saveName}
            onChange={(e) => setSaveName(e.target.value)}
            placeholder="Search name..."
            className="flex-1 max-w-xs px-3 py-1.5 bg-surface-100 border border-line-1 rounded font-mono text-tool focus:outline-none focus:border-rose-500"
          />
          <button
            type="button"
            onClick={handleSave}
            className="px-3 py-1.5 bg-rose-600 dark:bg-rose-500 text-on-fill text-mini font-mono font-semibold rounded"
          >
            Save
          </button>
          <button
            type="button"
            onClick={() => setShowSaveForm(false)}
            className="text-muted hover:text-heading dark:hover:text-slate-100"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* Filters */}
      {showFilters && (
        <div className="mb-4 surface-card p-4">
          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label htmlFor="tg-ch" className="block text-micro font-mono text-muted mb-1">
                Channel
              </label>
              <input
                id="tg-ch"
                value={filterChannel}
                onChange={(e) => setFilterChannel(e.target.value)}
                placeholder="@handle"
                className="px-2.5 py-1.5 bg-surface-200 border border-line-1 rounded font-mono text-meta focus:outline-none focus:border-rose-500 w-36"
              />
            </div>
            <div>
              <label htmlFor="tg-sev" className="block text-micro font-mono text-muted mb-1">
                Severity
              </label>
              <select
                id="tg-sev"
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="text-meta font-mono px-2 py-1.5 rounded border border-line-1 bg-surface-100 focus:outline-none"
              >
                <option value="">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label htmlFor="tg-from" className="block text-micro font-mono text-muted mb-1">
                From
              </label>
              <input
                id="tg-from"
                type="date"
                value={filterFrom}
                onChange={(e) => setFilterFrom(e.target.value)}
                className="px-2.5 py-1.5 bg-surface-200 border border-line-1 rounded font-mono text-meta focus:outline-none focus:border-rose-500"
              />
            </div>
            <div>
              <label htmlFor="tg-to" className="block text-micro font-mono text-muted mb-1">
                To
              </label>
              <input
                id="tg-to"
                type="date"
                value={filterTo}
                onChange={(e) => setFilterTo(e.target.value)}
                className="px-2.5 py-1.5 bg-surface-200 border border-line-1 rounded font-mono text-meta focus:outline-none focus:border-rose-500"
              />
            </div>
            <div>
              <label htmlFor="tg-days" className="block text-micro font-mono text-muted mb-1">
                Timeline
              </label>
              <select
                id="tg-days"
                value={timelineDays}
                onChange={(e) => setTimelineDays(Number(e.target.value))}
                className="text-meta font-mono px-2 py-1.5 rounded border border-line-1 bg-surface-100 focus:outline-none"
              >
                <option value={7}>7d</option>
                <option value={30}>30d</option>
                <option value={90}>90d</option>
                <option value={365}>1y</option>
              </select>
            </div>
            <button
              type="button"
              onClick={() => doSearch(query, 0)}
              className="px-3 py-1.5 bg-rose-600 dark:bg-rose-500 text-on-fill text-mini font-mono font-semibold rounded"
            >
              Apply
            </button>
          </div>
        </div>
      )}

      {/* Active filter pills */}
      {(filterChannel || filterSeverity || filterFrom || filterTo) && (
        <div className="flex flex-wrap gap-1.5 mb-4">
          {filterChannel && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300 text-micro font-mono border border-sky-200 dark:border-sky-800">
              @{filterChannel}{' '}
              <button
                type="button"
                onClick={() => {
                  setFilterChannel('');
                  doSearch(query, 0);
                }}
              >
                <X size={8} />
              </button>
            </span>
          )}
          {filterSeverity && (
            <span
              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-micro font-mono border ${SEV[filterSeverity] || SEV.low}`}
            >
              {filterSeverity}{' '}
              <button
                type="button"
                onClick={() => {
                  setFilterSeverity('');
                  doSearch(query, 0);
                }}
              >
                <X size={8} />
              </button>
            </span>
          )}
          {filterFrom && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 text-micro font-mono border border-emerald-200 dark:border-emerald-800">
              From: {filterFrom}{' '}
              <button
                type="button"
                onClick={() => {
                  setFilterFrom('');
                  doSearch(query, 0);
                }}
              >
                <X size={8} />
              </button>
            </span>
          )}
          {filterTo && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 text-micro font-mono border border-emerald-200 dark:border-emerald-800">
              To: {filterTo}{' '}
              <button
                type="button"
                onClick={() => {
                  setFilterTo('');
                  doSearch(query, 0);
                }}
              >
                <X size={8} />
              </button>
            </span>
          )}
        </div>
      )}

      {/* Timeline */}
      {timeline.length > 0 && (
        <div className="mb-6 surface-card p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-display font-semibold text-sm flex items-center gap-1.5">
              <BarChart3 size={12} className="text-rose-500" /> Activity Timeline
            </h3>
            <span className="text-micro font-mono text-muted">{total.toLocaleString()} events</span>
          </div>
          <div className="flex items-end gap-px h-20 overflow-x-auto">
            {timeline.map((t) => (
              <button
                type="button"
                key={t.day}
                onClick={() => handleTimelineClick(t.day)}
                title={`${t.day}: ${t.count}`}
                className="flex-1 min-w-[3px] rounded-t transition-opacity hover:opacity-80 group relative"
                style={{
                  height: `${Math.max((t.count / maxCount) * 100, 2)}%`,
                  background: `linear-gradient(to top, var(--color-emerald-500) 0%, var(--color-amber-500) ${Math.min(100, ((t.medium + t.high) / Math.max(t.count, 1)) * 100)}%, var(--color-red-500) ${Math.min(100, (t.critical / Math.max(t.count, 1)) * 100)}%)`,
                }}
              >
                <div className="hidden group-hover:block absolute bottom-full left-1/2 -translate-x-1/2 mb-1 px-1.5 py-0.5 bg-surface-100 dark:bg-surface-300 text-white dark:text-heading text-micro font-mono rounded whitespace-nowrap z-10">
                  {t.day}: {t.count}
                </div>
              </button>
            ))}
          </div>
          <div className="flex justify-between mt-1.5 text-micro font-mono text-muted">
            <span>{timeline[0]?.day}</span>
            <span>{timeline[timeline.length - 1]?.day}</span>
          </div>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex items-center gap-2 text-muted py-12 justify-center font-mono text-sm">
          <Loader2 className="w-5 h-5 animate-spin" /> Searching...
        </div>
      )}

      {error && (
        <div className="p-3 rounded-xl border border-rose-200 dark:border-rose-800 bg-rose-50 dark:bg-rose-900/20 text-rose-700 dark:text-rose-300 flex items-center gap-2 font-mono text-sm mb-4">
          <AlertTriangle className="w-4 h-4" /> {error}
        </div>
      )}

      {/* Results */}
      {!loading && results.length > 0 && (
        <>
          <div className="flex items-center justify-between mb-2">
            <span className="text-micro font-mono text-muted">{total.toLocaleString()} results</span>
            <div className="flex items-center gap-1.5">
              {topChannels.slice(0, 5).map((tc) => (
                <button
                  type="button"
                  key={tc.channel_handle}
                  onClick={() => {
                    setFilterChannel(tc.channel_handle);
                    doSearch(query, 0);
                  }}
                  className="text-micro font-mono px-1.5 py-0.5 rounded bg-surface-300 text-muted hover:bg-track dark:hover:bg-surface-300 transition-colors"
                >
                  @{tc.channel_handle} ({tc.count})
                </button>
              ))}
            </div>
          </div>
          <div className="space-y-1.5">
            {results.map((entry) => {
              const iocs = extractIOCs(entry.message_text || '');
              const isExpanded = expandedId === entry.id;
              const domains: string[] = (() => {
                try {
                  return JSON.parse(entry.domains_found || '[]');
                } catch (_catchErr) {
                  logCatch(_catchErr);
                  return [];
                }
              })();
              return (
                <div key={entry.id} className="surface-card overflow-hidden">
                  <div
                    role="button"
                    tabIndex={0}
                    onClick={() => toggleExpand(entry.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        toggleExpand(entry.id);
                      }
                    }}
                    className="flex items-start gap-3 p-3 cursor-pointer hover:bg-surface-200 dark:hover:bg-surface-100 transition-colors"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
                        <span className="text-micro font-mono font-semibold text-rose-600 dark:text-rose-400">
                          @{entry.channel_handle}
                        </span>
                        <span
                          className={`text-micro font-mono font-semibold px-1 py-0.5 rounded ${SEV[entry.severity] || SEV.low}`}
                        >
                          {entry.severity}
                        </span>
                        <span
                          className={`text-micro font-mono px-1 py-0.5 rounded ${LEAK_CLR[entry.leak_type] || LEAK_CLR.unknown}`}
                        >
                          {entry.leak_type}
                        </span>
                        {entry.credential_count > 0 && (
                          <span className="text-micro font-mono text-rose-600 dark:text-rose-400">
                            {entry.credential_count} creds
                          </span>
                        )}
                        <span className="text-micro font-mono text-muted ml-auto">
                          {entry.discovered_at?.split('T')[0]}
                        </span>
                      </div>
                      <p className={`text-meta font-mono text-body ${isExpanded ? '' : 'line-clamp-2'}`}>
                        {entry.message_text || '(no text)'}
                      </p>
                      {domains.length > 0 && !isExpanded && (
                        <div className="flex gap-1 mt-1">
                          {domains.slice(0, 3).map((d) => (
                            <span
                              key={d}
                              className="text-micro font-mono px-1 py-0.5 rounded bg-sky-50 dark:bg-sky-900/20 text-sky-600 dark:text-sky-400"
                            >
                              {d}
                            </span>
                          ))}
                          {domains.length > 3 && (
                            <span className="text-micro font-mono text-muted">+{domains.length - 3}</span>
                          )}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      {iocs.length > 0 && (
                        <span className="text-micro font-mono px-1 py-0.5 rounded bg-violet-100 dark:bg-violet-900/30 text-violet-600 dark:text-violet-400">
                          {iocs.length} IOC
                        </span>
                      )}
                      {entry.message_link && (
                        <a
                          href={entry.message_link}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="text-muted hover:text-rose-500 p-0.5"
                        >
                          <ExternalLink size={10} />
                        </a>
                      )}
                      {isExpanded ? (
                        <ChevronUp size={12} className="text-muted" />
                      ) : (
                        <ChevronDown size={12} className="text-muted" />
                      )}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="border-t border-line-1 p-3 bg-surface-200">
                      <div className="flex items-center gap-1.5 mb-2">
                        <Eye size={10} className="text-rose-500" />
                        <h4 className="text-mini font-display font-semibold">Observables</h4>
                        <span className="text-micro font-mono text-muted">({iocs.length})</span>
                      </div>
                      {iocs.length === 0 ? (
                        <p className="text-meta font-mono text-muted">No IOCs detected.</p>
                      ) : (
                        <div className="space-y-1.5">
                          {Object.entries(
                            iocs.reduce(
                              (a, i) => {
                                (a[i.type] = a[i.type] || []).push(i);
                                return a;
                              },
                              {} as Record<string, ParsedIOC[]>
                            )
                          ).map(([type, items]) => {
                            const Icon = IOC_ICO[type] || Globe;
                            return (
                              <div key={type}>
                                <div className="flex items-center gap-1 mb-0.5">
                                  <Icon size={8} className="text-muted" />
                                  <span className="text-micro font-mono font-semibold text-muted uppercase">
                                    {type}
                                  </span>
                                  <span className="text-micro font-mono text-muted">({items.length})</span>
                                </div>
                                <div className="flex flex-wrap gap-1">
                                  {items.map((i) => (
                                    <button
                                      type="button"
                                      key={i.value}
                                      onClick={() => copyIOC(i.value)}
                                      className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-micro font-mono ${IOC_CLR[i.type] || 'bg-slate-100 dark:bg-surface-300 text-muted'} hover:opacity-80`}
                                    >
                                      {i.value.length > 36 ? i.value.slice(0, 36) + '...' : i.value}
                                      {copiedIOC === i.value ? (
                                        <Check size={7} />
                                      ) : (
                                        <Copy size={7} className="opacity-40" />
                                      )}
                                    </button>
                                  ))}
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}
                      {domains.length > 0 && (
                        <div className="mt-2 pt-2 border-t border-line-1">
                          <span className="text-micro font-mono font-semibold text-muted">Domains:</span>
                          <div className="flex flex-wrap gap-1 mt-0.5">
                            {domains.map((d) => (
                              <button
                                type="button"
                                key={d}
                                onClick={() => copyIOC(d)}
                                className="text-micro font-mono px-1 py-0.5 rounded bg-sky-50 dark:bg-sky-900/20 text-sky-600 dark:text-sky-400 hover:opacity-80"
                              >
                                {d}{' '}
                                {copiedIOC === d ? <Check size={7} /> : <Copy size={7} className="opacity-40 inline" />}
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="mt-2 pt-2 border-t border-line-1">
                        <span className="text-micro font-mono text-muted">
                          Sender:{' '}
                          <span className="font-semibold text-rose-600 dark:text-rose-400">
                            @{entry.channel_handle}
                          </span>
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          {total > limit && (
            <div className="flex items-center justify-center gap-3 mt-4">
              <button
                type="button"
                onClick={() => doSearch(query, Math.max(0, (page - 1) * limit))}
                disabled={page === 0}
                className="px-3 py-1.5 text-mini font-mono font-semibold rounded border border-line-1 disabled:opacity-40 hover:border-rose-300 transition-colors"
              >
                Previous
              </button>
              <span className="text-micro font-mono text-muted">
                Page {page + 1} of {Math.ceil(total / limit)}
              </span>
              <button
                type="button"
                onClick={() => doSearch(query, (page + 1) * limit)}
                disabled={(page + 1) * limit >= total}
                className="px-3 py-1.5 text-mini font-mono font-semibold rounded border border-line-1 disabled:opacity-40 hover:border-rose-300 transition-colors"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}

      {!loading && results.length === 0 && query && !error && (
        <div className="text-center py-16 text-muted">
          <Search className="w-12 h-12 mx-auto mb-4 opacity-30" />
          <p className="font-display font-semibold text-lg mb-1">No results</p>
          <p className="font-mono text-sm">Try a different query or adjust filters</p>
        </div>
      )}

      {!query && results.length === 0 && !loading && (
        <div className="text-center py-16 text-muted">
          <Shield className="w-12 h-12 mx-auto mb-4 opacity-20" />
          <p className="font-display font-semibold text-lg mb-1">Telegram Intelligence Search</p>
          <p className="font-mono text-sm mb-3">Search across indexed Telegram messages</p>
          <div className="max-w-md mx-auto text-left space-y-1 text-meta font-mono">
            <p className="text-muted">Examples:</p>
            <p className="text-body">ransomware AND "dark web"</p>
            <p className="text-body">channel.title:TeamPCP AND text:credential</p>
            <p className="text-body">stealer NOT tutorial</p>
          </div>
        </div>
      )}
    </DataPageLayout>
  );
}

export default function TgIntelSearchPage() {
  return <TgIntelSearch />;
}
