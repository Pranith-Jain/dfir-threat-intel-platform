import { useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Search, Users, ExternalLink, CheckCircle2, Loader2 } from 'lucide-react';
import { errMessage } from '../../lib/log';

const USERNAME_RE = /^[A-Za-z0-9._-]{2,64}$/;

interface PlatformResult {
  platform: string;
  name: string;
  category: string;
  status: 'found' | 'not-found' | 'unknown' | 'error';
  url: string;
}

interface OsnitResponse {
  username: string;
  generated_at: string;
  total_checked: number;
  found: number;
  results: PlatformResult[];
  summary: Record<string, number>;
}

const CATEGORY_CLS: Record<string, string> = {
  social: 'border-pink-500/40 bg-pink-500/10 text-pink-700 dark:text-pink-300',
  dev: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  tech: 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300',
  gaming: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  creative: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  finance: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  other: 'border-slate-500/40 bg-slate-500/10 text-body',
};

export default function UsernameOsnit(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [input, setInput] = useState(searchParams.get('username') ?? '');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<OsnitResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'found'>('all');

  const valid = USERNAME_RE.test(input.trim());

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const username = input.trim();
    if (!USERNAME_RE.test(username)) return;
    setSearchParams({ username }, { replace: true });
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const r = await fetch(`/api/v1/username-osint?username=${encodeURIComponent(username)}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setResult(await r.json());
    } catch (err) {
      console.error('UsernameOsnit failed:', errMessage(err));
      setError(errMessage(err, 'search failed'));
    } finally {
      setLoading(false);
    }
  };

  const filtered = result?.results.filter((r) => filter === 'all' || r.status === 'found') ?? [];
  const found = filtered.filter((r) => r.status === 'found');
  const notFound = filtered.filter((r) => r.status === 'not-found');

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Users size={28} className="text-brand-600 dark:text-brand-400" /> Username OSINT
        </h1>
        <p className="text-muted mb-2 leading-relaxed">
          Check 60+ platforms for a username - social, dev, gaming, creative, finance. Server-side HTTP checks, bounded
          concurrency, 15-minute edge cache.
        </p>
        <p className="text-xs text-muted font-mono mb-8">
          Inspired by Sherlock (84k stars). Checks live HTTP status codes to determine presence - "found" means the
          profile page returned 200/3xx, not that the account belongs to the same person.
        </p>
      </div>

      <section className="surface-card p-4 mb-6">
        <form onSubmit={onSubmit} className="flex gap-2">
          <div className="relative flex-1 min-w-[220px]">
            <Users size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="username (letters / digits / . _ -)"
              className="w-full pl-9 pr-3 py-2 rounded-xl border border-line-1 bg-surface-200 font-mono text-sm text-heading focus:border-brand-500/60 focus:outline-none"
              autoComplete="off"
              spellCheck={false}
              aria-label="Username"
            />
          </div>
          <button
            type="submit"
            disabled={!valid || loading}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 transition-colors"
          >
            <Search size={16} className="inline mr-2" />
            Search
          </button>
        </form>
        {input && !valid && (
          <p className="mt-2 text-xs font-mono text-amber-600 dark:text-amber-400">2-64 chars, a-z 0-9 . _ - only.</p>
        )}
      </section>

      {loading && (
        <p className="text-sm font-mono text-muted mb-4 inline-flex items-center gap-2">
          <Loader2 size={14} className="animate-spin" /> Checking 60+ platforms…
        </p>
      )}
      {error && (
        <p className="text-sm font-mono text-rose-600 dark:text-rose-400 mb-4 inline-flex items-center gap-2">
          error: {error}
        </p>
      )}

      {result && (
        <div className="space-y-6">
          <div className="flex items-center gap-4 font-mono text-sm">
            <span className="text-muted">
              Checked <span className="text-heading font-bold">{result.total_checked}</span> platforms
            </span>
            <span className="text-muted">
              Found <span className="text-emerald-600 dark:text-emerald-400 font-bold">{result.found}</span>
            </span>
            <div className="flex gap-1 ml-auto">
              {(['all', 'found'] as const).map((f) => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`px-2.5 py-1 text-xs font-mono rounded-xl border ${
                    filter === f
                      ? 'bg-brand-600 text-white border-brand-600'
                      : 'border-line-1 text-muted hover:bg-slate-100 dark:hover:bg-surface-300'
                  }`}
                >
                  {f === 'all' ? 'All' : 'Found'}
                </button>
              ))}
            </div>
          </div>

          {/* Found */}
          {found.length > 0 && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-xl mb-4 flex items-center gap-2">
                <CheckCircle2 size={18} className="text-emerald-500" /> Found ({found.length})
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                {found.map((r) => (
                  <a
                    key={r.platform}
                    href={r.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 p-2.5 rounded-xl bg-emerald-500/5 border border-emerald-500/20 hover:bg-emerald-500/10 transition text-sm font-mono"
                  >
                    <span className="text-emerald-500">ok</span>
                    <span className="font-medium text-heading">{r.name}</span>
                    <span
                      className={`text-micro px-1.5 py-0.5 rounded border ${CATEGORY_CLS[r.category] ?? CATEGORY_CLS.other}`}
                    >
                      {r.category}
                    </span>
                    <ExternalLink size={10} className="text-muted ml-auto shrink-0" />
                  </a>
                ))}
              </div>
            </section>
          )}

          {/* Not Found */}
          {filter === 'all' && notFound.length > 0 && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-xl mb-4 text-muted">Not Found ({notFound.length})</h2>
              <div className="flex flex-wrap gap-1.5">
                {notFound.map((r) => (
                  <span
                    key={r.platform}
                    className="text-xs font-mono px-2 py-0.5 rounded-xl bg-surface-300 text-muted border border-line-1"
                  >
                    {r.name}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Category Breakdown */}
          {Object.keys(result.summary).length > 0 && (
            <section className="surface-card p-6">
              <h2 className="font-display font-bold text-xl mb-4 text-muted">Category Breakdown</h2>
              <div className="flex flex-wrap gap-2">
                {Object.entries(result.summary)
                  .sort((a, b) => b[1] - a[1])
                  .map(([cat, count]) => (
                    <span
                      key={cat}
                      className={`text-xs font-mono px-2.5 py-1 rounded-xl border ${CATEGORY_CLS[cat] ?? CATEGORY_CLS.other}`}
                    >
                      {cat}: {count}
                    </span>
                  ))}
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}
