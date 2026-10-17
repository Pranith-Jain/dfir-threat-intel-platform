import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ExternalLink,
  Search,
  X,
  Filter,
  Clock,
  BookOpen,
  GraduationCap,
  ChevronDown,
  Bookmark,
  Check,
  Share2,
  Download,
  Upload,
  Trash2,
  Sparkles,
} from 'lucide-react';
import { DataPageLayout } from '../components/DataPageLayout';
import {
  courseUrl,
  loadBookmarks,
  loadProgress,
  normalizeCourseId,
  parseLibraryImport,
  saveBookmarks,
  saveProgress,
  serializeLibrary,
  type AnarchyProgress,
} from '../lib/anarchy-library';
import { recommendCourses, similarCourses } from '../lib/anarchy-recommend';
import { downloadBlob } from '../lib/download';
import { errMessage } from '../lib/log';

interface AnarchyProvider {
  name: string;
  host: string;
  icon: string;
}
type AnarchyDifficulty = 'beginner' | 'intermediate' | 'advanced';

interface AnarchyCourseSlim {
  id: string;
  title: string;
  href: string;
  img: string | null;
  tags: string[];
  provider: AnarchyProvider;
  difficulty: AnarchyDifficulty;
  hours: number;
  preview: string;
  sizeBytes: number;
}

interface AnarchyIndex {
  source: string;
  url: string;
  coursesUrl: string;
  description: string;
  license: string;
  author: string;
  authorUrl: string;
  syncedAt: string;
  builtAt: string;
  counts: { courses: number; categories: number };
  categories: { tag: string; count: number }[];
  topTags: { tag: string; count: number }[];
  topProviders: { name: string; count: number }[];
  prereqGraph: Record<string, { tag: string; weight: number }[]>;
  courses: AnarchyCourseSlim[];
}

interface AnarchyCourseBody {
  id: string;
  title: string;
  desc: string;
  href: string;
  img: string | null;
  tags: string[];
  provider: AnarchyProvider;
  difficulty: AnarchyDifficulty;
  hours: number;
  prereqs: string[];
}

// Display mapping — mirrors kazamadono.github.io filter chips. Colors ride the
// portfolio's token system: tinted *-500/10 pills over surface cards, with the
// /30 borders matching the rest of the threat-intel pages.
const FILTER_META: Record<string, { label: string; color: string }> = {
  all: { label: 'All', color: 'border-line-1 text-muted' },
  aiml: { label: 'AI/ML', color: 'border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300' },
  exploits: { label: 'Low Level', color: 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300' },
  psyops: { label: 'PsyOps', color: 'border-pink-500/30 bg-pink-500/10 text-pink-700 dark:text-pink-300' },
  bio: { label: 'Bio/Med', color: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' },
  infra: { label: 'Infra', color: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300' },
  blue: { label: 'Defensive', color: 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300' },
  red: { label: 'Offensive', color: 'border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300' },
  osint: { label: 'OSINT', color: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300' },
  game: {
    label: 'Game Hacking',
    color: 'border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300',
  },
  webappsec: {
    label: 'BugBounty',
    color: 'border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  },
  crypto: { label: 'Crypto', color: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-700 dark:text-yellow-300' },
  re: { label: 'Reversing', color: 'border-zinc-500/30 bg-zinc-500/10 text-zinc-700 dark:text-zinc-300' },
  mobile: { label: 'Mobile', color: 'border-lime-500/30 bg-lime-500/10 text-lime-700 dark:text-lime-300' },
  cloud: { label: 'Cloud', color: 'border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-300' },
  forensics: { label: 'Forensics', color: 'border-teal-500/30 bg-teal-500/10 text-teal-700 dark:text-teal-300' },
  ctf: { label: 'CTF', color: 'border-indigo-500/30 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300' },
  blockchain: {
    label: 'Blockchain',
    color: 'border-purple-500/30 bg-purple-500/10 text-purple-700 dark:text-purple-300',
  },
  iot: { label: 'IoT/HW', color: 'border-stone-500/30 bg-stone-500/10 text-stone-700 dark:text-stone-300' },
  dev: { label: 'Dev/CS', color: 'border-cyan-600/30 bg-cyan-600/10 text-cyan-800 dark:text-cyan-200' },
  math: { label: 'Math', color: 'border-slate-500/30 bg-slate-500/10 text-slate-700 dark:text-slate-300' },
  project: { label: 'Project', color: 'border-teal-400/30 bg-teal-400/10 text-teal-700 dark:text-teal-200' },
};

const ALL_FILTERS = [
  'all',
  'aiml',
  'exploits',
  'psyops',
  'bio',
  'infra',
  'blue',
  'red',
  'osint',
  'game',
  'webappsec',
  'crypto',
  're',
  'mobile',
  'cloud',
  'forensics',
  'ctf',
  'blockchain',
  'iot',
  'dev',
  'math',
  'project',
];

// Shared input styling — identical to the threat-intel pages.
const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder:text-slate-400 focus:outline-none focus:border-brand-400';

function sanitizeUrl(url: string): string {
  try {
    const u = new URL(url);
    if (u.protocol === 'http:' || u.protocol === 'https:') return url;
    return '#';
  } catch {
    return '#';
  }
}

const DIFFICULTY_PILL: Record<AnarchyDifficulty, string> = {
  beginner: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  intermediate: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  advanced: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
};

const UPSTREAM = 'https://kazamadono.github.io/';
const UPSTREAM_AUTHOR = 'https://github.com/KazamaDono';

export default function Anarchy() {
  const [idx, setIdx] = useState<AnarchyIndex | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState<string>('all');
  const [difficulty, setDifficulty] = useState<string>('all');
  const [sort, setSort] = useState<'id' | 'hours' | 'difficulty'>('id');
  const [maxHours, setMaxHours] = useState<number>(12);
  const [visibleCount, setVisibleCount] = useState(48);
  const [selected, setSelected] = useState<AnarchyCourseSlim | null>(null);
  const [selectedBody, setSelectedBody] = useState<AnarchyCourseBody | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  // Phase 3 — personal library (localStorage) + deep-link routing
  const [bookmarks, setBookmarks] = useState<string[]>(() => loadBookmarks());
  const [progress, setProgress] = useState<Record<string, AnarchyProgress>>(() => loadProgress());
  const [savedOnly, setSavedOnly] = useState(false);
  const [hideDone, setHideDone] = useState(false);
  const [copied, setCopied] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const importRef = useRef<HTMLInputElement>(null);
  const routeParams = useParams<{ id?: string }>();
  const navigate = useNavigate();
  const searchRef = useRef<HTMLInputElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);

  const resetFilters = useCallback(() => {
    setQ('');
    setFilter('all');
    setDifficulty('all');
    setMaxHours(12);
    setSavedOnly(false);
    setHideDone(false);
    setVisibleCount(48);
  }, []);

  // Fetch index
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        let res = await fetch('/data/anarchy/index.json');
        if (!res.ok) res = await fetch('/data/anarchy/index.json', { cache: 'no-cache' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as AnarchyIndex;
        if (!cancelled) {
          setIdx(json);
          setLoading(false);
        }
      } catch (e) {
        if (!cancelled) {
          setError(errMessage(e));
          setLoading(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Fetch full body on selection
  useEffect(() => {
    if (!selected) {
      setSelectedBody(null);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`/data/anarchy/courses/${selected.id}.json`);
        if (res.ok) {
          const body = (await res.json()) as AnarchyCourseBody;
          if (!cancelled) setSelectedBody(body);
        } else {
          // Fallback to slim
          if (!cancelled)
            setSelectedBody({
              id: selected.id,
              title: selected.title,
              desc: selected.preview,
              href: selected.href,
              img: selected.img,
              tags: selected.tags,
              provider: selected.provider,
              difficulty: selected.difficulty,
              hours: selected.hours,
              prereqs: [],
            });
        }
      } catch {
        if (!cancelled)
          setSelectedBody({
            id: selected.id,
            title: selected.title,
            desc: selected.preview,
            href: selected.href,
            img: selected.img,
            tags: selected.tags,
            provider: selected.provider,
            difficulty: selected.difficulty,
            hours: selected.hours,
            prereqs: [],
          });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selected]);

  // Phase 3 — persist personal library
  useEffect(() => {
    saveBookmarks(bookmarks);
  }, [bookmarks]);
  useEffect(() => {
    saveProgress(progress);
  }, [progress]);

  const openCourse = useCallback(
    (c: AnarchyCourseSlim) => {
      setSelected(c);
      setCopied(false);
      navigate(`/anarchy/c/${c.id}`, { replace: true });
    },
    [navigate]
  );

  const closeSelected = useCallback(() => {
    setSelected(null);
    setCopied(false);
    navigate('/anarchy', { replace: true });
  }, [navigate]);

  // Phase 3 — deep link: /anarchy/c/:id opens the course once the index loads
  const routeId = normalizeCourseId(routeParams.id);
  useEffect(() => {
    if (!idx || !routeId) return;
    if (selected?.id === routeId) return;
    const found = idx.courses.find((c) => normalizeCourseId(c.id) === routeId);
    if (found) setSelected(found);
  }, [idx, routeId, selected?.id]);

  const toggleBookmark = useCallback((id: string) => {
    const norm = normalizeCourseId(id) ?? id;
    setBookmarks((prev) => (prev.includes(norm) ? prev.filter((b) => b !== norm) : [...prev, norm]));
  }, []);

  const setCourseProgress = useCallback((id: string, value: AnarchyProgress | null) => {
    const norm = normalizeCourseId(id) ?? id;
    setProgress((prev) => {
      if (value === null) {
        if (!(norm in prev)) return prev;
        const next = { ...prev };
        delete next[norm];
        return next;
      }
      return { ...prev, [norm]: value };
    });
  }, []);

  const copyCourseLink = useCallback(async (id: string) => {
    const url = courseUrl(id);
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      // Clipboard API unavailable (permissions / insecure context) — fall back to selection hack
      const ta = document.createElement('textarea');
      ta.value = url;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }, []);

  const shareCourse = useCallback(
    async (course: AnarchyCourseSlim | AnarchyCourseBody) => {
      const url = courseUrl(course.id);
      const nav = navigator as Navigator & {
        share?: (data: { title?: string; text?: string; url?: string }) => Promise<void>;
      };
      if (typeof nav.share === 'function') {
        try {
          await nav.share({ title: course.title, text: course.title, url });
          return;
        } catch {
          /* user dismissed — fall through to copy */
        }
      }
      await copyCourseLink(course.id);
    },
    [copyCourseLink]
  );

  // Keyboard shortcuts: / to focus, Esc to clear
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '/' && !(e.target instanceof HTMLInputElement)) {
        e.preventDefault();
        searchRef.current?.focus();
      }
      if (e.key === 'Escape') {
        if (selected) closeSelected();
        else if (showSettings) setShowSettings(false);
        else {
          setQ('');
          searchRef.current?.blur();
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selected, showSettings, closeSelected]);

  const filtered = useMemo(() => {
    if (!idx) return [];
    let list = idx.courses;
    if (filter !== 'all') {
      list = list.filter((c) => c.tags.includes(filter));
    }
    if (difficulty !== 'all') {
      list = list.filter((c) => c.difficulty === difficulty);
    }
    if (maxHours < 12) {
      list = list.filter((c) => c.hours <= maxHours);
    }
    if (savedOnly) {
      list = list.filter((c) => bookmarks.includes(normalizeCourseId(c.id) ?? c.id));
    }
    if (hideDone) {
      list = list.filter((c) => progress[normalizeCourseId(c.id) ?? c.id] !== 'done');
    }
    if (q.trim()) {
      const needle = q.toLowerCase();
      list = list.filter(
        (c) =>
          c.title.toLowerCase().includes(needle) ||
          c.preview.toLowerCase().includes(needle) ||
          c.tags.join(' ').includes(needle) ||
          c.provider.name.toLowerCase().includes(needle) ||
          c.provider.host.toLowerCase().includes(needle)
      );
    }
    // Sort
    if (sort === 'hours') list = [...list].sort((a, b) => a.hours - b.hours);
    else if (sort === 'difficulty') {
      const rank: Record<string, number> = { beginner: 0, intermediate: 1, advanced: 2 };
      list = [...list].sort((a, b) => (rank[a.difficulty] ?? 1) - (rank[b.difficulty] ?? 1));
    }
    return list;
  }, [idx, filter, difficulty, maxHours, sort, q, savedOnly, hideDone, bookmarks, progress]);

  const visible = useMemo(() => filtered.slice(0, visibleCount), [filtered, visibleCount]);

  const handleFilter = useCallback((f: string) => {
    setFilter(f);
    setVisibleCount(48);
    // Smooth scroll to grid on mobile
    if (window.innerWidth < 768) {
      gridRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, []);

  const tagCounts = useMemo(() => {
    if (!idx) return new Map<string, number>();
    const m = new Map<string, number>();
    for (const { tag, count } of idx.categories) m.set(tag, count);
    return m;
  }, [idx]);

  const libraryCounts = useMemo(() => {
    const done = Object.values(progress).filter((v) => v === 'done').length;
    const doing = Object.values(progress).filter((v) => v === 'doing').length;
    return { saved: bookmarks.length, doing, done };
  }, [bookmarks, progress]);

  // Phase 4 — deterministic picks from the local library (no fetch needed:
  // the full slim index is already in memory). Hidden until the user saves
  // or tracks at least one course.
  const forYou = useMemo(() => {
    if (!idx) return [];
    if (bookmarks.length + Object.keys(progress).length === 0) return [];
    const done = Object.entries(progress)
      .filter(([, v]) => v === 'done')
      .map(([k]) => k);
    const doing = Object.entries(progress)
      .filter(([, v]) => v === 'doing')
      .map(([k]) => k);
    return recommendCourses(idx.courses, { saved: bookmarks, done, doing, limit: 8 });
  }, [idx, bookmarks, progress]);

  const similar = useMemo(() => {
    if (!idx || !selected) return [];
    return similarCourses(idx.courses, selected.id, 4);
  }, [idx, selected]);

  const exportLibrary = useCallback(() => {
    const blob = new Blob([serializeLibrary(bookmarks, progress)], { type: 'application/json' });
    downloadBlob(blob, 'anarchy-library.json');
  }, [bookmarks, progress]);

  const importLibraryFile = useCallback(async (file: File) => {
    setImportError(null);
    try {
      const text = await file.text();
      const { bookmarks: b, progress: p } = parseLibraryImport(text);
      setBookmarks(b);
      setProgress(p);
    } catch (e) {
      setImportError(errMessage(e, 'Could not read that file — expected an anarchy-library.json export.'));
    }
  }, []);

  const clearLibrary = useCallback(() => {
    setBookmarks([]);
    setProgress({});
    setSavedOnly(false);
  }, []);

  return (
    <DataPageLayout
      backTo="/"
      backLabel="Home"
      icon={<GraduationCap size={28} />}
      title="Anarchy Course Catalog"
      description={
        <>
          A daily-synced mirror of the{' '}
          <a
            href={UPSTREAM}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sky-600 dark:text-sky-400 hover:underline"
          >
            Anarchy course portal
          </a>{' '}
          by KazamaDono — 1,708 free courses across 20 tracks (exploitation, AI/ML, cloud, forensics, CTF and more),
          with deep links, saved library, and progress tracking. Replicated with attribution; course links retained
          verbatim.
        </>
      }
      loading={loading && !idx}
      error={error}
      onRetry={() => window.location.reload()}
      maxWidthClass="max-w-7xl"
      headerExtra={
        <div className="flex flex-wrap items-center gap-2">
          <a
            href={UPSTREAM}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-xl border border-line-1 px-3 py-1.5 text-xs font-medium hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors"
          >
            Open upstream <ExternalLink className="w-3 h-3" />
          </a>
          <a
            href={UPSTREAM_AUTHOR}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-xl border border-line-1 px-3 py-1.5 text-xs font-medium hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors"
          >
            Source: @KazamaDono
          </a>
        </div>
      }
      metaDescription="Anarchy course catalog mirror (1,708 courses, 20 tracks) with deep links, saved library, and progress - daily sync."
    >
      {idx && (
        <>
          {/* Stats strip */}
          <div className="surface-card p-4 mb-4 flex flex-wrap items-center gap-x-8 gap-y-3">
            {[
              { label: 'Courses', value: idx.counts.courses },
              { label: 'Tracks', value: idx.counts.categories },
              { label: 'Saved', value: libraryCounts.saved },
              { label: 'In progress', value: libraryCounts.doing },
              { label: 'Done', value: libraryCounts.done },
            ].map(({ label, value }) => (
              <div key={label}>
                <div className="text-micro font-mono uppercase tracking-wider text-muted">{label}</div>
                <div className="text-2xl font-bold text-heading font-mono">{value}</div>
              </div>
            ))}
            <div className="ml-auto text-right">
              <div className="text-micro font-mono uppercase tracking-wider text-muted">Daily sync</div>
              <div className="text-sm font-bold text-heading font-mono">
                {new Date(idx.syncedAt).toLocaleDateString()}
              </div>
              <div className="text-mini font-mono text-muted">{new Date(idx.syncedAt).toLocaleTimeString()}</div>
            </div>
          </div>

          {/* Phase 4 — For you */}
          {forYou.length > 0 && (
            <section className="mb-4">
              <div className="flex items-center gap-2 mb-2">
                <Sparkles className="w-4 h-4 text-brand-400" />
                <h2 className="text-sm font-bold text-heading">For you — from your library</h2>
                <span className="text-mini font-mono text-muted">
                  {libraryCounts.saved} saved · {libraryCounts.done} done
                </span>
              </div>
              <div className="flex gap-3 overflow-x-auto pb-2 -mx-1 px-1">
                {forYou.map(({ course: c, score, reasons }, i) => {
                  const normId = normalizeCourseId(c.id) ?? c.id;
                  const saved = bookmarks.includes(normId);
                  return (
                    <article
                      key={c.id}
                      onClick={() => openCourse(c)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          openCourse(c);
                        }
                      }}
                      tabIndex={0}
                      role="button"
                      aria-label={`#${i + 1}: ${c.title} — open details`}
                      className="group shrink-0 w-64 text-left rounded-xl border border-line-1 bg-surface-100/50 p-4 hover:border-brand-400 transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-sm font-bold text-muted">#{i + 1}</span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleBookmark(c.id);
                          }}
                          aria-pressed={saved}
                          aria-label={saved ? `Remove ${c.title} from saved` : `Save ${c.title} for later`}
                          className={`w-7 h-7 rounded-full border flex items-center justify-center transition-colors ${
                            saved
                              ? 'bg-brand-500/10 border-brand-400 text-brand-400'
                              : 'border-line-1 text-muted hover:text-heading'
                          }`}
                        >
                          <Bookmark className="w-3.5 h-3.5" fill={saved ? 'currentColor' : 'none'} />
                        </button>
                      </div>
                      <h3 className="mt-2 text-sm font-bold text-heading leading-snug line-clamp-2">{c.title}</h3>
                      <p className="mt-1 text-mini font-mono text-muted line-clamp-2 leading-relaxed flex-1">
                        {reasons[0] ?? `Score ${score.toFixed(1)}`}
                        {reasons[1] ? ` · ${reasons[1]}` : ''}
                      </p>
                      <div className="mt-2 flex items-center gap-1.5 text-micro font-mono">
                        <span className="text-body">
                          {c.provider.icon} {c.provider.name}
                        </span>
                        <span className="text-muted">·</span>
                        <span className={`px-1.5 py-0.5 rounded border ${DIFFICULTY_PILL[c.difficulty]}`}>
                          {c.difficulty}
                        </span>
                        <span className="text-muted inline-flex items-center gap-0.5">
                          <Clock className="w-3 h-3" /> {c.hours}h
                        </span>
                      </div>
                    </article>
                  );
                })}
              </div>
            </section>
          )}

          {/* Controls */}
          <div className="surface-card p-4 mb-4 space-y-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
              <input
                ref={searchRef}
                value={q}
                onChange={(e) => {
                  setQ(e.target.value);
                  setVisibleCount(48);
                }}
                placeholder="Search courses, tags, providers…  (press / to focus, Esc clears)"
                className={`${inputCls} pl-9 font-mono`}
              />
            </div>

            <div className="flex flex-wrap gap-1.5 max-h-40 overflow-y-auto pr-1">
              {ALL_FILTERS.map((f) => {
                const meta = FILTER_META[f] ?? FILTER_META['all']!;
                const active = filter === f;
                const count = f === 'all' ? idx.counts.courses : (tagCounts.get(f) ?? 0);
                return (
                  <button
                    key={f}
                    onClick={() => handleFilter(f)}
                    className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                      active
                        ? 'bg-brand-500/10 border-brand-400 text-brand-400'
                        : `${meta.color} hover:border-brand-400/40`
                    }`}
                    aria-pressed={active}
                  >
                    {meta.label} <span className="opacity-60 ml-1">{count}</span>
                  </button>
                );
              })}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span className="text-micro font-mono uppercase tracking-wider text-muted">Difficulty</span>
              {(['all', 'beginner', 'intermediate', 'advanced'] as const).map((d) => (
                <button
                  key={d}
                  onClick={() => {
                    setDifficulty(d);
                    setVisibleCount(48);
                  }}
                  className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${
                    difficulty === d
                      ? 'border-brand-400 bg-brand-500/10 text-brand-400'
                      : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-400/40'
                  }`}
                >
                  {d}
                </button>
              ))}
              <span className="text-micro font-mono uppercase tracking-wider text-muted ml-2">Sort</span>
              <select
                value={sort}
                onChange={(e) => setSort(e.target.value as never)}
                className={`${inputCls} w-auto py-1.5 text-xs font-mono`}
              >
                <option value="id">ID</option>
                <option value="hours">Hours ↑</option>
                <option value="difficulty">Difficulty</option>
              </select>
              <span className="text-micro font-mono uppercase tracking-wider text-muted ml-2">Max hours</span>
              <input
                type="range"
                min={2}
                max={12}
                value={maxHours}
                onChange={(e) => {
                  setMaxHours(Number(e.target.value));
                  setVisibleCount(48);
                }}
                className="w-24 accent-brand-400"
              />
              <span className="text-xs font-mono text-heading w-8">{maxHours}h</span>
              <button
                onClick={() => {
                  setSavedOnly((v) => !v);
                  setVisibleCount(48);
                }}
                aria-pressed={savedOnly}
                className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-mono font-medium border transition ${
                  savedOnly
                    ? 'border-brand-400 bg-brand-500/10 text-brand-400'
                    : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-400/40'
                }`}
              >
                <Bookmark className="w-3 h-3" /> Saved ({libraryCounts.saved})
              </button>
              <button
                onClick={() => {
                  setHideDone((v) => !v);
                  setVisibleCount(48);
                }}
                aria-pressed={hideDone}
                className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${
                  hideDone
                    ? 'border-emerald-500 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                    : 'border-slate-300 dark:border-line-1 text-muted hover:border-emerald-500/40'
                }`}
              >
                Hide done{libraryCounts.done > 0 ? ` (${libraryCounts.done})` : ''}
              </button>
              <button
                onClick={() => setShowSettings((v) => !v)}
                className="px-2 py-1 rounded text-xs font-mono border border-line-2 text-muted hover:text-heading transition-colors"
                title="Settings — library export/import"
              >
                Library…
              </button>
              <button
                onClick={resetFilters}
                className="px-2 py-1 rounded text-xs font-mono text-muted hover:text-heading transition-colors"
              >
                Reset all
              </button>
              <span className="ml-auto text-xs font-mono text-muted">
                {filtered.length} match{filtered.length === 1 ? '' : 'es'}
              </span>
            </div>
          </div>

          {/* Grid */}
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-bold text-heading font-mono">
              {filter === 'all' ? 'All courses' : (FILTER_META[filter]?.label ?? filter)} · {filtered.length}
            </h2>
            <div className="flex items-center gap-1.5 text-mini font-mono text-muted">
              <Filter className="w-3 h-3" /> {visible.length} / {filtered.length} shown
            </div>
          </div>

          {filtered.length === 0 ? (
            <div className="surface-card p-12 text-center">
              <Search className="w-8 h-8 mx-auto text-muted mb-3" />
              <p className="text-sm text-body">
                No courses match “{q}”{savedOnly ? ' in your saved library' : ''}.
              </p>
              <button
                onClick={resetFilters}
                className="mt-4 px-4 py-2 rounded-xl border border-line-1 text-sm font-medium hover:bg-surface-200 dark:hover:bg-surface-300"
              >
                Reset filters
              </button>
            </div>
          ) : (
            <>
              <div ref={gridRef} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 mb-4">
                {visible.map((c) => {
                  const normId = normalizeCourseId(c.id) ?? c.id;
                  const saved = bookmarks.includes(normId);
                  const st = progress[normId];
                  return (
                    <article
                      key={c.id}
                      onClick={() => openCourse(c)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          openCourse(c);
                        }
                      }}
                      tabIndex={0}
                      role="button"
                      aria-label={`${c.title} — open details`}
                      className="group text-left rounded-xl border border-line-1 bg-surface-100/50 hover:border-brand-400 transition-colors overflow-hidden flex flex-col h-full cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-400"
                    >
                      {/* Image */}
                      <div className="h-28 bg-surface-300 relative overflow-hidden border-b border-line-1">
                        {c.img ? (
                          <img
                            src={`https://kazamadono.github.io/${c.img}`}
                            alt=""
                            className="w-full h-full object-cover group-hover:scale-[1.02] transition-transform duration-500"
                            loading="lazy"
                            onError={(e) => {
                              (e.target as HTMLImageElement).style.display = 'none';
                            }}
                          />
                        ) : (
                          <div className="w-full h-full flex items-center justify-center">
                            <BookOpen className="w-8 h-8 text-muted" />
                          </div>
                        )}
                        <div className="absolute top-2 left-2 flex gap-1 flex-wrap">
                          {c.tags.slice(0, 2).map((t) => {
                            const meta = FILTER_META[t] ?? {
                              label: t,
                              color: 'border-slate-300 dark:border-line-1 text-muted',
                            };
                            return (
                              <span
                                key={t}
                                className={`text-micro font-mono px-2 py-0.5 rounded-full border backdrop-blur ${meta.color}`}
                              >
                                {meta.label}
                              </span>
                            );
                          })}
                        </div>
                        <div className="absolute top-2 right-2 flex items-center gap-1.5">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleBookmark(c.id);
                            }}
                            aria-pressed={saved}
                            aria-label={saved ? `Remove ${c.title} from saved` : `Save ${c.title} for later`}
                            title={saved ? 'Saved — click to remove' : 'Save for later'}
                            className={`w-7 h-7 rounded-full backdrop-blur border flex items-center justify-center transition-colors ${
                              saved
                                ? 'bg-brand-500/20 border-brand-400 text-brand-400'
                                : 'bg-white/80 dark:bg-black/50 border-line-1 text-muted hover:text-heading'
                            }`}
                          >
                            <Bookmark className="w-3.5 h-3.5" fill={saved ? 'currentColor' : 'none'} />
                          </button>
                        </div>
                      </div>
                      <div className="p-4 flex-1 flex flex-col">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className="text-micro font-mono text-muted">#{c.id}</span>
                          <span
                            className={`px-1.5 py-0.5 text-micro font-mono rounded border ${DIFFICULTY_PILL[c.difficulty]}`}
                          >
                            {c.difficulty}
                          </span>
                          <span className="text-micro font-mono text-muted inline-flex items-center gap-0.5">
                            <Clock className="w-3 h-3" /> {c.hours}h
                          </span>
                        </div>
                        <h3 className="text-sm font-bold text-heading leading-snug line-clamp-2 group-hover:text-brand-400 transition-colors">
                          {c.title}
                        </h3>
                        <p className="mt-1.5 text-xs text-muted line-clamp-3 leading-relaxed flex-1">{c.preview}</p>
                        <div className="mt-3 pt-2 border-t border-line-1 flex items-center justify-between">
                          <span className="inline-flex items-center gap-1 text-mini font-mono text-body truncate">
                            <span>{c.provider.icon}</span> {c.provider.name}
                          </span>
                          {st ? (
                            <span
                              className={`text-micro font-mono px-2 py-0.5 rounded-full border ${
                                st === 'done'
                                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                                  : 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                              }`}
                            >
                              {st === 'done' ? 'Done' : 'In progress'}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-mini font-mono text-sky-600 dark:text-sky-400 group-hover:underline">
                              Open <ExternalLink className="w-3 h-3" />
                            </span>
                          )}
                        </div>
                      </div>
                    </article>
                  );
                })}
              </div>

              {visible.length < filtered.length && (
                <div className="flex justify-center">
                  <button
                    onClick={() => setVisibleCount((n) => n + 48)}
                    className="inline-flex items-center gap-2 px-6 py-3 rounded-xl border border-line-1 text-sm font-medium hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors"
                  >
                    Load more <ChevronDown className="w-4 h-4" />
                    <span className="text-muted font-mono text-xs">({filtered.length - visible.length} remaining)</span>
                  </button>
                </div>
              )}
            </>
          )}

          {/* Attribution — source links only */}
          <footer className="mt-6 surface-card-faint p-4 flex flex-wrap gap-3 items-center justify-between text-xs text-muted">
            <span>
              Source:{' '}
              <a
                href={UPSTREAM}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sky-600 dark:text-sky-400 hover:underline"
              >
                kazamadono.github.io
              </a>{' '}
              ·{' '}
              <a
                href={UPSTREAM_AUTHOR}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sky-600 dark:text-sky-400 hover:underline"
              >
                @KazamaDono
              </a>{' '}
              · {idx.license}
            </span>
            <span className="inline-flex items-center gap-2 font-mono">
              <Clock className="w-3 h-3" /> Daily sync 06:00 UTC · built {new Date(idx.builtAt).toLocaleString()}
            </span>
          </footer>
        </>
      )}

      {/* Course Modal */}
      {selected &&
        (() => {
          const modalNorm = normalizeCourseId(selected.id) ?? selected.id;
          const modalSaved = bookmarks.includes(modalNorm);
          const modalProgress = progress[modalNorm] ?? null;
          return (
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
              <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={closeSelected} />
              <div className="relative w-full max-w-2xl max-h-[90vh] overflow-hidden rounded-2xl border border-line-1 bg-surface-100 shadow-xl flex flex-col">
                <div className="h-48 relative overflow-hidden shrink-0 bg-surface-300">
                  {selected.img ? (
                    <img
                      src={`https://kazamadono.github.io/${selected.img}`}
                      alt=""
                      className="w-full h-full object-cover"
                    />
                  ) : (
                    <div className="w-full h-full flex items-center justify-center">
                      <BookOpen className="w-12 h-12 text-muted" />
                    </div>
                  )}
                  <div className="absolute top-3 right-3 flex items-center gap-2">
                    <button
                      onClick={() => toggleBookmark(selected.id)}
                      aria-pressed={modalSaved}
                      aria-label={modalSaved ? 'Remove from saved' : 'Save for later'}
                      title={modalSaved ? 'Saved — click to remove' : 'Save for later'}
                      className={`h-8 px-3 rounded-full backdrop-blur border flex items-center gap-1.5 text-xs font-medium transition-colors ${
                        modalSaved
                          ? 'bg-brand-500/20 border-brand-400 text-brand-400'
                          : 'bg-white/80 dark:bg-black/60 border-line-1 text-heading'
                      }`}
                    >
                      <Bookmark className="w-3.5 h-3.5" fill={modalSaved ? 'currentColor' : 'none'} />
                      {modalSaved ? 'Saved' : 'Save'}
                    </button>
                    <button
                      onClick={closeSelected}
                      aria-label="Close details"
                      className="w-8 h-8 rounded-full bg-surface-100/80 dark:bg-black/60 backdrop-blur border border-line-1 flex items-center justify-center text-heading hover:bg-surface-300 dark:hover:bg-black/80 transition-colors"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="absolute bottom-3 left-4 right-4">
                    <div className="flex gap-1.5 flex-wrap mb-2">
                      {(selectedBody?.tags ?? selected.tags).map((t) => {
                        const meta = FILTER_META[t] ?? {
                          label: t,
                          color: 'border-slate-300 dark:border-line-1 text-muted',
                        };
                        return (
                          <span
                            key={t}
                            className={`text-xs font-mono px-2.5 py-1 rounded-full border backdrop-blur ${meta.color}`}
                          >
                            {meta.label}
                          </span>
                        );
                      })}
                    </div>
                    <h3 className="text-xl font-bold text-heading leading-tight">
                      {selectedBody?.title ?? selected.title}
                    </h3>
                    <p className="text-xs font-mono text-muted mt-1">
                      #{selected.id} · {(selectedBody?.provider ?? selected.provider).name} ·{' '}
                      {selectedBody?.hours ?? selected.hours}h
                    </p>
                  </div>
                </div>
                <div className="p-6 overflow-y-auto flex-1">
                  <p className="text-sm text-body leading-relaxed">{selectedBody?.desc ?? selected.preview}</p>
                  <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
                    <div className="rounded-xl border border-line-1 p-3">
                      <div className="text-micro font-mono uppercase tracking-wider text-muted">Provider</div>
                      <div className="text-heading mt-1 flex items-center gap-1.5 truncate">
                        <span>{(selectedBody?.provider ?? selected.provider).icon}</span>{' '}
                        {(selectedBody?.provider ?? selected.provider).name} ·{' '}
                        {(selectedBody?.provider ?? selected.provider).host}
                      </div>
                    </div>
                    <div className="rounded-xl border border-line-1 p-3">
                      <div className="text-micro font-mono uppercase tracking-wider text-muted">
                        ID · Difficulty · Hours
                      </div>
                      <div className="text-heading mt-1 flex items-center gap-2 font-mono">
                        <span>#{selected.id}</span>
                        <span
                          className={`px-2 py-0.5 rounded-full text-micro border ${DIFFICULTY_PILL[selectedBody?.difficulty ?? selected.difficulty]}`}
                        >
                          {selectedBody?.difficulty ?? selected.difficulty}
                        </span>
                        <span className="inline-flex items-center gap-1">
                          <Clock className="w-3 h-3" /> {selectedBody?.hours ?? selected.hours}h
                        </span>
                      </div>
                    </div>
                  </div>
                  {selectedBody?.prereqs && selectedBody.prereqs.length > 0 && (
                    <div className="mt-4 rounded-xl border border-line-1 p-3">
                      <div className="text-micro font-mono uppercase tracking-wider text-muted">
                        Prerequisites · tag graph
                      </div>
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {selectedBody.prereqs.map((p) => {
                          const meta = FILTER_META[p] ?? {
                            label: p,
                            color: 'border-slate-300 dark:border-line-1 text-muted',
                          };
                          return (
                            <button
                              key={p}
                              onClick={() => {
                                setFilter(p);
                                closeSelected();
                                setVisibleCount(48);
                                gridRef.current?.scrollIntoView({ behavior: 'smooth' });
                              }}
                              className={`text-xs font-mono px-2.5 py-1 rounded-full border ${meta.color} hover:border-brand-400 transition-colors`}
                            >
                              → {meta.label}
                            </button>
                          );
                        })}
                      </div>
                      <p className="text-mini text-muted mt-2">Click a prereq tag to filter the catalog.</p>
                    </div>
                  )}
                  {/* Phase 4 — similar courses */}
                  {similar.length > 0 && (
                    <div className="mt-4 rounded-xl border border-line-1 p-3">
                      <div className="text-micro font-mono uppercase tracking-wider text-muted">Similar courses</div>
                      <div className="mt-2 grid gap-1.5">
                        {similar.map(({ course: c, reasons }) => (
                          <button
                            key={c.id}
                            onClick={() => openCourse(c)}
                            className="text-left rounded-lg border border-line-1 hover:border-brand-400 px-3 py-2 transition-colors"
                          >
                            <div className="text-xs font-medium text-heading truncate">{c.title}</div>
                            <div className="text-mini font-mono text-muted truncate">
                              #{c.id} · {reasons[0] ?? `${c.provider.name} · ${c.difficulty} · ${c.hours}h`}
                            </div>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                  {/* Phase 3 — my track: progress + share */}
                  <div className="mt-4 rounded-xl border border-line-1 p-3">
                    <div className="text-micro font-mono uppercase tracking-wider text-muted">
                      My track · saved in this browser
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      {(['todo', 'doing', 'done'] as const).map((s) => {
                        const active = (modalProgress ?? 'todo') === s;
                        return (
                          <button
                            key={s}
                            onClick={() => setCourseProgress(selected.id, s === 'todo' ? null : s)}
                            aria-pressed={active}
                            className={`text-xs font-mono px-3 py-1.5 rounded-full border transition-colors ${
                              active
                                ? s === 'done'
                                  ? 'bg-emerald-500/10 border-emerald-500 text-emerald-600 dark:text-emerald-400'
                                  : s === 'doing'
                                    ? 'bg-amber-500/10 border-amber-500 text-amber-600 dark:text-amber-400'
                                    : 'bg-brand-500/10 border-brand-400 text-brand-400'
                                : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-400/40'
                            }`}
                          >
                            {s === 'todo' ? 'Not started' : s === 'doing' ? 'In progress' : 'Done'}
                          </button>
                        );
                      })}
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      <button
                        onClick={() => copyCourseLink(selected.id)}
                        className="inline-flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-full border border-brand-400 bg-brand-500/10 text-brand-400 hover:bg-brand-500/20 transition-colors"
                      >
                        {copied ? <Check className="w-3.5 h-3.5" /> : <Share2 className="w-3.5 h-3.5" />}
                        {copied ? 'Link copied!' : 'Copy link'}
                      </button>
                      <button
                        onClick={() => shareCourse(selectedBody ?? selected)}
                        className="inline-flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-full border border-line-1 text-muted hover:text-heading transition-colors"
                      >
                        <ExternalLink className="w-3.5 h-3.5" /> Share…
                      </button>
                      <span className="text-mini font-mono text-muted truncate">{courseUrl(selected.id)}</span>
                    </div>
                  </div>
                </div>
                <div className="p-4 border-t border-line-1 flex gap-3">
                  <a
                    href={sanitizeUrl(selected.href)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex-1 inline-flex items-center justify-center gap-2 rounded-xl bg-brand-500 dark:bg-brand-400 text-on-fill dark:text-[#0b1220] text-sm font-bold py-3 hover:bg-brand-600 dark:hover:bg-brand-300 transition-colors"
                  >
                    Open course <ExternalLink className="w-4 h-4" />
                  </a>
                  <button
                    onClick={closeSelected}
                    className="rounded-xl border border-line-1 px-6 py-3 text-sm font-medium hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors"
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          );
        })()}

      {/* Library settings modal */}
      {showSettings && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setShowSettings(false)} />
          <div className="relative w-full max-w-md rounded-2xl border border-line-1 bg-surface-100 p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-heading">My library</h3>
              <button
                onClick={() => setShowSettings(false)}
                aria-label="Close settings"
                className="w-8 h-8 rounded-full border border-line-1 flex items-center justify-center text-muted hover:text-heading"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-4">
              <div className="rounded-xl border border-line-1 p-3">
                <div className="text-xs text-muted">
                  {libraryCounts.saved} saved · {libraryCounts.doing} in progress · {libraryCounts.done} done — stored
                  in this browser only.
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <button
                    onClick={exportLibrary}
                    className="inline-flex items-center gap-1.5 rounded-full border border-line-1 px-3 py-1.5 text-xs font-medium text-heading hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" /> Export
                  </button>
                  <button
                    onClick={() => {
                      setImportError(null);
                      importRef.current?.click();
                    }}
                    className="inline-flex items-center gap-1.5 rounded-full border border-line-1 px-3 py-1.5 text-xs font-medium text-heading hover:bg-surface-200 dark:hover:bg-surface-300 transition-colors"
                  >
                    <Upload className="w-3.5 h-3.5" /> Import
                  </button>
                  <button
                    onClick={clearLibrary}
                    className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/40 px-3 py-1.5 text-xs font-medium text-rose-600 dark:text-rose-400 hover:bg-rose-500/10 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" /> Clear
                  </button>
                  <input
                    ref={importRef}
                    type="file"
                    accept="application/json,.json"
                    className="hidden"
                    aria-label="Import library file"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      e.target.value = '';
                      if (f) void importLibraryFile(f);
                    }}
                  />
                </div>
                {importError && (
                  <div className="mt-2 text-xs text-rose-600 dark:text-rose-400">Import failed: {importError}</div>
                )}
              </div>
              <div className="rounded-xl border border-line-1 p-3 text-xs text-muted">
                <div>
                  Source:{' '}
                  <a
                    href={UPSTREAM}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sky-600 dark:text-sky-400 hover:underline"
                  >
                    kazamadono.github.io
                  </a>{' '}
                  · daily sync 06:00 UTC
                </div>
                <div className="mt-1">Synced: {new Date(idx!.syncedAt).toLocaleString()}</div>
                <div>Built: {new Date(idx!.builtAt).toLocaleString()}</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </DataPageLayout>
  );
}
