import { useEffect, useMemo, useState } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Link } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { ShieldCheck, ExternalLink, RotateCcw, Download } from 'lucide-react';
import { OWASP_LISTS, OWASP_ITEMS, type OwaspList, type OwaspItem } from '../../data/owasp';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

const STORAGE_KEY = 'dfir.owasp.checks';

type Check = 'unset' | 'covered' | 'partial' | 'gap';
const CHECK_CYCLE: Record<Check, Check> = { unset: 'covered', covered: 'partial', partial: 'gap', gap: 'unset' };

const CHECK_STYLES: Record<Check, { label: string; bg: string; text: string; border: string }> = {
  unset: {
    label: '- unset',
    bg: 'bg-slate-50 dark:bg-surface-200',
    text: 'text-slate-500',
    border: 'border-slate-300 dark:border-line-1',
  },
  covered: {
    label: 'covered',
    bg: 'bg-emerald-50 dark:bg-emerald-900/20',
    text: 'text-emerald-700 dark:text-emerald-300',
    border: 'border-emerald-400/60',
  },
  partial: {
    label: '~ partial',
    bg: 'bg-amber-50 dark:bg-amber-900/20',
    text: 'text-amber-700 dark:text-amber-300',
    border: 'border-amber-400/60',
  },
  gap: {
    label: 'gap',
    bg: 'bg-rose-50 dark:bg-rose-900/20',
    text: 'text-rose-700 dark:text-rose-300',
    border: 'border-rose-400/60',
  },
};

function loadChecks(): Record<string, Check> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Record<string, Check>) : {};
  } catch (_catchErr) {
    console.error('loadChecks failed:', errMessage(_catchErr));
    return {};
  }
}

function saveChecks(checks: Record<string, Check>): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(checks));
  } catch (_catchErr) {
    console.error('saveChecks failed:', errMessage(_catchErr));
    /* private mode */
  }
}

export default function Owasp(): JSX.Element {
  const [activeList, setActiveList] = useState<OwaspList>('web');
  const [checks, setChecks] = useState<Record<string, Check>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    setChecks(loadChecks());
  }, []);

  const items: OwaspItem[] = useMemo(() => OWASP_ITEMS.filter((i) => i.list === activeList), [activeList]);

  const stats = useMemo(() => {
    let covered = 0,
      partial = 0,
      gap = 0,
      unset = 0;
    for (const it of items) {
      const c = checks[it.id] ?? 'unset';
      if (c === 'covered') covered++;
      else if (c === 'partial') partial++;
      else if (c === 'gap') gap++;
      else unset++;
    }
    return { covered, partial, gap, unset, total: items.length };
  }, [items, checks]);

  const cycleCheck = (id: string) => {
    setChecks((prev) => {
      const current = prev[id] ?? 'unset';
      const next = { ...prev, [id]: CHECK_CYCLE[current] };
      saveChecks(next);
      return next;
    });
  };

  const resetList = () => {
    if (!confirm(`Reset all checks for ${OWASP_LISTS.find((l) => l.id === activeList)?.label}?`)) return;
    setChecks((prev) => {
      const next = { ...prev };
      for (const it of items) delete next[it.id];
      saveChecks(next);
      return next;
    });
  };

  const exportReport = () => {
    const list = OWASP_LISTS.find((l) => l.id === activeList);
    const lines: string[] = [
      `# ${list?.label} ${list?.year} - Self-Assessment`,
      `Generated: ${new Date().toISOString().slice(0, 10)}`,
      '',
      `Coverage: ${stats.covered}/${stats.total} covered, ${stats.partial} partial, ${stats.gap} gaps, ${stats.unset} unset`,
      '',
    ];
    for (const it of items) {
      const c = checks[it.id] ?? 'unset';
      lines.push(`## ${it.id}: ${it.title}  [${CHECK_STYLES[c].label}]`);
      lines.push('');
      lines.push(it.summary);
      lines.push('');
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    downloadBlob(blob, `owasp-${activeList}-${new Date().toISOString().slice(0, 10)}.md`);
  };

  const toggleExpanded = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <ShieldCheck size={28} className="text-brand-600 dark:text-brand-400" /> OWASP Top 10
        </h1>
        <p className="text-muted mb-8 max-w-3xl">
          Reference for the three current authoritative OWASP lists: Web (2021), API (2023), and LLM (2025). Each item
          gives the definition, a concrete attack example, and a code-level mitigation. Click an item's{' '}
          <span className="font-mono">unset</span> chip to mark it{' '}
          <span className="text-emerald-600 dark:text-emerald-400 font-mono">covered</span>,{' '}
          <span className="text-amber-600 dark:text-amber-400 font-mono">partial</span>, or{' '}
          <span className="text-rose-600 dark:text-rose-400 font-mono">gap</span> - your assessment is stored locally
          and exportable as a Markdown audit trail.
        </p>
      </div>

      {/* List tabs */}
      <div className="flex flex-wrap gap-2 mb-8">
        {OWASP_LISTS.map((l) => {
          const on = l.id === activeList;
          return (
            <button
              key={l.id}
              type="button"
              onClick={() => setActiveList(l.id)}
              className={`px-4 py-2 rounded-xl border text-sm font-mono transition-colors ${
                on
                  ? 'border-brand-500/50 bg-brand-50 dark:bg-brand-900/20 text-heading'
                  : 'border-line-1 text-slate-500 hover:border-brand-500/30'
              }`}
            >
              <span className="font-display font-semibold">{l.label}</span>
              <span className="text-xs ml-2 text-muted">{l.year}</span>
            </button>
          );
        })}
      </div>

      {/* Stats */}
      <section className="mb-6 surface-card p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-4">
          <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 text-xs font-mono">
            <span className="text-muted">Coverage:</span>
            <span className="text-emerald-600 dark:text-emerald-400">{stats.covered} covered</span>
            <span className="text-amber-600 dark:text-amber-400">{stats.partial} partial</span>
            <span className="text-rose-600 dark:text-rose-400">{stats.gap} gap</span>
            <span className="text-muted">{stats.unset} unset</span>
          </div>
          <div className="flex gap-2 text-xs font-mono">
            <button
              type="button"
              onClick={exportReport}
              className="inline-flex items-center gap-1 px-2 py-1 rounded border border-line-1 hover:border-brand-500/40 transition-colors"
            >
              <Download size={11} /> export markdown
            </button>
            <button
              type="button"
              onClick={resetList}
              className="inline-flex items-center gap-1 px-2 py-1 rounded border border-line-1 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
            >
              <RotateCcw size={11} /> reset
            </button>
          </div>
        </div>
        {/* Coverage bar */}
        {stats.total > 0 && (
          <div className="mt-3 flex h-2 overflow-hidden rounded-full bg-track">
            <div className="bg-emerald-500" style={{ width: `${(stats.covered / stats.total) * 100}%` }} />
            <div className="bg-amber-500" style={{ width: `${(stats.partial / stats.total) * 100}%` }} />
            <div className="bg-rose-500" style={{ width: `${(stats.gap / stats.total) * 100}%` }} />
          </div>
        )}
      </section>

      {/* Items */}
      <section className="space-y-3">
        {items.map((it) => {
          const c = checks[it.id] ?? 'unset';
          const style = CHECK_STYLES[c];
          const isExpanded = expanded.has(it.id);
          return (
            <article key={it.id} className={`rounded-xl border ${style.border} ${style.bg} transition-colors`}>
              <header className="flex items-start gap-3 p-4">
                <button
                  type="button"
                  onClick={() => cycleCheck(it.id)}
                  className={`shrink-0 text-xs font-mono px-2 py-1 rounded border ${style.border} ${style.text} bg-surface-100 dark:bg-surface-200 hover:opacity-80 transition-opacity`}
                  aria-label={`mark ${it.id} status (current: ${c})`}
                >
                  {style.label}
                </button>
                <button type="button" onClick={() => toggleExpanded(it.id)} className="flex-1 text-left">
                  <div className="flex items-baseline gap-2">
                    <span className="font-mono text-xs text-muted">{it.id}</span>
                    <h3 className="font-display font-semibold text-heading">{it.title}</h3>
                  </div>
                  <p className="text-sm text-muted mt-1 leading-relaxed">{it.summary}</p>
                </button>
              </header>
              {isExpanded && (
                <div className="px-4 pb-4 pt-0 grid sm:grid-cols-2 gap-3 text-sm">
                  <div className="rounded border border-line-1 p-3 bg-surface-100">
                    <div className="text-micro font-mono uppercase tracking-wider text-rose-600 dark:text-rose-400 mb-1">
                      Attack
                    </div>
                    <p className="text-body leading-relaxed">{it.example}</p>
                  </div>
                  <div className="rounded border border-line-1 p-3 bg-surface-100">
                    <div className="text-micro font-mono uppercase tracking-wider text-emerald-600 dark:text-emerald-400 mb-1">
                      Mitigation
                    </div>
                    <p className="text-body leading-relaxed">{it.mitigation}</p>
                  </div>
                  {it.attack && it.attack.length > 0 && (
                    <div className="sm:col-span-2 flex flex-wrap items-center gap-2 text-xs font-mono text-muted">
                      <span>MITRE ATT&CK:</span>
                      {it.attack.map((t) => (
                        <Link
                          key={t}
                          to={`/threatintel/mitre?id=${encodeURIComponent(t)}`}
                          className="px-1.5 py-0.5 rounded bg-surface-300 hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1"
                        >
                          {t} <ExternalLink size={10} />
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </article>
          );
        })}
      </section>

      <footer className="mt-12 text-xs font-mono text-muted leading-relaxed">
        References:{' '}
        {OWASP_LISTS.map((l, i) => (
          <span key={l.id}>
            {i > 0 && ' · '}
            <a
              href={sanitizeUrl(l.reference) || undefined}
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline transition-colors"
            >
              {l.label}
            </a>
          </span>
        ))}
        . Self-assessment state is stored in your browser's localStorage; nothing is uploaded.
      </footer>
    </div>
  );
}
