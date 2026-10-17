import { useEffect, useMemo, useState } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { Link } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { Scale, ExternalLink, Download, RotateCcw } from 'lucide-react';
import { REGIMES, type Article, type RegimeId } from '../../data/privacy-hub';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

const STORAGE_KEY = 'dfir.privacy-hub.checks.v1';

type CheckStatus = 'unset' | 'covered' | 'partial' | 'gap' | 'na';

const CYCLE: Record<CheckStatus, CheckStatus> = {
  unset: 'covered',
  covered: 'partial',
  partial: 'gap',
  gap: 'na',
  na: 'unset',
};

const STATUS_STYLES: Record<CheckStatus, { label: string; cls: string }> = {
  unset: { label: '- unset', cls: 'border-slate-300 dark:border-line-1 text-slate-500' },
  covered: {
    label: 'covered',
    cls: 'border-emerald-400/60 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  },
  partial: { label: '~ partial', cls: 'border-amber-400/60 bg-amber-500/10 text-amber-700 dark:text-amber-300' },
  gap: { label: 'gap', cls: 'border-rose-400/60 bg-rose-500/10 text-rose-700 dark:text-rose-300' },
  na: { label: 'n/a', cls: 'border-slate-300 dark:border-line-1 text-muted' },
};

const REGIME_STYLES: Record<RegimeId, string> = {
  gdpr: 'bg-brand-500/15 text-brand-700 dark:text-brand-300 border-brand-500/30',
  ccpa: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30',
  dpdp: 'bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30',
  'hipaa-privacy': 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30',
  'pci-dss': 'bg-violet-500/15 text-violet-700 dark:text-violet-300 border-violet-500/30',
};

interface State {
  checks: Record<string, CheckStatus>;
}

function loadState(): State {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { checks: {} };
    const parsed = JSON.parse(raw) as State;
    return { checks: parsed.checks ?? {} };
  } catch (_catchErr) {
    console.error('loadState failed:', errMessage(_catchErr));
    return { checks: {} };
  }
}

function coverage(items: Article[], state: State): { score: number; covered: number; total: number } {
  if (items.length === 0) return { score: 0, covered: 0, total: 0 };
  let weight = 0;
  for (const it of items) {
    const s = state.checks[it.id] ?? 'unset';
    if (s === 'covered') weight += 1;
    else if (s === 'partial') weight += 0.5;
  }
  return { score: Math.round((weight / items.length) * 100), covered: Math.round(weight), total: items.length };
}

function exportMd(state: State): string {
  const lines: string[] = ['# Privacy & Data-Protection Assessment', ''];
  for (const r of REGIMES) {
    const c = coverage([...r.rights, ...r.obligations], state);
    lines.push(`## ${r.short} - ${c.score}% (${c.covered}/${c.total})`);
    lines.push('');
    lines.push(`**Jurisdiction:** ${r.jurisdiction}  `);
    lines.push(`**Effective:** ${r.effectiveDate}`);
    lines.push('');
    lines.push(`**Breach notification:** ${r.breachNotification.summary}`);
    lines.push('');
    if (r.rights.length > 0) {
      lines.push('### Rights');
      for (const a of r.rights) {
        const s = state.checks[a.id] ?? 'unset';
        lines.push(`- ${a.title}${a.citation ? ` (${a.citation})` : ''}: **${s}**`);
      }
      lines.push('');
    }
    lines.push('### Obligations');
    for (const a of r.obligations) {
      const s = state.checks[a.id] ?? 'unset';
      lines.push(`- ${a.title}${a.citation ? ` (${a.citation})` : ''}: **${s}**`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

export default function PrivacyHub(): JSX.Element {
  const [state, setState] = useState<State>({ checks: {} });
  const [tab, setTab] = useState<RegimeId>('gdpr');

  useEffect(() => {
    setState(loadState());
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (_catchErr) {
      console.error('PrivacyHub failed:', errMessage(_catchErr));
      /* quota */
    }
  }, [state]);

  const cycle = (id: string) =>
    setState((prev) => ({ ...prev, checks: { ...prev.checks, [id]: CYCLE[prev.checks[id] ?? 'unset'] } }));

  const reset = () => {
    if (typeof window !== 'undefined' && confirm("Clear every regime's coverage marks? This cannot be undone.")) {
      setState({ checks: {} });
    }
  };

  const downloadMd = () => {
    const md = exportMd(state);
    const blob = new Blob([md], { type: 'text/markdown' });
    downloadBlob(blob, 'privacy-hub-assessment.md');
  };

  const allCoverage = useMemo(
    () =>
      REGIMES.map((r) => ({
        regime: r,
        coverage: coverage([...r.rights, ...r.obligations], state),
      })),
    [state]
  );

  const active = REGIMES.find((r) => r.id === tab)!;

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <Scale size={28} className="text-brand-600 dark:text-brand-400" /> Privacy &amp; Data-Protection Hub
        </h1>
        <p className="text-muted mb-2 leading-relaxed">
          {REGIMES.length} privacy regimes side by side: <strong>GDPR</strong>, <strong>CCPA / CPRA</strong>,{' '}
          <strong>DPDP</strong> (India), <strong>HIPAA Privacy Rule</strong>, <strong>PCI DSS 4.0</strong>. Rights,
          controller / fiduciary obligations, breach-notification timelines, enforcement &amp; penalties - all
          cross-mapped to the framework controls in /dfir/grc.
        </p>
        <p className="text-xs text-muted font-mono mb-8">
          Reference only - not legal advice. Pairs with the{' '}
          <Link to="/dfir/grc" className="text-brand-600 dark:text-brand-400 hover:underline">
            GRC hub
          </Link>{' '}
          (security frameworks),{' '}
          <Link to="/dfir/data-classification" className="text-brand-600 dark:text-brand-400 hover:underline">
            Data Classification
          </Link>{' '}
          and{' '}
          <Link to="/dfir/dlp-scan" className="text-brand-600 dark:text-brand-400 hover:underline">
            Sensitive Data Detector
          </Link>
          .
        </p>
      </div>

      {/* Coverage dashboard */}
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5 mb-6">
        {allCoverage.map(({ regime, coverage: c }) => (
          <button
            key={regime.id}
            onClick={() => setTab(regime.id)}
            className={`text-left rounded-xl border p-3 transition-colors ${
              tab === regime.id
                ? 'border-brand-500/60 bg-brand-500/5'
                : 'border-line-1 bg-white dark:bg-surface-200 hover:border-brand-500/40'
            }`}
          >
            <div className="flex items-baseline justify-between gap-2 mb-1">
              <span
                className={`text-mini font-mono uppercase tracking-[0.2em] px-1.5 py-0.5 rounded border ${REGIME_STYLES[regime.id]}`}
              >
                {regime.short}
              </span>
              <span className="text-xs font-mono font-bold text-heading">{c.score}%</span>
            </div>
            <div className="h-1.5 rounded bg-track overflow-hidden mb-1">
              <div
                className={`h-full ${
                  c.score >= 75 ? 'bg-emerald-500' : c.score >= 40 ? 'bg-amber-500' : 'bg-rose-500'
                }`}
                style={{ width: `${Math.max(2, c.score)}%` }}
              />
            </div>
            <div className="text-micro font-mono text-muted">
              {c.covered}/{c.total} items
            </div>
          </button>
        ))}
      </section>

      {/* Action bar */}
      <div className="flex flex-wrap gap-2 mb-6">
        <button
          onClick={downloadMd}
          className="text-sm font-mono px-3 py-1.5 rounded border border-line-2 hover:border-brand-500/40 inline-flex items-center gap-1.5 transition-colors"
        >
          <Download size={13} /> Export markdown
        </button>
        <button
          onClick={reset}
          className="text-sm font-mono px-3 py-1.5 rounded border border-line-2 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-1.5 transition-colors"
        >
          <RotateCcw size={13} /> Reset
        </button>
      </div>

      {/* Active regime */}
      <section className="surface-card p-4 mb-6">
        <div className="flex flex-wrap items-baseline gap-2 mb-2">
          <span
            className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${REGIME_STYLES[active.id]}`}
          >
            {active.short}
          </span>
          <h2 className="font-display font-bold text-xl text-heading">{active.longTitle}</h2>
        </div>
        <div className="grid gap-2 sm:grid-cols-2 mb-3 text-meta font-mono text-muted">
          <div>
            <span className="text-muted">Jurisdiction: </span>
            <span className="text-body">{active.jurisdiction}</span>
          </div>
          <div>
            <span className="text-muted">Effective: </span>
            <span className="text-body">{active.effectiveDate}</span>
          </div>
        </div>
        <p className="text-sm font-mono text-body leading-relaxed mb-2">{active.scope}</p>
        <p className="text-meta font-mono text-muted">{active.appliesTo}</p>
      </section>

      {/* Breach notification */}
      <section className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-4 mb-6">
        <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-rose-700 dark:text-rose-300 font-mono mb-2">
          Breach notification - {active.breachNotification.summary}
        </h3>
        <p className="text-sm font-mono text-body leading-relaxed mb-2">{active.breachNotification.detail}</p>
        <p className="text-mini font-mono text-muted mb-1">
          <strong className="text-body">Trigger:</strong> {active.breachNotification.trigger}
        </p>
        {active.breachNotification.toIndividuals && (
          <p className="text-mini font-mono text-muted">
            <strong className="text-body">Individuals:</strong> {active.breachNotification.toIndividuals}
          </p>
        )}
      </section>

      {/* Rights */}
      {active.rights.length > 0 && (
        <section className="surface-card p-4 mb-6">
          <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">
            Data subject / individual rights ({active.rights.length})
          </h3>
          <ul className="space-y-2">
            {active.rights.map((a) => (
              <ArticleRow key={a.id} article={a} state={state} cycle={cycle} />
            ))}
          </ul>
        </section>
      )}

      {/* Obligations */}
      <section className="surface-card p-4 mb-6">
        <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">
          Controller / fiduciary obligations ({active.obligations.length})
        </h3>
        <ul className="space-y-2">
          {active.obligations.map((a) => (
            <ArticleRow key={a.id} article={a} state={state} cycle={cycle} />
          ))}
        </ul>
      </section>

      {/* Enforcement */}
      <section className="surface-card p-4 mb-6">
        <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-2">
          Enforcement &amp; penalties
        </h3>
        <p className="text-sm font-mono text-body leading-relaxed">{active.enforcement}</p>
      </section>

      {/* Cross-references */}
      {active.crossRef.length > 0 && (
        <section className="surface-card p-4 mb-6">
          <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-2">
            Cross-references in /dfir/grc
          </h3>
          <div className="flex flex-wrap gap-1.5">
            {active.crossRef.map((id) => (
              <span
                key={id}
                className="text-mini font-mono px-2 py-1 rounded border border-brand-500/30 bg-brand-500/10 text-brand-700 dark:text-brand-300"
              >
                {id}
              </span>
            ))}
          </div>
        </section>
      )}

      <section className="surface-card p-4">
        <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-2">
          Authoritative sources
        </h3>
        <ul className="space-y-1.5 text-sm font-mono text-muted">
          {active.links.map((l) => (
            <li key={l.href}>
              <a
                href={sanitizeUrl(l.href) || undefined}
                target="_blank"
                rel="noopener noreferrer"
                className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
              >
                {l.label}
                <ExternalLink size={11} aria-hidden="true" />
              </a>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function ArticleRow({
  article,
  state,
  cycle,
}: {
  article: Article;
  state: State;
  cycle: (id: string) => void;
}): JSX.Element {
  const s = state.checks[article.id] ?? 'unset';
  return (
    <li className="rounded border border-line-1 bg-surface-200 p-3">
      <div className="flex flex-wrap items-center gap-2 mb-1">
        <button
          onClick={() => cycle(article.id)}
          className={`text-micro font-mono px-1.5 py-0.5 rounded border ${STATUS_STYLES[s].cls}`}
        >
          {STATUS_STYLES[s].label}
        </button>
        <span className="font-display font-semibold text-sm text-heading">{article.title}</span>
        {article.citation && <span className="text-micro font-mono text-muted">{article.citation}</span>}
      </div>
      <p className="text-meta font-mono text-muted leading-relaxed">{article.body}</p>
    </li>
  );
}
