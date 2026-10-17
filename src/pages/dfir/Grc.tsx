import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { FileCheck, ChevronDown, ChevronRight, Download, RotateCcw, ExternalLink } from 'lucide-react';
import {
  NIST_CSF,
  ISO_27001,
  ISO_42001,
  CIS_CONTROLS,
  SOC2_TSC,
  SOC_CMM,
  STORAGE_KEY,
  STATUS_CYCLE,
  FRAMEWORK_META,
  emptyAssessment,
  loadAssessment,
  coverage,
  nistCsfControlIds,
  isoControlIds,
  iso42001ControlIds,
  cisControlIds,
  soc2ControlIds,
  type CoverageStatus,
  type FrameworkId,
  type GrcAssessment,
  type MaturityLevel,
} from '../../data/grc';
import { downloadBlob } from '../../lib/download';
import { errMessage } from '../../lib/log';

const STATUS_STYLES: Record<CoverageStatus, { label: string; cls: string }> = {
  unset: { label: '- unset', cls: 'border-slate-300 dark:border-line-1 text-slate-500' },
  covered: {
    label: 'covered',
    cls: 'border-emerald-400/60 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  },
  partial: { label: '~ partial', cls: 'border-amber-400/60 bg-amber-500/10 text-amber-700 dark:text-amber-300' },
  gap: { label: 'gap', cls: 'border-rose-400/60 bg-rose-500/10 text-rose-700 dark:text-rose-300' },
  na: { label: 'n/a', cls: 'border-slate-300 dark:border-line-1 text-muted' },
};

function scoreColour(score: number): string {
  if (score >= 80) return 'bg-emerald-500';
  if (score >= 50) return 'bg-amber-500';
  if (score >= 25) return 'bg-orange-500';
  return 'bg-rose-500';
}

export default function Grc(): JSX.Element {
  const [tab, setTab] = useState<FrameworkId>('nist-csf');
  const [a, setA] = useState<GrcAssessment>(emptyAssessment);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  useEffect(() => {
    setA(loadAssessment());
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(a));
    } catch (_catchErr) {
      console.error('Grc failed:', errMessage(_catchErr));
      /* quota */
    }
  }, [a]);

  const cycle = (id: string) =>
    setA((prev) => ({
      ...prev,
      controls: { ...prev.controls, [id]: STATUS_CYCLE[prev.controls[id] ?? 'unset'] },
    }));

  const setMaturity = (domainId: string, level: MaturityLevel) =>
    setA((prev) => ({ ...prev, socCmm: { ...prev.socCmm, [domainId]: level } }));

  const reset = () => {
    if (typeof window !== 'undefined' && confirm('Reset all GRC assessments? This cannot be undone.')) {
      setA(emptyAssessment());
    }
  };

  const overall = useMemo(
    () => ({
      'nist-csf': coverage(nistCsfControlIds(), a),
      'iso-27001': coverage(isoControlIds(), a),
      'iso-42001': coverage(iso42001ControlIds(), a),
      cis: coverage(cisControlIds(), a),
      soc2: coverage(soc2ControlIds(), a),
    }),
    [a]
  );

  const exportMd = () => {
    const lines: string[] = ['# GRC Compliance & Maturity Assessment', ''];
    lines.push('## Coverage by framework', '');
    for (const fid of ['nist-csf', 'iso-27001', 'iso-42001', 'cis', 'soc2'] as FrameworkId[]) {
      const c = overall[fid as keyof typeof overall];
      lines.push(`- **${FRAMEWORK_META[fid].label}** - ${c.score}% (${c.covered}/${c.total})`);
    }
    lines.push('', '## SOC-CMM target levels', '');
    for (const d of SOC_CMM) {
      const lvl = a.socCmm[d.id] ?? 0;
      lines.push(`- **${d.title}** - level ${lvl}: ${d.levels[lvl]}`);
    }
    lines.push('', '## Per-control status', '');
    for (const f of NIST_CSF) {
      lines.push(`### NIST CSF - ${f.title}`);
      for (const cat of f.categories) {
        for (const ctl of cat.controls) {
          const s = a.controls[ctl.id] ?? 'unset';
          lines.push(`- ${ctl.shortId} ${ctl.title}: **${s}**`);
        }
      }
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    downloadBlob(blob, 'grc-assessment.md');
  };

  const toggleExpanded = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  return (
    <DataPageLayout
      backTo="/dfir"
      maxWidthClass="max-w-6xl"
      icon={<FileCheck size={28} />}
      title="GRC Compliance & Maturity"
      description="Six major frameworks side-by-side with cross-mapping and self-assessment. NIST CSF 2.0 is the spine; ISO 27001:2022, ISO 42001:2023 (AI Management System), CIS Controls v8, and SOC 2 are mapped to NIST where official cross-references exist. SOC-CMM gives a maturity view across Business / People / Process / Technology / Services."
      headerExtra={
        <p className="text-xs text-muted font-mono">
          All data stays in your browser. Cross-mappings are illustrative - for audit work, validate against official
          OSCAL mapping documents. Pairs with the{' '}
          <Link to="/dfir/nhi" className="text-brand-600 dark:text-brand-400 hover:underline">
            NHI Inventory
          </Link>{' '}
          (operational identity posture) and{' '}
          <Link to="/dfir/owasp" className="text-brand-600 dark:text-brand-400 hover:underline">
            OWASP Top 10
          </Link>{' '}
          (Web/API/LLM application controls).
        </p>
      }
    >
      {/* Coverage dashboard */}
      <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 mb-6">
        {(['nist-csf', 'iso-27001', 'iso-42001', 'cis', 'soc2'] as FrameworkId[]).map((fid) => {
          const c = overall[fid as keyof typeof overall];
          return (
            <button
              key={fid}
              onClick={() => setTab(fid)}
              className={`text-left rounded-xl border p-3 transition-colors ${
                tab === fid
                  ? 'border-brand-500/60 bg-brand-500/5'
                  : 'border-line-1 bg-white dark:bg-surface-200 hover:border-brand-500/40'
              }`}
            >
              <div className="flex items-baseline justify-between gap-2 mb-1">
                <span className="text-mini font-mono uppercase tracking-[0.2em] text-muted">
                  {FRAMEWORK_META[fid].label}
                </span>
                <span className="text-xs font-mono font-bold text-heading">{c.score}%</span>
              </div>
              <div className="h-1.5 rounded bg-track overflow-hidden mb-1">
                <div className={`h-full ${scoreColour(c.score)}`} style={{ width: `${Math.max(2, c.score)}%` }} />
              </div>
              <div className="text-micro font-mono text-muted">
                {c.covered}/{c.total} controls
              </div>
            </button>
          );
        })}
      </section>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 mb-4">
        {(['nist-csf', 'iso-27001', 'iso-42001', 'cis', 'soc2', 'soc-cmm'] as FrameworkId[]).map((fid) => (
          <button
            key={fid}
            onClick={() => setTab(fid)}
            className={`text-sm font-mono px-3 py-1.5 rounded border transition-colors ${
              tab === fid
                ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
            }`}
          >
            {FRAMEWORK_META[fid].label}
          </button>
        ))}
      </div>

      {/* Action bar */}
      <div className="flex flex-wrap gap-2 mb-6">
        <button
          onClick={exportMd}
          className="text-sm font-mono px-3 py-1.5 rounded border border-line-2 hover:border-brand-500/40 inline-flex items-center gap-1.5 transition-colors"
        >
          <Download size={13} /> Export markdown
        </button>
        <button
          onClick={reset}
          className="text-sm font-mono px-3 py-1.5 rounded border border-line-2 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-1.5 transition-colors"
        >
          <RotateCcw size={13} /> Reset all
        </button>
      </div>

      {/* NIST CSF */}
      {tab === 'nist-csf' && (
        <div className="space-y-3">
          {NIST_CSF.map((fn) => (
            <div key={fn.id}>
              <button
                onClick={() => toggleExpanded(fn.id)}
                className="w-full flex items-center gap-3 text-left surface-card hover:border-brand-500/40 px-4 py-3"
                aria-expanded={expanded.has(fn.id)}
              >
                <span className="flex-none w-12 font-mono text-xs font-bold text-brand-600 dark:text-brand-400">
                  {fn.shortId}
                </span>
                <span className="flex-1 min-w-0">
                  <span className="block font-display font-semibold text-heading">{fn.title}</span>
                  <span className="block text-xs font-mono text-muted truncate">{fn.description}</span>
                </span>
                <span className="flex-none text-micro font-mono uppercase tracking-wider text-muted">
                  {fn.categories.reduce((n, c) => n + c.controls.length, 0)} subcat
                </span>
                {expanded.has(fn.id) ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
              </button>
              {expanded.has(fn.id) && (
                <div className="rounded-xl border border-line-1 bg-surface-200/50 mt-2 p-4 space-y-4">
                  {fn.categories.map((cat) => (
                    <div key={cat.id}>
                      <h4 className="font-display font-semibold text-sm text-heading mb-1">
                        {cat.shortId} - {cat.title}
                      </h4>
                      <p className="text-xs font-mono text-muted mb-2">{cat.description}</p>
                      <div className="space-y-1.5">
                        {cat.controls.map((ctl) => {
                          const s: CoverageStatus = a.controls[ctl.id] ?? 'unset';
                          return (
                            <div key={ctl.id} className="rounded border border-line-1 bg-surface-100 p-2.5">
                              <div className="flex flex-wrap items-center gap-2 mb-1">
                                <button
                                  onClick={() => cycle(ctl.id)}
                                  className={`text-micro font-mono px-1.5 py-0.5 rounded border ${STATUS_STYLES[s].cls}`}
                                >
                                  {STATUS_STYLES[s].label}
                                </button>
                                <span className="font-display font-semibold text-xs text-heading">
                                  {ctl.shortId} {ctl.title}
                                </span>
                                {ctl.mappings?.map((m) => (
                                  <span
                                    key={m.to}
                                    title={m.label ?? m.to}
                                    className="text-micro font-mono px-1 py-0.5 rounded border border-brand-500/30 bg-brand-500/10 text-brand-700 dark:text-brand-300"
                                  >
                                    {m.label ?? m.to.split(':')[1]}
                                  </span>
                                ))}
                              </div>
                              <p className="text-mini font-mono text-muted leading-relaxed">{ctl.body}</p>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ISO 27001 */}
      {tab === 'iso-27001' && (
        <div className="space-y-3">
          {ISO_27001.map((theme) => (
            <div key={theme.id} className="surface-card p-4">
              <div className="flex flex-wrap items-baseline gap-2 mb-1">
                <span className="font-mono text-xs font-bold text-brand-600 dark:text-brand-400">A.{theme.number}</span>
                <h3 className="font-display font-semibold text-heading">{theme.title}</h3>
                <span className="text-micro font-mono text-muted ml-auto">
                  {theme.controls.length}/{theme.controlCount} sampled
                </span>
              </div>
              <p className="text-xs font-mono text-muted mb-3">{theme.description}</p>
              <div className="space-y-1.5">
                {theme.controls.map((ctl) => {
                  const s: CoverageStatus = a.controls[ctl.id] ?? 'unset';
                  return (
                    <div key={ctl.id} className="rounded border border-line-1 bg-surface-200 p-2.5">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <button
                          onClick={() => cycle(ctl.id)}
                          className={`text-micro font-mono px-1.5 py-0.5 rounded border ${STATUS_STYLES[s].cls}`}
                        >
                          {STATUS_STYLES[s].label}
                        </button>
                        <span className="font-display font-semibold text-xs text-heading">
                          {ctl.shortId} {ctl.title}
                        </span>
                        {ctl.mappings?.map((m) => (
                          <span
                            key={m.to}
                            className="text-micro font-mono px-1 py-0.5 rounded border border-brand-500/30 bg-brand-500/10 text-brand-700 dark:text-brand-300"
                          >
                            {m.label ?? m.to.split(':')[1]}
                          </span>
                        ))}
                      </div>
                      <p className="text-mini font-mono text-muted leading-relaxed">{ctl.body}</p>
                    </div>
                  );
                })}
                {theme.controls.length === 0 && (
                  <p className="text-mini font-mono text-muted">
                    Detail-level controls not enumerated - use the official ISO 27001:2022 Annex A for the full set (
                    {theme.controlCount} controls in this theme).
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ISO 42001 - AI Management System */}
      {tab === 'iso-42001' && (
        <div className="space-y-3">
          <p className="text-xs font-mono text-muted mb-2">
            ISO/IEC 42001:2023 - first international standard for AI management systems. Annex A defines 9 control
            domains (A.2-A.10). Pairs with{' '}
            <Link to="/dfir/owasp" className="text-brand-600 dark:text-brand-400 hover:underline">
              OWASP LLM Top 10
            </Link>{' '}
            (technical risks) and{' '}
            <Link to="/dfir/mcp-audit" className="text-brand-600 dark:text-brand-400 hover:underline">
              the MCP / Claude Code Auditor
            </Link>{' '}
            (operational AI tooling).
          </p>
          {ISO_42001.map((domain) => (
            <div key={domain.id} className="surface-card p-4">
              <div className="flex flex-wrap items-baseline gap-2 mb-1">
                <span className="font-mono text-xs font-bold text-brand-600 dark:text-brand-400">{domain.shortId}</span>
                <h3 className="font-display font-semibold text-heading">{domain.title}</h3>
                <span className="text-micro font-mono text-muted ml-auto">
                  {domain.controls.length} control{domain.controls.length === 1 ? '' : 's'}
                </span>
              </div>
              <p className="text-xs font-mono text-muted mb-3">{domain.description}</p>
              <div className="space-y-1.5">
                {domain.controls.map((ctl) => {
                  const s: CoverageStatus = a.controls[ctl.id] ?? 'unset';
                  return (
                    <div key={ctl.id} className="rounded border border-line-1 bg-surface-200 p-2.5">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <button
                          onClick={() => cycle(ctl.id)}
                          className={`text-micro font-mono px-1.5 py-0.5 rounded border ${STATUS_STYLES[s].cls}`}
                        >
                          {STATUS_STYLES[s].label}
                        </button>
                        <span className="font-display font-semibold text-xs text-heading">
                          {ctl.shortId} {ctl.title}
                        </span>
                        {ctl.mappings?.map((m) => (
                          <span
                            key={m.to}
                            title={m.label ?? m.to}
                            className="text-micro font-mono px-1 py-0.5 rounded border border-brand-500/30 bg-brand-500/10 text-brand-700 dark:text-brand-300"
                          >
                            {m.label ?? m.to.split(':')[1]}
                          </span>
                        ))}
                      </div>
                      <p className="text-mini font-mono text-muted leading-relaxed">{ctl.body}</p>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* CIS Controls */}
      {tab === 'cis' && (
        <div className="grid gap-2 lg:grid-cols-2">
          {CIS_CONTROLS.map((c) => {
            const s: CoverageStatus = a.controls[c.id] ?? 'unset';
            return (
              <div key={c.id} className="rounded border border-line-1 bg-surface-100 p-3">
                <div className="flex flex-wrap items-center gap-2 mb-1">
                  <span className="flex-none w-7 h-7 rounded bg-brand-500/10 text-brand-600 dark:text-brand-400 font-mono text-xs font-bold flex items-center justify-center">
                    {c.number}
                  </span>
                  <span className="font-display font-semibold text-sm text-heading flex-1">{c.title}</span>
                  <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-line-2 text-muted">
                    IG{c.igLevel}
                  </span>
                  <button
                    onClick={() => cycle(c.id)}
                    className={`text-micro font-mono px-1.5 py-0.5 rounded border ${STATUS_STYLES[s].cls}`}
                  >
                    {STATUS_STYLES[s].label}
                  </button>
                </div>
                <p className="text-mini font-mono text-muted leading-relaxed">{c.description}</p>
              </div>
            );
          })}
        </div>
      )}

      {/* SOC 2 */}
      {tab === 'soc2' && (
        <div className="space-y-3">
          {(['Common Criteria', 'Availability', 'Confidentiality', 'Processing Integrity', 'Privacy'] as const).map(
            (cat) => {
              const items = SOC2_TSC.filter((c) => c.category === cat);
              if (items.length === 0) return null;
              return (
                <div key={cat} className="surface-card p-4">
                  <h3 className="font-display font-semibold text-sm text-heading mb-2">
                    {cat} ({items.length})
                  </h3>
                  <div className="space-y-1.5">
                    {items.map((c) => {
                      const s: CoverageStatus = a.controls[c.id] ?? 'unset';
                      return (
                        <div key={c.id} className="rounded border border-line-1 bg-surface-200 p-2.5">
                          <div className="flex flex-wrap items-center gap-2 mb-1">
                            <button
                              onClick={() => cycle(c.id)}
                              className={`text-micro font-mono px-1.5 py-0.5 rounded border ${STATUS_STYLES[s].cls}`}
                            >
                              {STATUS_STYLES[s].label}
                            </button>
                            <span className="font-display font-semibold text-xs text-heading">
                              {c.shortId} {c.title}
                            </span>
                          </div>
                          <p className="text-mini font-mono text-muted leading-relaxed">{c.description}</p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            }
          )}
        </div>
      )}

      {/* SOC-CMM */}
      {tab === 'soc-cmm' && (
        <div className="space-y-3">
          <p className="text-xs font-mono text-muted mb-2">
            Pick the maturity level that best describes each domain in your SOC today.
          </p>
          {SOC_CMM.map((d) => {
            const lvl: MaturityLevel = a.socCmm[d.id] ?? 0;
            return (
              <div key={d.id} className="surface-card p-4">
                <div className="flex flex-wrap items-baseline gap-3 mb-1">
                  <h3 className="font-display font-semibold text-heading">{d.title}</h3>
                  <span className="text-micro font-mono text-muted">{d.description}</span>
                </div>
                <div className="flex flex-wrap gap-1.5 mt-2 mb-2">
                  {([0, 1, 2, 3, 4, 5] as MaturityLevel[]).map((n) => (
                    <button
                      key={n}
                      onClick={() => setMaturity(d.id, n)}
                      className={`text-xs font-mono px-2 py-1 rounded border transition-colors ${
                        lvl === n
                          ? 'border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300'
                          : 'border-slate-300 dark:border-line-1 text-muted hover:border-brand-500/40'
                      }`}
                    >
                      {n}
                    </button>
                  ))}
                </div>
                <p className="text-xs font-mono text-body leading-relaxed">
                  <span className="font-semibold">Level {lvl}:</span> {d.levels[lvl]}
                </p>
              </div>
            );
          })}
        </div>
      )}

      <section className="mt-8 surface-card p-4">
        <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">References</h2>
        <ul className="space-y-1.5 text-sm font-mono text-muted">
          <li>
            <a
              href="https://www.nist.gov/cyberframework"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              NIST Cybersecurity Framework 2.0
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
          <li>
            <a
              href="https://www.iso.org/standard/27001"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              ISO/IEC 27001:2022
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
          <li>
            <a
              href="https://www.iso.org/standard/81230.html"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              ISO/IEC 42001:2023 - AI Management System
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
          <li>
            <a
              href="https://www.cisecurity.org/controls/v8"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              CIS Critical Security Controls v8
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
          <li>
            <a
              href="https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              AICPA SOC 2 Trust Services Criteria
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
          <li>
            <a
              href="https://www.soc-cmm.com/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              SOC-CMM - SOC Capability Maturity Model
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
        </ul>
      </section>
    </DataPageLayout>
  );
}
