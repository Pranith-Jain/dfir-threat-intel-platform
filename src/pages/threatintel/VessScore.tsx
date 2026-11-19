import { useMemo, useState, type ReactNode } from 'react';
import { Download, ExternalLink, Info, Printer, RotateCcw } from 'lucide-react';
import {
  CATS,
  EXTRA_DEFAULTS,
  EXTREME_GROUPS,
  METADATA,
  WORKAROUND,
  activeTechnicalFamily,
  bandFor,
  requiredCpuBarrier,
  scoreAssessment,
  syncKnownQuantities,
  type Answers,
  type Option,
} from '../../lib/vess';

/**
 * VESS (Vulnerability Exploitability Scoring System) calculator.
 *
 * Faithful React port of the local-only calculator at isitwormable.com
 * (prototype v4, inspected 2026-11-19). Upstream publishes no API or CVE feed —
 * it is a scoring methodology and an in-browser calculator. The question
 * wording, weights, category caps, extreme escalators and feasibility rules
 * are verbatim upstream (src/lib/vess.ts); only the rendering is ours.
 *
 * VESS measures additional exploitation restrictions relative to affected
 * deployments — not impact or severity.
 */

const UPSTREAM = 'https://www.isitwormable.com/';

function value(answers: Answers, key: string, options: Option[]): string {
  return answers[key] ?? options[0]?.[0] ?? '';
}

function labelFor(options: Option[], v: string): string {
  return options.find(([value]) => value === v)?.[1] ?? 'Not specified';
}

function Panel({ title, desc, children, cap }: { title: string; desc?: string; children: ReactNode; cap?: number }) {
  return (
    <section className="surface-card rounded-xl border border-line-1 p-4">
      <h3 className="flex flex-wrap items-center gap-2 text-sm font-bold text-heading">
        {title}
        {cap != null && <span className="font-mono text-[10px] font-normal text-muted">· max {cap} points</span>}
      </h3>
      {desc && <p className="mt-1 text-[11px] leading-relaxed text-muted">{desc}</p>}
      <div className="mt-3 space-y-3">{children}</div>
    </section>
  );
}

function SelectField({
  answers,
  id,
  label,
  options,
  disabled = false,
  onChange,
}: {
  answers: Answers;
  id: string;
  label: string;
  options: Option[];
  disabled?: boolean;
  onChange: (key: string, value: string) => void;
}) {
  return (
    <label className={`block ${disabled ? 'opacity-50' : ''}`}>
      <span className="mb-1 block text-[11px] font-semibold text-body">{label}</span>
      <select
        value={value(answers, id, options)}
        disabled={disabled}
        onChange={(e) => onChange(id, e.target.value)}
        className="w-full rounded-lg border border-line-1 bg-surface-100 px-2.5 py-2 text-xs text-body focus:border-rose-500 focus:outline-none disabled:cursor-not-allowed"
      >
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
    </label>
  );
}

function TextField({
  answers,
  id,
  label,
  placeholder,
  onChange,
}: {
  answers: Answers;
  id: string;
  label: string;
  placeholder?: string;
  onChange: (key: string, value: string) => void;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] font-semibold text-body">{label}</span>
      <input
        type="text"
        value={answers[id] ?? ''}
        placeholder={placeholder}
        onChange={(e) => onChange(id, e.target.value)}
        className="w-full rounded-lg border border-line-1 bg-surface-100 px-2.5 py-2 text-xs text-body placeholder:text-muted focus:border-rose-500 focus:outline-none"
      />
    </label>
  );
}

function NumberField({
  answers,
  id,
  label,
  placeholder,
  onChange,
}: {
  answers: Answers;
  id: string;
  label: string;
  placeholder?: string;
  onChange: (key: string, value: string) => void;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] font-semibold text-body">{label}</span>
      <input
        type="number"
        min="0"
        step="any"
        value={answers[id] ?? ''}
        placeholder={placeholder}
        onChange={(e) => onChange(id, e.target.value)}
        className="w-full rounded-lg border border-line-1 bg-surface-100 px-2.5 py-2 font-mono text-xs text-body placeholder:text-muted focus:border-rose-500 focus:outline-none"
      />
    </label>
  );
}

export default function VessScore(): JSX.Element {
  const [answers, setAnswers] = useState<Answers>({ ...EXTRA_DEFAULTS, vclass: 'memory' });
  const [notes, setNotes] = useState('');
  const result = useMemo(() => scoreAssessment(answers), [answers]);
  const band = bandFor(result.rounded);
  const family = activeTechnicalFamily(answers);

  const setValue = (key: string, next: string) => {
    setAnswers((prev) => {
      let updated = { ...prev, [key]: next };
      updated = syncKnownQuantities(updated, key);
      // Manually choosing a tier clears the exact quantity that auto-set it.
      if (key === 'volume' && String(updated.requiredTrafficGb ?? '').trim()) {
        updated.requiredTrafficGb = '';
      }
      if ((key === 'attempts' || key === 'attemptExtreme') && String(updated.requiredAttemptsExact ?? '').trim()) {
        updated.requiredAttemptsExact = '';
      }
      return updated;
    });
  };

  const reset = () => {
    setAnswers({ ...EXTRA_DEFAULTS, vclass: 'memory' });
    setNotes('');
  };

  const exportJson = () => {
    const payload = {
      schema: 'VESS-prototype-4',
      created_at: new Date().toISOString(),
      score: result.rounded,
      raw_score: result.rawTotal,
      base_score: result.baseTotal,
      extreme_bonus: result.bonus,
      feasibility: result.feasibility,
      vulnerability_class: answers.vclass,
      technical_family: family.name,
      category_scores: Object.fromEntries(result.base.map((c) => [c.id, c.points])),
      extreme_groups: Object.fromEntries(result.escalators.map((g) => [g.id, { score: g.points, factors: g.factors }])),
      answers,
      notes,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vess-assessment.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const activeExtreme: Record<string, boolean> = {
    cpuExtreme: requiredCpuBarrier(answers),
    raceExtreme: Number(answers.race || 0) > 0,
    recoveryExtreme: Number(answers.failure || 0) > 0 || Number(answers.restart || 0) > 0,
    configExtreme: Number(answers.config || 0) > 0,
    interactionExtreme: Number(answers.interaction || 0) > 0,
    chainExtreme: Number(answers.chain || 0) > 0,
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-bold text-heading">VESS exploitability scoring</h2>
          <p className="mt-1 max-w-3xl text-[11px] leading-relaxed text-muted">
            Researcher-led scoring of the <strong className="text-body">restrictions on exploitation</strong>, not
            impact or severity. Port of the local calculator at{' '}
            <a
              href={UPSTREAM}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 underline hover:text-accent"
            >
              isitwormable.com <ExternalLink size={10} />
            </a>{' '}
            (VESS prototype v4). The upstream tool has no API or CVE feed; this is a faithful calculator.
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={exportJson}
            className="inline-flex items-center gap-1 rounded border border-line-1 px-2.5 py-1.5 font-mono text-[11px] text-muted hover:text-heading"
          >
            <Download size={11} /> Export JSON
          </button>
          <button
            type="button"
            onClick={() => window.print()}
            className="inline-flex items-center gap-1 rounded border border-line-1 px-2.5 py-1.5 font-mono text-[11px] text-muted hover:text-heading"
          >
            <Printer size={11} /> Print
          </button>
          <button
            type="button"
            onClick={reset}
            className="inline-flex items-center gap-1 rounded border border-line-1 px-2.5 py-1.5 font-mono text-[11px] text-muted hover:text-heading"
          >
            <RotateCcw size={11} /> Reset
          </button>
        </div>
      </div>

      {/* Score hero */}
      <div className="surface-card rounded-xl border border-line-1 p-4">
        <div className="flex flex-wrap items-center gap-5">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-wider text-muted">VESS difficulty</div>
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-5xl font-bold tabular-nums text-heading">{result.rounded}</span>
              <span className="font-mono text-sm text-muted">/ 100</span>
            </div>
            <div className="mt-1 font-mono text-xs" style={{ color: band.color }}>
              {band.label} · {band.range}
            </div>
          </div>
          <div className="min-w-[180px] flex-1">
            <div className="h-2 w-full overflow-hidden rounded-full bg-surface-2">
              <div
                className="h-full rounded-full transition-all"
                style={{ width: `${result.score}%`, background: band.color }}
              />
            </div>
            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] text-muted">
              <span>base {result.baseTotal.toFixed(2)}</span>
              <span>extreme +{result.bonus.toFixed(2)}</span>
              <span>uncapped {result.rawTotal.toFixed(2)}</span>
            </div>
            {result.rawTotal > 100 && (
              <p className="mt-1 text-[10px] text-amber-600 dark:text-amber-400">
                The uncapped total exceeds 100 and is displayed at the maximum.
              </p>
            )}
          </div>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-line-1 pt-3 text-[11px]">
          <span
            className={`rounded border px-2 py-0.5 font-mono ${result.feasibility.status === 'infeasible' ? 'border-rose-500/50 bg-rose-500/10 text-rose-600 dark:text-rose-400' : 'border-emerald-500/40 text-emerald-700 dark:text-emerald-300'}`}
          >
            {result.feasibility.status === 'infeasible'
              ? 'INFEASIBLE EXPLOIT PATH'
              : 'No infeasible prerequisite identified'}
          </span>
          <span className="text-muted">
            Evidence: {labelFor(METADATA.questions!.find(([id]) => id === 'evidence')![2], answers.evidence ?? '0')}
          </span>
          <span className="text-muted">
            Path: {labelFor(METADATA.questions!.find(([id]) => id === 'path')![2], answers.path ?? '0')}
          </span>
        </div>
        {result.feasibility.issues.length > 0 && (
          <ul className="mt-2 space-y-1 text-[11px] text-rose-700 dark:text-rose-300">
            {result.feasibility.issues.map((issue, i) => (
              <li key={i}>{issue}</li>
            ))}
          </ul>
        )}
        {result.feasibility.diagnostics.requiredTransferMinutes !== undefined && (
          <p className="mt-1 font-mono text-[10px] text-muted">
            Minimum transfer time:{' '}
            {result.feasibility.diagnostics.requiredTransferMinutes.toLocaleString('en-US', {
              maximumFractionDigits: 1,
            })}{' '}
            minutes at the supplied bandwidth.
          </p>
        )}
        <div className="mt-3 grid gap-1 sm:grid-cols-2 lg:grid-cols-3">
          {result.base.map((c) => (
            <div
              key={c.id}
              className="flex items-center justify-between gap-2 rounded border border-line-1 px-2 py-1 font-mono text-[10px]"
            >
              <span className="truncate text-muted">{c.title.replace(/^\d+\. /, '')}</span>
              <span className="tabular-nums text-heading">
                {c.points.toFixed(2)} / {c.cap}
              </span>
            </div>
          ))}
          <div className="flex items-center justify-between gap-2 rounded border border-line-1 px-2 py-1 font-mono text-[10px]">
            <span className="text-muted">Extreme escalator</span>
            <span className="tabular-nums text-heading">+{result.bonus.toFixed(2)}</span>
          </div>
        </div>
      </div>

      <div className="flex items-start gap-2 rounded-lg border border-sky-500/30 bg-sky-500/5 p-3 text-[11px] leading-relaxed text-body">
        <Info size={14} className="mt-0.5 shrink-0 text-sky-600 dark:text-sky-400" />
        Score only restrictions <strong>additional</strong> to the affected deployment population — a supported OS,
        processor or commonly exposed port contributes zero. Unreported attacks do not add points, and confirmed
        exploitation is context only. An infeasible mandatory prerequisite is flagged separately, not hidden by a low
        numerical score.
      </div>

      {/* Data-driven form sections */}
      <Panel title={METADATA.title} desc={METADATA.desc}>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {METADATA.questions!.map(([id, label, options]) => (
            <SelectField key={id} answers={answers} id={id} label={label} options={options} onChange={setValue} />
          ))}
        </div>
      </Panel>

      <Panel
        title="Assessment baseline · required context"
        desc="Supported OS / processor types and commonly exposed service ports are the baseline, not added restrictions."
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <TextField
            answers={answers}
            id="affectedPopulation"
            label="Affected deployment population"
            placeholder="e.g., unpatched SQL Server 2000 on supported x86"
            onChange={setValue}
          />
          <TextField
            answers={answers}
            id="exploitScenario"
            label="Specific exploit path and environment"
            placeholder="e.g., single-packet UDP/1434 RCE on a reachable server"
            onChange={setValue}
          />
        </div>
      </Panel>

      {CATS.map((cat) => {
        if (cat.dynamic) {
          const barrierPoints = result.base.find((c) => c.id === 'technical')?.barriers ?? {};
          return (
            <Panel
              key={cat.id}
              title={`2. ${family.name}`}
              desc="Score only mitigations obstructing the selected exploit path. A demonstrated workaround reduces the remaining points."
              cap={cat.cap}
            >
              {answers.vclass === 'memory' && (
                <SelectField
                  answers={answers}
                  id="cpuScope"
                  label="CPU restriction relative to affected deployments"
                  options={[
                    ['baseline', 'No additional CPU restriction: supported architecture / standard processor (0 pts)'],
                    ['subset', 'Extra architecture or CPU feature narrows otherwise vulnerable installations'],
                    ['unverified', 'Unknown: do not score CPU restrictions until verified'],
                  ]}
                  onChange={setValue}
                />
              )}
              <div className="space-y-2">
                {family.barriers.map(([id, label, max]) => {
                  const key = `tech_${answers.vclass}_${id}`;
                  const cpu = id === 'cpuarch' || id === 'cpufeature';
                  const disabled = cpu && answers.cpuScope !== 'subset';
                  return (
                    <div
                      key={key}
                      className={`grid gap-2 rounded-lg border border-line-1 p-2.5 sm:grid-cols-[1fr_150px_170px_70px] ${disabled ? 'opacity-50' : ''}`}
                    >
                      <div className="text-[11px] font-semibold text-body">
                        {label}
                        <div className="font-mono text-[10px] font-normal text-muted">up to {max} points</div>
                      </div>
                      <SelectField
                        answers={answers}
                        id={`${key}_required`}
                        label="Applicability"
                        options={[
                          ['0', 'Not required / N/A'],
                          ['1', 'Required obstacle'],
                        ]}
                        disabled={disabled}
                        onChange={setValue}
                      />
                      <SelectField
                        answers={answers}
                        id={`${key}_residual`}
                        label="Workaround"
                        options={WORKAROUND}
                        disabled={disabled}
                        onChange={setValue}
                      />
                      <div className="flex items-end justify-end pb-2 font-mono text-xs tabular-nums text-heading">
                        {(barrierPoints[key] ?? 0).toFixed(2)}
                      </div>
                    </div>
                  );
                })}
              </div>
              {answers.vclass === 'memory' && (
                <TextField
                  answers={answers}
                  id="cpuDetails"
                  label="Required processor / CPU flags (documentation only)"
                  placeholder="e.g., x86-64; AVX512F"
                  onChange={setValue}
                />
              )}
            </Panel>
          );
        }
        return (
          <Panel key={cat.id} title={cat.title} desc={cat.desc} cap={cat.cap}>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {cat.questions!.map(([id, label, options]) => (
                <SelectField key={id} answers={answers} id={id} label={label} options={options} onChange={setValue} />
              ))}
            </div>
          </Panel>
        );
      })}

      {/* Extreme escalators */}
      <Panel
        title="7. Extreme Restriction Escalator"
        desc="Exceptionally difficult prerequisites receive nonlinear points after the category caps. Each group contributes only its highest applicable penalty so correlated factors are not double-counted."
      >
        <div className="flex flex-wrap gap-2 font-mono text-[10px] text-muted">
          <span>Significant +5</span>
          <span>Severe +10</span>
          <span>Extreme +20</span>
          <span>Impossible flagged separately</span>
        </div>
        {EXTREME_GROUPS.map((group) => {
          const groupScore = result.escalators.find((g) => g.id === group.id);
          return (
            <div key={group.id} className="rounded-lg border border-line-1 p-3">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <h4 className="text-xs font-bold text-heading">{group.title}</h4>
                  <p className="mt-0.5 max-w-3xl text-[10px] leading-relaxed text-muted">{group.description}</p>
                </div>
                <span className="font-mono text-sm font-bold text-rose-600 dark:text-rose-400">
                  +{groupScore?.points ?? 0}
                </span>
              </div>
              <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {group.id === 'resources' && (
                  <NumberField
                    answers={answers}
                    id="requiredTrafficGb"
                    label="Exact transfer volume (GB, optional)"
                    placeholder="128"
                    onChange={setValue}
                  />
                )}
                {group.fields.map(([id, label, options]) => (
                  <SelectField
                    key={id}
                    answers={answers}
                    id={id}
                    label={label}
                    options={options}
                    disabled={activeExtreme[id] === false}
                    onChange={setValue}
                  />
                ))}
              </div>
            </div>
          );
        })}
      </Panel>

      <Panel
        title="Feasibility of the specified exploit path"
        desc="Optional values that do not add points. A requirement that cannot be satisfied is flagged Infeasible for this path and target environment."
      >
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <NumberField
            answers={answers}
            id="availableMbps"
            label="Available sustained bandwidth (Mbit/s)"
            placeholder="100"
            onChange={setValue}
          />
          <NumberField
            answers={answers}
            id="maxConnectionMinutes"
            label="Maximum uninterrupted connection window (minutes)"
            placeholder="60"
            onChange={setValue}
          />
          <NumberField
            answers={answers}
            id="requiredAttemptsExact"
            label="Required attempts (exact, optional)"
            placeholder="10001"
            onChange={setValue}
          />
          <NumberField
            answers={answers}
            id="maxAttemptsAvailable"
            label="Maximum attempts possible (optional)"
            placeholder="3"
            onChange={setValue}
          />
          <SelectField
            answers={answers}
            id="cpuCompat"
            label="Does the target support the mandatory CPU features?"
            options={[
              ['unknown', 'Unknown / not assessed'],
              ['yes', 'Yes'],
              ['no', 'No — CPU requirement cannot be met'],
            ]}
            onChange={setValue}
          />
          <SelectField
            answers={answers}
            id="manualBlocked"
            label="Another mandatory prerequisite is impossible?"
            options={[
              ['no', 'No known impossible requirement'],
              ['yes', 'Yes — specified exploit path is infeasible'],
            ]}
            onChange={setValue}
          />
          <TextField
            answers={answers}
            id="manualReason"
            label="Description of impossible prerequisite"
            placeholder="e.g., no supported instruction-set extension"
            onChange={setValue}
          />
        </div>
      </Panel>

      <Panel
        title="Research notes"
        desc="Optional notes on exploit primitives, evidence, environmental assumptions and unresolved mitigations."
      >
        <textarea
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Document essential evidence and assumptions..."
          rows={4}
          className="w-full rounded-lg border border-line-1 bg-surface-100 p-3 text-xs text-body placeholder:text-muted focus:border-rose-500 focus:outline-none"
        />
      </Panel>

      <p className="border-t border-line-1 pt-3 text-[10px] leading-relaxed text-muted">
        VESS research prototype v4 · weights and thresholds are provisional · mirrored from {UPSTREAM}. Inclusion is a
        mirror of a public methodology, not an endorsement.
      </p>
    </div>
  );
}
