import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Check, ClipboardList, Copy, Download, Lock, Pause, Play, Printer, RotateCcw } from 'lucide-react';
import { useDataFetch } from '../../../hooks/useDataFetch';
import { sanitizeUrl } from '../../../lib/sanitize-url';
import { CyberViewPage, OutLink } from './shared-ui';
import { asArray, fmtDayFull, text } from './shared-utils';

// CyberView weekly tabletop: a real verified event + an invented practice scenario
// wrapped in facilitator tooling. All copy comes from the mirrored tabletop.json.

interface Fact {
  text: string;
  source_url: string;
}
interface Inject {
  at_min: number;
  title: string;
  text: string;
  ask: string;
}
interface Source {
  name?: string;
  url: string;
}
interface Exercise {
  id?: string;
  date: string;
  title: string;
  based_on?: string[];
  real_story: string;
  facts: Fact[];
  scenario: string;
  duration_min: number;
  roles: string[];
  injects: Inject[];
  questions: string[];
  good_looks_like: string[];
  adapt: string;
  sources: Source[];
}
interface TabletopData {
  built_at: string;
  current: Exercise;
  exercises: Exercise[];
}
interface PickerOption {
  key: string;
  label: string;
  exercise: Exercise;
}
type CopyStatus = 'idle' | 'ok' | 'error';

const CARD = 'surface-card rounded-xl border border-line-1 p-5';
const H2 = 'text-base font-bold text-heading';
const H3 = 'text-sm font-bold text-heading';
const BTN =
  'inline-flex items-center gap-1.5 rounded-control border border-line-1 bg-surface-100 px-2.5 py-1.5 font-mono text-[11px] text-heading transition-colors hover:border-brand-400 hover:bg-wash';
const ATTRIBUTION =
  "Written by CyberView AI (a Claude model) from the event's verified record and the sources above, under the same rules as every event. Check the facts against the sources before you rely on them. Free to use and adapt for your own team's exercises.";

/** Current week first, then every other exercise, de-duplicated by date. */
function buildOptions(data: TabletopData): PickerOption[] {
  const current = data.current;
  const options: PickerOption[] = [
    { key: 'current', label: `This week: ${current.date} · ${current.title}`, exercise: current },
  ];
  const seen = new Set<string>([current.date]);
  for (const ex of asArray(data.exercises)) {
    if (!ex || seen.has(ex.date)) continue;
    seen.add(ex.date);
    options.push({ key: ex.id ?? ex.date, label: `${ex.date} · ${ex.title}`, exercise: ex });
  }
  return options;
}

const fmtClock = (s: number): string =>
  `${Math.floor(s / 60)
    .toString()
    .padStart(2, '0')}:${Math.floor(s % 60)
    .toString()
    .padStart(2, '0')}`;

function fmtBuilt(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : new Intl.DateTimeFormat('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short',
        timeZone: 'UTC',
      }).format(d);
}

/** Plain-text rendering shared by "Copy as text" and "Download". */
function exerciseToText(ex: Exercise): string {
  const eventId = ex.based_on?.[0] ?? null;
  const lines = [
    ex.title,
    `${fmtDayFull(ex.date)} · ${ex.duration_min} minutes`,
    `For: ${asArray(ex.roles).join(', ')}`,
    '',
    'Exercise. Built from a real, verified event. The scenario for your organisation is invented for practice: nothing here says your organisation is affected.',
    '',
    'What really happened',
    ex.real_story,
    '',
    'Verified facts',
  ];
  asArray(ex.facts).forEach((f, i) => lines.push(`${i + 1}. ${f.text} (${f.source_url})`));
  if (eventId) lines.push(`On the map: /threatintel/cyberview#e=${eventId}`);
  lines.push('', 'Your scenario', ex.scenario, '', 'Timed updates (injects)');
  asArray(ex.injects).forEach((inj) =>
    lines.push(`+${inj.at_min} min — ${inj.title}`, inj.text, `Ask: ${inj.ask}`, '')
  );
  lines.push('Discussion questions');
  asArray(ex.questions).forEach((q, i) => lines.push(`${i + 1}. ${q}`));
  lines.push('', 'What good looks like');
  asArray(ex.good_looks_like).forEach((item) => lines.push(`- ${item}`));
  lines.push('', 'Make it yours', ex.adapt, '', 'Sources read');
  asArray(ex.sources).forEach((s) => lines.push(`- ${s.name ?? s.url} — ${s.url}`));
  return [...lines, '', ATTRIBUTION].join('\n');
}

function FactList({ facts }: { facts: Fact[] }): JSX.Element {
  return (
    <ul className="mt-2 space-y-2">
      {asArray(facts).map((fact, i) => {
        const href = sanitizeUrl(fact.source_url);
        return (
          <li key={i} className="flex gap-2 text-xs leading-relaxed text-body">
            <span className="mt-0.5 shrink-0 font-mono text-muted">{String(i + 1).padStart(2, '0')}</span>
            <span>
              {fact.text}{' '}
              {href && (
                <OutLink href={fact.source_url} className="font-mono text-[11px]">
                  source
                </OutLink>
              )}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function InjectList({
  injects,
  elapsed,
  reveal,
}: {
  injects: Inject[];
  elapsed: number;
  reveal: boolean;
}): JSX.Element {
  return (
    <ol className="mt-4 space-y-3">
      {asArray(injects).map((inject, i) => {
        const locked = reveal && elapsed < inject.at_min * 60;
        return (
          <li key={i} className="rounded-lg border border-line-1 p-3">
            <div className="flex items-center gap-2">
              <span className="rounded border border-brand-500/40 bg-brand-500/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-accent-text">
                +{inject.at_min} min
              </span>
              <h3 className={H3}>{inject.title}</h3>
            </div>
            {locked ? (
              <p
                className="mt-2 flex items-center gap-1.5 font-mono text-[11px] text-muted"
                aria-label={`Update locked until minute ${inject.at_min}`}
              >
                <Lock size={12} aria-hidden="true" /> Locked until +{inject.at_min} min
              </p>
            ) : (
              <>
                <p className="mt-2 text-xs leading-relaxed text-body">{inject.text}</p>
                <p className="mt-2 text-xs leading-relaxed text-muted">
                  <strong className="text-heading">Ask:</strong> {inject.ask}
                </p>
              </>
            )}
          </li>
        );
      })}
    </ol>
  );
}

function SourceList({ sources }: { sources: Source[] }): JSX.Element {
  const list = asArray(sources);
  return (
    <ul className="mt-3 flex flex-wrap gap-x-2 gap-y-1 text-xs">
      {list.map((source, i) => {
        const label = source.name ?? source.url;
        return (
          <li key={i} className="flex items-center gap-2">
            {sanitizeUrl(source.url) ? (
              <OutLink href={source.url}>{label}</OutLink>
            ) : (
              <span className="text-body">{label}</span>
            )}
            {i < list.length - 1 && (
              <span aria-hidden="true" className="text-muted">
                ·
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

export default function CyberViewTabletop({ bare = false }: { bare?: boolean }): JSX.Element {
  const feed = useDataFetch<TabletopData>({ url: '/data/cyberview/data/tabletop.json', ttl: 600_000 });
  const [selectedKey, setSelectedKey] = useState('current');
  const [elapsed, setElapsed] = useState(0);
  const [running, setRunning] = useState(false);
  const [reveal, setReveal] = useState(false);
  const [copyStatus, setCopyStatus] = useState<CopyStatus>('idle');

  const options = useMemo(() => (feed.data ? buildOptions(feed.data) : []), [feed.data]);
  const active = options.find((o) => o.key === selectedKey)?.exercise ?? options[0]?.exercise ?? null;

  // One interval, torn down when paused or unmounted. Switching exercise resets the clock.
  useEffect(() => {
    if (!running) return;
    const id = window.setInterval(() => setElapsed((s) => s + 1), 1000);
    return () => window.clearInterval(id);
  }, [running]);

  useEffect(() => {
    setElapsed(0);
    setRunning(false);
    setReveal(false);
  }, [selectedKey]);

  useEffect(() => {
    if (copyStatus === 'idle') return;
    const id = window.setTimeout(() => setCopyStatus('idle'), 1800);
    return () => window.clearTimeout(id);
  }, [copyStatus]);

  const handleCopy = async (): Promise<void> => {
    if (!active) return;
    try {
      await navigator.clipboard.writeText(exerciseToText(active));
      setCopyStatus('ok');
    } catch {
      setCopyStatus('error');
    }
  };

  const handleDownload = (): void => {
    if (!active) return;
    const url = URL.createObjectURL(new Blob([exerciseToText(active)], { type: 'text/plain;charset=utf-8' }));
    const anchor = Object.assign(document.createElement('a'), {
      href: url,
      download: `${active.date}-cyberview-tabletop.txt`,
    });
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <CyberViewPage
      bare={bare}
      icon={<ClipboardList size={28} />}
      maxWidthClass="max-w-4xl"
      title="CyberView — Weekly tabletop exercise"
      loading={feed.loading}
      error={feed.error}
      onRetry={feed.refetch}
      description="Replication of CyberView's exercise page: a real event, an invented scenario, timed injects, discussion questions and a facilitator clock."
    >
      {feed.loading && !feed.data && (
        <p className="font-mono text-xs text-muted" role="status">
          Loading tabletop data…
        </p>
      )}
      {feed.error && <p className="font-mono text-xs text-rose-500">error: {feed.error}</p>}

      {active && (
        <article className="space-y-6">
          <header>
            <p className="font-mono text-[11px] uppercase tracking-wide text-accent-text">Weekly tabletop exercise</p>
            <h1 className="mt-1 text-2xl font-bold leading-snug text-heading sm:text-3xl">{active.title}</h1>
            <p className="mt-2 text-xs leading-relaxed text-muted" aria-live="polite">
              <time dateTime={active.date}>{fmtDayFull(active.date)}</time> · {active.duration_min} minutes · for{' '}
              {asArray(active.roles).join(', ')}
            </p>
          </header>

          <p className="rounded-xl border border-brand-500/30 bg-wash px-4 py-3 text-xs leading-relaxed text-body">
            <strong className="text-heading">Exercise.</strong> Built from a real, verified event. The scenario for your
            organisation is invented for practice: nothing here says your organisation is affected.
          </p>

          <div className={`${CARD} flex flex-wrap items-center gap-3`}>
            <label className="flex flex-wrap items-center gap-2 font-mono text-xs text-muted">
              Exercise
              <select
                aria-label="Choose an exercise"
                value={selectedKey}
                onChange={(e) => setSelectedKey(e.target.value)}
                className="max-w-full rounded-control border border-line-input bg-input-200 px-2 py-1.5 font-mono text-xs text-heading"
              >
                {options.map((o) => (
                  <option key={o.key} value={o.key}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
            <div className="flex flex-wrap items-center gap-2 sm:ml-auto">
              <button type="button" className={BTN} onClick={() => void handleCopy()}>
                <Copy size={12} aria-hidden="true" /> Copy as text
              </button>
              <button type="button" className={BTN} onClick={handleDownload}>
                <Download size={12} aria-hidden="true" /> Download
              </button>
              <button type="button" className={BTN} onClick={() => window.print()}>
                <Printer size={12} aria-hidden="true" /> Print
              </button>
            </div>
            {copyStatus !== 'idle' && (
              <span role="status" className="w-full font-mono text-[11px] text-muted">
                {copyStatus === 'ok' ? 'Copied to clipboard.' : 'Could not copy — use Download instead.'}
              </span>
            )}
          </div>

          <section className={CARD}>
            <h2 className={H2}>What really happened</h2>
            <p className="mt-3 text-sm leading-relaxed text-body">{active.real_story}</p>
            <h3 className={`${H3} mt-5`}>Verified facts</h3>
            <FactList facts={active.facts} />
            {active.based_on?.[0] && (
              <p className="mt-5 border-t border-line-1 pt-3 text-xs text-muted">
                On the map:{' '}
                <Link
                  to={`/threatintel/cyberview#e=${encodeURIComponent(text(active.based_on[0]))}`}
                  className="font-mono text-accent-text hover:underline"
                >
                  {active.based_on[0]}
                </Link>
              </p>
            )}
          </section>

          <section className={CARD}>
            <h2 className={H2}>Your scenario</h2>
            <p className="mt-2 font-mono text-[10px] font-semibold uppercase tracking-wide text-rose-600 dark:text-rose-400">
              Hypothetical
            </p>
            <p className="mt-2 text-sm leading-relaxed text-body">{active.scenario}</p>
          </section>

          <section className={CARD}>
            <h2 className={H2}>Timed updates (injects)</h2>
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-line-1 bg-surface-100 px-3 py-2">
              <time
                dateTime={`PT${elapsed}S`}
                aria-label="Elapsed time"
                className="font-mono text-xl tabular-nums text-heading"
              >
                {fmtClock(elapsed)}
              </time>
              <button type="button" className={BTN} onClick={() => setRunning((r) => !r)}>
                {running ? <Pause size={12} aria-hidden="true" /> : <Play size={12} aria-hidden="true" />}
                {running ? 'Pause' : 'Start clock'}
              </button>
              <button
                type="button"
                className={BTN}
                onClick={() => {
                  setRunning(false);
                  setElapsed(0);
                }}
              >
                <RotateCcw size={12} aria-hidden="true" /> Reset
              </button>
              <label className="ml-auto flex items-center gap-2 font-mono text-[11px] text-muted">
                <input
                  type="checkbox"
                  checked={reveal}
                  onChange={(e) => setReveal(e.target.checked)}
                  className="accent-brand-600"
                />
                Reveal each update when its time comes
              </label>
            </div>
            <p className="mt-2 text-[11px] leading-relaxed text-muted">
              The facilitator drops each update in at its minute. Turn on reveal to hide updates until the clock reaches
              them, so the team can&rsquo;t read ahead on a shared screen.
            </p>
            <InjectList injects={active.injects} elapsed={elapsed} reveal={reveal} />
          </section>

          <section className={CARD}>
            <h2 className={H2}>Discussion questions</h2>
            <ol className="mt-3 space-y-2">
              {asArray(active.questions).map((q, i) => (
                <li key={i} className="flex gap-2 text-xs leading-relaxed text-body">
                  <span className="shrink-0 font-mono text-muted">{i + 1}.</span>
                  <span>{q}</span>
                </li>
              ))}
            </ol>
          </section>

          <section className={CARD}>
            <h2 className={H2}>What good looks like</h2>
            <ul className="mt-3 space-y-2">
              {asArray(active.good_looks_like).map((item, i) => (
                <li key={i} className="flex gap-2 text-xs leading-relaxed text-body">
                  <span className="mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                    <Check size={11} aria-hidden="true" />
                  </span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </section>

          <section className={CARD}>
            <h2 className={H2}>Make it yours</h2>
            <p className="mt-3 text-sm leading-relaxed text-body">{active.adapt}</p>
          </section>

          <section className={CARD}>
            <h2 className={H2}>Sources read</h2>
            <SourceList sources={active.sources} />
            <p className="mt-4 border-t border-line-1 pt-3 text-[11px] leading-relaxed text-muted">{ATTRIBUTION}</p>
          </section>

          <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-line-1 pt-4 font-mono text-meta text-muted">
            <span>CyberView · weekly tabletop exercise</span>
            <span>{feed.data?.built_at ? `Built ${fmtBuilt(feed.data.built_at)}` : ''}</span>
          </footer>
        </article>
      )}
    </CyberViewPage>
  );
}
