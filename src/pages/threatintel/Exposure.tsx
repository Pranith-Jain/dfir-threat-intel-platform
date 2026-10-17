import { useCallback, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Search, Loader2, ShieldAlert, ExternalLink } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage, logCatch } from '../../lib/log';

type Verdict = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

interface ExposureResponse {
  domain: string;
  generated_at: string;
  verdict: Verdict;
  score: number;
  sections: {
    ransomware: { status: string; hits: { victim: string; group: string; discovered: string }[] };
    heatwave: {
      status: string;
      listed: boolean | null;
      stage: number | null;
      score_band: number | null;
      observation_age: string | null;
      dns_answer: string | null;
      related: { domain: string; classification: string; score: number }[];
    };
    destroylist: { status: string; listed: boolean; tags: string[] };
    dphish: { status: string; listed: boolean; tags: string[] };
  };
  notes: string[];
}

const VERDICT_TONE: Record<Verdict, string> = {
  critical: 'border-rose-500/50 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  low: 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300',
  unknown: 'border-slate-300 dark:border-line-1 text-slate-500',
};

export default function ExposureCheck(): JSX.Element {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ExposureResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const clean = input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^.*@/, '')
    .replace(/\/.*$/, '')
    .replace(/\.$/, '');

  const run = useCallback(async () => {
    if (!clean) return;
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setLoading(true);
    setError(null);
    try {
      const r = await fetch(`/api/v1/exposure/check?domain=${encodeURIComponent(clean)}`, {
        signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(20000)]),
      });
      if (!r.ok) {
        const body = await r.text().catch(() => '');
        throw new Error(body ? `API ${r.status}: ${body.slice(0, 120)}` : `API ${r.status}`);
      }
      setResult((await r.json()) as ExposureResponse);
    } catch (e) {
      logCatch(e);
      if (!ctrl.signal.aborted) setError(errMessage(e, 'check failed'));
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  }, [clean]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="Threat Intel"
      icon={<ShieldAlert size={28} />}
      title="Exposure Check"
      description="One search across everything monitored — ransomware victim claims, sender-domain blocklist, phishing blacklists. Unknown means nothing found, never a clean bill of health."
      headerExtra={
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void run();
          }}
        >
          <div className="flex gap-2">
            <div className="flex-1 relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="example.com"
                aria-label="Domain to check"
                className="w-full pl-9 pr-3 py-3 bg-surface-100 border border-line-1 rounded-xl font-mono text-sm focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !clean}
              className="px-5 py-3 bg-rose-600 dark:bg-rose-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-rose-700 dark:hover:bg-rose-400 transition-colors"
            >
              {loading ? (
                <Loader2 size={16} className="animate-spin inline" />
              ) : (
                <Search size={16} className="inline" />
              )}{' '}
              Check
            </button>
          </div>
        </form>
      }
      loading={loading && !result}
      error={error}
      onRetry={run}
      empty={!loading && !error && !result}
      emptyMessage="Enter a domain above to scan every monitored source at once."
    >
      {result && (
        <div className="space-y-4">
          <section className="surface-card p-4">
            <div className="flex items-baseline justify-between gap-2 mb-1">
              <h2 className="font-display font-bold text-xl font-mono">{result.domain}</h2>
              <span
                className={`text-xs font-mono uppercase tracking-wider px-2.5 py-1 rounded border ${VERDICT_TONE[result.verdict]}`}
              >
                {result.verdict} · {result.score}/100
              </span>
            </div>
            {result.notes.map((n) => (
              <p key={n} className="text-xs font-mono text-muted mt-1">
                {n}
              </p>
            ))}
          </section>

          <section className="surface-card p-4">
            <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-rose-600 dark:text-rose-400 font-mono mb-2">
              Ransomware victim claims ({result.sections.ransomware.hits.length})
            </h3>
            {result.sections.ransomware.status !== 'ok' ? (
              <p className="text-xs font-mono text-muted">Feed unavailable — try again shortly.</p>
            ) : result.sections.ransomware.hits.length === 0 ? (
              <p className="text-xs font-mono text-muted">No victim claims match this domain.</p>
            ) : (
              <ul className="space-y-1.5">
                {result.sections.ransomware.hits.map((h) => (
                  <li key={`${h.victim}-${h.group}`} className="text-sm font-mono text-body">
                    {h.victim}{' '}
                    <span className="text-muted">
                      · {h.group} · {h.discovered.slice(0, 10)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            <Link
              to="/threatintel/ransomware-groups"
              className="inline-flex items-center gap-1 mt-2 text-xs font-mono text-rose-600 dark:text-rose-400 hover:underline"
            >
              <ExternalLink size={10} /> Ransomware Groups directory
            </Link>
          </section>

          <section className="surface-card p-4">
            <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-amber-600 dark:text-amber-400 font-mono mb-2">
              Sender reputation (Heatwave)
            </h3>
            {result.sections.heatwave.status !== 'ok' ? (
              <p className="text-xs font-mono text-muted">Lookup unavailable — try again shortly.</p>
            ) : result.sections.heatwave.listed ? (
              <div className="text-sm font-mono text-body space-y-1">
                <p>
                  Listed · stage {result.sections.heatwave.stage} · score band {result.sections.heatwave.score_band}/100
                </p>
                {result.sections.heatwave.observation_age && (
                  <p className="text-muted">warming {result.sections.heatwave.observation_age}</p>
                )}
                {result.sections.heatwave.dns_answer && (
                  <p className="text-muted">{result.sections.heatwave.dns_answer}</p>
                )}
              </div>
            ) : (
              <p className="text-xs font-mono text-muted">Not listed (not a clean verdict).</p>
            )}
          </section>

          <div className="grid gap-4 sm:grid-cols-2">
            {(
              [
                { key: 'destroylist', label: 'Phishing blacklist (Destroylist)' },
                { key: 'dphish', label: 'Phishing indicators (dPhish)' },
              ] as const
            ).map(({ key, label }) => {
              const s = result.sections[key];
              return (
                <section key={key} className="surface-card p-4">
                  <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-muted font-mono mb-2">{label}</h3>
                  {s.status !== 'ok' ? (
                    <p className="text-xs font-mono text-muted">Feed unavailable.</p>
                  ) : s.listed ? (
                    <p className="text-sm font-mono text-rose-600 dark:text-rose-400">
                      Listed{' '}
                      {s.tags.length > 0 && <span className="text-muted">· {s.tags.slice(0, 4).join(', ')}</span>}
                    </p>
                  ) : (
                    <p className="text-xs font-mono text-muted">Not listed.</p>
                  )}
                </section>
              );
            })}
          </div>
        </div>
      )}
    </DataPageLayout>
  );
}
