/**
 * CVE Triage — single-CVE decision support.
 *
 * `/threatintel/cve-triage`
 *
 * The feed surfaces answer "what is new". This page answers "should I patch
 * this today, and why?" — which is the question a CVE id in a scanner report
 * actually raises.
 *
 * Three views on one surface:
 *
 * 1. **Triage** — one CVE, fully scored: the composite risk score with its
 *    components, the SSVC v2 Deployer decision, the public-exploit tier and
 *    the evidence behind it, and the patch urgency with a written reason.
 * 2. **Compare** — two to ten CVEs in a patch order, where every position
 *    states the signal that separated it from the one below.
 * 3. **Landscape** — the weekly multi-source briefing, with the
 *    cross-source correlation that says which CVEs more than one source
 *    agrees on.
 *
 * The score is shown as a number *and* as its parts. A score an analyst
 * cannot decompose is a score they have to trust, and a score they have to
 * trust is a score they will get wrong.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowRight,
  Crosshair,
  ExternalLink,
  Flame,
  Globe,
  Layers,
  Search,
  ShieldAlert,
  Target,
  TrendingUp,
} from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Card, CardHeader } from '../../components/ui/Card';
import { Tabs } from '../../components/ui/Tabs';
import { StatCards } from '../../components/ui/StatCards';
import { useApiData } from '../../hooks/useApiData';
import { api, ApiError } from '../../lib/api-client';
import { errMessage } from '../../lib/log';

/* ─── Shared types ────────────────────────────────────────────────────────── */

interface RiskComponents {
  cvss_score: number;
  epss_probability: number;
  in_kev: boolean;
  poc_confidence: string;
  cvss_contribution: number;
  epss_contribution: number;
  kev_contribution: number;
  poc_contribution: number;
  cvss_role: string;
}

interface RiskScore {
  cve_id: string;
  scoring_version: string;
  risk_score: number;
  risk_label: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  urgency: string;
  recommendation: string;
  components: RiskComponents;
  boosters_applied: string[];
  days_since_published: number | null;
}

interface SsvcDecision {
  scoring_version: string;
  exploitation: string;
  exposure: string;
  automatable: string;
  technical_impact: string;
  mission_wellbeing: string;
  action: string;
  rationale: string;
  inputs_source: string;
}

interface ExploitSummary {
  confidence: string;
  confidence_label: string;
  total_sources_found: number;
  poc_in_github: number;
  degraded: string[];
  github: Array<{
    full_name: string;
    html_url: string;
    stars: number;
    language: string;
    score: number;
    source: string;
    description: string;
  }>;
  exploitdb: Array<{
    id: string;
    description: string;
    type: string;
    platform: string;
    date_published: string;
    url: string;
  }>;
  nuclei: Array<{ name: string; html_url: string; path: string }>;
  metasploit: Array<{
    fullname: string;
    type: string;
    rank: string;
    disclosure_date: string;
    mod_time: string;
    url: string;
  }>;
}

interface TriageResponse {
  cve_id: string;
  depth: 'quick' | 'standard' | 'deep';
  generated_at: string;
  title: string;
  description: string;
  published: string | null;
  cvss: { score: number | null; vector: string; severity: string };
  cwe: string[];
  vendor: string | null;
  product: string | null;
  affected_versions: string[];
  epss: { score: number | null; percentile: number | null };
  kev: {
    in_kev: boolean;
    date_added: string | null;
    due_date: string | null;
    known_ransomware: boolean;
    required_action: string | null;
  };
  exploited_per: string[];
  exploit: ExploitSummary;
  risk: RiskScore;
  ssvc_v2: SsvcDecision;
  euvd: { exploited: boolean; exploitedSince?: string; url: string } | null;
  sources: Array<{ id: string; name: string; ok: boolean; note?: string }>;
}

interface CompareRow {
  cve_id: string;
  error?: string | null;
  risk_score: number;
  risk_label: string;
  in_kev: boolean;
  known_ransomware: boolean;
  epss_probability: number;
  cvss_score: number;
  exploit_confidence: string;
  kev_due_date: string;
  score_breakdown: {
    cvss: number;
    epss: number;
    kev: number;
    poc: number;
    boosters: string[];
  };
  patch_priority_rank: number | null;
  why_above_next: string | null;
}

interface CompareResponse {
  generated_at: string;
  depth: string;
  summary: {
    total: number;
    triaged: number;
    errored: number;
    in_kev: number;
    known_ransomware: number;
    critical: number;
  };
  comparison_matrix: CompareRow[];
  order: string;
  tie_breakers: string[];
}

interface LandscapePanel {
  id: string;
  title: string;
  source: string;
  source_url: string;
  retrieved_at: string;
  total: number;
  items: Array<Record<string, unknown>>;
  error?: string;
  note?: string;
}

interface LandscapeResponse {
  days: number;
  since: string;
  generated_at: string;
  headline: string;
  multi_signal: Array<{ cve_id: string; signals: string[] }>;
  panels: LandscapePanel[];
}

/* ─── Presentation helpers ────────────────────────────────────────────────── */

const RISK_TONE: Record<string, string> = {
  CRITICAL: 'text-rose-600 dark:text-rose-400',
  HIGH: 'text-amber-600 dark:text-amber-400',
  MEDIUM: 'text-sky-600 dark:text-sky-400',
  LOW: 'text-emerald-600 dark:text-emerald-400',
};

const ACTION_TONE: Record<string, string> = {
  Act: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/40',
  Attend: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/40',
  'Track*': 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/40',
  Track: 'bg-surface-300 text-muted border-line-1',
};

const EXPLOIT_TONE: Record<string, string> = {
  WEAPONIZED: 'text-rose-600 dark:text-rose-400',
  PUBLIC_EXPLOIT_REMOTE: 'text-amber-600 dark:text-amber-400',
  PUBLIC_EXPLOIT: 'text-amber-600 dark:text-amber-400',
  PUBLIC_POC_HIGH_QUALITY: 'text-sky-600 dark:text-sky-400',
  PUBLIC_POC_LOW_QUALITY: 'text-sky-600 dark:text-sky-400',
  NONE: 'text-muted',
};

function fmtDate(value: string | null | undefined): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function fmtPct(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  return `${(value * 100).toFixed(1)}%`;
}

/** One row of the risk decomposition. */
function ComponentRow({
  label,
  points,
  max,
  detail,
}: {
  label: string;
  points: number;
  max: number;
  detail: string;
}): JSX.Element {
  const pct = max > 0 ? Math.max(0, Math.min(100, (points / max) * 100)) : 0;
  return (
    <li className="py-2.5">
      <div className="mb-1 flex items-baseline justify-between gap-3">
        <span className="text-tool font-medium">{label}</span>
        <span className="font-mono text-meta text-muted">
          {points.toFixed(1)} / {max}
        </span>
      </div>
      <div className="mb-1 h-1.5 w-full overflow-hidden rounded-full bg-surface-300">
        <div className="h-full rounded-full bg-brand-500" style={{ width: `${pct}%` }} />
      </div>
      <p className="font-mono text-micro text-muted">{detail}</p>
    </li>
  );
}

/* ─── Triage view ─────────────────────────────────────────────────────────── */

function TriageView(): JSX.Element {
  const [input, setInput] = useState('');
  const [cveId, setCveId] = useState<string | null>(null);
  const [depth, setDepth] = useState<'quick' | 'standard' | 'deep'>('standard');
  const [submitError, setSubmitError] = useState<string | null>(null);

  const url = cveId ? `/api/v1/cve-triage/${encodeURIComponent(cveId)}?depth=${depth}` : null;
  const { data, loading, error, refetch } = useApiData<TriageResponse>(url, { ttl: 60_000 });

  const submit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      const id = input.trim().toUpperCase();
      if (!/^CVE-\d{4}-\d{4,7}$/.test(id)) {
        setSubmitError('Enter a CVE id like CVE-2024-3400.');
        return;
      }
      setSubmitError(null);
      setCveId(id);
    },
    [input]
  );

  if (!cveId) {
    return (
      <Card padding="lg" radius="panel" tone="rose">
        <CardHeader>
          <div>
            <h2 className="font-display text-lg font-semibold text-heading">Triage a CVE</h2>
            <p className="mt-1 text-meta text-muted">
              One CVE, fully scored: risk components, SSVC v2 decision, public-exploit tier and the patch urgency — with
              the reasoning behind each.
            </p>
          </div>
        </CardHeader>
        <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
          <div className="min-w-[16rem] flex-1">
            <label htmlFor="cve-id" className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted">
              CVE id
            </label>
            <input
              id="cve-id"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="CVE-2024-3400"
              autoComplete="off"
              spellCheck={false}
              className="w-full rounded border border-line-1 bg-surface-100 px-3 py-2 font-mono text-tool text-heading placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            />
          </div>
          <div>
            <label
              htmlFor="cve-depth"
              className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted"
            >
              Depth
            </label>
            <select
              id="cve-depth"
              value={depth}
              onChange={(e) => setDepth(e.target.value as 'quick' | 'standard' | 'deep')}
              className="rounded border border-line-1 bg-surface-100 px-3 py-2 font-mono text-tool text-heading focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            >
              <option value="quick">quick — cached signals only</option>
              <option value="standard">standard — + exploit evidence</option>
              <option value="deep">deep — + ENISA EUVD</option>
            </select>
          </div>
          <button
            type="submit"
            className="inline-flex items-center gap-1.5 rounded bg-brand-600 px-4 py-2 font-mono text-meta text-on-fill transition-colors hover:bg-brand-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
          >
            <Search size={14} /> Triage
          </button>
        </form>
        {submitError && (
          <p role="alert" className="mt-3 flex items-center gap-1.5 text-meta text-rose-600 dark:text-rose-400">
            <AlertTriangle size={13} /> {submitError}
          </p>
        )}
        <div className="mt-5 grid gap-2 sm:grid-cols-3">
          {[
            { k: 'CVE-2021-44228', n: 'Log4Shell' },
            { k: 'CVE-2024-3400', n: 'PAN-OS command injection' },
            { k: 'CVE-2023-44487', n: 'HTTP/2 Rapid Reset' },
          ].map((ex) => (
            <button
              key={ex.k}
              type="button"
              onClick={() => {
                setInput(ex.k);
                setSubmitError(null);
                setCveId(ex.k);
              }}
              className="rounded border border-line-1 bg-surface-100 px-3 py-2 text-left transition-colors hover:border-brand-500/40"
            >
              <span className="block font-mono text-tool text-heading">{ex.k}</span>
              <span className="block text-micro text-muted">{ex.n}</span>
            </button>
          ))}
        </div>
      </Card>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-16" role="status" aria-busy="true">
        <span className="font-mono text-meta text-muted">Triaging {cveId}…</span>
      </div>
    );
  }

  if (error) {
    return (
      <Card padding="lg" radius="panel" tone="rose">
        <p role="alert" className="flex items-center gap-2 text-tool text-rose-600 dark:text-rose-400">
          <AlertTriangle size={15} /> {error}
        </p>
        <div className="mt-4 flex gap-2">
          <button
            type="button"
            onClick={refetch}
            className="rounded border border-line-1 px-3 py-1.5 font-mono text-meta text-muted hover:border-brand-500/40"
          >
            Retry
          </button>
          <button
            type="button"
            onClick={() => setCveId(null)}
            className="rounded border border-line-1 px-3 py-1.5 font-mono text-meta text-muted hover:border-brand-500/40"
          >
            Triage another
          </button>
        </div>
      </Card>
    );
  }

  if (!data) return <></>;

  const { risk, ssvc_v2: ssvc, exploit, kev, epss } = data;

  return (
    <div className="space-y-5">
      {/* ── Headline verdict ─────────────────────────────────────────── */}
      <Card padding="lg" radius="panel" tone="rose">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-[16rem] flex-1">
            <div className="mb-1 flex flex-wrap items-center gap-2">
              <Link
                to={`/threatintel/cves/${data.cve_id}`}
                className="font-mono text-meta text-heading hover:underline"
              >
                {data.cve_id}
              </Link>
              {kev.in_kev && (
                <span className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 font-mono text-micro text-rose-700 dark:text-rose-300">
                  <Flame size={11} /> CISA KEV
                </span>
              )}
              {kev.known_ransomware && (
                <span className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 font-mono text-micro text-rose-700 dark:text-rose-300">
                  <ShieldAlert size={11} /> Ransomware use
                </span>
              )}
              <span className="font-mono text-micro text-muted">
                depth {data.depth} · scoring v{risk.scoring_version}
              </span>
            </div>
            <p className="text-tool leading-relaxed text-heading">{data.description || data.title}</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className={`font-display text-4xl font-bold ${RISK_TONE[risk.risk_label]}`}>
                {risk.risk_score.toFixed(0)}
              </div>
              <div className={`font-mono text-micro uppercase tracking-wider ${RISK_TONE[risk.risk_label]}`}>
                {risk.risk_label}
              </div>
            </div>
            <span className={`rounded border px-3 py-1.5 font-mono text-meta ${ACTION_TONE[ssvc.action] ?? ''}`}>
              {ssvc.action}
            </span>
          </div>
        </div>

        <div className="mt-4 rounded border border-line-1 bg-surface-100 p-3">
          <p className="font-mono text-micro uppercase tracking-wider text-muted">{risk.urgency}</p>
          <p className="mt-1 text-tool text-heading">{risk.recommendation}</p>
        </div>

        {data.exploited_per.length > 0 && (
          <p className="mt-3 text-meta text-muted">
            Reported as exploited by: <span className="font-mono text-heading">{data.exploited_per.join(', ')}</span>
          </p>
        )}
      </Card>

      {/* ── Risk decomposition ───────────────────────────────────────── */}
      <div className="grid gap-5 lg:grid-cols-2">
        <Card padding="md" radius="panel" tone="rose">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Target size={16} className="text-rose-500" />
              <h2 className="font-display text-base font-semibold text-heading">Risk score components</h2>
            </div>
          </CardHeader>
          <ul className="divide-y divide-line-1">
            <ComponentRow
              label="CVSS (severity)"
              points={risk.components.cvss_contribution}
              max={20}
              detail={`${data.cvss.score ?? '—'} · ${data.cvss.vector || 'no vector'}`}
            />
            <ComponentRow
              label="EPSS (likelihood)"
              points={risk.components.epss_contribution}
              max={35}
              detail={`${fmtPct(epss.score)} probability · ${fmtPct(epss.percentile)} percentile`}
            />
            <ComponentRow
              label="CISA KEV"
              points={risk.components.kev_contribution}
              max={30}
              detail={
                kev.in_kev
                  ? `added ${fmtDate(kev.date_added)} · remediate by ${fmtDate(kev.due_date)}`
                  : 'not in the catalog'
              }
            />
            <ComponentRow
              label="Public exploit"
              points={risk.components.poc_contribution}
              max={15}
              detail={`${exploit.confidence_label} (${exploit.confidence})`}
            />
          </ul>
          {risk.boosters_applied.length > 0 && (
            <div className="mt-3 border-t border-line-1 pt-3">
              <p className="mb-1.5 font-mono text-micro uppercase tracking-wider text-muted">Boosters applied</p>
              <div className="flex flex-wrap gap-1.5">
                {risk.boosters_applied.map((b) => (
                  <span
                    key={b}
                    className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 font-mono text-micro text-amber-700 dark:text-amber-300"
                  >
                    {b}
                  </span>
                ))}
              </div>
            </div>
          )}
        </Card>

        <Card padding="md" radius="panel" tone="rose">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Crosshair size={16} className="text-rose-500" />
              <h2 className="font-display text-base font-semibold text-heading">SSVC v2 — CISA Deployer</h2>
            </div>
          </CardHeader>
          <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
            {[
              { k: 'Exploitation', v: ssvc.exploitation },
              { k: 'Exposure', v: ssvc.exposure },
              { k: 'Automatable', v: ssvc.automatable },
              { k: 'Technical impact', v: ssvc.technical_impact },
              { k: 'Mission well-being', v: ssvc.mission_wellbeing },
              { k: 'Decision', v: ssvc.action },
            ].map((row) => (
              <div key={row.k} className="rounded border border-line-1 bg-surface-100 p-2.5">
                <p className="font-mono text-micro uppercase tracking-wider text-muted">{row.k}</p>
                <p className="mt-0.5 font-mono text-tool text-heading">{row.v}</p>
              </div>
            ))}
          </div>
          <p className="text-meta leading-relaxed text-muted">{ssvc.rationale}</p>
          <p className="mt-2 font-mono text-micro text-muted">
            inputs: {ssvc.inputs_source} · SSVC v{ssvc.scoring_version}
          </p>
        </Card>
      </div>

      {/* ── Exploit evidence ─────────────────────────────────────────── */}
      <Card padding="md" radius="panel" tone="rose">
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Layers size={16} className="text-rose-500" />
              <h2 className="font-display text-base font-semibold text-heading">Public exploit evidence</h2>
            </div>
            <span className={`font-mono text-meta ${EXPLOIT_TONE[exploit.confidence] ?? ''}`}>
              {exploit.confidence_label}
            </span>
          </div>
        </CardHeader>

        {exploit.degraded.length > 0 && (
          <p className="mb-3 rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-micro text-amber-700 dark:text-amber-300">
            {exploit.degraded.join(' · ')}
          </p>
        )}

        <div className="grid gap-4 md:grid-cols-2">
          {exploit.metasploit.length > 0 && (
            <div>
              <h3 className="mb-1.5 font-mono text-micro uppercase tracking-wider text-muted">Metasploit modules</h3>
              <ul className="space-y-1.5">
                {exploit.metasploit.map((m) => (
                  <li key={m.fullname} className="rounded border border-line-1 bg-surface-100 p-2">
                    <a
                      href={m.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="inline-flex items-center gap-1 font-mono text-tool text-heading hover:underline"
                    >
                      {m.fullname} <ExternalLink size={11} />
                    </a>
                    <p className="font-mono text-micro text-muted">
                      {m.type} · rank {m.rank} · disclosed {m.disclosure_date || '—'}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {exploit.exploitdb.length > 0 && (
            <div>
              <h3 className="mb-1.5 font-mono text-micro uppercase tracking-wider text-muted">Exploit-DB</h3>
              <ul className="space-y-1.5">
                {exploit.exploitdb.map((e) => (
                  <li key={e.id} className="rounded border border-line-1 bg-surface-100 p-2">
                    <a
                      href={e.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="inline-flex items-center gap-1 text-tool text-heading hover:underline"
                    >
                      {e.description} <ExternalLink size={11} />
                    </a>
                    <p className="font-mono text-micro text-muted">
                      {e.type} · {e.platform} · {e.date_published}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {exploit.github.length > 0 && (
            <div>
              <h3 className="mb-1.5 font-mono text-micro uppercase tracking-wider text-muted">Public repositories</h3>
              <ul className="space-y-1.5">
                {exploit.github.map((g) => (
                  <li key={g.full_name} className="rounded border border-line-1 bg-surface-100 p-2">
                    <a
                      href={g.html_url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="inline-flex items-center gap-1 font-mono text-tool text-heading hover:underline"
                    >
                      {g.full_name} <ExternalLink size={11} />
                    </a>
                    <p className="font-mono text-micro text-muted">
                      ★ {g.stars} · {g.language || '—'} · score {g.score} · {g.source}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {exploit.nuclei.length > 0 && (
            <div>
              <h3 className="mb-1.5 font-mono text-micro uppercase tracking-wider text-muted">Nuclei templates</h3>
              <ul className="space-y-1.5">
                {exploit.nuclei.map((n) => (
                  <li key={n.path} className="rounded border border-line-1 bg-surface-100 p-2">
                    <a
                      href={n.html_url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="inline-flex items-center gap-1 font-mono text-tool text-heading hover:underline"
                    >
                      {n.name} <ExternalLink size={11} />
                    </a>
                    <p className="font-mono text-micro text-muted">{n.path}</p>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {exploit.total_sources_found === 0 && (
          <p className="text-meta text-muted">
            No public exploit evidence was found across GitHub, Exploit-DB, Metasploit and Nuclei.
          </p>
        )}
      </Card>

      {/* ── Sources ───────────────────────────────────────────────────── */}
      <Card padding="md" radius="panel" tone="rose">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Globe size={16} className="text-rose-500" />
            <h2 className="font-display text-base font-semibold text-heading">Sources consulted</h2>
          </div>
        </CardHeader>
        <ul className="flex flex-wrap gap-2">
          {data.sources.map((s) => (
            <li
              key={s.id}
              className="rounded border border-line-1 bg-surface-100 px-2.5 py-1 font-mono text-micro text-muted"
              title={s.note}
            >
              {s.ok ? '✓' : '✗'} {s.name}
            </li>
          ))}
        </ul>
        {data.euvd && (
          <p className="mt-3 text-meta text-muted">
            ENISA EUVD: {data.euvd.exploited ? 'reported as exploited' : 'not reported as exploited'}
            {data.euvd.exploitedSince ? ` since ${fmtDate(data.euvd.exploitedSince)}` : ''} ·{' '}
            <a
              href={data.euvd.url}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1 hover:underline"
            >
              record <ExternalLink size={11} />
            </a>
          </p>
        )}
      </Card>

      <div className="flex justify-end">
        <button
          type="button"
          onClick={() => setCveId(null)}
          className="rounded border border-line-1 px-3 py-1.5 font-mono text-meta text-muted hover:border-brand-500/40"
        >
          Triage another CVE
        </button>
      </div>
    </div>
  );
}

/* ─── Compare view ────────────────────────────────────────────────────────── */

function CompareView(): JSX.Element {
  const [input, setInput] = useState('');
  const [cves, setCves] = useState<string[] | null>(null);
  const [depth, setDepth] = useState<'quick' | 'standard'>('quick');
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<CompareResponse | null>(null);

  const run = useCallback(async (ids: string[], d: 'quick' | 'standard') => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<CompareResponse>(
        `/api/v1/cve-compare?cves=${encodeURIComponent(ids.join(','))}&depth=${d}`,
        { timeoutMs: 45_000 }
      );
      setData(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : errMessage(err));
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const ids = [
      ...new Set(
        input
          .split(/[\s,]+/)
          .map((s) => s.trim().toUpperCase())
          .filter(Boolean)
      ),
    ];
    const invalid = ids.filter((id) => !/^CVE-\d{4}-\d{4,7}$/.test(id));
    if (invalid.length > 0) {
      setSubmitError(`Not a CVE id: ${invalid.join(', ')}.`);
      return;
    }
    if (ids.length < 2) {
      setSubmitError('Enter at least two CVE ids.');
      return;
    }
    if (ids.length > 10) {
      setSubmitError('Compare at most ten at a time — split the list.');
      return;
    }
    setSubmitError(null);
    setCves(ids);
    void run(ids, depth);
  };

  const depthNote =
    depth === 'quick'
      ? 'Quick depth uses the cached NVD/EPSS/KEV signals — fast, but exploit maturity is not collected.'
      : 'Standard depth adds the live exploit lookups. Slower, and it can change the order when exploit maturity is the tiebreaker.';

  return (
    <div className="space-y-5">
      <Card padding="lg" radius="panel" tone="rose">
        <CardHeader>
          <div>
            <h2 className="font-display text-lg font-semibold text-heading">Patch order</h2>
            <p className="mt-1 text-meta text-muted">
              Two to ten CVEs, ordered by what to fix first — with the reason for every position.
            </p>
          </div>
        </CardHeader>
        <form onSubmit={submit} className="space-y-3">
          <div>
            <label
              htmlFor="compare-cves"
              className="mb-1.5 block font-mono text-micro uppercase tracking-wider text-muted"
            >
              CVE ids (comma or space separated)
            </label>
            <textarea
              id="compare-cves"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              rows={3}
              placeholder="CVE-2024-3400, CVE-2023-44487, CVE-2021-44228"
              spellCheck={false}
              className="w-full rounded border border-line-1 bg-surface-100 px-3 py-2 font-mono text-tool text-heading placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            />
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <label className="inline-flex items-center gap-2 font-mono text-meta text-muted">
              <input
                type="radio"
                name="compare-depth"
                checked={depth === 'quick'}
                onChange={() => setDepth('quick')}
                className="focus-visible:ring-2 focus-visible:ring-brand-500"
              />
              quick
            </label>
            <label className="inline-flex items-center gap-2 font-mono text-meta text-muted">
              <input
                type="radio"
                name="compare-depth"
                checked={depth === 'standard'}
                onChange={() => setDepth('standard')}
                className="focus-visible:ring-2 focus-visible:ring-brand-500"
              />
              standard
            </label>
            <button
              type="submit"
              className="inline-flex items-center gap-1.5 rounded bg-brand-600 px-4 py-2 font-mono text-meta text-on-fill transition-colors hover:bg-brand-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            >
              <ArrowRight size={14} /> Rank them
            </button>
          </div>
          <p className="font-mono text-micro text-muted">{depthNote}</p>
          {submitError && (
            <p role="alert" className="flex items-center gap-1.5 text-meta text-rose-600 dark:text-rose-400">
              <AlertTriangle size={13} /> {submitError}
            </p>
          )}
        </form>
      </Card>

      {loading && (
        <div className="flex items-center justify-center py-12" role="status" aria-busy="true">
          <span className="font-mono text-meta text-muted">Triaging {cves?.length} CVEs…</span>
        </div>
      )}

      {error && (
        <Card padding="md" radius="panel" tone="rose">
          <p role="alert" className="flex items-center gap-2 text-tool text-rose-600 dark:text-rose-400">
            <AlertTriangle size={15} /> {error}
          </p>
        </Card>
      )}

      {data && !loading && (
        <>
          <StatCards
            cards={[
              { label: 'Compared', value: data.summary.total, icon: <Layers size={16} /> },
              { label: 'In KEV', value: data.summary.in_kev, icon: <Flame size={16} /> },
              { label: 'Ransomware', value: data.summary.known_ransomware, icon: <ShieldAlert size={16} /> },
              { label: 'Critical', value: data.summary.critical, icon: <TrendingUp size={16} /> },
            ]}
          />

          <Card padding="none" radius="panel" tone="rose">
            <ol className="divide-y divide-line-1">
              {data.comparison_matrix.map((row) => (
                <li key={row.cve_id} className="p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="flex items-start gap-3">
                      <span className="mt-0.5 flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full bg-surface-300 font-mono text-meta font-bold text-heading">
                        {row.patch_priority_rank ?? '—'}
                      </span>
                      <div>
                        <Link
                          to={`/threatintel/cves/${row.cve_id}`}
                          className="font-mono text-tool text-heading hover:underline"
                        >
                          {row.cve_id}
                        </Link>
                        <div className="mt-1 flex flex-wrap gap-1.5">
                          {row.in_kev && (
                            <span className="rounded border border-rose-500/40 bg-rose-500/15 px-1.5 py-0.5 font-mono text-micro text-rose-700 dark:text-rose-300">
                              KEV
                            </span>
                          )}
                          {row.known_ransomware && (
                            <span className="rounded border border-rose-500/40 bg-rose-500/15 px-1.5 py-0.5 font-mono text-micro text-rose-700 dark:text-rose-300">
                              ransomware
                            </span>
                          )}
                          <span className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-micro text-muted">
                            CVSS {row.cvss_score}
                          </span>
                          <span className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-micro text-muted">
                            EPSS {fmtPct(row.epss_probability)}
                          </span>
                          <span className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-micro text-muted">
                            {row.exploit_confidence}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`font-display text-xl font-bold ${RISK_TONE[row.risk_label] ?? ''}`}>
                        {row.risk_score.toFixed(0)}
                      </div>
                      <div className="font-mono text-micro uppercase tracking-wider text-muted">{row.risk_label}</div>
                    </div>
                  </div>
                  {row.why_above_next && (
                    <p className="mt-2 border-l-2 border-line-1 pl-3 text-meta text-muted">{row.why_above_next}</p>
                  )}
                </li>
              ))}
            </ol>
          </Card>

          <p className="text-meta text-muted">
            Order: {data.order}. Ties fall to {data.tie_breakers.slice(0, -1).join(', ')}, then{' '}
            {data.tie_breakers[data.tie_breakers.length - 1]}.
          </p>
        </>
      )}
    </div>
  );
}

/* ─── Landscape view ──────────────────────────────────────────────────────── */

function LandscapeView(): JSX.Element {
  const [days, setDays] = useState(7);
  const url = `/api/v1/cve-landscape?days=${days}`;
  const { data, loading, error, refetch } = useApiData<LandscapeResponse>(url, { ttl: 300_000 });

  const panelCount = useMemo(() => data?.panels.length ?? 0, [data]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-meta text-muted">
          {days} days · {panelCount} panels · a CVE needs two independent signals to be listed below
        </p>
        <div className="flex gap-1.5">
          {[1, 7, 14, 30].map((d) => (
            <button
              key={d}
              type="button"
              onClick={() => setDays(d)}
              className={`rounded px-3 py-1.5 font-mono text-meta border transition-colors ${
                days === d
                  ? 'border-brand-500/60 bg-brand-500/10 text-brand-600 dark:text-brand-400'
                  : 'border-line-1 text-muted hover:border-brand-500/30'
              }`}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-16" role="status" aria-busy="true">
          <span className="font-mono text-meta text-muted">Building the landscape…</span>
        </div>
      )}

      {error && (
        <Card padding="md" radius="panel" tone="rose">
          <p role="alert" className="flex items-center gap-2 text-tool text-rose-600 dark:text-rose-400">
            <AlertTriangle size={15} /> {error}
          </p>
          <button
            type="button"
            onClick={refetch}
            className="mt-3 rounded border border-line-1 px-3 py-1.5 font-mono text-meta text-muted hover:border-brand-500/40"
          >
            Retry
          </button>
        </Card>
      )}

      {data && !loading && (
        <>
          <Card padding="md" radius="panel" tone="rose">
            <p className="text-tool leading-relaxed text-heading">{data.headline}</p>
          </Card>

          {data.multi_signal.length > 0 && (
            <Card padding="md" radius="panel" tone="rose">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Target size={16} className="text-rose-500" />
                  <h2 className="font-display text-base font-semibold text-heading">Multiple sources agree</h2>
                </div>
              </CardHeader>
              <ul className="space-y-2">
                {data.multi_signal.map((row) => (
                  <li
                    key={row.cve_id}
                    className="flex flex-wrap items-center justify-between gap-2 rounded border border-line-1 bg-surface-100 p-2.5"
                  >
                    <Link
                      to={`/threatintel/cves/${row.cve_id}`}
                      className="font-mono text-tool text-heading hover:underline"
                    >
                      {row.cve_id}
                    </Link>
                    <div className="flex flex-wrap gap-1.5">
                      {row.signals.map((s) => (
                        <span
                          key={s}
                          className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 font-mono text-micro text-rose-700 dark:text-rose-300"
                        >
                          {s}
                        </span>
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <div className="grid gap-4 lg:grid-cols-2">
            {data.panels.map((panel) => (
              <Card key={panel.id} padding="md" radius="panel" tone="rose">
                <CardHeader>
                  <div>
                    <h2 className="font-display text-base font-semibold text-heading">{panel.title}</h2>
                    <p className="font-mono text-micro text-muted">{panel.source}</p>
                  </div>
                  <span className="font-mono text-meta text-muted">{panel.total}</span>
                </CardHeader>
                {panel.error ? (
                  <p className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-micro text-amber-700 dark:text-amber-300">
                    {panel.error}
                  </p>
                ) : panel.items.length === 0 ? (
                  <p className="text-meta text-muted">Nothing in this window.</p>
                ) : (
                  <ul className="max-h-72 space-y-1.5 overflow-y-auto">
                    {panel.items.slice(0, 12).map((item, i) => {
                      const cve = (item.cve_id as string | undefined) ?? (item.cve_ids as string[])?.[0];
                      return (
                        <li key={`${panel.id}-${cve ?? i}`} className="rounded border border-line-1 bg-surface-100 p-2">
                          {cve ? (
                            <Link
                              to={`/threatintel/cves/${cve}`}
                              className="font-mono text-tool text-heading hover:underline"
                            >
                              {cve}
                            </Link>
                          ) : (
                            <span className="font-mono text-tool text-heading">
                              {(item.title as string | undefined)?.slice(0, 90) ?? '—'}
                            </span>
                          )}
                          <p className="font-mono text-micro text-muted">
                            {(item.vendor as string | undefined) ? `${item.vendor} · ` : ''}
                            {(item.title as string | undefined)?.slice(0, 70) ?? ''}
                            {(item.date as string | undefined) ? ` · ${item.date}` : ''}
                          </p>
                        </li>
                      );
                    })}
                  </ul>
                )}
                {panel.note && <p className="mt-2 font-mono text-micro text-muted">{panel.note}</p>}
              </Card>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

/* ─── Page ────────────────────────────────────────────────────────────────── */

export default function CveTriage(): JSX.Element {
  const [tab, setTab] = useState('triage');

  useEffect(() => {
    // Deep-link support: /threatintel/cve-triage?cve=CVE-2024-3400
    const params = new URLSearchParams(window.location.search);
    const cve = params.get('cve');
    if (cve && /^CVE-\d{4}-\d{4,7}$/i.test(cve)) {
      setTab('triage');
    }
  }, []);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Target size={28} />}
      title="CVE Triage"
      description="Score a single CVE, order a patch list, and see what changed this week — with the reasoning behind every call."
      maxWidthClass="max-w-6xl"
    >
      <Tabs
        variant="pills"
        tabs={[
          { id: 'triage', label: 'Triage' },
          { id: 'compare', label: 'Compare' },
          { id: 'landscape', label: 'Landscape' },
        ]}
        active={tab}
        onChange={setTab}
        className="mb-6"
      >
        {(active) => {
          if (active === 'compare') return <CompareView />;
          if (active === 'landscape') return <LandscapeView />;
          return <TriageView />;
        }}
      </Tabs>
    </DataPageLayout>
  );
}
