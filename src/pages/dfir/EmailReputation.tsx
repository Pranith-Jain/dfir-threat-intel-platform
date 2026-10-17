import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Mail, Search, Loader2, ExternalLink, Globe } from 'lucide-react';
import {
  checkIpBlacklists,
  checkDomainBlacklists,
  queryDoh,
  IP_DNSBLS,
  DOMAIN_DNSBLS,
} from '../../lib/dfir/reputation';
import { BlacklistBadge } from '../../components/dfir/BlacklistBadge';
import type { BlacklistCheck } from '../../lib/dfir/reputation';

export default function EmailReputation(): JSX.Element {
  const [searchParams] = useSearchParams();
  const [input, setInput] = useState(searchParams.get('domain') ?? searchParams.get('q') ?? '');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    domain: string;
    mx: Array<{ exchange: string; priority: number }>;
    score: number;
    verdict: 'safe' | 'suspicious' | 'poor';
    spf: string;
    dmarc: string;
    dkim: string;
    bimi: string;
    mta_sts: string;
    tls_rpt: string;
    domainBl: BlacklistCheck[];
    mxBl: Array<{ exchange: string; ip: string; checks: BlacklistCheck[] }>;
    truncated: boolean;
    emailRep?: {
      email: string;
      ok: boolean;
      verdict?: 'malicious' | 'suspicious' | 'clean' | 'unknown';
      score?: number;
      reputation?: 'high' | 'medium' | 'low' | 'unknown';
      tags?: string[];
      references?: number;
      details?: {
        domain_exists?: boolean;
        free_provider?: boolean;
        disposable?: boolean;
        deliverable?: boolean;
        first_seen?: string;
        last_seen?: string;
      };
      error?: string;
    };
    heatwave?: {
      domain: string;
      ok: boolean;
      listed?: boolean;
      status?: 'warming' | 'active' | 'pre-warming' | 'not-listed';
      stage?: 2 | 3 | 4 | null;
      score?: number | null;
      observation_age?: string | null;
      first_observed?: string | null;
      listed_since?: string | null;
      dns_answer?: string | null;
      verdict?: 'suspicious' | 'unknown';
      tags?: string[];
      related?: Array<{ domain: string; classification: string; score: number }>;
      error?: string;
    };
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState('');
  const abortRef = useRef<AbortController | null>(null);

  // Preserve the original input form so we can run emailrep.io when the
  // user gave us a full email address. `clean` keeps the domain-only form
  // for the existing DNSBL/auth checks.
  const trimmed = input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '');
  const emailAddress = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(trimmed) ? trimmed : null;
  const clean = trimmed.replace(/^.*@/, '');

  const lookup = async () => {
    if (!clean) return;
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    const signal = abortRef.current.signal;

    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setProgress('Fetching email auth records…');
      const r = await fetch(`/api/v1/domain/lookup?domain=${encodeURIComponent(clean)}`, { signal });
      if (!r.ok) {
        const body = await r.text().catch(() => '');
        throw new Error(body ? `API ${r.status}: ${body.slice(0, 100)}` : `API ${r.status}`);
      }
      const ct = r.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON response');
      const data = (await r.json()) as {
        email_auth: {
          spf: { present: boolean; policy?: string };
          dmarc: { present: boolean; policy?: string };
          dkim: { selectors_found: string[] };
          bimi: { present: boolean };
          mta_sts: { present: boolean; mode?: string };
          tls_rpt: { present: boolean; rua?: string };
        };
        dns?: { mx?: Array<{ exchange: string; priority: number }> };
      };
      if (signal.aborted) return;

      const mx = data.dns?.mx ?? [];
      const truncated = mx.length > 5;
      const mxSlice = mx.slice(0, 5);
      setProgress(`Resolving ${mxSlice.length} mail server(s) against ${IP_DNSBLS.length} IP blacklists…`);

      const [domainBl, ...mxNested] = await Promise.all([
        checkDomainBlacklists(clean),
        ...mxSlice.map(async (mxRecord) => {
          const ips = await queryDoh(mxRecord.exchange, 'A');
          const ipChecks = await Promise.all(ips.slice(0, 2).map((ip) => checkIpBlacklists(ip)));
          return ips.slice(0, 2).map((ip, i) => ({ exchange: mxRecord.exchange, ip, checks: ipChecks[i]! }));
        }),
      ]);
      const mxResults = mxNested.flat();
      if (signal.aborted) return;

      const spf = data.email_auth.spf;
      const dmarc = data.email_auth.dmarc;
      const dkim = data.email_auth.dkim;
      let scoreValue = 0;
      if (!spf.present) scoreValue += 25;
      else if (spf.policy !== 'fail') scoreValue += 10;
      if (!dmarc.present) scoreValue += 30;
      else if (dmarc.policy !== 'reject') scoreValue += 15;
      if (dkim.selectors_found.length === 0) scoreValue += 10;
      if (mx.length === 0) scoreValue += 20;
      const allDnsbl = [...domainBl, ...mxResults.flatMap((r) => r.checks)];
      const listedCount = allDnsbl.filter((b) => b!.listed).length;
      scoreValue += Math.min(25, listedCount * 5);

      // Fan out the emailrep.io call only when the input was a full email
      // address. emailrep is per-address - it doesn't have a useful
      // domain-level lookup, and calling it with a bare domain just wastes
      // the rate limit on a guaranteed miss.
      let emailRepResult: NonNullable<typeof result>['emailRep'] | undefined;
      if (emailAddress) {
        try {
          setProgress('Looking up address reputation (emailrep.io)…');
          const rr = await fetch(`/api/v1/email-rep?email=${encodeURIComponent(emailAddress)}`, { signal });
          const rj = (await rr.json()) as {
            ok: boolean;
            verdict?: 'malicious' | 'suspicious' | 'clean' | 'unknown';
            score?: number;
            reputation?: 'high' | 'medium' | 'low' | 'unknown';
            tags?: string[];
            references?: number;
            details?: Record<string, unknown>;
            error?: string;
          };
          emailRepResult = {
            email: emailAddress,
            ok: rj.ok,
            verdict: rj.verdict,
            score: rj.score,
            reputation: rj.reputation,
            tags: rj.tags,
            references: rj.references,
            details: rj.details as NonNullable<typeof result>['emailRep'] extends infer T
              ? T extends { details?: infer D }
                ? D
                : never
              : never,
            error: rj.error,
          };
          // Roll the email-level score into the page composite. The DNSBL
          // score is domain-level; emailrep specifically flags the address.
          if (rj.ok && rj.verdict === 'malicious') scoreValue = Math.max(scoreValue, 75);
          else if (rj.ok && rj.verdict === 'suspicious') scoreValue = Math.max(scoreValue, 50);
        } catch (e) {
          logCatch(e);
          if ((e as { name?: string }).name !== 'AbortError') {
            emailRepResult = {
              email: emailAddress,
              ok: false,
              error: errMessage(e),
            };
          }
        }
      }
      if (signal.aborted) return;

      // Heatwave sender-domain reputation (Validity cold-email blocklist).
      // Domain-level like the DNSBL checks above — run for every lookup,
      // not just full addresses. Warming on your own domain often means a
      // vendor warming on your behalf; active means live cold outreach.
      let heatwaveResult: NonNullable<typeof result>['heatwave'] | undefined;
      try {
        setProgress('Checking sender-domain reputation (Heatwave)…');
        const hr = await fetch(`/api/v1/heatwave/lookup?domain=${encodeURIComponent(clean)}`, { signal });
        if (hr.ok) {
          const hj = (await hr.json()) as {
            domain: string;
            listed: boolean;
            status: 'warming' | 'active' | 'pre-warming' | 'not-listed';
            stage: 2 | 3 | 4 | null;
            score: number | null;
            observation_age: string | null;
            first_observed: string | null;
            listed_since: string | null;
            dns_answer: string | null;
            verdict: 'suspicious' | 'unknown';
            tags: string[];
            related: Array<{ domain: string; classification: string; score: number }>;
          };
          heatwaveResult = { ...hj, ok: true };
          if (hj.listed && hj.status === 'active') scoreValue = Math.max(scoreValue, 60);
          else if (hj.listed && hj.status === 'warming') scoreValue = Math.max(scoreValue, 40);
        } else {
          heatwaveResult = { domain: clean, ok: false, error: `Heatwave lookup failed (HTTP ${hr.status})` };
        }
      } catch (e) {
        logCatch(e);
        if ((e as { name?: string }).name !== 'AbortError') {
          heatwaveResult = { domain: clean, ok: false, error: errMessage(e) };
        }
      }
      if (signal.aborted) return;

      // Recompute verdict if emailrep bumped the score.
      const finalVerdict = scoreValue < 20 ? 'safe' : scoreValue < 50 ? 'suspicious' : 'poor';

      setResult({
        domain: clean,
        mx,
        score: scoreValue,
        verdict: finalVerdict,
        spf: spf.present ? (spf.policy === 'fail' ? '-all' : (spf.policy ?? 'present')) : 'missing',
        dmarc: dmarc.present ? (dmarc.policy ?? 'present') : 'missing',
        dkim: dkim.selectors_found.length > 0 ? dkim.selectors_found.join(', ') : 'none',
        bimi: data.email_auth.bimi.present ? 'published' : 'missing',
        mta_sts: data.email_auth.mta_sts.present ? (data.email_auth.mta_sts.mode ?? 'present') : 'missing',
        tls_rpt: data.email_auth.tls_rpt.present ? 'configured' : 'missing',
        domainBl,
        mxBl: mxResults,
        truncated,
        emailRep: emailRepResult,
        heatwave: heatwaveResult,
      });
    } catch (e) {
      logCatch(e);
      if (!signal.aborted) setError(errMessage(e, 'lookup failed'));
    } finally {
      if (!signal.aborted) setLoading(false);
      setProgress('');
    }
  };

  useEffect(() => {
    if (searchParams.get('domain') || searchParams.get('q')) lookup();
    return () => abortRef.current?.abort();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Mail size={28} />}
      title="Email Reputation"
      description={
        <>
          Full email infrastructure health check - MX, SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT <strong>plus</strong>{' '}
          real-time DNSBL checks of your mail server IPs against <strong>{IP_DNSBLS.length} IP blacklists</strong>{' '}
          (Spamhaus, Barracuda, SORBS, CBL, SpamCop, PSBL, SpamEatingMonkey, UCEPROTECT, Hostkarma, SPFBL) and the
          domain against <strong>{DOMAIN_DNSBLS.length} domain blacklists</strong> (Spamhaus DBL, URIBL, SURBL,
          Invaluement). No API key required.
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          lookup();
        }}
        className="mb-6"
      >
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="example.com or user@example.com"
              className="w-full pl-9 pr-3 py-3 bg-surface-100 border border-line-1 rounded-xl font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
              aria-label="Domain or email to check"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !clean}
            className="px-5 py-3 bg-brand-600 dark:bg-brand-500 text-on-fill font-mono font-semibold rounded-xl disabled:opacity-30 hover:bg-brand-700 dark:hover:bg-brand-400 inline-flex items-center gap-2 transition-colors"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}{' '}
            {loading ? 'Checking' : 'Check'}
          </button>
        </div>
      </form>

      {loading && <p className="text-xs font-mono text-muted animate-pulse mb-4">{progress}</p>}
      {error && (
        <p role="alert" className="text-xs font-mono text-rose-600 dark:text-rose-400 mb-4">
          {error}
        </p>
      )}

      {result && (
        <div className="space-y-4">
          <section className="surface-card p-4">
            <div className="flex items-baseline justify-between mb-3">
              <h2 className="font-display font-bold text-xl">{result.domain}</h2>
              <span
                className={`text-xs font-mono uppercase tracking-wider px-2.5 py-1 rounded border ${result.verdict === 'safe' ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' : result.verdict === 'suspicious' ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30' : 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30'}`}
              >
                {result.verdict} · {result.score}/100
              </span>
            </div>
            <div className="h-2 rounded bg-track overflow-hidden mb-4">
              <div
                className={`h-full transition-all ${result.verdict === 'safe' ? 'bg-emerald-500' : result.verdict === 'suspicious' ? 'bg-amber-500' : 'bg-rose-500'}`}
                style={{ width: `${Math.max(2, result.score)}%` }}
              />
            </div>
            <p className="text-sm font-mono text-muted">
              Lower score = better email infrastructure health. 0 means well-configured for deliverability.
            </p>
          </section>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Fact
              label="MX records"
              value={result.mx.length > 0 ? result.mx.map((m) => `${m.exchange} (${m.priority})`).join(', ') : 'none'}
              good={result.mx.length > 0}
            />
            <Fact label="SPF" value={result.spf} good={result.spf === '-all'} />
            <Fact label="DMARC" value={result.dmarc} good={result.dmarc === 'reject'} />
            <Fact label="DKIM" value={result.dkim} good={result.dkim !== 'none'} />
            <Fact label="BIMI" value={result.bimi} good={result.bimi === 'published'} />
            <Fact label="MTA-STS" value={result.mta_sts} good={result.mta_sts === 'enforce'} />
            <Fact label="TLS-RPT" value={result.tls_rpt} good={result.tls_rpt === 'configured'} />
          </div>

          {result.emailRep && (
            <section className="surface-card p-4">
              <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3 inline-flex items-center gap-2">
                <Mail size={12} aria-hidden="true" /> Address reputation (emailrep.io){' '}
                <span className="font-normal text-muted normal-case">· {result.emailRep.email}</span>
              </h3>
              {result.emailRep.ok ? (
                <>
                  <div className="flex flex-wrap items-center gap-2 mb-3">
                    {result.emailRep.verdict && (
                      <span
                        className={`text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border ${
                          result.emailRep.verdict === 'malicious'
                            ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30'
                            : result.emailRep.verdict === 'suspicious'
                              ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30'
                              : result.emailRep.verdict === 'clean'
                                ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30'
                                : 'bg-slate-500/15 text-body border-slate-500/30'
                        }`}
                      >
                        {result.emailRep.verdict}
                        {result.emailRep.score !== undefined ? ` · ${result.emailRep.score}/100` : ''}
                      </span>
                    )}
                    {result.emailRep.reputation && (
                      <span className="text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border border-line-2">
                        rep: {result.emailRep.reputation}
                      </span>
                    )}
                    {result.emailRep.references !== undefined && result.emailRep.references > 0 && (
                      <span className="text-micro font-mono text-muted">{result.emailRep.references} references</span>
                    )}
                  </div>
                  {result.emailRep.tags && result.emailRep.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mb-2">
                      {result.emailRep.tags.map((t) => (
                        <span
                          key={t}
                          className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-1 bg-surface-200 text-body"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                  <p className="text-mini font-mono text-muted">
                    {result.emailRep.details?.first_seen && `first seen ${result.emailRep.details.first_seen} · `}
                    {result.emailRep.details?.last_seen && `last seen ${result.emailRep.details.last_seen} · `}
                    {result.emailRep.details?.deliverable !== undefined &&
                      `deliverable: ${result.emailRep.details.deliverable ? 'yes' : 'no'}`}
                  </p>
                </>
              ) : (
                <p className="text-xs font-mono text-amber-700 dark:text-amber-300">
                  {result.emailRep.error === 'emailrep_not_configured'
                    ? 'EmailRep enrichment is currently disabled.'
                    : `emailrep lookup failed: ${result.emailRep.error ?? 'unknown error'}`}
                </p>
              )}
            </section>
          )}

          {result.heatwave && (
            <section className="surface-card p-4">
              <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3 inline-flex items-center gap-2">
                <Mail size={12} aria-hidden="true" /> Sender-domain reputation (Heatwave){' '}
                <span className="font-normal text-muted normal-case">· {result.heatwave.domain}</span>
              </h3>
              {result.heatwave.ok ? (
                <>
                  <div className="flex flex-wrap items-center gap-2 mb-3">
                    <span
                      className={`text-micro font-mono uppercase tracking-wider px-2 py-0.5 rounded border ${
                        result.heatwave.listed
                          ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30'
                          : 'bg-slate-500/15 text-body border-slate-500/30'
                      }`}
                    >
                      {result.heatwave.listed
                        ? `${result.heatwave.status} · stage ${result.heatwave.stage}`
                        : 'not listed'}
                    </span>
                    {result.heatwave.score !== undefined && result.heatwave.score !== null && (
                      <span className="text-micro font-mono text-muted">score band {result.heatwave.score}/100</span>
                    )}
                    {result.heatwave.observation_age && (
                      <span className="text-micro font-mono text-muted">warming {result.heatwave.observation_age}</span>
                    )}
                    {result.heatwave.first_observed && (
                      <span className="text-micro font-mono text-muted">since {result.heatwave.first_observed}</span>
                    )}
                  </div>
                  {result.heatwave.dns_answer && (
                    <p className="text-mini font-mono text-muted mb-2">{result.heatwave.dns_answer}</p>
                  )}
                  {result.heatwave.related && result.heatwave.related.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mb-2">
                      <span className="text-mini font-mono text-muted mr-1">related listed:</span>
                      {result.heatwave.related.slice(0, 8).map((rel) => (
                        <span
                          key={rel.domain}
                          className="text-micro font-mono px-1.5 py-0.5 rounded border border-line-1 bg-surface-200 text-body"
                          title={`${rel.classification} · score ${rel.score}`}
                        >
                          {rel.domain}
                        </span>
                      ))}
                    </div>
                  )}
                  <p className="text-mini font-mono text-muted">
                    Sending-domain reputation only — a hit means cold-email infrastructure, not phishing. Not listed is
                    not a clean verdict, and the score is a relative band, not a threshold.
                  </p>
                </>
              ) : (
                <p className="text-xs font-mono text-amber-700 dark:text-amber-300">
                  Heatwave lookup failed: {result.heatwave.error ?? 'unknown error'}
                </p>
              )}
            </section>
          )}

          {result.domainBl.length > 0 && (
            <section className="surface-card p-4">
              <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3 inline-flex items-center gap-2">
                <Globe size={12} aria-hidden="true" /> Domain blacklist status ({result.domainBl.length} sources)
              </h3>
              <div className="flex flex-wrap gap-2">
                {result.domainBl.map((bl) => (
                  <BlacklistBadge key={bl.source} bl={bl} />
                ))}
              </div>
            </section>
          )}

          {result.mxBl.map(({ exchange, ip, checks }) => {
            const { score: blScore } = checks.reduce(
              (a, c) => ({ score: a.score + (c.listed ? 1 : 0), total: a.total + 1 }),
              { score: 0, total: 0 }
            );
            const cleanCount = checks.length - blScore;
            return (
              <section key={ip} className="surface-card p-4">
                <div className="flex items-baseline justify-between gap-2 mb-3">
                  <h3 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono inline-flex items-center gap-2">
                    <Mail size={12} aria-hidden="true" /> {exchange}{' '}
                    <span className="text-muted normal-case text-micro">({ip})</span>
                  </h3>
                  <span
                    className={`text-micro font-mono px-2 py-0.5 rounded border ${blScore === 0 ? 'bg-emerald-500/15 text-emerald-700 border-emerald-500/30' : blScore < 2 ? 'bg-amber-500/15 text-amber-700 border-amber-500/30' : 'bg-rose-500/15 text-rose-700 border-rose-500/30'}`}
                  >
                    {cleanCount}/{checks.length} clean
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {checks.map((bl) => (
                    <BlacklistBadge key={bl.source} bl={bl} compact={true} showName={false} />
                  ))}
                </div>
              </section>
            );
          })}

          {result.truncated && (
            <p className="text-xs font-mono text-muted">
              First 5 of {result.mx.length} MX servers shown. Check the full list on Domain Lookup.
            </p>
          )}

          <div className="flex gap-2 flex-wrap">
            <Link
              to={`/dfir/email-defense?domain=${encodeURIComponent(result.domain)}`}
              className="inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded border border-line-1 text-muted hover:border-brand-500/40"
            >
              <ExternalLink size={10} /> BEC Score
            </Link>
            <Link
              to={`/dfir/domain?domain=${encodeURIComponent(result.domain)}`}
              className="inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded border border-line-1 text-muted hover:border-brand-500/40"
            >
              <ExternalLink size={10} /> Domain Lookup
            </Link>
            <Link
              to={`/dfir/url-risk?url=${encodeURIComponent('https://' + result.domain)}`}
              className="inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded border border-line-1 text-muted hover:border-brand-500/40"
            >
              <ExternalLink size={10} /> URL Reputation
            </Link>
            <Link
              to={`/dfir/domain-rep?domain=${encodeURIComponent(result.domain)}`}
              className="inline-flex items-center gap-1 text-xs font-mono px-3 py-1.5 rounded border border-line-1 text-muted hover:border-brand-500/40"
            >
              <ExternalLink size={10} /> Full Blacklist
            </Link>
          </div>
        </div>
      )}
    </DataPageLayout>
  );
}

function Fact({ label, value, good }: { label: string; value: string; good: boolean }): JSX.Element {
  return (
    <div
      className={`rounded-xl border p-3 ${good ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-line-1 bg-white dark:bg-surface-200'}`}
    >
      <div className="text-micro font-mono uppercase tracking-[0.2em] text-muted mb-1">{label}</div>
      <div className={`text-sm font-mono ${good ? 'text-emerald-700 dark:text-emerald-300' : 'text-heading'}`}>
        {value}
      </div>
    </div>
  );
}
