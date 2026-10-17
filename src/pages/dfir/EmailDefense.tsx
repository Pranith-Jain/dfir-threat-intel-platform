import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { ToolDocs } from '../../components/dfir/ToolDocs';
import { Mail, Search, Loader2, CheckCircle2, AlertTriangle, ExternalLink } from 'lucide-react';
import { CopyChip } from '../../components/dfir/CopyButton';
import { assess, type DomainApiResponse, type BecAssessment } from '../../lib/dfir/bec-score';
import { SEVERITY_TONE as SEV_STYLES, SEVERITY_BAR, type Severity } from '../../components/severity';
import { IntodnsPanel } from '../../components/dfir/IntodnsPanel';

// `safe` grade maps to the `info` severity tone (sky); the other grades are
// already canonical severity keys.
const gradeSeverity = (grade: BecAssessment['grade']): Severity => (grade === 'safe' ? 'info' : grade);

export default function EmailDefense(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const initial = searchParams.get('q') ?? '';
  const [domain, setDomain] = useState(initial);
  const [data, setData] = useState<DomainApiResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (domain) setSearchParams({ q: domain }, { replace: true });
    else setSearchParams({}, { replace: true });
  }, [domain, setSearchParams]);

  useEffect(() => {
    if (initial) lookup();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const lookup = async () => {
    const trimmed = domain
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '');
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    setData(null);
    try {
      const res = await fetch(`/api/v1/domain/lookup?domain=${encodeURIComponent(trimmed)}`);
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        let msg = `API ${res.status}`;
        try {
          const parsed = JSON.parse(body) as { error?: string };
          msg = parsed.error ?? msg;
        } catch (_catchErr) {
          logCatch(_catchErr);
          msg = `${msg}: ${body.slice(0, 200)}`;
        }
        throw new Error(msg);
      }
      const ct = res.headers.get('content-type') ?? '';
      if (!ct.includes('json')) throw new Error('Server returned non-JSON response');
      const json = (await res.json()) as DomainApiResponse;
      setData(json);
    } catch (e) {
      logCatch(e);
      setError(errMessage(e, 'Lookup failed'));
    } finally {
      setLoading(false);
    }
  };

  const assessment = data ? assess(data) : null;

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Mail size={28} />}
      title="Email Defense / BEC Score"
      maxWidthClass="max-w-6xl"
      description={
        <>
          Look up a domain's SPF / DMARC / DKIM / MTA-STS posture and score how easy it is to spoof for a BEC pretext.
          Each gap is paired with the specific BEC scenario it enables and a copy-pastable corrected record.
          <p className="text-xs text-muted font-mono mt-2">
            Different angle from the generic{' '}
            <Link to="/dfir/domain-investigator" className="text-brand-600 dark:text-brand-400 hover:underline">
              Domain Lookup
            </Link>{' '}
            - same data, defender-side framing focused on direct-domain spoofing.
          </p>
        </>
      }
    >
      <ToolDocs path="/dfir/email-defense" />

      <section className="surface-card p-4 mb-6">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            lookup();
          }}
          className="flex flex-wrap gap-2"
        >
          <div className="relative flex-1 min-w-[220px]">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className="w-full pl-9 pr-3 py-2 rounded border border-line-2 bg-surface-200 font-mono text-sm focus:border-brand-500/60 focus:outline-none"
              aria-label="Domain to check"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="text-sm font-mono px-3 py-2 rounded border border-brand-500/60 bg-brand-500/15 text-brand-700 dark:text-brand-300 hover:border-brand-500 disabled:opacity-50 disabled:cursor-not-allowed inline-flex items-center gap-1.5 transition-colors"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
            {loading ? 'Looking up' : 'Check'}
          </button>
        </form>

        {error && (
          <p className="mt-2 text-xs font-mono text-rose-600 dark:text-rose-400 inline-flex items-center gap-1.5">
            <AlertTriangle size={12} /> {error}
          </p>
        )}
      </section>

      {assessment && data && (
        <>
          {/* Score */}
          <section className="surface-card p-4 mb-6">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono">
                Spoofability score for {data.domain}
              </h2>
              <span
                className={`text-xs font-mono uppercase tracking-wider px-2.5 py-1 rounded border ${
                  assessment.grade === 'safe'
                    ? SEV_STYLES.info
                    : assessment.grade === 'low'
                      ? SEV_STYLES.low
                      : assessment.grade === 'medium'
                        ? SEV_STYLES.medium
                        : assessment.grade === 'high'
                          ? SEV_STYLES.high
                          : SEV_STYLES.critical
                }`}
              >
                {assessment.grade} · {assessment.spoofScore}/100
              </span>
            </div>
            <div className="h-2 rounded bg-track overflow-hidden mb-3">
              <div
                className={`h-full transition-all ${SEVERITY_BAR[gradeSeverity(assessment.grade)]}`}
                style={{ width: `${Math.max(2, assessment.spoofScore)}%` }}
              />
            </div>
            <p className="text-sm font-mono text-body mb-3">{assessment.headline}</p>
            <p className="text-mini font-mono text-muted">
              Higher score = easier for an attacker to send mail "from" {data.domain} that lands in someone's inbox. 0
              means well-defended.
            </p>
          </section>

          {/* Quick facts */}
          <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 mb-6">
            <Fact
              label="SPF"
              value={
                data.email_auth.spf.present
                  ? data.email_auth.spf.policy === 'fail'
                    ? '-all (hard fail)'
                    : (data.email_auth.spf.policy ?? 'present')
                  : 'missing'
              }
              good={data.email_auth.spf.present && data.email_auth.spf.policy === 'fail'}
            />
            <Fact
              label="DMARC"
              value={
                data.email_auth.dmarc.present
                  ? `${data.email_auth.dmarc.policy ?? 'present'} (pct ${data.email_auth.dmarc.pct ?? 100})`
                  : 'missing'
              }
              good={data.email_auth.dmarc.present && data.email_auth.dmarc.policy === 'reject'}
            />
            <Fact
              label="DKIM selectors"
              value={
                data.email_auth.dkim.selectors_found.length === 0
                  ? 'none observed'
                  : data.email_auth.dkim.selectors_found.join(', ')
              }
              good={data.email_auth.dkim.selectors_found.length > 0}
            />
            <Fact
              label="MTA-STS"
              value={data.email_auth.mta_sts.present ? (data.email_auth.mta_sts.mode ?? 'present') : 'missing'}
              good={data.email_auth.mta_sts.mode === 'enforce'}
            />
            <Fact
              label="BIMI"
              value={data.email_auth.bimi.present ? 'published' : 'missing'}
              good={data.email_auth.bimi.present}
            />
            <Fact
              label="TLS-RPT"
              value={
                data.email_auth.tls_rpt.present
                  ? `reporting${data.email_auth.tls_rpt.rua ? ` (${data.email_auth.tls_rpt.rua})` : ''}`
                  : 'missing'
              }
              good={data.email_auth.tls_rpt.present}
            />
          </section>

          {/* Records observed */}
          {(data.email_auth.spf.record ||
            data.email_auth.dmarc.record ||
            data.email_auth.bimi.present ||
            data.email_auth.tls_rpt.present) && (
            <section className="surface-card p-4 mb-6">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">
                Records observed
              </h2>
              <div className="space-y-2">
                {data.email_auth.spf.record && (
                  <RecordRow name={`${data.domain} TXT`} value={data.email_auth.spf.record} />
                )}
                {data.email_auth.dmarc.record && (
                  <RecordRow name={`_dmarc.${data.domain} TXT`} value={data.email_auth.dmarc.record} />
                )}
                {data.email_auth.bimi.present && (
                  <RecordRow
                    name={`default._bimi.${data.domain} TXT`}
                    value={`v=BIMI1${data.email_auth.bimi.logo ? `; l=${data.email_auth.bimi.logo}` : ''};`}
                  />
                )}
                {data.email_auth.tls_rpt.present && (
                  <RecordRow
                    name={`_smtp._tls.${data.domain} TXT`}
                    value={`v=TLSRPTv1; rua=${data.email_auth.tls_rpt.rua ?? `mailto:tls-reports@${data.domain}`};`}
                  />
                )}
              </div>
            </section>
          )}

          {/* Gaps */}
          {assessment.gaps.length > 0 && (
            <section className="surface-card p-4 mb-6">
              <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">
                Gaps & BEC scenarios ({assessment.gaps.length})
              </h2>
              <ul className="space-y-3">
                {assessment.gaps.map((g) => (
                  <li key={g.id} className="rounded border border-line-1 bg-surface-200 p-3">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="font-display font-semibold text-heading">{g.title}</span>
                      <span
                        className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${SEV_STYLES[g.severity]}`}
                      >
                        {g.severity}
                      </span>
                    </div>
                    <p className="text-sm font-mono text-body mb-2">
                      <span className="text-rose-600 dark:text-rose-400 font-bold">Attack: </span>
                      {g.scenario}
                    </p>
                    <p className="text-sm font-mono text-emerald-700 dark:text-emerald-400 mb-2">→ {g.remediation}</p>
                    {g.record && (
                      <div className="rounded border border-line-1 bg-surface-100 p-2.5 mt-2">
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <span className="text-micro font-mono uppercase tracking-[0.2em] text-muted">
                            Suggested record · {g.record.name} {g.record.type}
                          </span>
                          <CopyChip value={g.record.value} />
                        </div>
                        <pre className="text-meta font-mono text-heading whitespace-pre-wrap break-all">
                          {g.record.value}
                        </pre>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* Positives */}
          {assessment.positives.length > 0 && (
            <section className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 mb-6">
              <h2 className="text-xs font-bold uppercase tracking-[0.2em] text-emerald-600 dark:text-emerald-400 font-mono mb-2 inline-flex items-center gap-1.5">
                <CheckCircle2 size={12} /> What you're already doing
              </h2>
              <ul className="space-y-1 text-sm font-mono text-body list-disc pl-5">
                {assessment.positives.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </section>
          )}
        </>
      )}

      {data && (
        <div className="mb-4">
          <IntodnsPanel domain={data.domain} title="IntoDNS.ai email-security grade" />
        </div>
      )}

      <section className="surface-card p-4">
        <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">References</h2>
        <ul className="space-y-1.5 text-sm font-mono text-muted">
          <li>
            <a
              href="https://datatracker.ietf.org/doc/html/rfc7489"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              RFC 7489 - Domain-based Message Authentication, Reporting &amp; Conformance (DMARC)
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
          <li>
            <a
              href="https://www.cisa.gov/news-events/news/binding-operational-directive-18-01"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              CISA BOD 18-01 - DMARC enforcement requirements
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
          <li>
            <a
              href="https://datatracker.ietf.org/doc/html/rfc8461"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              RFC 8461 - SMTP MTA Strict Transport Security (MTA-STS)
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
        </ul>
      </section>
    </DataPageLayout>
  );
}

function Fact({ label, value, good }: { label: string; value: string; good: boolean }): JSX.Element {
  return (
    <div
      className={`rounded-xl border p-3 ${
        good ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-line-1 bg-white dark:bg-surface-200'
      }`}
    >
      <div className="text-micro font-mono uppercase tracking-[0.2em] text-muted mb-1">{label}</div>
      <div className={`text-sm font-mono ${good ? 'text-emerald-700 dark:text-emerald-300' : 'text-heading'}`}>
        {value}
      </div>
    </div>
  );
}

function RecordRow({ name, value }: { name: string; value: string }): JSX.Element {
  return (
    <div className="rounded border border-line-1 bg-surface-200 p-2.5">
      <div className="flex items-center justify-between gap-2 mb-1">
        <span className="text-micro font-mono uppercase tracking-[0.2em] text-muted">{name}</span>
        <CopyChip value={value} />
      </div>
      <pre className="text-meta font-mono text-heading whitespace-pre-wrap break-all">{value}</pre>
    </div>
  );
}
