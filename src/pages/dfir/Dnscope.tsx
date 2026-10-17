import { errMessage, logCatch } from '../../lib/log';
import { useState, useCallback } from 'react';
import { Globe, Search, ShieldCheck, Loader2, AlertTriangle } from 'lucide-react';
import { IntodnsPanel } from '../../components/dfir/IntodnsPanel';

interface DnsSection {
  id: string;
  label: string;
  data: string[];
}

interface DomainLookupResponse {
  domain: string;
  score: number;
  verdict: string;
  rdap: {
    registrar?: string;
    registrar_abuse_email?: string;
    created?: string;
    expires?: string;
    nameservers: string[];
    status: string[];
    error?: string;
  };
  dns: Record<string, { records: string[]; error?: string }>;
  email_auth: {
    spf: { present: boolean; policy?: string; record?: string };
    dmarc: { present: boolean; policy?: string; record?: string };
    dkim: { selectors_found: string[] };
    bimi: { present: boolean; logo?: string };
    mta_sts: { present: boolean; mode?: string };
    tls_rpt: { present: boolean; rua?: string };
  };
  certificates: Array<{ id: number; issuer: string; not_before: string; not_after: string; subjects: string[] }>;
  threat_intel: {
    verdict: string;
    hits: number;
    sources: Array<{ source: string; status: string; verdict: string; tags: string[] }>;
  };
}

export default function Dnscope(): JSX.Element {
  const [domain, setDomain] = useState('');
  const [scanning, setScanning] = useState(false);
  const [sections, setSections] = useState<DnsSection[]>([]);
  const [error, setError] = useState<string | null>(null);

  const runScan = useCallback(async () => {
    const d = domain.trim();
    if (!d) return;
    setScanning(true);
    setError(null);
    setSections([]);

    try {
      const res = await fetch(`/api/v1/domain/lookup?domain=${encodeURIComponent(d)}`);
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        let msg = `HTTP ${res.status}`;
        try {
          const p = JSON.parse(body) as { message?: string; error?: string };
          msg = p.message ?? p.error ?? msg;
        } catch (_catchErr) {
          console.error('Dnscope failed:', errMessage(_catchErr));
          /* */
        }
        throw new Error(msg);
      }

      const data = (await res.json()) as DomainLookupResponse;
      const built: DnsSection[] = [];

      if (data.rdap && !data.rdap.error) {
        const lines: string[] = [];
        if (data.rdap.registrar) lines.push(`Registrar: ${data.rdap.registrar}`);
        if (data.rdap.created) lines.push(`Created: ${data.rdap.created}`);
        if (data.rdap.expires) lines.push(`Expires: ${data.rdap.expires}`);
        if (data.rdap.nameservers?.length) lines.push(`Name servers: ${data.rdap.nameservers.join(', ')}`);
        if (lines.length) built.push({ id: 'whois', label: 'WHOIS · RDAP', data: lines });
      }

      if (data.dns) {
        const lines: string[] = [];
        for (const [type, result] of Object.entries(data.dns)) {
          if (result.records?.length) {
            lines.push(`${type} → ${result.records.join(', ')}`);
          }
        }
        if (lines.length) built.push({ id: 'dns', label: 'Live DNS Records', data: lines });
      }

      if (data.email_auth) {
        const lines: string[] = [];
        const { spf, dmarc, dkim, bimi, mta_sts } = data.email_auth;
        if (spf.present) lines.push(`SPF: ${spf.policy ?? 'present'}${spf.record ? ` - ${spf.record}` : ''}`);
        if (dmarc.present) lines.push(`DMARC: ${dmarc.policy ?? 'present'}${dmarc.record ? ` - ${dmarc.record}` : ''}`);
        if (dkim.selectors_found?.length) lines.push(`DKIM: ${dkim.selectors_found.length} selector(s) found`);
        if (bimi.present) lines.push(`BIMI: logo configured`);
        if (mta_sts.present) lines.push(`MTA-STS: ${mta_sts.mode ?? 'enabled'}`);
        if (lines.length) built.push({ id: 'email', label: 'Email Infrastructure', data: lines });
      }

      if (data.certificates?.length) {
        const lines = data.certificates.slice(0, 5).map((c) => {
          const san = c.subjects
            ?.filter((s) => s !== data.domain)
            .slice(0, 2)
            .join(', ');
          return `${c.issuer?.slice(0, 40)}… - ${c.not_before?.slice(0, 10)}${san ? ` SAN: ${san}` : ''}`;
        });
        lines.unshift(`${data.certificates.length} certificate(s) found`);
        built.push({ id: 'certs', label: 'Certificates · CT Logs', data: lines });
      }

      if (data.threat_intel) {
        const lines: string[] = [];
        lines.push(`Verdict: ${data.threat_intel.verdict}`);
        lines.push(`Hits: ${data.threat_intel.hits}`);
        if (data.threat_intel.sources?.length) {
          const active = data.threat_intel.sources.filter((s) => s.status === 'ok');
          lines.push(`Responding sources: ${active.length}/${data.threat_intel.sources.length}`);
        }
        built.push({ id: 'threat', label: 'Threat Intelligence', data: lines });
      }

      built.push(
        {
          id: 'subs',
          label: 'Subdomains (coming soon)',
          data: ['Subdomain enumeration via external API - not yet wired'],
        },
        {
          id: 'lookalike',
          label: 'Lookalike · Permutations (coming soon)',
          data: ['Permutation analysis - not yet wired'],
        },
        {
          id: 'ports',
          label: 'Ports · Services (coming soon)',
          data: ['Port scan via Shodan/InternetDB - not yet wired'],
        }
      );

      setSections(built);
    } catch (err) {
      logCatch(err);
      setError(errMessage(err));
    } finally {
      setScanning(false);
    }
  }, [domain]);

  return (
    <div className="max-w-6xl">
      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">DNSCOPE</h1>
        <p className="text-muted mb-8 max-w-2xl">
          Deep domain infrastructure mapping via live DNS, RDAP, certificate transparency, email auth, and threat
          intelligence - all in one scan.
        </p>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-300/70 dark:border-rose-800/60 bg-rose-50/60 dark:bg-rose-950/30 p-4 flex items-start gap-3 mb-6">
          <AlertTriangle size={16} className="text-rose-600 dark:text-rose-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-rose-700 dark:text-rose-300">Scan failed</p>
            <p className="text-xs text-rose-600 dark:text-rose-400 mt-1 font-mono break-all">{error}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div className="surface-card/40 shadow-e1 p-5">
            <div className="flex items-center gap-2 mb-3">
              <Search size={14} className="text-muted" />
              <span className="text-micro font-mono uppercase tracking-wider text-muted">Target Domain</span>
            </div>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              className="w-full rounded-xl border border-line-1 bg-surface-200 p-3 text-sm text-heading focus:outline-none focus:ring-2 focus:ring-brand-500/40 font-mono"
            />
            <div className="flex gap-2 mt-3">
              <button
                type="button"
                onClick={runScan}
                disabled={scanning || !domain.trim()}
                className="flex items-center gap-2 px-5 py-2.5 bg-brand-600 hover:bg-brand-500 disabled:bg-disabled text-on-fill rounded-xl text-sm font-semibold transition-colors"
              >
                {scanning ? <Loader2 size={16} className="animate-spin" /> : <Globe size={16} />}
                {scanning ? 'Scanning…' : 'Scan'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setDomain('');
                  setSections([]);
                  setError(null);
                }}
                className="flex items-center gap-2 px-4 py-2.5 bg-surface-100/40 border border-line-1 text-muted text-sm font-medium rounded-xl hover:bg-surface-200 dark:hover:bg-surface-300/60 transition-colors"
              >
                Clear
              </button>
            </div>
          </div>
        </div>

        <div>
          {scanning && (
            <div className="surface-card/40 shadow-e1 p-8 flex flex-col items-center gap-3">
              <Loader2 size={32} className="animate-spin text-brand-600" />
              <p className="text-sm font-mono text-muted">Querying DNS, RDAP, certificates, and threat intel…</p>
            </div>
          )}

          {!scanning && sections.length === 0 && !error && (
            <div className="rounded-xl border-2 border-dashed border-line-1 bg-surface-100/20 p-8 flex flex-col items-center justify-center text-center">
              <Globe size={48} className="text-inverted mb-4" />
              <p className="text-sm font-mono text-muted">Enter a domain above to map its infrastructure</p>
              <p className="text-micro font-mono text-muted mt-2">DNS · RDAP · CT logs · Email auth · Threat intel</p>
            </div>
          )}

          {!scanning && sections.length > 0 && (
            <>
              <div className="mb-4">
                <IntodnsPanel domain={domain} title="IntoDNS.ai DNS health grade" />
              </div>
              <div className="space-y-2">
                {sections.map((section) => (
                  <div key={section.id} className="surface-card/40 shadow-e1 p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="font-mono text-xs font-semibold text-body uppercase tracking-wider">
                        {section.label}
                      </h3>
                      <ShieldCheck size={12} className="text-emerald-500" />
                    </div>
                    <ul className="space-y-0.5">
                      {section.data.map((line, i) => (
                        <li key={i} className="text-xs font-mono text-muted">
                          {line}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      <p className="mt-8 text-micro font-mono text-muted text-center">
        H3AD-X / DNSCOPE - Live multi-source domain scan
      </p>
    </div>
  );
}
