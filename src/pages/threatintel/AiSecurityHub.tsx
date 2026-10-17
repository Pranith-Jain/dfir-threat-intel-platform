import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Bot, Newspaper, Wrench, ScanLine, Bug, AlertTriangle, Rss } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';

interface HubIndex {
  hub: string;
  builtAt: string;
  counts: {
    matrixTools: number;
    matrixCategories: number;
    incidentReports: number;
    escapeDrift: boolean | null;
    vulns?: number;
    vulnKev?: number;
    advisories?: number;
    research?: number;
  };
  matrixByCategory: Record<string, number>;
  latestIncidentAt: string | null;
  latestMatrixCheck: string | null;
  latestAdvisoryAt?: string | null;
  latestResearchAt?: string | null;
}

interface Parity {
  drift: boolean;
  onlyUpstream: string[];
  onlyLocal: string[];
  local: { entries: number };
  upstream: { embeddedIds: number };
}

const CARDS = [
  {
    to: '/threatintel/ai-escape',
    icon: Bot,
    title: 'AI Escape / Rogue Agents',
    desc: 'Containment-failure registry — indexed by the failed control, with CBS scores and guardrail analysis.',
    key: 'escape',
  },
  {
    to: '/threatintel/ai-incidents',
    icon: Newspaper,
    title: 'AI Incidents',
    desc: 'Daily mirror of incidentdatabase.ai reports — harms in the wild, linked back to the cite.',
    key: 'incidents',
  },
  {
    to: '/threatintel/ai-security-matrix',
    icon: Wrench,
    title: 'AI Security Matrix Tools',
    desc: 'Daily mirror of aisecuritymatrix.com — AI-enabled pentest / scanner / MCP / skill tooling.',
    key: 'matrix',
  },
  {
    to: '/dfir/nhi-scan',
    icon: ScanLine,
    title: 'NHI Scanner',
    desc: 'Non-human & agent identity risk — deterministic Tier 1–4 vs OWASP NHI Top 10, fully local.',
    key: 'nhi',
  },
  {
    to: '/threatintel/wiki/llm',
    icon: Bug,
    title: 'AI Vulns — LLM Threat Atlas',
    desc: '480 curated LLM/agentic attack vectors with OWASP + MITRE ATLAS crosswalk.',
    key: 'atlas',
  },
  {
    to: '/threatintel/ai-vulns',
    icon: Bug,
    title: 'AI Vulns — Live Tracking',
    desc: 'Realtime CVE tracking — EUVD + NVD + OSV watchlist, KEV overlap, EPSS exploit-probability.',
    key: 'vulns',
  },
  {
    to: '/threatintel/ai-advisories',
    icon: Rss,
    title: 'Advisories & Research',
    desc: 'CVE firehose, tool release trains, ExploitDB PoCs, plus Hacktron/Unit42/CSA research.',
    key: 'advisories',
  },
  {
    to: '/threatintel/glasswing',
    icon: Bot,
    title: 'Project Glasswing Ledger',
    desc: "CVEs Anthropic's AI programme disclosed, with the project and weakness class the CVE record drops.",
    key: 'glasswing',
  },
];

export default function AiSecurityHub(): JSX.Element {
  const [hub, setHub] = useState<HubIndex | null>(null);
  const [parity, setParity] = useState<Parity | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [hRes, pRes] = await Promise.all([
        fetch('/api/v1/ai-security/'),
        fetch('/api/v1/ai-security/escape-parity'),
      ]);
      if (!hRes.ok) throw new Error(`hub HTTP ${hRes.status}`);
      setHub((await hRes.json()) as HubIndex);
      if (pRes.ok) setParity((await pRes.json()) as Parity);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const countFor = (key: string): string => {
    if (!hub) return '—';
    if (key === 'matrix') return String(hub.counts.matrixTools);
    if (key === 'incidents') return String(hub.counts.incidentReports);
    if (key === 'escape') return String(parity?.local.entries ?? '—');
    if (key === 'vulns') return String(hub.counts.vulns ?? '—');
    if (key === 'advisories') return String((hub.counts.advisories ?? 0) + (hub.counts.research ?? 0));
    return '';
  };

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="Threat Intel"
      icon={<Shield size={28} />}
      title="AI Security Hub"
      description="One tracking surface for AI risk: rogue-agent containment failures, real-world AI incidents, offensive tooling, non-human identities, live vuln tracking, and advisories. Matrix + incidents + vulns sync daily; Escape Watch stays curatorial with a two-way parity check against ai-escape.watch."
      loading={loading && !hub}
      error={error}
      onRetry={load}
    >
      {hub?.counts.escapeDrift && parity && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 mb-4 flex gap-3">
          <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs leading-relaxed text-body">
            <span className="font-bold">Escape Watch drift:</span> ai-escape.watch lists {parity.upstream.embeddedIds}{' '}
            embedded IDs vs local {parity.local.entries}. Only upstream:{' '}
            <span className="font-mono">{parity.onlyUpstream.join(', ') || '—'}</span>
            {parity.onlyLocal.length > 0 && (
              <>
                {' '}
                · only local: <span className="font-mono">{parity.onlyLocal.join(', ')}</span>
              </>
            )}
            . Port via reviewed PR — the seed never auto-overwrites.
          </div>
        </div>
      )}
      {(hub || !loading) && (
        <>
          <div className="surface-card p-4 mb-4 flex flex-wrap gap-x-8 gap-y-3">
            {[
              { label: 'Matrix tools', value: hub?.counts.matrixTools ?? '—' },
              { label: 'Incident reports', value: hub?.counts.incidentReports ?? '—' },
              { label: 'AI vulns', value: hub?.counts.vulns ?? '—' },
              { label: 'KEV-listed', value: hub?.counts.vulnKev ?? '—' },
              { label: 'Advisories', value: hub?.counts.advisories ?? '—' },
              { label: 'Research', value: hub?.counts.research ?? '—' },
              {
                label: 'Latest incident',
                value: hub?.latestIncidentAt ? new Date(hub.latestIncidentAt).toLocaleDateString() : '—',
              },
              {
                label: 'Matrix checked',
                value: hub?.latestMatrixCheck ? new Date(hub.latestMatrixCheck).toLocaleDateString() : '—',
              },
            ].map(({ label, value }) => (
              <div key={label}>
                <div className="text-micro font-mono uppercase tracking-wider text-muted">{label}</div>
                <div className="text-xl font-bold text-heading">{value}</div>
              </div>
            ))}
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {CARDS.map(({ to, icon: Icon, title, desc, key }) => (
              <Link
                key={key}
                to={to}
                className="rounded-xl border border-line-1 bg-surface-100/50 p-4 hover:border-rose-500/50 transition-colors group"
              >
                <div className="flex items-center justify-between gap-2">
                  <h3 className="flex items-center gap-2 text-sm font-bold text-heading group-hover:text-rose-600 dark:group-hover:text-rose-400">
                    <Icon className="w-4 h-4 text-muted" /> {title}
                  </h3>
                  {countFor(key) && <span className="text-sm font-mono font-bold text-heading">{countFor(key)}</span>}
                </div>
                <p className="text-xs text-muted mt-1 leading-relaxed">{desc}</p>
              </Link>
            ))}
          </div>
          <p className="mt-4 text-micro font-mono text-muted text-center">
            matrix: aisecuritymatrix.com/data.json · incidents: incidentdatabase.ai/rss.xml · vulns: EUVD+NVD+OSV+EPSS ·
            advisories: cvelistV5+atoms+exploitdb · research: hacktron/unit42/csa/bleeping · escape: ai-escape.watch
            parity-only · built {hub?.builtAt ? new Date(hub.builtAt).toLocaleString() : '—'}
          </p>
        </>
      )}
    </DataPageLayout>
  );
}
