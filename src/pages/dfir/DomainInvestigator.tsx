import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Globe } from 'lucide-react';

const Domain = lazy(() => import('./Domain'));
const DomainReputation = lazy(() => import('./DomainReputation'));
const DomainWebcheck = lazy(() => import('./DomainWebcheck'));
const Exposure = lazy(() => import('./Exposure'));
const FullSpectrum = lazy(() => import('./FullSpectrum'));
const Dnscope = lazy(() => import('./Dnscope'));
const WhoisHistory = lazy(() => import('./WhoisHistory'));
const CertSearch = lazy(() => import('./CertSearch'));
const Wayback = lazy(() => import('./Wayback'));
const PassiveDns = lazy(() => import('./PassiveDns'));
const HostGraph = lazy(() => import('./HostGraph'));
const AsnLookup = lazy(() => import('./AsnLookup'));

type TabId =
  | 'dns'
  | 'reputation'
  | 'web'
  | 'surface'
  | 'full'
  | 'infrastructure'
  | 'whois-history'
  | 'certs'
  | 'wayback'
  | 'passive-dns'
  | 'host-graph'
  | 'asn';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  // ── Core assessment ────────────────────────────────────────────
  { id: 'dns', label: 'DNS & WHOIS', desc: 'WHOIS, DNS records, email auth (SPF/DKIM/DMARC), CT logs' },
  { id: 'reputation', label: 'Reputation', desc: 'DNSBL blacklist checks across 11 sources for domain/IP' },
  { id: 'web', label: 'Web & TLS', desc: 'HTTP probe, TLS inspection, security headers, tech fingerprint' },
  { id: 'surface', label: 'Attack Surface', desc: 'Internet-facing assets, exposed hosts, open ports' },
  { id: 'full', label: 'Full Scan', desc: 'Orchestrator: runs all checks in parallel with composite scoring' },

  // ── Infrastructure mapping ─────────────────────────────────────
  {
    id: 'infrastructure',
    label: 'Infrastructure',
    desc: 'Live multi-source domain scan - DNS, RDAP, CT, email auth, TI',
  },
  {
    id: 'host-graph',
    label: 'Host Graph',
    desc: 'IP/ASN/CIDR pivot to announcing prefix, holder, registry, abuse contact',
  },
  { id: 'passive-dns', label: 'Passive DNS', desc: 'Historical DNS resolutions and infrastructure relationships' },
  { id: 'asn', label: 'ASN', desc: 'Autonomous system ownership, announced prefixes, abuse contacts' },

  // ── History & certificates ─────────────────────────────────────
  {
    id: 'whois-history',
    label: 'WHOIS History',
    desc: 'Historic WHOIS records - registrant, nameserver, and ownership changes',
  },
  { id: 'certs', label: 'Certificates', desc: 'Search issued certificates by domain, org, or serial' },
  { id: 'wayback', label: 'Wayback', desc: 'Historic snapshots of the site and its URLs' },
];

export default function DomainInvestigator(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'dns');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Globe size={28} />}
      title="Domain Security Investigator"
      description="Domain and network intelligence in one place - DNS/WHOIS, reputation, web and TLS, attack surface, infrastructure mapping, passive DNS, ASN ownership, certificate search, and archive history. Pick the depth you need."
    >
      <Tabs
        tabs={TABS.map((t) => ({ id: t.id, label: t.label }))}
        active={activeTab}
        onChange={(id) => setActiveTab(id as TabId)}
        variant="underline"
        tabListClassName="mb-4"
      >
        {(active) => (
          <>
            <p className="text-xs font-mono text-muted mb-4">{TABS.find((t) => t.id === active)?.desc}</p>
            <Suspense fallback={<TabLoader />}>
              {active === 'dns' && <Domain />}
              {active === 'reputation' && <DomainReputation />}
              {active === 'web' && <DomainWebcheck />}
              {active === 'surface' && <Exposure />}
              {active === 'full' && <FullSpectrum />}
              {active === 'infrastructure' && <Dnscope />}
              {active === 'host-graph' && <HostGraph />}
              {active === 'passive-dns' && <PassiveDns />}
              {active === 'asn' && <AsnLookup />}
              {active === 'whois-history' && <WhoisHistory />}
              {active === 'certs' && <CertSearch />}
              {active === 'wayback' && <Wayback />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
