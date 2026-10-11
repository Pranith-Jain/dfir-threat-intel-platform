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

type TabId = 'dns' | 'reputation' | 'web' | 'surface' | 'full';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'dns', label: 'DNS & WHOIS', desc: 'WHOIS, DNS records, email auth (SPF/DKIM/DMARC), CT logs' },
  { id: 'reputation', label: 'Reputation', desc: 'DNSBL blacklist checks across 11 sources for domain/IP' },
  { id: 'web', label: 'Web & TLS', desc: 'HTTP probe, TLS inspection, security headers, tech fingerprint' },
  { id: 'surface', label: 'Attack Surface', desc: 'Internet-facing assets, exposed hosts, open ports' },
  { id: 'full', label: 'Full Scan', desc: 'Orchestrator: runs all checks in parallel with composite scoring' },
];

export default function DomainInvestigator(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'dns');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Globe size={28} />}
      title="Domain Security Investigator"
      description="Domain security analysis - DNS, reputation, web security, attack surface, and full automated scans. Pick the depth you need."
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
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
