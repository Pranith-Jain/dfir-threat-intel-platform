import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Crosshair } from 'lucide-react';

const IocCheck = lazy(() => import('./IocCheck'));
const IocPivot = lazy(() => import('./IocPivot'));
const ThreatHunt = lazy(() => import('./ThreatHunt'));

type TabId = 'table' | 'graph' | 'hunt';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'table', label: 'Table View', desc: 'Stream IOC results from 60+ providers in table format' },
  {
    id: 'graph',
    label: 'Pivot Graph',
    desc: 'Same 60+ source checker rendered as radial graph with clickable pivot nodes',
  },
  { id: 'hunt', label: 'Threat Hunt', desc: 'Extended with Telegram leak cross-ref + breach DB links' },
];

export default function IocInvestigate(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'table');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Crosshair size={28} />}
      title="IOC Investigator"
      description="Unified IOC investigation - table view, pivot graph, and extended threat hunt. Paste an IP, domain, URL, or hash to start."
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
              {active === 'table' && <IocCheck />}
              {active === 'graph' && <IocPivot />}
              {active === 'hunt' && <ThreatHunt />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
