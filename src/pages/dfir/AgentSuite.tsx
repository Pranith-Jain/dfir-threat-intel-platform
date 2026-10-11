import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Bot } from 'lucide-react';

const AgentInvestigator = lazy(() => import('./AgentInvestigator'));
const TieEnrich = lazy(() => import('./TieEnrich'));
const AgentMap = lazy(() => import('./AgentMap'));
const AgentMetrics = lazy(() => import('./AgentMetrics'));

type TabId = 'investigator' | 'enrich' | 'map' | 'metrics';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'investigator', label: 'INVESTIGATOR', desc: 'Autonomous investigation agent for threat triage' },
  { id: 'enrich', label: 'ENRICH', desc: 'Threat intelligence enrichment agent' },
  { id: 'map', label: 'MAP', desc: 'Visualise investigation relationships and findings' },
  {
    id: 'metrics',
    label: 'METRICS',
    desc: 'Agent observability — quality, per-tool latency/success, feature telemetry',
  },
];

export default function AgentSuite(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'investigator');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Bot size={28} />}
      title="Agent Suite"
      description="Autonomous investigation, enrichment, and mapping agents for threat intelligence workflows."
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
              {active === 'investigator' && <AgentInvestigator />}
              {active === 'enrich' && <TieEnrich />}
              {active === 'map' && <AgentMap />}
              {active === 'metrics' && <AgentMetrics />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
