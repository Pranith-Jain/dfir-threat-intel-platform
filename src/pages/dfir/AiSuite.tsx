import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Sparkles } from 'lucide-react';

const InsightAi = lazy(() => import('./InsightAi'));
const QuerycraftAi = lazy(() => import('./QuerycraftAi'));
const ChronoAi = lazy(() => import('./ChronoAi'));
const MalbriefAi = lazy(() => import('./MalbriefAi'));
const VerdiktAi = lazy(() => import('./VerdiktAi'));

type TabId = 'insight' | 'querycraft' | 'chrono' | 'malbrief' | 'verdikt';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'insight', label: 'INSIGHT-AI', desc: 'AI-assisted incident summarisation and pattern detection' },
  { id: 'querycraft', label: 'QUERYCRAFT-AI', desc: 'AI-assisted KQL / SPL / Lucene generation' },
  { id: 'chrono', label: 'CHRONO-AI', desc: 'AI-assisted timeline reconstruction from logs + reports' },
  { id: 'malbrief', label: 'MALBRIEF-AI', desc: 'AI-assisted malware family briefing from sample + sandbox output' },
  { id: 'verdikt', label: 'VERDIKT-AI', desc: 'AI-assisted IOC verdict - explain cross-source disagreement' },
];

export default function AiSuite(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'insight');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Sparkles size={28} />}
      title="AI Suite"
      description="AI-assisted investigation tools - incident summarisation, query generation, timeline reconstruction, malware briefing, and IOC verdicts."
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
              {active === 'insight' && <InsightAi />}
              {active === 'querycraft' && <QuerycraftAi />}
              {active === 'chrono' && <ChronoAi />}
              {active === 'malbrief' && <MalbriefAi />}
              {active === 'verdikt' && <VerdiktAi />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
