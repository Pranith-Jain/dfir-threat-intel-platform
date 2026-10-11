import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { ScrollText } from 'lucide-react';

const ReportAnalyzer = lazy(() => import('./ReportAnalyzer'));
const ReportComposer = lazy(() => import('./ReportComposer'));

type TabId = 'analyzer' | 'composer';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'analyzer', label: 'Report Analyzer', desc: 'AI summary - IOC extraction - MITRE TTP mapping - STIX bundle' },
  {
    id: 'composer',
    label: 'Report Composer',
    desc: 'Cover - summary - findings - IOCs - sources - TLP - export to PDF/DOCX',
  },
];

export default function ReportHub(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'analyzer');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<ScrollText size={28} />}
      title="Report Hub"
      description="Analyze external reports and compose investigation reports - AI summarisation, IOC extraction, MITRE mapping, and PDF/DOCX export."
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
              {active === 'analyzer' && <ReportAnalyzer />}
              {active === 'composer' && <ReportComposer />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
