import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { FileText } from 'lucide-react';

const StixBuilder = lazy(() => import('./StixBuilder'));
const StixViewer = lazy(() => import('./StixViewer'));
const TaxiiServer = lazy(() => import('./TaxiiServer'));

type TabId = 'build' | 'view' | 'taxii';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'build', label: 'Build', desc: 'Build STIX bundle from text/IOCs/URL/file upload' },
  { id: 'view', label: 'View & Graph', desc: 'Paste/view STIX 2.1 bundle with interactive graph' },
  { id: 'taxii', label: 'TAXII Server', desc: 'In-browser TAXII 2.1 server for STIX sharing' },
];

export default function StixWorkbench(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'build');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<FileText size={28} />}
      title="STIX/TAXII Workbench"
      description="Unified STIX/TAXII workflow - build bundles, visualize with interactive graphs, and share via TAXII server."
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
              {active === 'build' && <StixBuilder />}
              {active === 'view' && <StixViewer />}
              {active === 'taxii' && <TaxiiServer />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
