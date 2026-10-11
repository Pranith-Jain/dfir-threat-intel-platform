import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { FileCode } from 'lucide-react';

const YaraManager = lazy(() => import('./YaraManager'));
const RulePlayground = lazy(() => import('./RulePlayground'));

type TabId = 'library' | 'test';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'library', label: 'Rule Library', desc: 'Create, edit, validate, and export YARA rules (localStorage-backed)' },
  { id: 'test', label: 'Test Lab', desc: 'Paste a YARA/Sigma rule + sample, highlight matches' },
];

export default function YaraWorkbench(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'library');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<FileCode size={28} />}
      title="YARA Workbench"
      description="Unified YARA workflow - build rules in the library, then test them against samples in the test lab."
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
              {active === 'library' && <YaraManager />}
              {active === 'test' && <RulePlayground />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
