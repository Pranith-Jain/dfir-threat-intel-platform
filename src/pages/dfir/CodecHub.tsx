import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Code2 } from 'lucide-react';

const Decode = lazy(() => import('./Decode'));
const Encoder = lazy(() => import('./Encoder'));

type TabId = 'decode' | 'encode';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'decode', label: 'DECODE', desc: 'Decode encoded strings and payloads' },
  { id: 'encode', label: 'ENCODE', desc: 'Encode strings into various formats' },
];

export default function CodecHub(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'decode');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Code2 size={28} />}
      title="Codec Hub"
      description="Encode and decode strings across common formats used in security analysis."
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
              {active === 'decode' && <Decode />}
              {active === 'encode' && <Encoder />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
