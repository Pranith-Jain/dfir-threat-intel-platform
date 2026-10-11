import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Phone } from 'lucide-react';

const PhoneOsint = lazy(() => import('./PhoneOsint'));
const PhoneOsintNew = lazy(() => import('./PhoneOsintNew'));

type TabId = 'osint' | 'ai';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'osint', label: 'PHONE OSINT', desc: 'Phone number OSINT lookup across public sources' },
  { id: 'ai', label: 'AI PHONE INTEL', desc: 'AI-assisted phone number intelligence and analysis' },
];

export default function PhoneHub(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'osint');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Phone size={28} />}
      title="Phone Intelligence"
      description="Phone number OSINT and AI-assisted intelligence gathering."
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
              {active === 'osint' && <PhoneOsint />}
              {active === 'ai' && <PhoneOsintNew />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
