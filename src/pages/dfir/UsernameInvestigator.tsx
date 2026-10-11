import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Users } from 'lucide-react';

const IdentityLookup = lazy(() => import('./IdentityLookup'));
const UsernamePivot = lazy(() => import('./UsernamePivot'));
const UsernameOsnit = lazy(() => import('./UsernameOsnit'));
const ExploratoresBoard = lazy(() => import('./ExploratoresBoard'));

type TabId = 'profiles' | 'quick' | 'deep' | 'board';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'profiles', label: 'Rich Profiles', desc: 'Live profile data from GitHub/GitLab/Reddit/HN/Bluesky/Dev.to' },
  { id: 'quick', label: 'Quick Pivot', desc: 'Client-side existence check across 50+ services via CORS probes' },
  { id: 'deep', label: 'Deep Scan', desc: 'Server-side HTTP checks across 60+ platforms with 15-min cache' },
  { id: 'board', label: 'Pivot Board', desc: '71 manual OSINT pivots from Exploratores - social, crypto, breach, RU' },
];

export default function UsernameInvestigator(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'profiles');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Users size={28} />}
      title="Username & Identity Investigator"
      description="Unified username investigation - rich profiles, quick existence checks, and deep server-side scans across 60+ platforms. Pick a tab based on the depth you need."
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
              {active === 'profiles' && <IdentityLookup />}
              {active === 'quick' && <UsernamePivot />}
              {active === 'deep' && <UsernameOsnit />}
              {active === 'board' && <ExploratoresBoard />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
