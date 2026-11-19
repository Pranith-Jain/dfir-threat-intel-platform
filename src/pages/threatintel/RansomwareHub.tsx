import { TabLoader } from '../../components/ui/TabLoader';
import { Suspense, lazy } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { ClusterTabs, RANSOMWARE_TABS } from '../../components/threatintel/ClusterTabs';
import { useHubTab } from '../../hooks/useHubTab';
import { ShieldAlert } from 'lucide-react';

const RansomReport = lazy(() => import('./RansomReport'));
const RansomwareActivity = lazy(() => import('./RansomwareActivity'));
const RansomwareMap = lazy(() => import('./RansomwareMap'));
const Ransomwhere = lazy(() => import('./Ransomwhere'));
const RansomwareRecovery = lazy(() => import('./RansomwareRecovery'));

type TabId = 'report' | 'activity' | 'map' | 'ransomwhere' | 'recovery';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'report', label: 'RANSOM REPORT', desc: 'Ransomware group and victim reporting' },
  { id: 'activity', label: 'ACTIVITY', desc: 'Recent ransomware activity and trends' },
  { id: 'map', label: 'MAP', desc: 'Geographic map of ransomware victims' },
  { id: 'ransomwhere', label: 'RANSOMWHERE', desc: 'Ransomware payment tracking via Ransomwhere' },
  { id: 'recovery', label: 'RECOVERY', desc: 'Family identification, free decryptors, and payment legality' },
];

export default function RansomwareHub(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'report');

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<ShieldAlert size={28} />}
      title="Ransomware Hub"
      description="Ransomware intelligence - victim reporting, activity trends, geographic mapping, and payment tracking."
      headerExtra={
        <div className="space-y-4">
          <ClusterTabs tabs={RANSOMWARE_TABS} ariaLabel="Ransomware intel" />
          <nav className="flex flex-wrap gap-1 border-b border-line-1" aria-label="Ransomware hub tools">
            {TABS.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setActiveTab(t.id)}
                className={`border-b-2 px-3 py-2 font-mono text-sm font-semibold transition-colors ${
                  activeTab === t.id
                    ? 'border-brand-600 text-brand-600 dark:border-brand-400 dark:text-brand-400'
                    : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                }`}
                aria-selected={activeTab === t.id}
                role="tab"
              >
                {t.label}
              </button>
            ))}
          </nav>
          <p className="text-xs font-mono text-muted">{TABS.find((t) => t.id === activeTab)?.desc}</p>
        </div>
      }
    >
      <div role="tabpanel">
        <Suspense fallback={<TabLoader />}>
          {activeTab === 'report' && <RansomReport embedded />}
          {activeTab === 'activity' && <RansomwareActivity embedded />}
          {activeTab === 'map' && <RansomwareMap embedded />}
          {activeTab === 'ransomwhere' && <Ransomwhere embedded />}
          {activeTab === 'recovery' && <RansomwareRecovery embedded />}
        </Suspense>
      </div>
    </DataPageLayout>
  );
}
