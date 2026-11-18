import { TabLoader } from '../../components/ui/TabLoader';
import { Suspense, lazy, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Users } from 'lucide-react';

const ActorDirectory = lazy(() => import('./ActorDirectory'));
const ActorTimeline = lazy(() => import('./ActorTimeline'));
const ActorDNA = lazy(() => import('./ActorDNA'));
const ActorUsernameSearch = lazy(() => import('./ActorUsernameSearch'));
const ActorProfiles = lazy(() => import('./ActorProfiles'));
const ThreatActorCatalog = lazy(() => import('./ThreatActorCatalog'));
const RelationshipGraph = lazy(() => import('./RelationshipGraph'));
const RdintelActors = lazy(() => import('./RdintelActors'));

type TabId = 'rdintel' | 'directory' | 'timeline' | 'dna' | 'usernames' | 'profiles' | 'catalog' | 'graph';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  {
    id: 'rdintel',
    label: 'RDIntel Actors',
    desc: 'Mirror of rdintel.com/cve/actors - tracked APT groups and cybercriminal organizations with country attribution and aliases',
  },
  { id: 'directory', label: 'Directory', desc: 'Unified actor browser - MITRE ATT&CK, MISP Galaxy, and platform DB' },
  { id: 'timeline', label: 'Timeline', desc: 'Posting activity and operational tempo per actor' },
  { id: 'dna', label: 'DNA', desc: 'TTP signatures and infrastructure fingerprints' },
  { id: 'usernames', label: 'Usernames', desc: 'Search forum handles across 2M+ records' },
  { id: 'profiles', label: 'Profiles', desc: 'Expandable actor cards - aliases, malware, targeted sectors, campaigns' },
  { id: 'catalog', label: 'Catalog', desc: 'Curated profiles of 15 major groups - APTs, cybercrime, and ransomware' },
  { id: 'graph', label: 'Graph', desc: 'Visualize actor to actor to IOC connections' },
];

export default function ActorHub(): JSX.Element {
  const [params] = useSearchParams();
  const [activeTab, setActiveTab] = useState<TabId>(() => {
    const tab = params.get('tab');
    if (tab && TABS.some((t) => t.id === tab)) return tab as TabId;
    return 'rdintel';
  });

  useEffect(() => {
    const tab = params.get('tab');
    if (tab && TABS.some((t) => t.id === tab)) setActiveTab(tab as TabId);
  }, [params]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Users size={28} />}
      title="Actor Hub"
      description="Threat actor intelligence - RDIntel actor roster, directory, timelines, DNA, usernames, profiles, and relationship graphs."
    >
      <nav className="flex flex-wrap gap-1 border-b border-line-1 mb-6" aria-label="Actor Hub">
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

      <p className="text-xs font-mono text-muted mb-4">{TABS.find((t) => t.id === activeTab)?.desc}</p>

      <div role="tabpanel">
        <Suspense fallback={<TabLoader />}>
          {activeTab === 'rdintel' && <RdintelActors bare />}
          {activeTab === 'directory' && <ActorDirectory />}
          {activeTab === 'timeline' && <ActorTimeline />}
          {activeTab === 'dna' && <ActorDNA />}
          {activeTab === 'usernames' && <ActorUsernameSearch />}
          {activeTab === 'profiles' && <ActorProfiles />}
          {activeTab === 'catalog' && <ThreatActorCatalog />}
          {activeTab === 'graph' && <RelationshipGraph />}
        </Suspense>
      </div>
    </DataPageLayout>
  );
}
