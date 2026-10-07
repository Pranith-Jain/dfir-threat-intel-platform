import { Suspense, lazy } from 'react';
import { useSearchParams } from 'react-router-dom';
import { TabLoader } from '../../components/ui/TabLoader';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Bug } from 'lucide-react';

const CveList = lazy(() => import('./CveList'));
const CveTrends = lazy(() => import('./CveTrends'));
const CveDigest = lazy(() => import('./CveDigest'));
const ExploitableCves = lazy(() => import('./ExploitableCves'));
const CisaKevCatalog = lazy(() => import('./CisaKevCatalog'));
const K8sCve = lazy(() => import('./K8sCve'));
const CertInAdvisories = lazy(() => import('./CertInAdvisories'));
const PocScanner = lazy(() => import('./PocScanner'));
const CyberNewsFeed = lazy(() => import('./CyberNewsFeed'));
const CveHealthCheck = lazy(() => import('./CveHealthCheck'));

type TabId = 'all' | 'trending' | 'digest' | 'exploitable' | 'kev' | 'k8s' | 'cert-in' | 'poc' | 'news' | 'health';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'all', label: 'All Recent', desc: 'NVD + KEV + MyThreatIntel + cvefeed.io + CVE Telegram channels + EPSS' },
  {
    id: 'trending',
    label: 'Trending',
    desc: 'CVEs trending on social media (cvemon) with CVSS, KEV, EPSS and exploit status — discussion ahead of confirmation',
  },
  {
    id: 'digest',
    label: '24h Digest',
    desc: 'Every CVE published in the last 24 hours, anchored on ctiwatch — the complete window, not a sample',
  },
  {
    id: 'exploitable',
    label: 'Exploitable',
    desc: 'CVEs with known exploits from vendor labs, security research, and KEV',
  },
  { id: 'kev', label: 'CISA KEV', desc: 'CISA Known Exploited Vulnerabilities catalog with filtering and CSV export' },
  {
    id: 'poc',
    label: 'PoC Scanner',
    desc: 'Search GitHub for public exploit/PoC repositories - stars, code, and metadata',
  },
  { id: 'news', label: 'Cyber News', desc: '11-source security news feed across 5 tiers - advisories to community' },
  { id: 'k8s', label: 'Kubernetes', desc: 'Kubernetes-specific CVE feed from official security advisories' },
  {
    id: 'cert-in',
    label: 'CERT-In',
    desc: 'Indian CERT advisories (CIAD-YYYY-NNNN) with severity, products, and CVE mapping',
  },
  { id: 'health', label: 'Health', desc: 'Data pipeline health - NVD, EPSS, KEV, GitHub, and Exploit-DB status' },
];

export default function CveIntel(): JSX.Element {
  const [params, setParams] = useSearchParams();
  // Derive the tab from the URL on every render (not just mount state init)
  // so back/forward, redirects that append ?tab=, and manual URL edits all
  // land on the right tab; clicks write ?tab= back so refresh/share keep it.
  const urlTab = params.get('tab');
  const activeTab: TabId = urlTab && TABS.some((t) => t.id === urlTab) ? (urlTab as TabId) : 'all';

  const selectTab = (id: TabId) => {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set('tab', id);
        return next;
      },
      { replace: true }
    );
  };

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Bug size={28} />}
      title="CVE Intelligence"
      description="Unified CVE intelligence - recent vulnerabilities, exploitable CVEs, CISA KEV catalog, and Kubernetes-specific advisories. All feeds updated regularly."
    >
      <nav className="flex flex-wrap gap-1 border-b border-line-1 mb-6" aria-label="CVE intelligence" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => selectTab(t.id)}
            className={`border-b-2 px-3 py-2 font-mono text-sm font-semibold transition-colors ${
              activeTab === t.id
                ? 'border-rose-600 text-rose-600 dark:border-rose-400 dark:text-rose-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
            }`}
            aria-selected={activeTab === t.id}
            aria-controls={`tabpanel-${t.id}`}
            id={`tab-${t.id}`}
            role="tab"
          >
            {t.label}
          </button>
        ))}
      </nav>

      <p className="text-xs font-mono text-muted mb-4">{TABS.find((t) => t.id === activeTab)?.desc}</p>

      <div role="tabpanel" id={`tabpanel-${activeTab}`} aria-labelledby={`tab-${activeTab}`}>
        <Suspense fallback={<TabLoader />}>
          {activeTab === 'all' && <CveList bare />}
          {activeTab === 'trending' && <CveTrends />}
          {activeTab === 'digest' && <CveDigest bare />}
          {activeTab === 'exploitable' && <ExploitableCves bare />}
          {activeTab === 'kev' && <CisaKevCatalog bare />}
          {activeTab === 'poc' && <PocScanner bare />}
          {activeTab === 'news' && <CyberNewsFeed />}
          {activeTab === 'k8s' && <K8sCve bare />}
          {activeTab === 'cert-in' && <CertInAdvisories bare />}
          {activeTab === 'health' && <CveHealthCheck bare />}
        </Suspense>
      </div>
    </DataPageLayout>
  );
}
