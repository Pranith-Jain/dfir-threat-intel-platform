import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Lock } from 'lucide-react';

const IamPolicyAnalyzer = lazy(() => import('./IamPolicyAnalyzer'));
const GcpIamAnalyzer = lazy(() => import('./GcpIamAnalyzer'));
const AzureRbacAnalyzer = lazy(() => import('./AzureRbacAnalyzer'));
const K8sRbacAnalyzer = lazy(() => import('./K8sRbacAnalyzer'));

type TabId = 'aws' | 'gcp' | 'azure' | 'k8s';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'aws', label: 'AWS IAM', desc: 'Analyze AWS IAM policies for over-permission and risk' },
  { id: 'gcp', label: 'GCP IAM', desc: 'Analyze GCP IAM bindings and service account privileges' },
  { id: 'azure', label: 'AZURE RBAC', desc: 'Analyze Azure RBAC role assignments and scope' },
  { id: 'k8s', label: 'K8S RBAC', desc: 'Analyze Kubernetes RBAC roles and bindings' },
];

export default function IamHub(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'aws');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Lock size={28} />}
      title="IAM & RBAC Hub"
      description="Identity and access management analysis across AWS, GCP, Azure, and Kubernetes."
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
              {active === 'aws' && <IamPolicyAnalyzer />}
              {active === 'gcp' && <GcpIamAnalyzer />}
              {active === 'azure' && <AzureRbacAnalyzer />}
              {active === 'k8s' && <K8sRbacAnalyzer />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
