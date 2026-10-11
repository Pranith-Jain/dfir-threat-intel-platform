import { TabLoader } from '../../components/ui/TabLoader';
import { Tabs } from '../../components/ui/Tabs';
import { Suspense, lazy } from 'react';
import { useHubTab } from '../../hooks/useHubTab';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Image } from 'lucide-react';

const ReverseImage = lazy(() => import('./ReverseImage'));
const ImageFingerprint = lazy(() => import('./ImageFingerprint'));
const ScreenshotIntel = lazy(() => import('./ScreenshotIntel'));

type TabId = 'reverse' | 'fingerprint' | 'ocr';

const TABS: Array<{ id: TabId; label: string; desc: string }> = [
  { id: 'reverse', label: 'REVERSE SEARCH', desc: 'Reverse image search across multiple engines' },
  { id: 'fingerprint', label: 'FINGERPRINT', desc: 'Generate perceptual hashes and fingerprints for images' },
  { id: 'ocr', label: 'SCREENSHOT OCR', desc: 'Extract text from screenshots and images' },
];

export default function ImageIntel(): JSX.Element {
  const [activeTab, setActiveTab] = useHubTab(TABS, 'reverse');

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Image size={28} />}
      title="Image Intelligence"
      description="Reverse search, fingerprint, and OCR tools for image-based intelligence gathering."
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
              {active === 'reverse' && <ReverseImage />}
              {active === 'fingerprint' && <ImageFingerprint />}
              {active === 'ocr' && <ScreenshotIntel />}
            </Suspense>
          </>
        )}
      </Tabs>
    </DataPageLayout>
  );
}
