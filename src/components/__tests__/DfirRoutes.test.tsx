import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect } from 'vitest';
import { AppContent } from '../../App';

// jsdom doesn't have EventSource; stub it for tests that don't exercise streaming
if (typeof EventSource === 'undefined') {
  (globalThis as unknown as { EventSource: unknown }).EventSource = class {
    addEventListener() {}
    close() {}
    onerror: (() => void) | null = null;
  };
}

const subRoutes: Array<{ path: string; heading: string; skipComingSoon?: boolean }> = [
  { path: '/dfir/ioc-check', heading: 'IOC Checker', skipComingSoon: true },
  { path: '/dfir/phishing', heading: 'Phishing Email Analyzer', skipComingSoon: true },
  { path: '/dfir/domain', heading: 'Domain Lookup', skipComingSoon: true },
  { path: '/dfir/exposure', heading: 'Exposure Scanner', skipComingSoon: true },
  { path: '/threatintel/wiki/wiki', heading: 'Knowledge Base', skipComingSoon: true },

  { path: '/threatintel/briefings', heading: 'Threat Intel Briefings', skipComingSoon: true },
  { path: '/dfir/cve', heading: 'CVE Lookup', skipComingSoon: true },
  { path: '/dfir/decode', heading: 'Decoder', skipComingSoon: true },
  // /dfir/asn and /dfir/host-graph are tabs of /dfir/domain-investigator now.
  { path: '/dfir/domain-investigator', heading: 'Domain Security Investigator', skipComingSoon: true },
  { path: '/dfir/breach', heading: 'Breach Checker', skipComingSoon: true },
  { path: '/dfir/exif', heading: 'EXIF Parser', skipComingSoon: true },
  { path: '/threatintel/mitre', heading: 'MITRE ATT&CK', skipComingSoon: true },
  { path: '/dfir/url-preview', heading: 'URL Preview', skipComingSoon: true },
  { path: '/threatintel/external-resources', heading: 'External Resources', skipComingSoon: true },
];

describe('DFIR sub-routes', () => {
  it.each(subRoutes)('renders for $path', async ({ path, heading, skipComingSoon }) => {
    render(
      <MemoryRouter initialEntries={[path]}>
        <AppContent />
      </MemoryRouter>
    );

    // Use a regex match so headings that decorate the title with a status
    // pill (e.g. <h1>Threat Intel Briefings<LiveFreshnessPill/></h1>) still
    // match - the accessible name is the concatenation of all the text
    // nodes, and exact string match would break for any future decoration.
    expect(
      await screen.findByRole('heading', { level: 1, name: new RegExp(heading) }, { timeout: 5000 })
    ).toBeInTheDocument();
    if (!skipComingSoon) {
      expect(screen.getByText(/coming soon/i)).toBeInTheDocument();
    }
  });
});
