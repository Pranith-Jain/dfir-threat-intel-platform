import { describe, it, expect } from 'vitest';
import { rootRedirectForHost } from '../../worker/surface';

/**
 * Every tool host's root must open its own app, not the portfolio home.
 * Keep this in sync with vars.TOOLS_HOSTS in wrangler.jsonc.
 */
const TOOLS_HOSTS =
  '/dfir=crucible.pranithjain.qzz.io,/threatintel=panopticon.pranithjain.qzz.io,/radar=scout.pranithjain.qzz.io,/argus=argus.pranithjain.qzz.io,/dfir/agent-suite=agent.pranithjain.qzz.io,/threatintel/tools/copilot=copilot.pranithjain.qzz.io,/daily-briefs=brief.pranithjain.qzz.io';

const EXPECTED: Record<string, string> = {
  'crucible.pranithjain.qzz.io': '/dfir',
  'panopticon.pranithjain.qzz.io': '/threatintel',
  'scout.pranithjain.qzz.io': '/radar',
  'argus.pranithjain.qzz.io': '/argus',
  'agent.pranithjain.qzz.io': '/dfir/agent-suite',
  'copilot.pranithjain.qzz.io': '/threatintel/tools/copilot',
  'brief.pranithjain.qzz.io': '/daily-briefs',
};

describe('tool-host root redirects', () => {
  it('redirects every configured tool host root to its owned prefix', () => {
    for (const [host, prefix] of Object.entries(EXPECTED)) {
      expect(rootRedirectForHost('/', host, 'tools', TOOLS_HOSTS), host).toBe(prefix);
    }
  });

  it('does not redirect the apex portfolio or non-root paths', () => {
    expect(rootRedirectForHost('/', 'pranithjain.qzz.io', 'portfolio', TOOLS_HOSTS)).toBeNull();
    expect(rootRedirectForHost('/dfir', 'crucible.pranithjain.qzz.io', 'tools', TOOLS_HOSTS)).toBeNull();
    expect(rootRedirectForHost('/', 'unknown.example.com', 'portfolio', TOOLS_HOSTS)).toBeNull();
  });
});
