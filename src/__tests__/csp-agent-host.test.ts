import { describe, it, expect } from 'vitest';
import { cspHeader } from '../../worker/csp';

/**
 * The investigator DO streams live steps over `wss://<current host>`.
 * Tool hosts are separate origins, so the CSP must derive the WS source
 * from the response origin — otherwise the socket is silently blocked.
 */
describe('agent host WebSocket CSP', () => {
  it('allows WSS on the agent tool host as well as the apex', () => {
    const csp = cspHeader(undefined, 'https://agent.pranithjain.qzz.io');
    expect(csp).toContain('wss://agent.pranithjain.qzz.io');
    expect(csp).toContain('wss://pranithjain.qzz.io');
  });

  it('allows WSS on the agent host for HTML responses with a nonce', () => {
    const csp = cspHeader('test-nonce', 'https://agent.pranithjain.qzz.io');
    expect(csp).toContain("script-src https://agent.pranithjain.qzz.io 'nonce-test-nonce'");
    expect(csp).toContain('wss://agent.pranithjain.qzz.io');
  });

  it('keeps the apex as the default WS source', () => {
    const csp = cspHeader();
    expect(csp).toContain('wss://pranithjain.qzz.io');
    expect(csp).not.toContain('wss://undefined');
  });
});
