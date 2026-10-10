import { describe, it, expect } from 'vitest';
import { recentWarmJob, type FeedQueueMessage } from '../../src/lib/live-iocs-slices';

/**
 * The hourly alarm used to run `warmCveRecentCache` and
 * `warmRansomwareRecentCache` inline. Each is an unconditional ~25-subrequest
 * fan-out with no cache short-circuit, so the pair spent the entire free-plan
 * 50-subrequest budget before the branch reached anything else.
 *
 * Measured on the 2026-10-10T06:00 tick the consequences were concrete:
 *   - `telegram-watched-scrape`: channels_unreachable 22 of 25
 *   - `x-health-diagnostic`: the probe itself threw "Too many subrequests"
 *
 * Both now run as queue messages → their own consumer invocation → their own
 * budget. `recentWarmJob` is the dispatch rule that makes that work, and it
 * lives here (rather than inline in the consumer) precisely because the failure
 * mode is silent: a mismatched field name means the warm never runs, the slice
 * goes stale, and nothing is logged anywhere.
 */
describe('recentWarmJob — queue dispatch for the recent-slice warms', () => {
  it('maps the cve-recent flag to its job', () => {
    expect(recentWarmJob({ cveRecentWarm: true })).toBe('cve-recent-warm');
  });

  it('maps the ransomware-recent flag to its job', () => {
    expect(recentWarmJob({ ransomwareRecentWarm: true })).toBe('ransomware-recent-warm');
  });

  it('returns null for messages that are not a recent-slice warm', () => {
    // A consumer branch that matched too broadly would hijack the live-iocs
    // batches, so every other message shape must fall through untouched.
    expect(recentWarmJob(undefined)).toBeNull();
    expect(recentWarmJob({})).toBeNull();
    expect(recentWarmJob({ digestWarm: true })).toBeNull();
    expect(recentWarmJob({ aiLlmWarm: true })).toBeNull();
    expect(recentWarmJob({ sourceId: 'shodan' })).toBeNull();
    expect(recentWarmJob({ sourceIds: ['shodan', 'vt'] })).toBeNull();
    expect(recentWarmJob({ gp: { key: 'telegram', path: '/api/v1/telegram-feed' } })).toBeNull();
  });

  it('requires the literal `true`, not a truthy value', () => {
    // A message that sets the key to something else is a malformed producer
    // bug; treating it as "run the warm" would burn a budget on a typo, and
    // treating it as a warm when it is false would skip a real refresh.
    const msg = { cveRecentWarm: 1 } as unknown as FeedQueueMessage;
    expect(recentWarmJob(msg)).toBeNull();
  });

  it('never returns both jobs for one message', () => {
    // One job per invocation is the entire point: the return type cannot
    // express "both", so the ~50-subrequest pairing cannot come back.
    const both: FeedQueueMessage = { cveRecentWarm: true, ransomwareRecentWarm: true };
    const job = recentWarmJob(both);
    expect(job === 'cve-recent-warm' || job === 'ransomware-recent-warm').toBe(true);
    expect(job).not.toBe('both');
  });

  it('prefers cve-recent when both flags are set (deterministic, first match wins)', () => {
    // Pins the ordering so a future refactor cannot make this ambiguous.
    expect(recentWarmJob({ cveRecentWarm: true, ransomwareRecentWarm: true })).toBe('cve-recent-warm');
  });
});
