/** UTC day-of-year (0-based). */
export function dayOfYear(now: Date): number {
  const start = Date.UTC(now.getUTCFullYear(), 0, 0);
  return Math.floor((Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) - start) / 86400000) - 1;
}

/**
 * Which runner names run today: every always-on name, plus the optional
 * runners whose round-robin group matches today. `groups` consecutive days
 * cover all optional runners exactly once → variety + bounded subrequests.
 * Optional runners are taken in their order in `all` for a stable partition.
 *
 * The call site passes `groups=4`: with ~16 optional runners, each optional
 * runner surfaces once every 4 days while the always-on core stays daily.
 */
export function activeRunnerNames(all: string[], alwaysOn: Set<string>, now: Date, groups: number): string[] {
  const optional = all.filter((n) => !alwaysOn.has(n));
  const g = ((dayOfYear(now) % groups) + groups) % groups;
  const todaysOptional = optional.filter((_, i) => i % groups === g);
  return all.filter((n) => alwaysOn.has(n) || todaysOptional.includes(n));
}

/**
 * Get the topic category for a runner name. Used for diversity tracking.
 */
export function runnerTopic(runnerName: string): string {
  const TOPIC_MAP: Record<string, string> = {
    cve: 'vulnerability',
    vulncheck: 'vulnerability',
    euvd: 'vulnerability',
    actor: 'threat-actor',
    malware: 'malware',
    ransom: 'ransomware',
    releak: 'ransomware',
    breach: 'data-breach',
    scam: 'fraud',
    aisec: 'ai-security',
    intel: 'intelligence',
    advisories: 'intelligence',
    platform: 'platform-data',
    trends: 'trending',
    briefing: 'briefing',
  };
  return TOPIC_MAP[runnerName] ?? runnerName;
}
