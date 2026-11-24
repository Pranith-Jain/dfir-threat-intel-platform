import { describe, it, expect } from 'vitest';
import {
  discoverThreatClusters,
  discoverLivingThreatIncidents,
  discoverIncidentDesk,
} from '../../../src/case-study/discovery/threat-intel';
import type { DedupRecord } from '../../../src/case-study/types';

/**
 * Field-shape regression tests for the threat-intel corpus runners.
 *
 * These fixtures are literal copies of the payloads the routes in
 * `api/src/routes/threat-intel-edge-tools.ts` return (which in turn match the
 * types in `worker/lib/threat-intel-manifest.ts`). The runners must read
 * those exact names: a drift here silently removes a source from the daily
 * mix with no error, which is the failure mode that left discovery CVE-only.
 */

const NOW = new Date('2026-11-20T12:00:00Z');
const noDedup = async (): Promise<DedupRecord | null> => null;

describe('discoverThreatClusters', () => {
  function deps(payload: unknown) {
    return { apiFetch: async () => payload, now: NOW, getDedup: noDedup };
  }

  it('surfaces fresh cyber-relevant clusters and drops kinetic/geopolitical noise', async () => {
    const out = await discoverThreatClusters(
      deps({
        total: 50,
        returned: 3,
        clusters: [
          {
            slug: 'storm-3358-targets-financial-sector-with-artex-framework-e18e80b2',
            title: 'Storm-3358 Targets Financial Sector with ARTEX Framework',
            pubDate: '2026-11-19T12:32:58.000Z',
            sourceCount: 2,
            sizeBytes: 131,
          },
          {
            slug: 'russian-drone-attacks-in-kherson-target-civilians-40c3d4be',
            title: 'Russian Drone Attacks in Kherson Target Civilians',
            pubDate: '2026-11-19T13:02:10.000Z',
            sourceCount: 1,
            sizeBytes: 134,
          },
          {
            slug: 'old-cyber-story',
            title: 'Old Ransomware Campaign Hits Manufacturers',
            pubDate: '2026-10-01T00:00:00.000Z',
            sourceCount: 3,
            sizeBytes: 120,
          },
        ],
      })
    );

    expect(out).toHaveLength(1);
    expect(out[0]?.type).toBe('intel');
    expect(out[0]?.key).toContain('tc-cluster');
    expect(out[0]?.title).toContain('Storm-3358');
    expect(out[0]?.evidence).toMatchObject({
      sourceCount: 2,
      clusterSlug: 'storm-3358-targets-financial-sector-with-artex-framework-e18e80b2',
    });
    expect(String(out[0]?.evidence.url)).toBe(
      'https://threatcluster.io/cluster/storm-3358-targets-financial-sector-with-artex-framework-e18e80b2'
    );
    expect(Number.isFinite(out[0]?.score)).toBe(true);
  });

  it('throws on a missing clusters array or an apiFetch failure so runnerStats can report it', async () => {
    await expect(discoverThreatClusters(deps({ total: 0 }))).rejects.toThrow('no clusters array');
    const broken = {
      apiFetch: async () => {
        throw new Error('SELF down');
      },
      now: NOW,
      getDedup: noDedup,
    };
    await expect(discoverThreatClusters(broken)).rejects.toThrow('SELF down');
  });
});

describe('discoverLivingThreatIncidents', () => {
  function deps(payload: unknown) {
    return { apiFetch: async () => payload, now: NOW, getDedup: noDedup };
  }

  it('surfaces high-priority recent incidents with ATT&CK context', async () => {
    const out = await discoverLivingThreatIncidents(
      deps({
        total: 5000,
        returned: 2,
        incidents: [
          {
            slug: 'PHP2Shell_Exploitation_of_PAN-OS_Management_Interfaces-022887',
            shard: 0,
            sequence: 22887,
            id: '79fb717d814dd0bdd4caec5bbd300e556a6c4146018d987ce4d71178ffbd4c0c',
            title: 'PHP2Shell Exploitation of PAN-OS Management Interfaces',
            timestamp: '2026-11-18T18:30:00Z',
            source: 'https://thehackernews.com/2026/11/everything-is-web-application-including.html',
            severity: 'Critical',
            priorityScore: 100,
            relevanceScore: 51,
            tactics: ['Reconnaissance', 'Initial Access', 'Impact'],
            techniques: ['T1595', 'T1190', 'T1486'],
            actors: [],
            techniqueCount: 3,
            cves: 3,
            tools: 2,
            sizeBytes: 8831,
          },
          {
            slug: 'low-priority-item',
            title: 'Routine Patch Notes',
            timestamp: '2026-11-18T18:30:00Z',
            source: 'https://example.com/patch-notes',
            severity: 'Low',
            priorityScore: 10,
            tactics: [],
            techniques: [],
            actors: [],
            techniqueCount: 0,
            cves: 0,
            tools: 0,
          },
        ],
      })
    );

    expect(out).toHaveLength(1);
    expect(out[0]?.type).toBe('analysis');
    expect(out[0]?.key).toContain('living-threat');
    expect(out[0]?.evidence).toMatchObject({
      priorityScore: 100,
      severity: 'Critical',
      cveCount: 3,
      source: 'threat-intel/living-threat',
    });
    expect(out[0]?.evidence.techniques).toEqual(['T1595', 'T1190', 'T1486']);
    expect(out[0]?.rationale).toContain('priority 100/100');
  });

  it('skips incidents with no http source URL', async () => {
    const out = await discoverLivingThreatIncidents(
      deps({
        incidents: [
          {
            slug: 'no-source',
            title: 'Critical Incident With No Link',
            timestamp: '2026-11-19T00:00:00Z',
            source: '',
            severity: 'Critical',
            priorityScore: 100,
            tactics: [],
            techniques: [],
            actors: [],
          },
        ],
      })
    );
    expect(out).toEqual([]);
  });
});

describe('discoverIncidentDesk', () => {
  function deps(payload: unknown) {
    return { apiFetch: async () => payload, now: NOW, getDedup: noDedup };
  }

  it('surfaces recent briefs with their canonical article URL', async () => {
    const out = await discoverIncidentDesk(
      deps({
        briefs: [
          {
            title: 'Uber’s 149,000-Record Breach Shows Why Vendor Credentials Are Your Problem Too',
            link: 'https://iamnicholasmartin.co.uk/blog/iam-incident-uber-20261118-67-93',
            guid: 'https://iamnicholasmartin.co.uk/blog/iam-incident-uber-20261118-67-93',
            published: '2026-11-18T11:09:05.000Z',
            publishedRaw: 'Wed, 18 Nov 2026 11:09:05 +0000',
            description:
              'Stolen credentials at AI vendor Fireworks let attackers reach an Uber cloud store of driver records.',
            imageUrl: null,
            slug: 'iam-incident-uber-20261118-67-93',
          },
          {
            title: 'Old Brief',
            link: 'https://example.com/old',
            guid: 'https://example.com/old',
            published: '2026-09-01T00:00:00.000Z',
            description: null,
            slug: 'old-brief',
          },
        ],
      })
    );

    expect(out).toHaveLength(1);
    expect(out[0]?.type).toBe('analysis');
    expect(out[0]?.key).toContain('incident-desk');
    expect(out[0]?.evidence.url).toBe('https://iamnicholasmartin.co.uk/blog/iam-incident-uber-20261118-67-93');
    expect(out[0]?.rationale).toContain('Incident Desk brief');
  });

  it('throws when the response shape is wrong so the pipeline can distinguish drift from a quiet day', async () => {
    await expect(discoverIncidentDesk(deps({ briefs: 'not-an-array' }))).rejects.toThrow('no briefs array');
    await expect(discoverIncidentDesk(deps(null))).rejects.toThrow('no briefs array');
  });
});
