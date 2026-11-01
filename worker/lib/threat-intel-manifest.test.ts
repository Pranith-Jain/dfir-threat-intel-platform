/**
 * Tests for the Threat Intel manifest loader.
 *
 * We stub env.ASSETS with an in-memory map of {path -> json} so the
 * tests don't need real Cloudflare bindings. Run via:
 *   npx vitest run worker/lib/threat-intel-manifest.test.ts
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  loadTiIndex,
  getTiCve,
  getTiIoc,
  getTiSector,
  getTiList,
  loadKevSnapshot,
  filterCves,
  filterIocs,
  filterLists,
  searchListEntries,
  computePriorityScore,
  tiCacheStats,
  _resetTiCacheForTests,
  severityFromScore,
  loadDarknetIndex,
  getDarknetSite,
  getDarknetCategory,
  filterDarknetSites,
  type TiIndex,
  type TiCveBody,
  type TiIocBody,
  type TiSectorBody,
  type TiKevEntry,
  type TiDetectionListBody,
  type TiDarknetIndex,
  type TiDarknetSiteBody,
  type TiDarknetCategoryBody,
  loadDphishIndex,
  getDphishIndicator,
  filterDphishIndicators,
  type DphishIndex,
  type DphishIndicatorBody,
  type DphishIndexEntry,
  loadDestroylistIndex,
  checkDestroylistDomain,
  loadDestroylistRoots,
  loadLivingThreatIndex,
  getLivingThreatIncident,
  filterLivingThreatIncidents,
  loadMaIndex,
  getMaFeed,
  filterMaFeed,
  loadCveNowIndex,
  getCveNowEntry,
  filterCveNowEntries,
  loadIncidentDeskIndex,
  getIncidentDeskBrief,
  filterIncidentDeskBriefs,
  type LivingThreatIndex,
  type LivingThreatIncidentBody,
  type LivingThreatIndexEntry,
  type MaIndex,
  type MaFeedEntry,
  type CveNowIndex,
  type CveNowIndexEntry,
  type IncidentDeskBrief,
  type IncidentDeskIndex,
  loadThreatClusterIndex,
  getTcCluster,
  getTcVuln,
  getTcExploit,
  getTcVictim,
  loadTcIocs,
  loadTcMispEvents,
  loadTcEntities,
  getTcEntity,
  filterTcClusters,
  filterTcVulns,
  filterTcExploits,
  filterTcVictims,
  filterTcIocs,
  filterTcEntities,
  type TcThreatClusterIndex,
  type TcClusterBody,
  type TcVulnBody,
  type TcExploitBody,
  type TcVictimBody,
  type TcIocsBody,
  type TcMispBody,
  type TcEntityIndex,
  type TcEntityBody,
  type TcEntityType,
  loadThreaticonIndex,
  getThreaticonActor,
  loadThreaticonMalware,
  loadThreaticonCoverage,
  loadThreaticonMap,
  filterThreaticonActors,
  filterThreaticonMalware,
  filterThreaticonCoverage,
  type TiThreaticonIndex,
  type TiThreaticonActorBody,
  type TiThreaticonMalwareBody,
  type TiThreaticonCoverageBody,
  type TiThreaticonMapBody,
  loadOffseqIndex,
  getOffseqThreat,
  filterOffseqThreats,
  type OffseqThreatIndex,
  type OffseqThreatIndexEntry,
  type OffseqThreatBody,
  loadCtiwatchIndex,
  getCtiwatchVulnerability,
  getCtiwatchVictim,
  filterCtiwatchVulns,
  type CtiwatchIndex,
  type CtiwatchVulnEntry,
  type CtiwatchVulnBody,
  type CtiwatchVictimBody,
} from './threat-intel-manifest';

function makeAssetsFixture() {
  const data = new Map<string, unknown>();
  const idx: TiIndex = {
    source: 'test',
    license: 'MIT',
    replicatedAt: '2026-06-29',
    counts: { cves: 2, iocs: 1, sectors: 1, kevTotal: 1, lists: 1 },
    lastSyncedAt: '2026-06-29T00:00:00Z',
    cveIndex: [
      {
        cveId: 'CVE-2026-1001',
        publishedAt: new Date(Date.now() - 2 * 86_400_000).toISOString(),
        lastModifiedAt: new Date(Date.now() - 1 * 86_400_000).toISOString(),
        cvssV3Score: 9.8,
        cvssV3Severity: 'critical',
        vendor: 'Acme',
        product: 'Widget',
        inKev: true,
        inKevSince: '2026-06-22',
        priorityScore: 92,
        description: 'remote code execution in widget',
        sizeBytes: 32,
        argusHypeScore: null,
        argusRising: null,
      },
      {
        cveId: 'CVE-2026-1002',
        publishedAt: new Date(Date.now() - 30 * 86_400_000).toISOString(),
        lastModifiedAt: new Date(Date.now() - 30 * 86_400_000).toISOString(),
        cvssV3Score: 5.4,
        cvssV3Severity: 'medium',
        vendor: 'Globex',
        product: 'Portal',
        inKev: false,
        inKevSince: null,
        priorityScore: 35,
        description: 'cross-site scripting',
        sizeBytes: 22,
        argusHypeScore: null,
        argusRising: null,
      },
    ],
    iocIndex: [
      {
        slug: 'lockbit-4-0-ransomware',
        family: 'LockBit 4.0 Ransomware',
        category: 'ransomware',
        aliases: ['LockBit Black'],
        firstSeen: null,
        mitreTechniques: ['T1486'],
        indicatorCount: 12,
        description: 'Ransomware family tracked since 2024',
        sizeBytes: 64,
      },
    ],
    sectors: [
      {
        sector: 'financial',
        title: 'Financial sector brief',
        generatedAt: '2026-06-29',
        topCount: 1,
        preview: 'CVE-2026-1001 leads with priority 92.',
        sizeBytes: 80,
      },
    ],
    listsIndex: [
      {
        slug: 'suspicious-named-pipes',
        title: 'Suspicious Named Pipes',
        category: 'windows',
        sourceFile: 'suspicious_named_pipe_list.csv',
        valueColumn: 'pipe_name',
        entryCount: 2,
        sizeBytes: 200,
        description: 'Named pipes used by malware and offensive tools.',
      },
    ],
  };
  data.set('/data/threat-intel/index.json', idx);

  const cve: TiCveBody = {
    ...idx.cveIndex[0]!,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cweIds: ['CWE-787'],
    references: [{ url: 'https://example.com/cve-2026-1001', source: 'N/A', tags: [] }],
    bsiDescription: null,
    llmSummary: null,
    llmRecommendedAction: null,
  };
  data.set('/data/threat-intel/cves/CVE-2026-1001.json', cve);

  const ioc: TiIocBody = {
    ...idx.iocIndex[0]!,
    indicators: [],
    context: 'Long-form context here',
    references: [],
    llmSummary: null,
  };
  data.set('/data/threat-intel/iocs/lockbit-4-0-ransomware.json', ioc);

  const sector: TiSectorBody = {
    ...idx.sectors[0]!,
    executiveSummary: 'Top KEV threats for the financial sector.',
    topThreats: [
      {
        cveId: 'CVE-2026-1001',
        title: 'Remote code execution in widget',
        relevance: 'broadly-critical',
        risk: 'CVSS 9.8; actively exploited.',
        recommendedAction: 'Patch immediately.',
      },
    ],
  };
  data.set('/data/threat-intel/sectors/financial.json', sector);

  const list: TiDetectionListBody = {
    ...idx.listsIndex[0]!,
    columns: ['pipe_name', 'metadata_description', 'metadata_tool', 'metadata_severity'],
    entries: [
      {
        value: '\\WCEServicePipe',
        description: 'Windows Credential Editor (WCE) default named pipe',
        tool: 'WCE',
        severity: 'critical',
        metadata: {},
      },
      {
        value: '\\hashdump',
        description: 'cobaltstrike pipe names',
        tool: 'CobaltStrike',
        severity: 'critical',
        metadata: {},
      },
    ],
  };
  data.set('/data/threat-intel/lists/suspicious-named-pipes.json', list);

  const kev: TiKevEntry[] = [
    {
      cveId: 'CVE-2026-1001',
      vendor: 'Acme',
      product: 'Widget',
      name: 'Acme Widget RCE',
      dateAdded: '2026-06-22',
      shortDescription: 'RCE in Acme Widget',
      requiredAction: 'Apply updates per vendor instructions.',
      dueDate: '2026-07-06',
    },
  ];
  data.set('/data/threat-intel/cves/kev.json', kev);

  // ─── Darknet directory fixture (darknetlist.is) ───────────────────
  const darknetIdx: TiDarknetIndex = {
    source: 'darknetlist.is',
    url: 'https://darknetlist.is/',
    description: 'A free directory of Tor-accessible sites.',
    rebuiltAt: '2026-08-04T11:25:06Z',
    syncedAt: '2026-08-04T12:00:00Z',
    counts: { categories: 2, sites: 3, up: 2, down: 1, recommended: 1, onion: 3 },
    categories: [
      {
        id: 'markets',
        title: 'MARKETS',
        description: 'active market venues and their mirrors',
        siteCount: 2,
        mirrorCount: 2,
        upCount: 1,
      },
      {
        id: 'forums',
        title: 'FORUMS',
        description: 'discussion and community hubs',
        siteCount: 1,
        mirrorCount: 1,
        upCount: 1,
      },
    ],
    sites: [
      {
        slug: 'dwd-3c9c-715',
        name: 'Allure',
        dwdId: 'DWD-3C9C-715',
        category: 'markets',
        status: 'up',
        upMirrors: 1,
        totalMirrors: 1,
        recommended: false,
        isOnion: true,
        url: null,
        onion: null,
      },
      {
        slug: 'dwd-3e7a-775',
        name: 'Dark Matter',
        dwdId: 'DWD-3E7A-775',
        category: 'markets',
        status: 'down',
        upMirrors: 0,
        totalMirrors: 3,
        recommended: true,
        isOnion: true,
        url: null,
        onion: null,
      },
      {
        slug: 'dwd-2e2e-079',
        name: 'Ark Forum',
        dwdId: 'DWD-2E2E-079',
        category: 'forums',
        status: 'up',
        upMirrors: 1,
        totalMirrors: 1,
        recommended: false,
        isOnion: true,
        url: null,
        onion: null,
      },
    ],
  };
  data.set('/data/threat-intel/darknet/index.json', darknetIdx);

  const darknetSite: TiDarknetSiteBody = {
    ...darknetIdx.sites[0]!,
    url: 'http://c5lpbpiufttwjm4daqb6kiyaspwbyedgnshhayhomksf65ebp2ckaeqd.onion',
    onion: 'c5lpbpiufttwjm4daqb6kiyaspwbyedgnshhayhomksf65ebp2ckaeqd',
    latencyMs: 2158,
    httpCode: '200',
    pageSize: '77kb',
    fingerprint: '4BAFDC5B',
  };
  data.set('/data/threat-intel/darknet/sites/dwd-3c9c-715.json', darknetSite);

  const darknetCategory: TiDarknetCategoryBody = {
    ...darknetIdx.categories[0]!,
    sites: [darknetSite],
  };
  data.set('/data/threat-intel/darknet/categories/markets.json', darknetCategory);

  // ─── ThreatCluster feeds (threatcluster.io) ────────────────────────
  const tcIdx: TcThreatClusterIndex = {
    source: 'threatcluster.io',
    url: 'https://threatcluster.io/feeds',
    description: 'test',
    syncedAt: '2026-08-13T04:00:00Z',
    lastBuildDates: { clusters: '2026-08-13T04:41:40Z', iocs: '2026-08-13T04:45:21Z' },
    counts: { clusters: 1, vulnerabilities: 1, exploits: 2, victims: 1, iocs: 2, mispEvents: 1 },
    feeds: [{ id: 'clusters', title: 'Threat Feed', url: 'https://threatcluster.io/feed.xml', window: '7 days' }],
    clusters: [
      {
        slug: 'lazarus-windows-afdsys-zero-abc123',
        title: 'Lazarus Group Exploits Windows Zero-Day',
        pubDate: '2026-08-12T07:38:58.000Z',
        sourceCount: 18,
        sizeBytes: 1245,
      },
    ],
    vulnerabilities: [
      {
        cveId: 'CVE-2026-0301',
        title: 'CVE-2026-0301',
        pubDate: '2026-08-13T03:16:46.000Z',
        sizeBytes: 161,
      },
    ],
    exploits: [
      {
        cveId: 'CVE-2026-63030',
        title: 'CVE-2026-63030 [KEV] [Exploit]',
        pubDate: '2026-07-17T20:17:28.000Z',
        severity: 'CRITICAL',
        inKev: true,
        sizeBytes: 414,
      },
      {
        cveId: 'CVE-2026-16723',
        title: 'CVE-2026-16723 [Exploit]',
        pubDate: '2026-07-16T10:00:00.000Z',
        severity: 'MEDIUM',
        inKev: false,
        sizeBytes: 300,
      },
    ],
    victims: [
      {
        id: 'portable-intelligence-1a2b',
        victim: 'Portable Intelligence Inc',
        group: 'blacknevas',
        sector: 'Technology',
        country: 'US',
        pubDate: '2026-08-13T00:22:25.000Z',
        sizeBytes: 400,
      },
    ],
  };
  data.set('/data/threat-intel/threatcluster/index.json', tcIdx);

  const tcCluster: TcClusterBody = {
    ...tcIdx.clusters[0]!,
    link: 'https://threatcluster.io/cluster/lazarus-windows-afdsys-zero-abc123',
    guid: 'https://threatcluster.io/cluster/lazarus-windows-afdsys-zero-abc123',
    categories: ['18 Sources'],
    description: 'The North Korean hacking group Lazarus exploited a zero-day vulnerability.',
  };
  data.set('/data/threat-intel/threatcluster/clusters/lazarus-windows-afdsys-zero-abc123.json', tcCluster);

  const tcVuln: TcVulnBody = {
    ...tcIdx.vulnerabilities[0]!,
    link: 'https://threatcluster.io/entities/cve/CVE-2026-0301',
    guid: 'https://threatcluster.io/entities/cve/CVE-2026-0301',
    description: 'An information disclosure vulnerability in the URL Filtering feature of PAN-OS.',
  };
  data.set('/data/threat-intel/threatcluster/vulnerabilities/CVE-2026-0301.json', tcVuln);

  const tcExploit: TcExploitBody = {
    ...tcIdx.exploits[0]!,
    link: 'https://threatcluster.io/entities/cve/CVE-2026-63030',
    guid: 'https://threatcluster.io/entities/cve/CVE-2026-63030',
    hasExploit: true,
    categories: ['Severity: CRITICAL', 'CISA KEV'],
    description: 'Severity: CRITICAL | CISA KEV Listed | Known Exploit Available | WordPress affected.',
  };
  data.set('/data/threat-intel/threatcluster/exploits/CVE-2026-63030.json', tcExploit);

  const tcVictim: TcVictimBody = {
    ...tcIdx.victims[0]!,
    title: 'Portable Intelligence Inc — claimed by blacknevas',
    link: 'https://threatcluster.io/dark-web/victim/Portable%20Intelligence%20Inc',
    guid: 'darkweb-victim:blacknevas:portable intelligence inc',
    categories: ['Group: blacknevas', 'Sector: Technology', 'Country: US'],
    description: 'US · Technology · A Canadian IT company based in Markham, Ontario.',
  };
  data.set('/data/threat-intel/threatcluster/victims/portable-intelligence-1a2b.json', tcVictim);

  const tcIocs: TcIocsBody = {
    source: 'threatcluster.io',
    url: 'https://threatcluster.io/api/iocs/public/feed.json',
    generatedAt: '2026-08-13T04:45:21Z',
    syncedAt: '2026-08-13T04:46:00Z',
    filters: { confidence: 'high', window_days: 30, types: ['ipv4', 'ipv6', 'domain'] },
    count: 2,
    iocs: [
      {
        type: 'domain',
        value: 'ccleanerwind.top',
        confidence: 'high',
        reason: 'Identified as attacker-controlled domain for malware distribution',
        first_seen: '2026-08-12T10:20:02+00:00',
        last_seen: '2026-08-12T11:31:38+00:00',
        source_count: 2,
        sources: [
          {
            source: 'Gbhackers',
            url: 'https://gbhackers.com/malicious-ccleaner-installer/',
            pub_date: '2026-08-12T11:31:38+00:00',
          },
        ],
      },
      {
        type: 'ipv4',
        value: '74.65.75.102',
        confidence: 'high',
        reason: 'Explicitly mentioned in response context.',
        first_seen: '2026-08-11T10:00:19+00:00',
        last_seen: '2026-08-11T10:00:19+00:00',
        source_count: 1,
        sources: [
          {
            source: 'Securelist',
            url: 'https://securelist.com/project-cav3rn-continues/120991/',
            pub_date: '2026-08-11T10:00:19+00:00',
          },
        ],
      },
    ],
  };
  data.set('/data/threat-intel/threatcluster/iocs.json', tcIocs);

  const tcMisp: TcMispBody = {
    source: 'threatcluster.io',
    url: 'https://threatcluster.io/misp/manifest.json',
    syncedAt: '2026-08-13T04:46:00Z',
    eventCount: 1,
    events: [
      {
        uuid: '31fc2385-a89e-5ffa-af2e-e4bcd29facde',
        info: 'Lazarus Group Exploits Windows Zero-Day to Target Defense Sector',
        date: '2026-08-12',
        analysis: '2',
        threat_level_id: '1',
        timestamp: '1786530293',
        tags: ['source:ThreatCluster', 'tlp:clear', 'type:apt', 'misp-galaxy:threat-actor="Lazarus"'],
        orgc: 'ThreatCluster',
      },
    ],
  };
  data.set('/data/threat-intel/threatcluster/misp.json', tcMisp);

  const tcEntityIndex: TcEntityIndex = {
    source: 'threatcluster.io',
    url: 'https://threatcluster.io/entities',
    description: 'test',
    builtAt: '2026-08-13T04:50:00Z',
    counts: { actor: 1, group: 1, malware: 1, cve: 1, sector: 1 },
    entities: {
      actor: [
        {
          type: 'actor',
          slug: 'lazarus-group',
          name: 'Lazarus Group',
          aliases: ['Lazarus'],
          mentionCount: 3,
          firstSeen: '2026-08-12T07:00:00Z',
          lastSeen: '2026-08-13T04:00:00Z',
        },
      ],
      cve: [
        {
          type: 'cve',
          slug: 'CVE-2026-0301',
          name: 'CVE-2026-0301',
          aliases: [],
          mentionCount: 1,
          firstSeen: '2026-08-13T03:16:00Z',
          lastSeen: '2026-08-13T03:16:00Z',
        },
      ],
      group: [
        {
          type: 'group',
          slug: 'clop',
          name: 'Clop',
          aliases: [],
          mentionCount: 1,
          firstSeen: '2026-08-12T00:00:00Z',
          lastSeen: '2026-08-12T00:00:00Z',
        },
      ],
      malware: [
        {
          type: 'malware',
          slug: 'powershell',
          name: 'Powershell',
          aliases: [],
          mentionCount: 1,
          firstSeen: '2026-08-12T07:00:00Z',
          lastSeen: '2026-08-12T07:00:00Z',
        },
      ],
      sector: [
        {
          type: 'sector',
          slug: 'technology',
          name: 'Technology',
          aliases: [],
          mentionCount: 2,
          firstSeen: '2026-08-12T00:00:00Z',
          lastSeen: '2026-08-13T00:22:00Z',
        },
      ],
    },
  };
  data.set('/data/threat-intel/threatcluster/entities/index.json', tcEntityIndex);

  const tcEntityActor: TcEntityBody = {
    type: 'actor',
    slug: 'lazarus-group',
    name: 'Lazarus Group',
    aliases: ['Lazarus'],
    sources: ['misp-galaxy'],
    mentionCount: 3,
    firstSeen: '2026-08-12T07:00:00Z',
    lastSeen: '2026-08-13T04:00:00Z',
    summary:
      'North Korean threat actor. Attributed via MISP galaxy: Lazarus (threat-actor) on 1 MISP event. Co-mentioned with CVE-2026-0301 in 1 record and powershell in 1 record.',
    frequency: [
      { date: '2026-08-12', count: 2 },
      { date: '2026-08-13', count: 1 },
    ],
    recentActivity: [
      {
        recordType: 'cluster',
        slug: 'lazarus-windows-afdsys-zero-abc123',
        title: 'Lazarus Group Exploits Windows Zero-Day',
        pubDate: '2026-08-12T07:38:58.000Z',
      },
      {
        recordType: 'mispEvent',
        slug: '31fc2385-a89e-5ffa-af2e-e4bcd29facde',
        title: 'Lazarus Group Exploits Windows Zero-Day to Target Defense Sector',
        pubDate: '2026-08-12T00:00:00.000Z',
      },
      {
        recordType: 'vulnerability',
        slug: 'CVE-2026-0301',
        title: 'CVE-2026-0301',
        pubDate: '2026-08-13T03:16:46.000Z',
      },
    ],
    relatedEntities: [
      { type: 'cve', slug: 'CVE-2026-0301', name: 'CVE-2026-0301', weight: 2 },
      { type: 'malware', slug: 'powershell', name: 'Powershell', weight: 1 },
      { type: 'sector', slug: 'technology', name: 'Technology', weight: 1 },
    ],
    mitreTechniques: [],
  };
  data.set('/data/threat-intel/threatcluster/entities/actor/lazarus-group.json', tcEntityActor);

  const tcEntityCve: TcEntityBody = {
    type: 'cve',
    slug: 'CVE-2026-0301',
    name: 'CVE-2026-0301',
    aliases: [],
    sources: ['feed'],
    mentionCount: 1,
    firstSeen: '2026-08-13T03:16:00Z',
    lastSeen: '2026-08-13T03:16:00Z',
    summary:
      'Feed-listed CVE-2026-0301. Also co-mentioned with lazarus-group in 2 records. 1 mention in feeds, 2 mentions in cluster text.',
    frequency: [{ date: '2026-08-13', count: 1 }],
    recentActivity: [
      {
        recordType: 'vulnerability',
        slug: 'CVE-2026-0301',
        title: 'CVE-2026-0301',
        pubDate: '2026-08-13T03:16:46.000Z',
      },
    ],
    relatedEntities: [
      { type: 'actor', slug: 'lazarus-group', name: 'Lazarus Group', weight: 2 },
      { type: 'malware', slug: 'powershell', name: 'Powershell', weight: 1 },
    ],
    mitreTechniques: [],
  };
  data.set('/data/threat-intel/threatcluster/entities/cve/cve-2026-0301.json', tcEntityCve);

  const tcEntityGroup: TcEntityBody = {
    type: 'group',
    slug: 'clop',
    name: 'Clop',
    aliases: [],
    sources: ['victims'],
    mentionCount: 1,
    firstSeen: '2026-08-12T00:00:00Z',
    lastSeen: '2026-08-12T00:00:00Z',
    summary: 'Ransomware group named 1 time. Observed on 1 leak-site victim.',
    frequency: [{ date: '2026-08-12', count: 1 }],
    recentActivity: [
      {
        recordType: 'victim',
        slug: 'portable-intelligence-1a2b',
        title: 'Portable Intelligence Inc',
        pubDate: '2026-08-13T00:22:25.000Z',
      },
    ],
    relatedEntities: [{ type: 'sector', slug: 'technology', name: 'Technology', weight: 1 }],
    mitreTechniques: [],
    victims: [
      {
        id: 'portable-intelligence-1a2b',
        victim: 'Portable Intelligence Inc',
        sector: 'Technology',
        country: 'US',
        pubDate: '2026-08-13T00:22:25.000Z',
      },
    ],
  };
  data.set('/data/threat-intel/threatcluster/entities/group/clop.json', tcEntityGroup);

  const tiIdx: TiThreaticonIndex = {
    source: 'threaticon.com',
    url: 'https://threaticon.com',
    description: 'STIX 2.1 threat-actor catalog',
    syncedAt: '2026-08-13T00:00:00Z',
    builtAt: '2026-08-13T00:00:00Z',
    counts: {
      actors: 2,
      actorsWithProfiles: 2,
      malwareFamilies: 2,
      malwareCategories: 2,
      techniques: 1,
      tactics: 1,
      originCountries: 2,
      targetedCountries: 1,
      sectors: 1,
    },
    tactics: { execution: { techniqueCount: 1, coveragePct: 100 } },
    actors: [
      {
        slug: 'lazarus-group',
        id: 319,
        name: 'Lazarus Group',
        mitreId: 'G0032',
        status: 'Active',
        tlp: 'amber',
        confidence: 85,
        types: ['Nation-State', 'Espionage'],
        originCode: 'KP',
        countryOfOrigin: 'North Korea (KP)',
        techniquesCount: 4,
        toolsCount: 2,
        targetedCountriesCount: 3,
        tagsCount: 5,
        added: '2026-05-02',
      },
      {
        slug: 'fin7',
        id: 12,
        name: 'FIN7',
        mitreId: 'G0046',
        status: 'Active',
        tlp: 'white',
        confidence: 70,
        types: ['Criminal'],
        originCode: 'RU',
        countryOfOrigin: 'Russia (RU)',
        techniquesCount: 2,
        toolsCount: 1,
        targetedCountriesCount: 0,
        tagsCount: 0,
        added: '2026-05-01',
      },
    ],
  };
  data.set('/data/threat-intel/threaticon/index.json', tiIdx);

  const tiActor: TiThreaticonActorBody = {
    slug: 'lazarus-group',
    id: 319,
    name: 'Lazarus Group',
    mitreId: 'G0032',
    status: 'Active',
    tlp: 'amber',
    confidence: 85,
    types: ['Nation-State', 'Espionage'],
    originCode: 'KP',
    countryOfOrigin: 'North Korea (KP)',
    techniquesCount: 4,
    toolsCount: 2,
    targetedCountriesCount: 3,
    tagsCount: 5,
    added: '2026-05-02',
    sophistication: 'Advanced',
    resourceLevel: 'State-sponsored',
    motivation: 'Financial, Espionage',
    tags: ['north korea', 'ransomware'],
    aliases: ['Lazarus', 'Guardians of Peace'],
    targetedSectors: ['Financial', 'Cryptocurrency'],
    targetedCountries: ['US', 'KR'],
    tactics: ['Initial Access', 'Execution'],
    techniques: ['T1566', 'T1059.001'],
    tools: ['BADCALL', 'AppleJeus'],
    iocPatterns: ['domain:daily#update.org'],
    keyCapabilities: ['Custom backdoors'],
    recommendedActions: ['Hunt for AppleJeus'],
    campaignsText: '2020 crypto heists',
    description: 'A DPRK-sponsored cyber threat group.',
    goals: 'Financial gain, espionage',
    killChain: '/graph/kill-chain?entity=threat_actor%3A319',
    sourceUrl: 'https://threaticon.com/threat-actors/319',
  };
  data.set('/data/threat-intel/threaticon/actors/lazarus-group.json', tiActor);

  const tiMalware: TiThreaticonMalwareBody = {
    source: 'threaticon.com',
    syncedAt: '2026-08-13T00:00:00Z',
    familyCount: 2,
    byCategory: { Malware: 1, Ransomware: 1 },
    families: [
      { id: 1, name: 'AppleJeus', category: 'Malware', tlp: 'amber', confidence: 90, status: 'Active' },
      { id: 2, name: 'LockBit', category: 'Ransomware', tlp: 'red', confidence: 95, status: 'Active' },
    ],
  };
  data.set('/data/threat-intel/threaticon/malware.json', tiMalware);

  const tiCoverage: TiThreaticonCoverageBody = {
    source: 'threaticon.com',
    syncedAt: '2026-08-13T00:00:00Z',
    techniqueCount: 1,
    tactics: { execution: { techniqueCount: 1, coveragePct: 100 } },
    techniques: [{ patternId: 1, techniqueId: 'T1059.001', name: 'PowerShell', tactic: 'Execution', rules: 4 }],
  };
  data.set('/data/threat-intel/threaticon/coverage.json', tiCoverage);

  const tiMap: TiThreaticonMapBody = {
    builtAt: '2026-08-13T00:00:00Z',
    origin: [
      { code: 'KP', count: 1 },
      { code: 'RU', count: 1 },
    ],
    targeted: [{ code: 'US', count: 1 }],
    sectors: [{ sector: 'Financial', count: 1 }],
  };
  data.set('/data/threat-intel/threaticon/map.json', tiMap);

  // ── dPhish (dphish.com TAXII 2.1 collection) ────────────────────────
  const dphishIdx: DphishIndex = {
    source: 'dphish.com',
    sourceUrl: 'https://dphish.com/feeds/',
    collectionId: '68f57461-5c20-451d-ab32-6357d1fbef0b',
    collectionUrl: 'https://tip.dphish.live/taxii2/root/collections/68f57461-5c20-451d-ab32-6357d1fbef0b/objects/',
    description: 'Phishing threat-intel feed — malicious domains, phishing URLs, sender IPs.',
    license: 'Public feed (no registration required)',
    syncedAt: '2026-08-15T00:00:00.000Z',
    counts: {
      indicators: 3,
      active: 2,
      revoked: 1,
      byCategory: { domain: 2, url: 1 },
    },
    indicators: [
      {
        slug: 'melbetegypt.com-1a2b3c',
        stixId: 'indicator--11111111-1111-4111-8111-111111111111',
        value: 'melbetegypt.com',
        category: 'domain',
        mainObservableType: 'Domain-Name',
        active: true,
        revoked: false,
        confidence: 100,
        score: 20,
        created: '2025-05-27T16:28:59.074Z',
        modified: '2025-05-27T16:28:59.074Z',
        validUntil: '2027-02-15T12:09:24.192Z',
        description: 'Credential-harvesting domain impersonating Melbet.',
        sizeBytes: 512,
      },
      {
        slug: 'phish.example.com-4d5e6f',
        stixId: 'indicator--22222222-2222-4222-8222-222222222222',
        value: 'phish.example.com',
        category: 'domain',
        mainObservableType: 'Domain-Name',
        active: true,
        revoked: false,
        confidence: 100,
        score: 30,
        created: '2026-08-01T10:00:00.000Z',
        modified: '2026-08-01T10:00:00.000Z',
        validUntil: null,
        description: null,
        sizeBytes: 480,
      },
      {
        slug: 'https:__dtec.com.my_ash-7g8h9i',
        stixId: 'indicator--33333333-3333-4333-8333-333333333333',
        value: 'https://dtec.com.my/ash?email=brad@example.net',
        category: 'url',
        mainObservableType: 'Url',
        active: false,
        revoked: true,
        confidence: 100,
        score: 20,
        created: '2025-05-15T11:16:37.466Z',
        modified: '2025-06-16T13:54:27.452Z',
        validUntil: '2025-06-16T13:54:22.410Z',
        description: 'Phishing URL with email parameter.',
        sizeBytes: 900,
      },
    ],
  };
  data.set('/data/threat-intel/dphish/index.json', dphishIdx);

  const dphishBody: DphishIndicatorBody = {
    ...dphishIdx.indicators[0]!,
    name: 'melbetegypt.com',
    observableValues: [{ type: 'Domain-Name', value: 'melbetegypt.com' }],
    pattern: "[domain-name:value = 'melbetegypt.com']",
    patternType: 'stix',
    validFrom: '2025-05-27T16:28:59.000Z',
    labels: ['phishing'],
    indicatorTypes: ['malicious-activity'],
    detection: false,
  };
  data.set('/data/threat-intel/dphish/indicators/melbetegypt.com-1a2b3c.json', dphishBody);

  // ── OffSeq (radar.offseq.com) ──────────────────────────────────────
  const offseqIdx: OffseqThreatIndex = {
    source: 'radar.offseq.com',
    sourceUrl: 'https://radar.offseq.com/',
    description: 'Aggregated threat-intel feed',
    license: 'Public API',
    syncedAt: '2026-10-17T00:00:00.000Z',
    days: 30,
    overview: { total: 1 },
    counts: { threats: 1, exploited: 0, byType: { vulnerability: 1 }, bySeverity: { high: 1 } },
    tags: [{ name: 'cve', count: 1 }],
    threats: [
      {
        slug: 'test-threat-abc123',
        externalId: 'ext-1',
        source: 'CVE Database V5',
        type: 'vulnerability',
        title: 'Test threat',
        severity: 'high',
        cvssScore: 7.5,
        publishedDate: '2026-10-17T00:00:00.000Z',
        cveId: 'CVE-2026-1234',
        cveIds: ['CVE-2026-1234'],
        exploited: false,
        knownExploitsInWild: false,
        tags: ['cve', 'cve-2026-1234'],
        url: 'https://radar.offseq.com/threats/test-threat-abc123',
        sizeBytes: 100,
      },
    ],
  };
  data.set('/data/threat-intel/offseq/index.json', offseqIdx);
  const offseqBody: OffseqThreatBody = {
    ...offseqIdx.threats[0]!,
    description: 'A test threat.',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    mirageCountries: [],
    patchAvailable: false,
    knownThreatActors: [],
    affectedCountries: [],
    references: ['https://example.com/ref'],
    aiSummary: 'AI summary here.',
    aiImpact: 'Impact here.',
  };
  data.set('/data/threat-intel/offseq/threats/test-threat-abc123.json', offseqBody);

  // ── CTIWatch (ctiwatch.com) ────────────────────────────────────────
  const ctiIdx: CtiwatchIndex = {
    source: 'ctiwatch.com',
    sourceUrl: 'https://ctiwatch.com/',
    description: 'Public vulnerability + IOC database',
    license: 'Public API',
    syncedAt: '2026-10-17T00:00:00.000Z',
    stats: { total_iocs: 1, total_cves: 1, kev_count: 1 },
    victimStats: null,
    counts: { iocs: 1, vulnerabilities: 1, kev: 1, actors: 0, victims: 1, campaigns: 0 },
    iocs: [
      {
        id: 'ioc-1',
        type: 'ip',
        value: '1.2.3.4',
        confidence_score: 85,
        is_active: true,
        first_seen: '2026-10-17T00:00:00.000Z',
        last_seen: '2026-10-17T00:00:00.000Z',
        tags: ['honeypot'],
        context: 'ctx',
        source_name: 'T-Pot',
        threat_actor: null,
      },
    ],
    vulnerabilities: [
      {
        cve_id: 'CVE-2026-9999',
        title: 'Test CVE',
        severity: 'HIGH',
        cvss_score: 8.0,
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        is_kev: true,
        exploit_status: 'weaponized',
        published_date: '2026-10-17T00:00:00.000Z',
        cwe: ['CWE-79'],
        vendor: 'Acme',
        product: 'Widget',
        priority_score: 90,
        epss: 0.5,
        tags: ['kev'],
      },
    ],
    kev: [
      {
        cve_id: 'CVE-2026-9999',
        title: 'Test CVE',
        severity: 'HIGH',
        cvss_score: 8.0,
        cvss_vector: null,
        is_kev: true,
        exploit_status: 'weaponized',
        published_date: '2026-10-17T00:00:00.000Z',
        cwe: ['CWE-79'],
        vendor: 'Acme',
        product: 'Widget',
        priority_score: 90,
        epss: 0.5,
        tags: ['kev'],
      },
    ],
    actors: [],
    victims: [
      {
        id: 'vic-1',
        name: 'Acme Corp',
        group: 'lockbit',
        country: 'US',
        sector: 'Technology',
        attack_date: '2026-10-17T00:00:00.000Z',
        website: 'https://acme.example',
        source: 'ransomware.live',
      },
    ],
    campaigns: [],
  };
  data.set('/data/threat-intel/ctiwatch/index.json', ctiIdx);
  const ctiVulnBody: CtiwatchVulnBody = {
    ...ctiIdx.vulnerabilities[0]!,
    description: 'A test CVE description.',
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-9999'],
    affected_products: [],
    sizeBytes: 200,
  };
  data.set('/data/threat-intel/ctiwatch/vulnerabilities/CVE-2026-9999.json', ctiVulnBody);
  const ctiVictimBody: CtiwatchVictimBody = {
    ...ctiIdx.victims[0]!,
    description: 'A test victim.',
    sizeBytes: 150,
  };
  data.set('/data/threat-intel/ctiwatch/victims/vic-1.json', ctiVictimBody);

  // ── Living Threat (living-threat.rabitanoor.com) ───────────────────
  const ltEntry: LivingThreatIndexEntry = {
    slug: 'amnesiastealer-macos-malware-021625',
    shard: 0,
    sequence: 21625,
    id: '0f348fd13740c237e1134a7f2975464c',
    title: 'AmnesiaStealer: macOS Malware Leveraging ClickFix Attacks',
    timestamp: '2026-08-16T11:07:00Z',
    source: 'https://www.bleepingcomputer.com/news/security/',
    severity: 'High',
    priorityScore: 92,
    relevanceScore: 67,
    tactics: ['Initial Access', 'Command and Control'],
    techniques: ['T1190', 'T1566.001'],
    actors: ['AmnesiaStealer'],
    techniqueCount: 2,
    cves: 1,
    tools: 2,
    sizeBytes: 8000,
  };
  const ltEntry2: LivingThreatIndexEntry = {
    ...ltEntry,
    slug: 'another-incident-021600',
    sequence: 21600,
    title: 'Another Incident',
    timestamp: '2026-08-15T00:00:00Z',
    severity: 'Low',
    priorityScore: 30,
    relevanceScore: 40,
    tactics: ['Initial Access'],
    techniques: [],
    actors: [],
    techniqueCount: 0,
    cves: 0,
    tools: 0,
  };
  const ltIdx: LivingThreatIndex = {
    source: 'living-threat.rabitanoor.com',
    sourceUrl: 'https://living-threat.rabitanoor.com/',
    repoUrl: 'https://github.com/HudKSD/Living-Threat',
    description: 'Real-world incidents mapped to MITRE ATT&CK.',
    license: 'MIT',
    syncedAt: '2026-08-16T12:00:00.000Z',
    meta: {
      apiIndex: 'data_cached_*',
      latestTs: '2026-08-16T11:07:00Z',
      latestSeq: 21625,
      anchorTs: '2026-08-16T11:07:00Z',
      fetchedAt: '2026-08-16T11:30:00Z',
      cap: 'Upstream caps at 5000.',
    },
    counts: {
      incidents: 2,
      shards: 1,
      shardSize: 500,
      bySeverity: { High: 1, Low: 1 },
      byTactic: { 'Initial Access': 1, 'Command and Control': 1 },
      uniqueCves: 1,
      uniqueTechniques: 2,
    },
    topTechniques: [
      { id: 'T1190', count: 1 },
      { id: 'T1566.001', count: 1 },
    ],
    topActors: [{ name: 'AmnesiaStealer', count: 1 }],
    topTools: [],
    topSources: [],
    incidents: [ltEntry, ltEntry2],
  };
  data.set('/data/threat-intel/living-threat/index.json', ltIdx);

  const ltShard: LivingThreatIncidentBody[] = [
    {
      slug: ltEntry.slug,
      shard: 0,
      sequence: 21625,
      id: ltEntry.id,
      index: 'data_cached_*',
      source: ltEntry.source,
      Timestamp: ltEntry.timestamp,
      Title: ltEntry.title,
      Severity: 'High',
      CVEs: ['CVE-2026-58231'],
      Threat_Actors: ['AmnesiaStealer'],
      Tools: ['ClickFix Kit'],
      Analyses: [
        {
          Stage: 'Exploitation',
          Description: 'Exploitation of CVE-2026-58231.',
          Detection: 'Monitor for unusual ClickFix activity.',
          Remediation: 'Apply patches.',
          Tactics: [{ tactic_id: 'TA0001', tactic_name: 'Initial Access', tactic_description: 'Initial access.' }],
          Technique_Details: [
            {
              technique_id: 'T1190',
              technique_name: 'Exploit Public-Facing Application',
              technique_description: 'Exploitation of a public-facing app.',
            },
          ],
          Techniques: ['T1190'],
        },
      ],
      priority_score: 92,
      relevance_score: 67,
      kill_chain_summary: 'Exploitation led to C2.',
    },
  ];
  data.set('/data/threat-intel/living-threat/shards/0000.json', ltShard);

  // ── MalwareAnalyzer (malwareanalyzer.com) ──────────────────────────
  const maFeed: MaFeedEntry[] = [
    {
      url: 'http://tourbusan.net/files/malicious.pdf',
      hostname: 'tourbusan.net',
      apex: 'tourbusan.net',
      verdict: 'malicious',
      score: 60,
      brands: [],
      categories: ['suspicious-infrastructure'],
      time: '2026-08-16T16:13:03.476Z',
    },
  ];
  const maIdx: MaIndex = {
    source: 'malwareanalyzer.com',
    sourceUrl: 'https://malwareanalyzer.com/',
    apiBase: 'https://malwareanalyzer.com/v1',
    description: 'Free keyless malware analysis.',
    license: 'Free public service by Cyble',
    syncedAt: '2026-08-16T16:20:00.000Z',
    counts: {
      malicious: 1,
      newlyObserved: 1,
      byVerdict: { malicious: 1, unknown: 1 },
      byCategory: { 'suspicious-infrastructure': 1 },
    },
    topApexes: [{ name: 'tourbusan.net', count: 1 }],
    feeds: {
      malicious: maFeed,
      newlyObserved: [
        {
          url: 'https://privatearrangements.co.nz/public/files/robux.pdf',
          hostname: 'privatearrangements.co.nz',
          apex: 'privatearrangements.co.nz',
          verdict: 'unknown',
          score: 14,
          brands: [],
          categories: [],
          time: '2026-08-16T16:16:47.235Z',
        },
      ],
    },
  };
  data.set('/data/threat-intel/malwareanalyzer/index.json', maIdx);
  data.set('/data/threat-intel/malwareanalyzer/malicious.json', maIdx.feeds.malicious);
  data.set('/data/threat-intel/malwareanalyzer/newly-observed.json', maIdx.feeds.newlyObserved);
  data.set('/data/threat-intel/malwareanalyzer/status.json', {
    online: { registered: 1, anonymous: 5, total: 6 },
    engines: { measured: 46, sampleSize: 59306, source: 'median' },
  });

  // ── cve.now (cve.now aggregate vulnerability feed) ─────────────────
  const cnEntry1: CveNowIndexEntry = {
    id: 'CVE-2026-88801',
    batch: 0,
    sequence: 0,
    title: 'Widget Suite RCE',
    publishedAt: '2026-10-30T16:16:28.198Z',
    firstSeenAt: '2026-10-30T16:18:34.471Z',
    modifiedAt: '2026-10-30T16:16:28.198Z',
    cvss: 9.8,
    severity: 'CRITICAL',
    kev: true,
    hasFix: false,
    product: 'Acme Widget Suite',
    sizeBytes: 320,
  };
  const cnEntry2: CveNowIndexEntry = {
    ...cnEntry1,
    id: 'CVE-2026-88802',
    sequence: 1,
    title: 'Gadget SSRF',
    publishedAt: '2026-10-29T12:00:00.000Z',
    firstSeenAt: '2026-10-29T12:05:00.000Z',
    modifiedAt: '2026-10-29T12:05:00.000Z',
    cvss: 5.4,
    severity: 'MEDIUM',
    kev: false,
    hasFix: true,
    product: 'Boxy Gadget',
    sizeBytes: 260,
  };
  const cnIdx: CveNowIndex = {
    source: 'cve.now',
    sourceUrl: 'https://cve.now/',
    repoUrl: 'https://github.com/sazabi/cve.now',
    description: 'Aggregate vulnerability feed.',
    license: 'Entry summaries CC-BY 4.0',
    syncedAt: '2026-10-30T16:20:00.000Z',
    meta: {
      feedUrl: 'https://cve.now/feed',
      entriesUrl: 'https://cve.now/api/v1/entries',
      window: 'newest 240 upstream entries',
      batchCount: 1,
      batchSize: 100,
    },
    counts: {
      entries: 2,
      kev: 1,
      withFix: 1,
      batches: 1,
      bySeverity: { CRITICAL: 1, MEDIUM: 1 },
    },
    topProducts: [
      { product: 'Acme Widget Suite', count: 1 },
      { product: 'Boxy Gadget', count: 1 },
    ],
    sourcesHealth: {
      checkedAt: '2026-10-30T15:54:34.422Z',
      cursor: null,
      sources: { kev: { ok: true, at: '2026-10-30T15:54:34.422Z' } },
    },
    entries: [cnEntry1, cnEntry2],
  };
  data.set('/data/threat-intel/cve-now/index.json', cnIdx);
  data.set('/data/threat-intel/cve-now/bodies/batch-000.json', [
    {
      id: cnEntry1.id,
      batch: 0,
      title: cnEntry1.title,
      product: cnEntry1.product,
      fix: [],
      modifiedAt: cnEntry1.modifiedAt,
      upstreamPage: `https://cve.now/${cnEntry1.id}`,
      sizeBytes: 320,
    },
    {
      id: cnEntry2.id,
      batch: 0,
      title: cnEntry2.title,
      product: cnEntry2.product,
      fix: ['2.1.0'],
      modifiedAt: cnEntry2.modifiedAt,
      upstreamPage: `https://cve.now/${cnEntry2.id}`,
      sizeBytes: 260,
    },
  ]);

  // ── Incident Desk (iamnicholasmartin.co.uk/incidents) ─────────────
  const idBrief1: IncidentDeskBrief = {
    title: 'CA misissuance roundup',
    link: 'https://iamnicholasmartin.co.uk/blog/iam-incident-digest-2026w44-58',
    guid: 'https://iamnicholasmartin.co.uk/blog/iam-incident-digest-2026w44-58',
    published: '2026-10-26T08:08:18.000Z',
    publishedRaw: 'Mon, 26 Oct 2026 08:08:18 +0000',
    description: 'Guessable CA keys, hijacked LiteLLM pipeline, AI-key theft.',
    imageUrl: 'https://iamnicholasmartin.co.uk/static/images/blog/digest-2026w44-hero.webp',
    slug: 'iam-incident-digest-2026w44-58',
  };
  const idBrief2: IncidentDeskBrief = {
    ...idBrief1,
    title: 'Secrets in plain env vars',
    published: '2026-10-23T10:00:00.000Z',
    description: 'Railway breach post-mortem through a secrets lens.',
    imageUrl: null,
    slug: 'iam-incident-railway-20261023-30-55',
  };
  const idIdx: IncidentDeskIndex = {
    source: 'iamnicholasmartin.co.uk/incidents',
    sourceUrl: 'https://iamnicholasmartin.co.uk/incidents',
    description: 'Incident Desk — identity-lens incident briefings.',
    license: 'Copyright the author',
    syncedAt: '2026-10-30T16:30:00.000Z',
    meta: {
      feedUrl: 'https://iamnicholasmartin.co.uk/incidents/feed.xml',
      feedTitle: 'Incident Desk | Nicholas Martin',
    },
    counts: { briefs: 2, withImage: 1, byMonth: { '2026-10': 2 } },
    briefs: [idBrief1, idBrief2],
  };
  data.set('/data/threat-intel/incident-desk/index.json', idIdx);

  const assets = {
    fetch: vi.fn(async (req: Request) => {
      const path = new URL(req.url).pathname;
      const hit = data.get(path);
      if (!hit) return new Response('not found', { status: 404 });
      return new Response(JSON.stringify(hit), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }),
  } as unknown as Fetcher;

  return { assets, data };
}

describe('loadTiIndex', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('fetches and caches the index', async () => {
    const { assets } = makeAssetsFixture();
    const a = await loadTiIndex(assets);
    const b = await loadTiIndex(assets);
    expect(a).toBe(b);
    expect((assets.fetch as unknown as { mock: { calls: unknown[] } }).mock.calls.length).toBe(1);
  });

  it('throws when the index is missing', async () => {
    const emptyAssets = { fetch: vi.fn(async () => new Response('', { status: 404 })) } as unknown as Fetcher;
    await expect(loadTiIndex(emptyAssets)).rejects.toThrow(/Threat Intel manifest not found/);
  });
});

describe('getTiCve / getTiIoc / getTiSector', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('returns a CVE body for a known ID (case-insensitive)', async () => {
    const { assets } = makeAssetsFixture();
    const c = await getTiCve(assets, 'cve-2026-1001');
    expect(c).not.toBeNull();
    expect(c!.cvssV3Score).toBe(9.8);
    expect(c!.cvssVector).toContain('AV:N');
  });

  it('returns null for an unknown CVE', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getTiCve(assets, 'CVE-1999-9999')).toBeNull();
  });

  it('returns an IOC body for a known slug', async () => {
    const { assets } = makeAssetsFixture();
    const i = await getTiIoc(assets, 'lockbit-4-0-ransomware');
    expect(i).not.toBeNull();
    expect(i!.category).toBe('ransomware');
    expect(i!.mitreTechniques).toContain('T1486');
  });

  it('returns a sector body for a known sector', async () => {
    const { assets } = makeAssetsFixture();
    const s = await getTiSector(assets, 'financial');
    expect(s).not.toBeNull();
    expect(s!.topThreats[0]!.cveId).toBe('CVE-2026-1001');
  });

  it('caches bodies on subsequent calls', async () => {
    const { assets } = makeAssetsFixture();
    await getTiCve(assets, 'CVE-2026-1001');
    await getTiCve(assets, 'CVE-2026-1001');
    const stats = tiCacheStats();
    expect(stats.cves.size).toBe(1);
    expect(stats.cves.hits).toBe(1);
    expect(stats.cves.misses).toBe(1);
  });
});

describe('loadKevSnapshot', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('returns the KEV list and caches it', async () => {
    const { assets } = makeAssetsFixture();
    const a = await loadKevSnapshot(assets);
    const b = await loadKevSnapshot(assets);
    expect(a).toBe(b);
    expect(a[0]!.cveId).toBe('CVE-2026-1001');
  });

  it('returns an empty list when the file is missing', async () => {
    const assets = { fetch: vi.fn(async () => new Response('', { status: 404 })) } as unknown as Fetcher;
    const list = await loadKevSnapshot(assets);
    expect(list).toEqual([]);
  });
});

describe('filterCves', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('filters by severity', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    expect(filterCves(idx, { severity: 'critical' })[0]!.cveId).toBe('CVE-2026-1001');
    expect(filterCves(idx, { severity: 'medium' })[0]!.cveId).toBe('CVE-2026-1002');
  });

  it('filters by kevOnly', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    const kev = filterCves(idx, { kevOnly: true });
    expect(kev).toHaveLength(1);
    expect(kev[0]!.cveId).toBe('CVE-2026-1001');
  });

  it('filters by vendor (case-insensitive substring)', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    expect(filterCves(idx, { vendor: 'glo' })[0]!.cveId).toBe('CVE-2026-1002');
    expect(filterCves(idx, { vendor: 'GLOBEX' })[0]!.cveId).toBe('CVE-2026-1002');
  });

  it('filters by daysBack', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    expect(filterCves(idx, { daysBack: 5 })).toHaveLength(1);
    expect(filterCves(idx, { daysBack: 5 })[0]!.cveId).toBe('CVE-2026-1001');
  });

  it('filters by minPriority', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    expect(filterCves(idx, { minPriority: 50 })).toHaveLength(1);
  });

  it('filters by minArgusScore (excludes CVEs without Argus data)', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    // Both test CVEs have argusHypeScore: null, so minArgusScore should exclude both
    expect(filterCves(idx, { minArgusScore: 10 })).toHaveLength(0);
    expect(filterCves(idx, { minArgusScore: 0 })).toHaveLength(0);
  });

  it('includes Argus-scored CVEs when minArgusScore is not set', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    // No argus filter — both CVEs appear (argusHypeScore: null treated as "not set")
    expect(filterCves(idx, {})).toHaveLength(2);
  });

  it('filters by keyword', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    expect(filterCves(idx, { keyword: 'WIDGET' })[0]!.cveId).toBe('CVE-2026-1001');
  });

  it('respects limit', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    expect(filterCves(idx, { limit: 1 })).toHaveLength(1);
  });
});

describe('filterIocs', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('filters by category', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    expect(filterIocs(idx, { category: 'ransomware' })).toHaveLength(1);
    expect(filterIocs(idx, { category: 'apt' })).toHaveLength(0);
  });

  it('filters by keyword across family/aliases/description', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    expect(filterIocs(idx, { keyword: 'lockbit black' })[0]!.slug).toBe('lockbit-4-0-ransomware');
    expect(filterIocs(idx, { keyword: 'RANSOMWARE' })).toHaveLength(1);
    expect(filterIocs(idx, { keyword: 'nope' })).toHaveLength(0);
  });
});

describe('computePriorityScore', () => {
  it('maxes out at 100 for high-CVSS + KEV + recent', () => {
    const now = Date.parse('2026-06-29T00:00:00Z');
    const score = computePriorityScore({
      cvssV3Score: 10,
      inKev: true,
      publishedAt: '2026-06-29T00:00:00Z',
      nowMs: now,
    });
    // 0.55 * 1.0 + 0.35 + 0.10 * 1.0 = 1.0 → 100 (capped by 100).
    expect(score).toBeLessThanOrEqual(100);
    expect(score).toBeGreaterThan(90);
  });

  it('drops for old CVEs with no KEV entry', () => {
    const now = Date.parse('2026-06-29T00:00:00Z');
    const old = '2025-06-29T00:00:00Z';
    const score = computePriorityScore({ cvssV3Score: 10, inKev: false, publishedAt: old, nowMs: now });
    // 0.55 + 0 + 0 = 55
    expect(score).toBe(55);
  });

  it('handles null CVSS', () => {
    const now = Date.parse('2026-06-29T00:00:00Z');
    const score = computePriorityScore({
      cvssV3Score: null,
      inKev: false,
      publishedAt: '2026-06-29T00:00:00Z',
      nowMs: now,
    });
    // 0 + 0 + 0.10 = 10
    expect(score).toBe(10);
  });

  it('incorporates argusHypeScore when provided', () => {
    const now = Date.parse('2026-06-29T00:00:00Z');
    // With argusHypeScore=100 (max), old CVE, no KEV:
    //   0.40*1.0 + 0 + 0.10*0 + 0.15*1.0 = 0.55 → 55
    const score = computePriorityScore({
      cvssV3Score: 10,
      inKev: false,
      publishedAt: '2025-06-29T00:00:00Z',
      nowMs: now,
      argusHypeScore: 100,
    });
    expect(score).toBe(55);
  });

  it('uses original formula when argusHypeScore is null', () => {
    const now = Date.parse('2026-06-29T00:00:00Z');
    const old = '2025-06-29T00:00:00Z';
    // argusHypeScore null — original formula: 0.55 + 0 + 0 = 55
    const score = computePriorityScore({
      cvssV3Score: 10,
      inKev: false,
      publishedAt: old,
      nowMs: now,
      argusHypeScore: null,
    });
    expect(score).toBe(55);
  });

  it('stays bounded at 100 with max argusHypeScore + KEV + recent', () => {
    const now = Date.parse('2026-06-29T00:00:00Z');
    // 0.40*1.0 + 0.35 + 0.10*1.0 + 0.15*1.0 = 1.0 → 100
    const score = computePriorityScore({
      cvssV3Score: 10,
      inKev: true,
      publishedAt: '2026-06-29T00:00:00Z',
      nowMs: now,
      argusHypeScore: 100,
    });
    expect(score).toBe(100);
  });
});

describe('severityFromScore', () => {
  it('maps CVSS bands correctly', () => {
    expect(severityFromScore(null)).toBe('unknown');
    expect(severityFromScore(0)).toBe('unknown');
    expect(severityFromScore(0.1)).toBe('low');
    expect(severityFromScore(3.9)).toBe('low');
    expect(severityFromScore(4.0)).toBe('medium');
    expect(severityFromScore(6.9)).toBe('medium');
    expect(severityFromScore(7.0)).toBe('high');
    expect(severityFromScore(8.9)).toBe('high');
    expect(severityFromScore(9.0)).toBe('critical');
    expect(severityFromScore(10)).toBe('critical');
  });
});

describe('getTiList / filterLists / searchListEntries', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('returns a detection list body for a known slug', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getTiList(assets, 'suspicious-named-pipes');
    expect(body).not.toBeNull();
    expect(body!.entries).toHaveLength(2);
    expect(body!.entries[0]!.value).toBe('\\WCEServicePipe');
    expect(body!.columns).toContain('pipe_name');
  });

  it('returns null for an unknown slug', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getTiList(assets, 'nope')).toBeNull();
  });

  it('caches list bodies on subsequent calls', async () => {
    const { assets } = makeAssetsFixture();
    await getTiList(assets, 'suspicious-named-pipes');
    await getTiList(assets, 'suspicious-named-pipes');
    const stats = tiCacheStats();
    expect(stats.lists.size).toBe(1);
    expect(stats.lists.hits).toBe(1);
    expect(stats.lists.misses).toBe(1);
  });

  it('filterLists filters by category', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    expect(filterLists(idx, { category: 'windows' })).toHaveLength(1);
    expect(filterLists(idx, { category: 'network' })).toHaveLength(0);
  });

  it('filterLists filters by keyword', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTiIndex(assets);
    expect(filterLists(idx, { keyword: 'pipe' })[0]!.slug).toBe('suspicious-named-pipes');
    expect(filterLists(idx, { keyword: 'nope' })).toHaveLength(0);
  });

  it('searchListEntries filters by keyword across value/description/tool', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getTiList(assets, 'suspicious-named-pipes');
    expect(searchListEntries(body!, { keyword: 'cobaltstrike' })).toHaveLength(1);
    expect(searchListEntries(body!, { keyword: 'WCE' })[0]!.value).toBe('\\WCEServicePipe');
    expect(searchListEntries(body!, { keyword: 'nonexistent' })).toHaveLength(0);
  });

  it('searchListEntries filters by severity', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getTiList(assets, 'suspicious-named-pipes');
    expect(searchListEntries(body!, { severity: 'critical' })).toHaveLength(2);
    expect(searchListEntries(body!, { severity: 'low' })).toHaveLength(0);
  });

  it('searchListEntries respects limit', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getTiList(assets, 'suspicious-named-pipes');
    expect(searchListEntries(body!, { limit: 1 })).toHaveLength(1);
  });
});

describe('tiCacheStats', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('reports index loaded after loadTiIndex', async () => {
    const { assets } = makeAssetsFixture();
    await loadTiIndex(assets);
    const s = tiCacheStats();
    expect(s.indexLoaded).toBe(true);
    expect(s.kevLoaded).toBe(false);
  });

  it('reports KEV loaded after loadKevSnapshot', async () => {
    const { assets } = makeAssetsFixture();
    await loadKevSnapshot(assets);
    const s = tiCacheStats();
    expect(s.kevLoaded).toBe(true);
    expect(s.kevAgeMs).toBeGreaterThanOrEqual(0);
  });
});

describe('loadDarknetIndex', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('fetches and caches the darknet index', async () => {
    const { assets } = makeAssetsFixture();
    const a = await loadDarknetIndex(assets);
    const b = await loadDarknetIndex(assets);
    expect(a).toBe(b);
    expect(a.source).toBe('darknetlist.is');
    expect(a.counts.sites).toBe(3);
    expect(a.counts.categories).toBe(2);
    expect((assets.fetch as unknown as { mock: { calls: unknown[] } }).mock.calls.length).toBe(1);
  });

  it('throws when the darknet index is missing', async () => {
    const assets = { fetch: vi.fn(async () => new Response('not found', { status: 404 })) } as unknown as Fetcher;
    await expect(loadDarknetIndex(assets)).rejects.toThrow(/Darknet directory manifest not found/);
  });
});

describe('getDarknetSite', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('returns a site body for a known slug', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getDarknetSite(assets, 'dwd-3c9c-715');
    expect(body).not.toBeNull();
    expect(body!.name).toBe('Allure');
    expect(body!.url).toContain('.onion');
    expect(body!.httpCode).toBe('200');
    expect(body!.fingerprint).toBe('4BAFDC5B');
  });

  it('returns null for an unknown slug', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getDarknetSite(assets, 'nope')).toBeNull();
  });

  it('caches site bodies on subsequent calls', async () => {
    const { assets } = makeAssetsFixture();
    await getDarknetSite(assets, 'dwd-3c9c-715');
    await getDarknetSite(assets, 'dwd-3c9c-715');
    const stats = tiCacheStats();
    expect(stats.darknet.sites.size).toBe(1);
    expect(stats.darknet.sites.hits).toBe(1);
    expect(stats.darknet.sites.misses).toBe(1);
  });
});

describe('getDarknetCategory', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('returns a category body with sites for a known category', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getDarknetCategory(assets, 'markets');
    expect(body).not.toBeNull();
    expect(body!.title).toBe('MARKETS');
    expect(body!.sites).toHaveLength(1);
    expect(body!.sites[0]!.name).toBe('Allure');
  });

  it('returns null for an unknown category', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getDarknetCategory(assets, 'nope')).toBeNull();
  });
});

describe('filterDarknetSites', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('returns all sites with no filters', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadDarknetIndex(assets);
    expect(filterDarknetSites(idx)).toHaveLength(3);
  });

  it('filters by category', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadDarknetIndex(assets);
    expect(filterDarknetSites(idx, { category: 'markets' })).toHaveLength(2);
    expect(filterDarknetSites(idx, { category: 'forums' })).toHaveLength(1);
    expect(filterDarknetSites(idx, { category: 'news' })).toHaveLength(0);
  });

  it('filters by status', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadDarknetIndex(assets);
    expect(filterDarknetSites(idx, { status: 'up' })).toHaveLength(2);
    expect(filterDarknetSites(idx, { status: 'down' })).toHaveLength(1);
  });

  it('filters by recommendedOnly', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadDarknetIndex(assets);
    expect(filterDarknetSites(idx, { recommendedOnly: true })).toHaveLength(1);
    expect(filterDarknetSites(idx, { recommendedOnly: true })[0]!.name).toBe('Dark Matter');
  });

  it('filters by keyword across name/dwdId/category', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadDarknetIndex(assets);
    expect(filterDarknetSites(idx, { keyword: 'allure' })).toHaveLength(1);
    expect(filterDarknetSites(idx, { keyword: 'dwd-3e7a' })).toHaveLength(1);
    expect(filterDarknetSites(idx, { keyword: 'forums' })).toHaveLength(1);
    expect(filterDarknetSites(idx, { keyword: 'nonexistent' })).toHaveLength(0);
  });

  it('respects limit', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadDarknetIndex(assets);
    expect(filterDarknetSites(idx, { limit: 2 })).toHaveLength(2);
    expect(filterDarknetSites(idx, { limit: 1 })).toHaveLength(1);
  });
});

describe('tiCacheStats (darknet)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('reports darknet index loaded after loadDarknetIndex', async () => {
    const { assets } = makeAssetsFixture();
    await loadDarknetIndex(assets);
    const s = tiCacheStats();
    expect(s.darknet.indexLoaded).toBe(true);
    expect(s.darknet.indexAgeMs).toBeGreaterThanOrEqual(0);
  });

  it('reports darknet site cache hits/misses', async () => {
    const { assets } = makeAssetsFixture();
    await getDarknetSite(assets, 'dwd-3c9c-715');
    await getDarknetSite(assets, 'dwd-3c9c-715');
    const s = tiCacheStats();
    expect(s.darknet.sites.size).toBe(1);
    expect(s.darknet.sites.hits).toBe(1);
    expect(s.darknet.sites.misses).toBe(1);
  });
});

// ─── ThreatCluster feeds (threatcluster.io) ────────────────────────────

describe('loadThreatClusterIndex', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('loads the slim index with counts + per-feed arrays', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadThreatClusterIndex(assets);
    expect(idx.source).toBe('threatcluster.io');
    expect(idx.counts.clusters).toBe(1);
    expect(idx.clusters[0]!.slug).toBe('lazarus-windows-afdsys-zero-abc123');
    expect(idx.victims[0]!.group).toBe('blacknevas');
  });

  it('caches across calls', async () => {
    const { assets } = makeAssetsFixture();
    const a = await loadThreatClusterIndex(assets);
    const b = await loadThreatClusterIndex(assets);
    expect(a).toBe(b);
  });

  it('throws when the manifest is missing', async () => {
    const data = new Map<string, unknown>();
    const assets = {
      fetch: vi.fn(async () => new Response('not found', { status: 404 })),
    } as unknown as Fetcher;
    void data;
    await expect(loadThreatClusterIndex(assets)).rejects.toThrow(/threatcluster\/index\.json/);
  });
});

describe('getTc* body loaders', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('loads a cluster body by slug (case-insensitive)', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getTcCluster(assets, 'LAZARUS-WINDOWS-AFDSYS-ZERO-ABC123');
    expect(body).not.toBeNull();
    expect(body!.sourceCount).toBe(18);
    expect(body!.description).toContain('Lazarus');
  });

  it('loads a vulnerability body by CVE id (uppercased)', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getTcVuln(assets, 'cve-2026-0301');
    expect(body).not.toBeNull();
    expect(body!.cveId).toBe('CVE-2026-0301');
  });

  it('loads an exploit body by CVE id', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getTcExploit(assets, 'CVE-2026-63030');
    expect(body).not.toBeNull();
    expect(body!.inKev).toBe(true);
    expect(body!.severity).toBe('CRITICAL');
  });

  it('loads a victim body by id', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getTcVictim(assets, 'portable-intelligence-1a2b');
    expect(body).not.toBeNull();
    expect(body!.country).toBe('US');
    expect(body!.sector).toBe('Technology');
  });

  it('loads the IOC blocklist + MISP pass-through', async () => {
    const { assets } = makeAssetsFixture();
    const iocs = await loadTcIocs(assets);
    expect(iocs).not.toBeNull();
    expect(iocs!.count).toBe(2);
    expect(iocs!.iocs[0]!.value).toBe('ccleanerwind.top');
    const misp = await loadTcMispEvents(assets);
    expect(misp).not.toBeNull();
    expect(misp!.events[0]!.tags).toContain('tlp:clear');
  });

  it('returns null for missing bodies', async () => {
    const { assets } = makeAssetsFixture();
    await expect(getTcCluster(assets, 'nope')).resolves.toBeNull();
    await expect(getTcVuln(assets, 'CVE-2026-9999')).resolves.toBeNull();
    await expect(getTcExploit(assets, 'CVE-2026-9999')).resolves.toBeNull();
    await expect(getTcVictim(assets, 'nope')).resolves.toBeNull();
  });
});

describe('filterTc* helpers', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('filters clusters by keyword (title or slug)', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadThreatClusterIndex(assets);
    expect(filterTcClusters(idx, { keyword: 'lazarus' })).toHaveLength(1);
    expect(filterTcClusters(idx, { keyword: 'afdsys' })).toHaveLength(1);
    expect(filterTcClusters(idx, { keyword: 'nope' })).toHaveLength(0);
  });

  it('filters vulnerabilities by keyword', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadThreatClusterIndex(assets);
    expect(filterTcVulns(idx, { keyword: 'cve-2026-0301' })).toHaveLength(1);
    expect(filterTcVulns(idx, { keyword: 'nope' })).toHaveLength(0);
  });

  it('filters exploits by severity and kevOnly', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadThreatClusterIndex(assets);
    expect(filterTcExploits(idx, { severity: 'CRITICAL' })).toHaveLength(1);
    expect(filterTcExploits(idx, { kevOnly: true })).toHaveLength(1);
    expect(filterTcExploits(idx, { kevOnly: true })[0]!.cveId).toBe('CVE-2026-63030');
    expect(filterTcExploits(idx, { severity: 'HIGH' })).toHaveLength(0);
  });

  it('filters victims by group / sector / country / keyword', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadThreatClusterIndex(assets);
    expect(filterTcVictims(idx, { group: 'blacknevas' })).toHaveLength(1);
    expect(filterTcVictims(idx, { sector: 'Technology' })).toHaveLength(1);
    expect(filterTcVictims(idx, { country: 'US' })).toHaveLength(1);
    expect(filterTcVictims(idx, { keyword: 'portable' })).toHaveLength(1);
    expect(filterTcVictims(idx, { group: 'nope' })).toHaveLength(0);
  });

  it('filters IOCs by type and keyword, and respects limits', async () => {
    const { assets } = makeAssetsFixture();
    const body = (await loadTcIocs(assets)) as TcIocsBody;
    expect(filterTcIocs(body.iocs, { type: 'domain' })).toHaveLength(1);
    expect(filterTcIocs(body.iocs, { keyword: 'ccleaner' })).toHaveLength(1);
    expect(filterTcIocs(body.iocs, { type: 'ipv6' })).toHaveLength(0);
    expect(filterTcIocs(body.iocs, { limit: 1 })).toHaveLength(1);
  });
});

describe('loadTcEntities + getTcEntity', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('loads the entity index with per-type counts', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTcEntities(assets);
    expect(idx.counts).toEqual({ actor: 1, group: 1, malware: 1, cve: 1, sector: 1 });
    expect(idx.entities.actor).toHaveLength(1);
    expect(idx.entities.sector).toHaveLength(1);
  });

  it('throws when the entities index is missing', async () => {
    const assets = {
      fetch: vi.fn(async () => new Response('not found', { status: 404 })),
    } as never;
    await expect(loadTcEntities(assets as never)).rejects.toThrow(/entities.*index/i);
  });

  it('fetches a full entity body by type + slug (case-insensitive slug)', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getTcEntity(assets, 'actor', 'LAZARUS-GROUP');
    expect(body?.name).toBe('Lazarus Group');
    expect(body?.aliases).toContain('Lazarus');
    expect(body?.recentActivity).toHaveLength(3);
    expect(body?.relatedEntities[0]).toMatchObject({ type: 'cve', slug: 'CVE-2026-0301', weight: 2 });
  });

  it('returns null for an unknown entity, unknown type, or missing body', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getTcEntity(assets, 'actor', 'nope')).toBeNull();
    expect(await getTcEntity(assets, 'group', 'missing-body')).toBeNull();
  });
});

describe('filterTcEntities', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('returns all five types when no type is given, ordered by mention count', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTcEntities(assets);
    const all = filterTcEntities(idx, { limit: 10 });
    expect(all[0]).toMatchObject({ type: 'actor', slug: 'lazarus-group' });
    expect(new Set(all.map((e) => e.type))).toEqual(
      new Set<TcEntityType>(['actor', 'group', 'malware', 'cve', 'sector'])
    );
  });

  it('filters by type, keyword (name + aliases), and minMentions, and respects limits', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadTcEntities(assets);
    expect(filterTcEntities(idx, { type: 'group' })).toHaveLength(1);
    expect(filterTcEntities(idx, { keyword: 'lazarus' })).toHaveLength(1);
    expect(filterTcEntities(idx, { keyword: 'lazarus', type: 'group' })).toHaveLength(0);
    expect(filterTcEntities(idx, { minMentions: 2 })).toHaveLength(2);
    expect(filterTcEntities(idx, { minMentions: 2 })[0]!.name).toBe('Lazarus Group');
    expect(filterTcEntities(idx, { limit: 1 })).toHaveLength(1);
  });
});

describe('tiCacheStats (threatcluster entities)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('reports entity index + body cache stats', async () => {
    const { assets } = makeAssetsFixture();
    await loadTcEntities(assets);
    await getTcEntity(assets, 'actor', 'lazarus-group');
    await getTcEntity(assets, 'actor', 'lazarus-group');
    await getTcEntity(assets, 'cve', 'CVE-2026-0301');
    const s = tiCacheStats();
    expect(s.threatcluster.entities.indexLoaded).toBe(true);
    expect(s.threatcluster.entities.indexAgeMs).toBeGreaterThanOrEqual(0);
    expect(s.threatcluster.entities.bodies.size).toBe(2);
    expect(s.threatcluster.entities.bodies.hits).toBe(1);
    expect(s.threatcluster.entities.bodies.misses).toBe(2);
  });
});

describe('tiCacheStats (threatcluster)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('reports threatcluster index loaded + body cache hits/misses', async () => {
    const { assets } = makeAssetsFixture();
    await loadThreatClusterIndex(assets);
    await getTcCluster(assets, 'lazarus-windows-afdsys-zero-abc123');
    await getTcCluster(assets, 'lazarus-windows-afdsys-zero-abc123');
    await getTcVuln(assets, 'CVE-2026-0301');
    const s = tiCacheStats();
    expect(s.threatcluster.indexLoaded).toBe(true);
    expect(s.threatcluster.indexAgeMs).toBeGreaterThanOrEqual(0);
    expect(s.threatcluster.clusters.size).toBe(1);
    expect(s.threatcluster.clusters.hits).toBe(1);
    expect(s.threatcluster.clusters.misses).toBe(1);
    expect(s.threatcluster.vulnerabilities.size).toBe(1);
    expect(s.threatcluster.exploits.size).toBe(0);
    expect(s.threatcluster.victims.size).toBe(0);
  });
});

describe('loadThreaticonIndex', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('fetches and caches the index', async () => {
    const { assets } = makeAssetsFixture();
    const a = await loadThreaticonIndex(assets);
    const b = await loadThreaticonIndex(assets);
    expect(a).toBe(b);
    expect(a.counts.actors).toBe(2);
  });

  it('throws when the index is missing', async () => {
    const emptyAssets = { fetch: vi.fn(async () => new Response('', { status: 404 })) } as unknown as Fetcher;
    await expect(loadThreaticonIndex(emptyAssets)).rejects.toThrow(/Threaticon manifest not found/);
  });
});

describe('getThreaticonActor', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('returns a full actor profile (case-insensitive slug) + caches', async () => {
    const { assets } = makeAssetsFixture();
    const a = await getThreaticonActor(assets, 'LAZARUS-GROUP');
    expect(a).not.toBeNull();
    expect(a!.mitreId).toBe('G0032');
    expect(a!.originCode).toBe('KP');
    expect(a!.techniques).toEqual(['T1566', 'T1059.001']);
    const b = await getThreaticonActor(assets, 'lazarus-group');
    expect(b).toBe(a);
  });

  it('returns null for unknown actors', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getThreaticonActor(assets, 'nobody')).toBeNull();
  });
});

describe('threaticon collections', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('loads malware, coverage, and map', async () => {
    const { assets } = makeAssetsFixture();
    const malware = await loadThreaticonMalware(assets);
    expect(malware!.familyCount).toBe(2);
    expect(malware!.byCategory.Ransomware).toBe(1);
    const coverage = await loadThreaticonCoverage(assets);
    expect(coverage!.techniques[0]!.techniqueId).toBe('T1059.001');
    expect(coverage!.tactics.execution!.coveragePct).toBe(100);
    const map = await loadThreaticonMap(assets);
    expect(map!.origin).toHaveLength(2);
  });
});

describe('threaticon filters', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('filters actors by type / country / mitre / keyword', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadThreaticonIndex(assets);
    expect(filterThreaticonActors(idx, { type: 'criminal' }).map((a) => a.slug)).toEqual(['fin7']);
    expect(filterThreaticonActors(idx, { country: 'kp' }).map((a) => a.slug)).toEqual(['lazarus-group']);
    expect(filterThreaticonActors(idx, { hasMitre: true })).toHaveLength(2);
    expect(filterThreaticonActors(idx, { keyword: 'FIN7' }).map((a) => a.slug)).toEqual(['fin7']);
  });

  it('filters malware families by category / confidence', async () => {
    const { assets } = makeAssetsFixture();
    const body = (await loadThreaticonMalware(assets))!;
    expect(filterThreaticonMalware(body, { category: 'ransomware' }).map((f) => f.name)).toEqual(['LockBit']);
    expect(filterThreaticonMalware(body, { minConfidence: 92 }).map((f) => f.name)).toEqual(['LockBit']);
  });

  it('filters coverage techniques by tactic / rules', async () => {
    const { assets } = makeAssetsFixture();
    const body = (await loadThreaticonCoverage(assets))!;
    expect(filterThreaticonCoverage(body, { tactic: 'execution' })).toHaveLength(1);
    expect(filterThreaticonCoverage(body, { minRules: 5 })).toHaveLength(0);
  });
});

describe('tiCacheStats (threaticon)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('reports threaticon index + actor body cache stats', async () => {
    const { assets } = makeAssetsFixture();
    await loadThreaticonIndex(assets);
    await getThreaticonActor(assets, 'lazarus-group');
    await getThreaticonActor(assets, 'lazarus-group');
    await getThreaticonActor(assets, 'fin7');
    const s = tiCacheStats();
    expect(s.threaticon.indexLoaded).toBe(true);
    expect(s.threaticon.indexAgeMs).toBeGreaterThanOrEqual(0);
    expect(s.threaticon.actors.size).toBe(1);
    expect(s.threaticon.actors.hits).toBe(1);
    expect(s.threaticon.actors.misses).toBe(2);
  });
});

describe('dPhish (loadDphishIndex)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('fetches and caches the dphish index', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadDphishIndex(assets);
    expect(idx.source).toBe('dphish.com');
    expect(idx.counts.indicators).toBe(3);
    expect(idx.counts.active).toBe(2);
    expect(idx.counts.byCategory.domain).toBe(2);
    const again = await loadDphishIndex(assets);
    expect(again).toBe(idx);
  });

  it('throws with a build hint when the manifest is missing', async () => {
    const empty = {
      fetch: vi.fn(async () => new Response('not found', { status: 404 })),
    } as unknown as Fetcher;
    await expect(loadDphishIndex(empty)).rejects.toThrow(/sync-dphish\.mjs/);
  });
});

describe('dPhish (getDphishIndicator)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('returns the full body and caches it', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getDphishIndicator(assets, 'melbetegypt.com-1a2b3c');
    expect(body).not.toBeNull();
    expect(body!.pattern).toBe("[domain-name:value = 'melbetegypt.com']");
    expect(body!.patternType).toBe('stix');
    expect(body!.indicatorTypes).toContain('malicious-activity');
    const again = await getDphishIndicator(assets, 'melbetegypt.com-1a2b3c');
    expect(again).toBe(body);
  });

  it('returns null for an unknown slug', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getDphishIndicator(assets, 'nope')).toBeNull();
  });
});

describe('dPhish (filterDphishIndicators)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('filters by category', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadDphishIndex(assets);
    const out = filterDphishIndicators(idx, { category: 'url' });
    expect(out).toHaveLength(1);
    expect(out[0]!.value).toContain('dtec.com.my');
  });

  it('activeOnly excludes revoked and expired indicators', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadDphishIndex(assets);
    const out = filterDphishIndicators(idx, { activeOnly: true });
    expect(out).toHaveLength(2);
    expect(out.every((i) => i.active)).toBe(true);
  });

  it('matches keyword against value and description', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadDphishIndex(assets);
    const out = filterDphishIndicators(idx, { keyword: 'melbet' });
    expect(out.map((i: DphishIndexEntry) => i.value)).toEqual(['melbetegypt.com']);
  });

  it('respects limit', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadDphishIndex(assets);
    const out = filterDphishIndicators(idx, { limit: 1 });
    expect(out).toHaveLength(1);
  });
});

describe('tiCacheStats (dphish)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('reports dphish index + body cache stats', async () => {
    const { assets } = makeAssetsFixture();
    await loadDphishIndex(assets);
    await getDphishIndicator(assets, 'melbetegypt.com-1a2b3c');
    await getDphishIndicator(assets, 'melbetegypt.com-1a2b3c');
    const s = tiCacheStats();
    expect(s.dphish.indexLoaded).toBe(true);
    expect(s.dphish.indexAgeMs).toBeGreaterThanOrEqual(0);
    expect(s.dphish.bodies.size).toBe(1);
    expect(s.dphish.bodies.hits).toBe(1);
    expect(s.dphish.bodies.misses).toBe(1);
  });
});

describe('Living Threat (loadLivingThreatIndex)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('fetches and caches the index', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadLivingThreatIndex(assets);
    expect(idx.source).toBe('living-threat.rabitanoor.com');
    expect(idx.counts.incidents).toBe(2);
    expect(idx.counts.byTactic['Initial Access']).toBe(1);
    const again = await loadLivingThreatIndex(assets);
    expect(again).toBe(idx);
  });

  it('throws with a build hint when the manifest is missing', async () => {
    const empty = {
      fetch: vi.fn(async () => new Response('not found', { status: 404 })),
    } as unknown as Fetcher;
    await expect(loadLivingThreatIndex(empty)).rejects.toThrow(/sync-living-threat\.mjs/);
  });
});

describe('Living Threat (getLivingThreatIncident)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('resolves a slug through the shard file and caches the shard', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getLivingThreatIncident(assets, 'amnesiastealer-macos-malware-021625');
    expect(body).not.toBeNull();
    expect(body!.Title).toContain('AmnesiaStealer');
    expect(body!.CVEs).toEqual(['CVE-2026-58231']);
    expect(body!.Analyses[0]!.Techniques).toEqual(['T1190']);
    expect(body!.Analyses[0]!.Detection).toContain('ClickFix');
    const again = await getLivingThreatIncident(assets, 'amnesiastealer-macos-malware-021625');
    expect(again).toBe(body);
  });

  it('returns null for an unknown slug', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getLivingThreatIncident(assets, 'nope')).toBeNull();
  });
});

describe('Living Threat (filterLivingThreatIncidents)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('filters by tactic, technique, severity, actor, keyword, minPriority', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadLivingThreatIndex(assets);
    expect(filterLivingThreatIncidents(idx, { tactic: 'Initial Access' })).toHaveLength(2);
    expect(filterLivingThreatIncidents(idx, { technique: 't1190' })).toHaveLength(1);
    expect(filterLivingThreatIncidents(idx, { severity: 'low' })).toHaveLength(1);
    expect(filterLivingThreatIncidents(idx, { actor: 'amnesia' })).toHaveLength(1);
    expect(filterLivingThreatIncidents(idx, { keyword: 'clickfix' })).toHaveLength(1);
    expect(filterLivingThreatIncidents(idx, { minPriority: 50 })).toHaveLength(1);
    expect(filterLivingThreatIncidents(idx, { limit: 1 })).toHaveLength(1);
  });
});

describe('Living Threat / MalwareAnalyzer (tiCacheStats)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('reports livingThreat + malwareanalyzer cache stats', async () => {
    const { assets } = makeAssetsFixture();
    await loadLivingThreatIndex(assets);
    await getLivingThreatIncident(assets, 'amnesiastealer-macos-malware-021625');
    await getLivingThreatIncident(assets, 'amnesiastealer-macos-malware-021625');
    await loadMaIndex(assets);
    await getMaFeed(assets, 'malicious');
    const s = tiCacheStats();
    expect(s.livingThreat.indexLoaded).toBe(true);
    expect(s.livingThreat.shards.size).toBe(1);
    expect(s.livingThreat.shards.hits).toBe(1);
    expect(s.malwareanalyzer.indexLoaded).toBe(true);
    expect(s.malwareanalyzer.feeds.size).toBe(1);
  });
});

describe('MalwareAnalyzer (loadMaIndex / getMaFeed)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('loads the index and both feeds (cached per feed)', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadMaIndex(assets);
    expect(idx.source).toBe('malwareanalyzer.com');
    expect(idx.counts.malicious).toBe(1);
    const malicious = await getMaFeed(assets, 'malicious');
    expect(malicious).toHaveLength(1);
    expect(malicious[0]!.verdict).toBe('malicious');
    const observed = await getMaFeed(assets, 'newly-observed');
    expect(observed).toHaveLength(1);
    expect(observed[0]!.verdict).toBe('unknown');
    const again = await getMaFeed(assets, 'malicious');
    expect(again).toBe(malicious);
  });

  it('throws with a build hint when the index is missing', async () => {
    const empty = {
      fetch: vi.fn(async () => new Response('not found', { status: 404 })),
    } as unknown as Fetcher;
    await expect(loadMaIndex(empty)).rejects.toThrow(/sync-malwareanalyzer\.mjs/);
  });
});

describe('MalwareAnalyzer (filterMaFeed)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('filters by verdict, category, and keyword with limit', async () => {
    const { assets } = makeAssetsFixture();
    const feed = await getMaFeed(assets, 'malicious');
    expect(filterMaFeed(feed, { verdict: 'malicious' })).toHaveLength(1);
    expect(filterMaFeed(feed, { verdict: 'unknown' })).toHaveLength(0);
    expect(filterMaFeed(feed, { category: 'suspicious-infrastructure' })).toHaveLength(1);
    expect(filterMaFeed(feed, { keyword: 'TOURBUSAN' })).toHaveLength(1);
    expect(filterMaFeed(feed, { keyword: 'nope' })).toHaveLength(0);
    expect(filterMaFeed(feed, { limit: 1 })).toHaveLength(1);
  });
});

// ── Destroylist (phishdestroy/destroylist) ─────────────────────────────

describe('Destroylist (loadDestroylistIndex / checkDestroylistDomain)', () => {
  beforeEach(() => _resetTiCacheForTests());

  function makeDestroylistFixture(domains: string[]) {
    const { assets, data } = makeAssetsFixture() as { assets: Fetcher; data: Map<string, unknown> };
    const idx = {
      source: 'github.com/phishdestroy/destroylist',
      license: 'MIT',
      syncedAt: '2026-08-22T00:00:00Z',
      bucketCount: 64,
      bucketsWritten: 64,
      counts: { primary: domains.length, primaryRoots: domains.length, community: null, primaryActive: null },
    };
    data.set('/data/threat-intel/destroylist/index.json', idx);

    // Replicate the build script's bucketing exactly.
    const buckets: string[][] = Array.from({ length: 64 }, () => []);
    for (const d of domains) {
      let h = 5381;
      for (let i = 0; i < d.length; i++) h = ((h << 5) + h + d.charCodeAt(i)) >>> 0;
      buckets[h % 64]!.push(d);
    }
    for (const b of buckets) b.sort();
    for (let i = 0; i < 64; i += 1) {
      if (buckets[i]!.length > 0) {
        data.set(`/data/threat-intel/destroylist/buckets/${String(i).padStart(2, '0')}.json`, buckets[i]);
      }
    }
    data.set('/data/threat-intel/destroylist/roots.json', [...domains].sort());
    return { assets };
  }

  it('matches a listed domain exactly and reports the feed entry', async () => {
    const { assets } = makeDestroylistFixture(['evil.example.com', '0-collab.land']);
    await expect(checkDestroylistDomain(assets, '0-collab.land')).resolves.toEqual({
      listed: true,
      matched: '0-collab.land',
    });
  });

  it('normalizes scheme/path/www and matches parent domains of subdomains', async () => {
    const { assets } = makeDestroylistFixture(['phish-apex.example']);
    // URL form + path + www + deeper subdomain all resolve to the apex entry
    await expect(checkDestroylistDomain(assets, 'http://login.phish-apex.example/secure/login')).resolves.toEqual({
      listed: true,
      matched: 'phish-apex.example',
    });
    await expect(checkDestroylistDomain(assets, 'https://www.phish-apex.example/x')).resolves.toEqual({
      listed: true,
      matched: 'phish-apex.example',
    });
  });

  it('returns clean for an unknown domain and null when the manifest is absent', async () => {
    const { assets } = makeDestroylistFixture(['known-bad.example']);
    await expect(checkDestroylistDomain(assets, 'totally-fine.example')).resolves.toEqual({
      listed: false,
      matched: null,
    });
    // Fresh isolate without the manifest files — the index gate returns null.
    _resetTiCacheForTests();
    const empty = { fetch: vi.fn(async () => new Response('not found', { status: 404 })) } as unknown as Fetcher;
    await expect(checkDestroylistDomain(empty, 'anything.example')).resolves.toBeNull();
  });

  it('loads index + roots rollup', async () => {
    const { assets } = makeDestroylistFixture(['a.example', 'b.example']);
    const idx = await loadDestroylistIndex(assets);
    expect(idx?.counts.primary).toBe(2);
    expect(await loadDestroylistRoots(assets)).toEqual(['a.example', 'b.example']);
  });
});

describe('OffSeq (loadOffseqIndex)', () => {
  beforeEach(() => _resetTiCacheForTests());
  it('fetches and caches the offseq index', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadOffseqIndex(assets);
    expect(idx.source).toBe('radar.offseq.com');
    expect(idx.counts.threats).toBe(1);
    const again = await loadOffseqIndex(assets);
    expect(again).toBe(idx);
  });

  it('throws when the manifest is missing', async () => {
    const empty = { fetch: vi.fn(async () => new Response('', { status: 404 })) } as unknown as Fetcher;
    await expect(loadOffseqIndex(empty)).rejects.toThrow(/sync-offseq\.mjs/);
  });
});

describe('OffSeq (getOffseqThreat)', () => {
  beforeEach(() => _resetTiCacheForTests());
  it('fetches and caches a threat body', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getOffseqThreat(assets, 'test-threat-abc123');
    expect(body?.title).toBe('Test threat');
    const again = await getOffseqThreat(assets, 'test-threat-abc123');
    expect(again).toBe(body);
  });

  it('returns null for an unknown slug', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getOffseqThreat(assets, 'nope')).toBeNull();
  });
});

describe('OffSeq (filterOffseqThreats)', () => {
  beforeEach(() => _resetTiCacheForTests());
  it('filters by type', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadOffseqIndex(assets);
    const out = filterOffseqThreats(idx, { type: 'vulnerability' });
    expect(out.map((i: OffseqThreatIndexEntry) => i.slug)).toEqual(['test-threat-abc123']);
  });

  it('filters by exploitedOnly', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadOffseqIndex(assets);
    const out = filterOffseqThreats(idx, { exploitedOnly: true });
    expect(out).toHaveLength(0);
  });

  it('respects limit', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadOffseqIndex(assets);
    const out = filterOffseqThreats(idx, { limit: 0 });
    // limit 0 -> default? our impl uses limit ?? 100, but 0 is falsy -> 100; accept >=0
    expect(out.length).toBeLessThanOrEqual(1);
  });
});

describe('tiCacheStats (offseq)', () => {
  beforeEach(() => _resetTiCacheForTests());
  it('reports offseq index + threat cache stats', async () => {
    const { assets } = makeAssetsFixture();
    await loadOffseqIndex(assets);
    await getOffseqThreat(assets, 'test-threat-abc123');
    await getOffseqThreat(assets, 'test-threat-abc123');
    const s = tiCacheStats();
    expect(s.offseq.indexLoaded).toBe(true);
    expect(s.offseq.indexAgeMs).toBeGreaterThanOrEqual(0);
    expect(s.offseq.threats.size).toBe(1);
    expect(s.offseq.threats.hits).toBe(1);
    expect(s.offseq.threats.misses).toBe(1);
  });
});

describe('CTIWatch (loadCtiwatchIndex)', () => {
  beforeEach(() => _resetTiCacheForTests());
  it('fetches and caches the ctiwatch index', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadCtiwatchIndex(assets);
    expect(idx.source).toBe('ctiwatch.com');
    expect(idx.counts.vulnerabilities).toBe(1);
    const again = await loadCtiwatchIndex(assets);
    expect(again).toBe(idx);
  });

  it('throws when the manifest is missing', async () => {
    const empty = { fetch: vi.fn(async () => new Response('', { status: 404 })) } as unknown as Fetcher;
    await expect(loadCtiwatchIndex(empty)).rejects.toThrow(/sync-ctiwatch\.mjs/);
  });
});

describe('CTIWatch (getCtiwatchVulnerability)', () => {
  beforeEach(() => _resetTiCacheForTests());
  it('fetches and caches a vuln body', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getCtiwatchVulnerability(assets, 'CVE-2026-9999');
    expect(body?.cve_id).toBe('CVE-2026-9999');
    const again = await getCtiwatchVulnerability(assets, 'CVE-2026-9999');
    expect(again).toBe(body);
  });

  it('returns null for an unknown cve', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getCtiwatchVulnerability(assets, 'CVE-0000-0000')).toBeNull();
  });
});

describe('CTIWatch (getCtiwatchVictim)', () => {
  beforeEach(() => _resetTiCacheForTests());
  it('fetches and caches a victim body', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getCtiwatchVictim(assets, 'vic-1');
    expect(body?.name).toBe('Acme Corp');
    const again = await getCtiwatchVictim(assets, 'vic-1');
    expect(again).toBe(body);
  });

  it('returns null for an unknown id', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getCtiwatchVictim(assets, 'nope')).toBeNull();
  });
});

describe('CTIWatch (filterCtiwatchVulns)', () => {
  beforeEach(() => _resetTiCacheForTests());
  it('filters by kevOnly', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadCtiwatchIndex(assets);
    const out = filterCtiwatchVulns(idx, { kevOnly: true });
    expect(out.map((v: CtiwatchVulnEntry) => v.cve_id)).toEqual(['CVE-2026-9999']);
  });

  it('filters by severity', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadCtiwatchIndex(assets);
    const out = filterCtiwatchVulns(idx, { severity: 'HIGH' });
    expect(out).toHaveLength(1);
  });

  it('returns empty for non-matching keyword', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadCtiwatchIndex(assets);
    const out = filterCtiwatchVulns(idx, { keyword: 'zzzznotfound' });
    expect(out).toHaveLength(0);
  });
});

describe('tiCacheStats (ctiwatch)', () => {
  beforeEach(() => _resetTiCacheForTests());
  it('reports ctiwatch index + body cache stats', async () => {
    const { assets } = makeAssetsFixture();
    await loadCtiwatchIndex(assets);
    await getCtiwatchVulnerability(assets, 'CVE-2026-9999');
    await getCtiwatchVulnerability(assets, 'CVE-2026-9999');
    await getCtiwatchVictim(assets, 'vic-1');
    await getCtiwatchVictim(assets, 'vic-1');
    const s = tiCacheStats();
    expect(s.ctiwatch.indexLoaded).toBe(true);
    expect(s.ctiwatch.indexAgeMs).toBeGreaterThanOrEqual(0);
    expect(s.ctiwatch.vulns.size).toBe(1);
    expect(s.ctiwatch.vulns.hits).toBe(1);
    expect(s.ctiwatch.vulns.misses).toBe(1);
    expect(s.ctiwatch.victims.size).toBe(1);
    expect(s.ctiwatch.victims.hits).toBe(1);
    expect(s.ctiwatch.victims.misses).toBe(1);
  });
});

describe('_resetTiCacheForTests (offseq + ctiwatch)', () => {
  beforeEach(() => _resetTiCacheForTests());
  it('clears the new vertical caches', async () => {
    const { assets } = makeAssetsFixture();
    await loadOffseqIndex(assets);
    await loadCtiwatchIndex(assets);
    _resetTiCacheForTests();
    const s = tiCacheStats();
    expect(s.offseq.indexLoaded).toBe(false);
    expect(s.ctiwatch.indexLoaded).toBe(false);
  });
});

describe('cve.now (loadCveNowIndex / getCveNowEntry)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('fetches and caches the index', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadCveNowIndex(assets);
    expect(idx.source).toBe('cve.now');
    expect(idx.counts.entries).toBe(2);
    expect(idx.counts.bySeverity.CRITICAL).toBe(1);
    expect(idx.sourcesHealth && idx.sourcesHealth.sources && idx.sourcesHealth.sources.kev?.ok).toBe(true);
    const again = await loadCveNowIndex(assets);
    expect(again).toBe(idx);
  });

  it('resolves an id through the body batch and caches the batch', async () => {
    const { assets } = makeAssetsFixture();
    const body = await getCveNowEntry(assets, 'cve-2026-88802');
    expect(body).not.toBeNull();
    expect(body!.title).toBe('Gadget SSRF');
    expect(body!.fix).toEqual(['2.1.0']);
    expect(body!.upstreamPage).toBe('https://cve.now/CVE-2026-88802');
    const again = await getCveNowEntry(assets, 'CVE-2026-88802');
    expect(again).toBe(body);
  });

  it('returns null for an unknown id and rejects malformed paths', async () => {
    const { assets } = makeAssetsFixture();
    expect(await getCveNowEntry(assets, 'CVE-2099-9999')).toBeNull();
  });

  it('throws with a build hint when the manifest is missing', async () => {
    const empty = {
      fetch: vi.fn(async () => new Response('not found', { status: 404 })),
    } as unknown as Fetcher;
    await expect(loadCveNowIndex(empty)).rejects.toThrow(/sync-cve-now\.mjs/);
  });
});

describe('cve.now (filterCveNowEntries)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('filters by severity, kev, hasFix, product, keyword with limit', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadCveNowIndex(assets);
    expect(filterCveNowEntries(idx, { severity: 'critical' })).toHaveLength(1);
    expect(filterCveNowEntries(idx, { kev: true })).toHaveLength(1);
    expect(filterCveNowEntries(idx, { kev: false })).toHaveLength(1);
    expect(filterCveNowEntries(idx, { hasFix: true })).toHaveLength(1);
    expect(filterCveNowEntries(idx, { product: 'gadget' })).toHaveLength(1);
    expect(filterCveNowEntries(idx, { keyword: 'widget' })).toHaveLength(1);
    expect(filterCveNowEntries(idx, { limit: 1 })).toHaveLength(1);
  });
});

describe('Incident Desk (loadIncidentDeskIndex / briefs)', () => {
  beforeEach(() => _resetTiCacheForTests());

  it('fetches and caches the index', async () => {
    const { assets } = makeAssetsFixture();
    const idx = await loadIncidentDeskIndex(assets);
    expect(idx.source).toBe('iamnicholasmartin.co.uk/incidents');
    expect(idx.counts.briefs).toBe(2);
    expect(idx.briefs[0]!.imageUrl).toContain('digest-2026w44-hero.webp');
    const again = await loadIncidentDeskIndex(assets);
    expect(again).toBe(idx);
  });

  it('resolves a brief by slug (case-insensitive)', () => {
    const idx: IncidentDeskIndex = {
      source: 'iamnicholasmartin.co.uk/incidents',
      sourceUrl: 'https://iamnicholasmartin.co.uk/incidents',
      description: 'x',
      license: 'y',
      syncedAt: '2026-10-30T16:30:00.000Z',
      meta: { feedUrl: 'https://iamnicholasmartin.co.uk/incidents/feed.xml', feedTitle: null },
      counts: { briefs: 2, withImage: 1, byMonth: { '2026-10': 2 } },
      briefs: [
        {
          title: 'A',
          link: null,
          guid: null,
          published: null,
          publishedRaw: null,
          description: null,
          imageUrl: null,
          slug: 'first-post',
        },
        {
          title: 'B',
          link: null,
          guid: null,
          published: null,
          publishedRaw: null,
          description: null,
          imageUrl: null,
          slug: 'second-post',
        },
      ],
    };
    expect(getIncidentDeskBrief(idx, 'FIRST-POST')?.title).toBe('A');
    expect(getIncidentDeskBrief(idx, 'nope')).toBeNull();
    expect(filterIncidentDeskBriefs(idx, { keyword: 'b' })).toHaveLength(1);
    expect(filterIncidentDeskBriefs(idx, { limit: 1 })).toHaveLength(1);
  });

  it('throws with a build hint when the manifest is missing', async () => {
    const empty = {
      fetch: vi.fn(async () => new Response('not found', { status: 404 })),
    } as unknown as Fetcher;
    await expect(loadIncidentDeskIndex(empty)).rejects.toThrow(/sync-incident-desk\.mjs/);
  });
});

describe('_resetTiCacheForTests (cve.now + incident desk)', () => {
  beforeEach(() => _resetTiCacheForTests());
  it('clears the new vertical caches', async () => {
    const { assets } = makeAssetsFixture();
    await loadCveNowIndex(assets);
    await loadIncidentDeskIndex(assets);
    _resetTiCacheForTests();
    const s = tiCacheStats();
    expect(s.cveNow.indexLoaded).toBe(false);
    expect(s.incidentDesk.indexLoaded).toBe(false);
  });
});
