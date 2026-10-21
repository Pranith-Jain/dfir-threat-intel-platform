import type { Context } from 'hono';
import type { Env } from '../env';
import { badRequest, serviceUnavailable } from '../lib/api-error';
import type { D1Database } from '@cloudflare/workers-types';
import { MITRE_TACTICS as MITRE_TACTIC_META } from '../lib/mitre-tactics';

/**
 * Attack Chain Reconstruction — map IOCs to MITRE ATT&CK kill chain.
 *
 * Given a set of IOCs, reconstruct the likely attack progression:
 *   1. Map each IOC to MITRE techniques
 *   2. Organize techniques by tactic (kill chain phase)
 *   3. Identify gaps and predict next moves
 *   4. Generate detection recommendations
 *
 * This turns flat IOC lists into actionable attack intelligence.
 */

// ── MITRE ATT&CK Framework ─────────────────────────────────────────────

interface MitreTactic {
  id: string;
  name: string;
  description: string;
  order: number; // Kill chain order
}

interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  detection: string;
  platforms: string[];
}

/**
 * The ATT&CK Enterprise tactics, in kill-chain order.
 *
 * Ids, names and order come from the generated tactic list (see
 * api/src/lib/mitre-tactics.ts) so they cannot drift from the matrix. The
 * short one-line descriptions are editorial and stay here.
 */
const TACTIC_DESCRIPTIONS: Record<string, string> = {
  reconnaissance: 'Gathering information for targeting',
  'resource-development': 'Establishing resources for operations',
  'initial-access': 'Gaining foothold in the network',
  execution: 'Running malicious code',
  persistence: 'Maintaining access',
  'privilege-escalation': 'Gaining higher permissions',
  stealth: 'Avoiding detection and hiding activity',
  'defense-impairment': 'Disabling defensive tooling and controls',
  'credential-access': 'Stealing credentials',
  discovery: 'Mapping the environment',
  'lateral-movement': 'Moving through the network',
  collection: 'Gathering data of interest',
  'command-and-control': 'Communicating with compromised systems',
  exfiltration: 'Stealing data',
  impact: 'Disrupting operations',
};

const MITRE_TACTICS: MitreTactic[] = MITRE_TACTIC_META.map((t) => ({
  id: t.id,
  name: t.name,
  description: TACTIC_DESCRIPTIONS[t.short_name] ?? '',
  order: t.order,
}));

// IOC pattern → technique mapping
const IOC_TECHNIQUE_MAP: Array<{
  pattern: RegExp;
  type: string;
  technique: string;
  tactic: string;
  confidence: number;
}> = [
  // Initial Access
  { pattern: /phish|spoof|fake/i, type: 'url', technique: 'T1566.002', tactic: 'TA0001', confidence: 80 },
  { pattern: /exploit|cve|vuln/i, type: 'domain', technique: 'T1190', tactic: 'TA0001', confidence: 75 },

  // Execution
  { pattern: /powershell|ps1|cmd/i, type: 'hash', technique: 'T1059.001', tactic: 'TA0002', confidence: 85 },
  { pattern: /javascript|js|vbs/i, type: 'hash', technique: 'T1059.007', tactic: 'TA0002', confidence: 80 },
  { pattern: /macro|office|doc/i, type: 'hash', technique: 'T1204.002', tactic: 'TA0002', confidence: 75 },

  // Persistence
  { pattern: /scheduled|task|schtasks/i, type: 'hash', technique: 'T1053.005', tactic: 'TA0003', confidence: 80 },
  { pattern: /registry|run.*key/i, type: 'hash', technique: 'T1547.001', tactic: 'TA0003', confidence: 85 },
  { pattern: /service|svchost/i, type: 'hash', technique: 'T1543.003', tactic: 'TA0003', confidence: 75 },

  // Defense Evasion
  { pattern: /obfuscat|encode|pack/i, type: 'hash', technique: 'T1027', tactic: 'TA0005', confidence: 70 },
  { pattern: /inject|hollow/i, type: 'hash', technique: 'T1055', tactic: 'TA0005', confidence: 85 },

  // Credential Access
  { pattern: /mimikatz|credential|dump/i, type: 'hash', technique: 'T1003', tactic: 'TA0006', confidence: 90 },
  { pattern: /keylog|stealer/i, type: 'hash', technique: 'T1056.001', tactic: 'TA0006', confidence: 80 },

  // Command and Control
  { pattern: /cobalt|beacon|c2/i, type: 'ip', technique: 'T1071', tactic: 'TA0011', confidence: 85 },
  { pattern: /tor|onion|proxy/i, type: 'domain', technique: 'T1090', tactic: 'TA0011', confidence: 70 },

  // Exfiltration
  { pattern: /exfil|upload|transfer/i, type: 'ip', technique: 'T1041', tactic: 'TA0010', confidence: 75 },

  // Impact
  { pattern: /ransom|encrypt|lockbit|conti/i, type: 'hash', technique: 'T1486', tactic: 'TA0040', confidence: 90 },
  { pattern: /wiper|destroy|shred/i, type: 'hash', technique: 'T1485', tactic: 'TA0040', confidence: 85 },
];

// Known malware → technique mappings
const MALWARE_TECHNIQUES: Record<string, string[]> = {
  'cobalt strike': ['T1071', 'T1055', 'T1059.001', 'T1053.005'],
  mimikatz: ['T1003', 'T1558.003', 'T1550.002'],
  emotet: ['T1566.001', 'T1204.002', 'T1059.001', 'T1547.001'],
  trickbot: ['T1566.001', 'T1059.001', 'T1003', 'T1021.002'],
  lockbit: ['T1486', 'T1489', 'T1490', 'T1078'],
  conti: ['T1486', 'T1059.001', 'T1071', 'T1021.002'],
  lazarus: ['T1566.001', 'T1059.001', 'T1055', 'T1071'],
  apt28: ['T1566.001', 'T1059.001', 'T1003', 'T1071'],
  apt29: ['T1190', 'T1059.001', 'T1055', 'T1078'],
};

// ── Reconstruction Logic ────────────────────────────────────────────────

interface AttackChain {
  id: string;
  indicators: string[];
  tactics: Array<{
    tactic: MitreTactic;
    techniques: Array<{
      id: string;
      name: string;
      indicators: string[];
      confidence: number;
    }>;
    coverage: number; // 0-100
  }>;
  kill_chain_progress: number; // 0-100
  predicted_next: {
    tactic: MitreTactic;
    techniques: string[];
    rationale: string;
  } | null;
  gaps: string[];
  recommendations: Array<{
    action: string;
    priority: 'critical' | 'high' | 'medium' | 'low';
    technique: string;
  }>;
}

/**
 * Reconstruct attack chain from a set of IOCs.
 */
export async function reconstructAttackChain(
  db: D1Database,
  indicators: string[],
  context?: {
    actors?: string[];
    malware?: string[];
  }
): Promise<AttackChain> {
  const techniqueMap = new Map<string, { indicators: string[]; confidence: number }>();

  // Phase 1: Map IOCs to techniques
  for (const indicator of indicators) {
    const type = detectIndicatorType(indicator);

    // Check IOC patterns
    for (const mapping of IOC_TECHNIQUE_MAP) {
      if (mapping.type === type && mapping.pattern.test(indicator)) {
        addTechnique(techniqueMap, mapping.technique, indicator, mapping.confidence);
      }
    }
  }

  // Check against known IOCs in the database in ONE batched query. The old
  // per-indicator query inside the loop fired up to 500 D1 subrequests and
  // blew the Free-plan 50-subrequest/invocation cap. SELECT `indicator` too
  // so techniques stay attributed to the correct IOC.
  //
  // DEFENSIVE: the `ioc_techniques` table is optional (no migration creates it;
  // no writer populates it). If it doesn't exist, D1 throws SQLITE_ERROR which
  // would 500 the whole route and make `reconstruct_attack_chain` report 0%
  // success in the agent's tool-health. Treat a missing/erroring table as an
  // empty result so the route degrades gracefully to the IOC pattern matcher
  // + malware/actor technique maps above.
  const uniqueIndicators = [...new Set(indicators)];
  if (uniqueIndicators.length > 0) {
    try {
      const placeholders = uniqueIndicators.map(() => '?').join(',');
      const rows = await db
        .prepare(`SELECT indicator, technique_id FROM ioc_techniques WHERE indicator IN (${placeholders})`)
        .bind(...uniqueIndicators)
        .all<{ indicator: string; technique_id: string }>();
      for (const row of rows.results ?? []) {
        addTechnique(techniqueMap, row.technique_id, row.indicator, 70);
      }
    } catch {
      // Table missing or D1 unavailable — skip; the pattern-based mappings
      // above still produce a useful attack chain.
    }
  }

  // Phase 2: Add techniques from known malware/actors
  if (context?.malware) {
    for (const malware of context.malware) {
      const techniques = MALWARE_TECHNIQUES[malware.toLowerCase()] ?? [];
      for (const technique of techniques) {
        addTechnique(techniqueMap, technique, `malware:${malware}`, 85);
      }
    }
  }

  // Phase 3: Organize by tactic
  const tactics = MITRE_TACTICS.map((tactic) => {
    const tacticTechniques: AttackChain['tactics'][0]['techniques'] = [];

    for (const [techniqueId, data] of techniqueMap) {
      const technique = getTechniqueInfo(techniqueId);
      if (technique?.tactic === tactic.id) {
        tacticTechniques.push({
          id: techniqueId,
          name: technique.name,
          indicators: data.indicators,
          confidence: data.confidence,
        });
      }
    }

    return {
      tactic,
      techniques: tacticTechniques,
      coverage: tacticTechniques.length > 0 ? Math.min(100, tacticTechniques.length * 30) : 0,
    };
  });

  // Phase 4: Calculate kill chain progress
  const coveredTactics = tactics.filter((t) => t.coverage > 0).length;
  const killChainProgress = Math.round((coveredTactics / MITRE_TACTICS.length) * 100);

  // Phase 5: Predict next move
  const predictedNext = predictNextMove(tactics, context);

  // Phase 6: Identify gaps
  const gaps = identifyGaps(tactics);

  // Phase 7: Generate recommendations
  const recommendations = generateRecommendations(tactics, gaps);

  return {
    id: crypto.randomUUID(),
    indicators,
    tactics,
    kill_chain_progress: killChainProgress,
    predicted_next: predictedNext,
    gaps,
    recommendations,
  };
}

function addTechnique(
  map: Map<string, { indicators: string[]; confidence: number }>,
  technique: string,
  indicator: string,
  confidence: number
) {
  const existing = map.get(technique);
  if (existing) {
    existing.indicators.push(indicator);
    existing.confidence = Math.max(existing.confidence, confidence);
  } else {
    map.set(technique, { indicators: [indicator], confidence });
  }
}

function detectIndicatorType(indicator: string): string {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(indicator)) return 'ip';
  if (/^[a-fA-F0-9]{32,64}$/.test(indicator)) return 'hash';
  if (/^https?:\/\//.test(indicator)) return 'url';
  if (/^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/.test(indicator)) return 'domain';
  return 'unknown';
}

function getTechniqueInfo(id: string): MitreTechnique | null {
  // Simplified lookup - in production, load from MITRE dataset
  const techniques: Record<string, { name: string; tactic: string }> = {
    'T1566.001': { name: 'Spearphishing Attachment', tactic: 'TA0001' },
    'T1566.002': { name: 'Spearphishing Link', tactic: 'TA0001' },
    T1190: { name: 'Exploit Public-Facing Application', tactic: 'TA0001' },
    'T1059.001': { name: 'PowerShell', tactic: 'TA0002' },
    'T1059.007': { name: 'JavaScript', tactic: 'TA0002' },
    'T1204.002': { name: 'Malicious File', tactic: 'TA0002' },
    'T1053.005': { name: 'Scheduled Task', tactic: 'TA0003' },
    'T1547.001': { name: 'Registry Run Keys', tactic: 'TA0003' },
    'T1543.003': { name: 'Windows Service', tactic: 'TA0003' },
    T1027: { name: 'Obfuscated Files', tactic: 'TA0005' },
    T1055: { name: 'Process Injection', tactic: 'TA0005' },
    T1003: { name: 'OS Credential Dumping', tactic: 'TA0006' },
    'T1056.001': { name: 'Keylogging', tactic: 'TA0006' },
    T1071: { name: 'Application Layer Protocol', tactic: 'TA0011' },
    T1090: { name: 'Proxy', tactic: 'TA0011' },
    T1041: { name: 'Exfiltration Over C2', tactic: 'TA0010' },
    T1486: { name: 'Data Encrypted for Impact', tactic: 'TA0040' },
    T1485: { name: 'Data Destruction', tactic: 'TA0040' },
    'T1021.002': { name: 'SMB/Windows Admin Shares', tactic: 'TA0008' },
    'T1558.003': { name: 'Kerberoasting', tactic: 'TA0006' },
    'T1550.002': { name: 'Pass the Hash', tactic: 'TA0005' },
    T1489: { name: 'Service Stop', tactic: 'TA0040' },
    T1490: { name: 'Inhibit System Recovery', tactic: 'TA0040' },
    T1078: { name: 'Valid Accounts', tactic: 'TA0003' },
  };

  const info = techniques[id];
  if (!info) return null;

  return {
    id,
    name: info.name,
    tactic: info.tactic,
    description: '',
    detection: '',
    platforms: ['Windows', 'Linux', 'macOS'],
  };
}

function predictNextMove(
  tactics: AttackChain['tactics'],
  context?: { actors?: string[]; malware?: string[] }
): AttackChain['predicted_next'] {
  // Find the last tactic with coverage
  const coveredTactics = tactics.filter((t) => t.coverage > 0);
  if (coveredTactics.length === 0) return null;

  const lastCovered = coveredTactics[coveredTactics.length - 1];
  if (!lastCovered) return null;

  const nextTacticIndex = MITRE_TACTICS.findIndex((t) => t.id === lastCovered.tactic.id) + 1;

  if (nextTacticIndex >= MITRE_TACTICS.length || nextTacticIndex < 0) return null;

  const nextTactic = MITRE_TACTICS[nextTacticIndex];
  if (!nextTactic) return null;

  // Predict techniques based on context
  const predictedTechniques: string[] = [];
  let rationale = '';

  if (nextTactic.id === 'TA0002' && context?.malware?.some((m) => m.toLowerCase().includes('emotet'))) {
    predictedTechniques.push('T1059.001'); // PowerShell
    rationale = 'Emotet typically uses PowerShell for execution';
  } else if (nextTactic.id === 'TA0011') {
    predictedTechniques.push('T1071'); // C2 protocol
    rationale = 'After execution, attackers typically establish C2';
  } else if (nextTactic.id === 'TA0010') {
    predictedTechniques.push('T1041'); // Exfil over C2
    rationale = 'Data exfiltration typically follows collection';
  }

  return {
    tactic: nextTactic,
    techniques: predictedTechniques,
    rationale: rationale || `Next logical phase: ${nextTactic.name}`,
  };
}

function identifyGaps(tactics: AttackChain['tactics']): string[] {
  const gaps: string[] = [];

  // Check for critical gaps in the kill chain
  const hasInitialAccess = tactics.some((t) => t.tactic.id === 'TA0001' && t.coverage > 0);
  const hasExecution = tactics.some((t) => t.tactic.id === 'TA0002' && t.coverage > 0);
  const hasC2 = tactics.some((t) => t.tactic.id === 'TA0011' && t.coverage > 0);

  if (!hasInitialAccess) gaps.push('Missing initial access vector');
  if (!hasExecution && hasC2) gaps.push('Execution method unknown despite C2 detection');
  if (hasInitialAccess && !hasExecution) gaps.push('No execution artifacts detected - may be fileless');

  return gaps;
}

function generateRecommendations(tactics: AttackChain['tactics'], gaps: string[]): AttackChain['recommendations'] {
  const recommendations: AttackChain['recommendations'] = [];

  // Generate recommendations based on detected tactics
  for (const tactic of tactics) {
    if (tactic.coverage === 0) continue;

    switch (tactic.tactic.id) {
      case 'TA0001':
        recommendations.push({
          action: 'Block phishing domains and URLs at the email gateway',
          priority: 'high',
          technique: 'T1566',
        });
        break;
      case 'TA0002':
        recommendations.push({
          action: 'Constrain PowerShell execution policy and enable script block logging',
          priority: 'high',
          technique: 'T1059.001',
        });
        break;
      case 'TA0011':
        recommendations.push({
          action: 'Implement network segmentation and monitor outbound C2 traffic',
          priority: 'critical',
          technique: 'T1071',
        });
        break;
      case 'TA0040':
        recommendations.push({
          action: 'Ensure offline backups and test restoration procedures',
          priority: 'high',
          technique: 'T1486',
        });
        break;
    }
  }

  // Gap-based recommendations
  if (gaps.includes('Missing initial access vector')) {
    recommendations.push({
      action: 'Review email logs and web proxy for suspicious activity',
      priority: 'medium',
      technique: 'T1566',
    });
  }

  return recommendations;
}

// ── Route Handlers ──────────────────────────────────────────────────────

/** POST /api/v1/attack-chain/reconstruct */
export async function attackChainHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  const body = await c.req.json<{
    indicators: string[];
    actors?: string[];
    malware?: string[];
  }>();

  if (!body.indicators || body.indicators.length === 0) {
    return badRequest(c, 'indicators array required');
  }

  const db = c.env.BRIEFINGS_DB;
  if (!db) return serviceUnavailable(c, 'Database not configured');

  const chain = await reconstructAttackChain(db, body.indicators, {
    actors: body.actors,
    malware: body.malware,
  });

  return c.json(chain, 200, { 'Cache-Control': 'no-store' });
}

/** GET /api/v1/attack-chain/techniques — List all MITRE techniques */
export async function attackChainTechniquesHandler(c: Context<{ Bindings: Env }>): Promise<Response> {
  return c.json(
    {
      tactics: MITRE_TACTICS,
    },
    200,
    { 'Cache-Control': 'public, max-age=3600' }
  );
}
