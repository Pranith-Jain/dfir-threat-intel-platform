import { errMessage } from './err';
/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any */
/**
 * PROMPTVAULT — Community-driven AI prompt library.
 *
 * Edge-native prompt vault replicated from
 * https://h3ad-sec.github.io/PROMPTVAULT/. Prompts are stored in
 * D1 (BRIEFINGS_DB) and can be created, listed, fetched, rated, and
 * versioned. Ships with a small seed catalogue of SOC/DFIR prompts
 * so the route is useful on day one.
 *
 * Table: promptvault_entries
 *   id TEXT PK, slug TEXT UNIQUE, title TEXT, category TEXT,
 *   tags TEXT (JSON), author TEXT, version INT, body TEXT,
 *   rating_sum INT, rating_count INT, downloads INT,
 *   created_at TEXT, updated_at TEXT
 *
 * Exposed as:
 *   - MCP tools `si_promptvault_list`, `si_promptvault_get`,
 *     `si_promptvault_create`, `si_promptvault_rate`
 *   - REST  /api/v1/si/promptvault
 */

export interface EnvWithDb {
  BRIEFINGS_DB?: D1Database;
  ASSETS?: Fetcher;
}

export interface PromptVaultEntry {
  id: string;
  slug: string;
  title: string;
  category: string;
  tags: string[];
  author: string;
  version: number;
  body: string;
  ratingSum: number;
  ratingCount: number;
  downloads: number;
  createdAt: string;
  updatedAt: string;
  /** Computed on read: ratingSum / ratingCount rounded to 2 dp. */
  ratingAvg: number;
}

export interface CreatePromptInput {
  slug: string;
  title: string;
  category: string;
  tags?: string[];
  author: string;
  body: string;
}

export interface RatePromptInput {
  slug: string;
  rating: number; // 1..5
}

const ALLOWED_CATEGORIES = [
  'detection-engineering',
  'threat-hunting',
  'incident-response',
  'threat-intelligence',
  'malware-analysis',
  'cloud-security',
  'identity-security',
  'osint',
  'phishing-analysis',
  'reverse-engineering',
  'forensics',
  'governance',
  'general',
];

let schemaReady: Promise<void> | null = null;
const seedReady: Promise<void> | null = null;

const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function generateId(now: Date = new Date()): string {
  let ts = '';
  let t = now.getTime();
  for (let i = 0; i < 10; i++) {
    ts = B32[t % 32] + ts;
    t = Math.floor(t / 32);
  }
  let rand = '';
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  for (let i = 0; i < bytes.length; i++) rand += B32[bytes[i]! % 32];
  return `pv_${ts}${rand}`;
}

function ensureSchema(db: D1Database): Promise<void> {
  if (!schemaReady) {
    schemaReady = (async () => {
      await db
        .prepare(
          `CREATE TABLE IF NOT EXISTS promptvault_entries (
          id TEXT PRIMARY KEY,
          slug TEXT UNIQUE NOT NULL,
          title TEXT NOT NULL,
          category TEXT NOT NULL,
          tags TEXT NOT NULL DEFAULT '[]',
          author TEXT NOT NULL,
          version INTEGER NOT NULL DEFAULT 1,
          body TEXT NOT NULL,
          rating_sum INTEGER NOT NULL DEFAULT 0,
          rating_count INTEGER NOT NULL DEFAULT 0,
          downloads INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )`
        )
        .run();
      await db.prepare('CREATE INDEX IF NOT EXISTS idx_pv_category ON promptvault_entries(category)').run();
      await db.prepare('CREATE INDEX IF NOT EXISTS idx_pv_updated ON promptvault_entries(updated_at DESC)').run();
    })().catch((err) => {
      schemaReady = null;
      throw err;
    });
  }
  return schemaReady;
}

const SEED_PROMPTS: CreatePromptInput[] = [
  {
    slug: 'sigma-rule-from-narrative',
    title: 'Sigma rule from incident narrative',
    category: 'detection-engineering',
    tags: ['sigma', 'detection', 'kql', 'sentinel'],
    author: 'system',
    body: `You are a senior detection engineer. Given an incident narrative (paste below), output a Sigma rule in YAML that would have detected the malicious behaviour.

CONSTRAINTS:
- One rule per narrative. Do not split into multi-stage rules unless absolutely necessary.
- logsource.product and logsource.service MUST be filled.
- Use the most specific MITRE ATT&CK technique ID that fits.
- Provide a 'falsepositives:' block with 2-3 plausible benign scenarios.
- Use 'level:' from {informational, low, medium, high, critical}.
- Output only the YAML — no markdown fences, no commentary.

NARRATIVE:
{{narrative}}`,
  },
  {
    slug: 'kql-hunt-from-ioc',
    title: 'KQL hunt from a single IOC',
    category: 'threat-hunting',
    tags: ['kql', 'hunt', 'defender', 'sentinel'],
    author: 'system',
    body: `You are a threat hunter. Given a single IOC (IP, domain, URL, hash, or email), generate a Microsoft Defender / Sentinel KQL hunt that finds any activity involving that indicator across a 30-day window.

CONSTRAINTS:
- Use DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, SigninLogs, EmailEvents, or IdentityLogonEvents as appropriate.
- For network IOCs (IP/domain/URL), correlate the indicator with the process that initiated the connection.
- For hashes, walk the process tree 2 levels up to surface parent context.
- For emails, show sender, recipient, subject, and attachment info.
- Return a JSON object: {query: "..." , tables: ["..."], mitre: ["Txxxx"], explanation: "..."}.
- Output only the JSON. No prose.`,
  },
  {
    slug: 'phishing-email-triage',
    title: 'Phishing email triage',
    category: 'phishing-analysis',
    tags: ['phish', 'email', 'triage', 'verdict'],
    author: 'system',
    body: `You are a phishing triage analyst. Given a raw email (headers + body), produce a verdict in 60 seconds.

OUTPUT JSON with: {verdict: "phishing" | "spam" | "benign" | "suspicious", confidence: 0..100, key_signals: [string, ...], recommended_action: "block" | "monitor" | "deliver" | "quarantine", iocs: {ips:[], domains:[], urls:[], hashes:[], emails:[]}}.

CONSTRAINTS:
- The headers tell you the real story. Examine Authentication-Results, Received chain, and From/Return-Path mismatch.
- Brand impersonation = display name advertises one domain, address is another.
- Look for first-time sender + urgency + financial-action language as a high-signal combo.`,
  },
  {
    slug: 'incident-timeline-builder',
    title: 'Incident timeline builder',
    category: 'incident-response',
    tags: ['timeline', 'ir', 'forensic', 'chronology'],
    author: 'system',
    body: `You are a DFIR lead. Given an unordered set of events (logs, alerts, user reports), produce a chronological timeline with one row per minute-bucket.

OUTPUT Markdown table with columns: Timestamp (UTC ISO), Source, Action, Host, User, MITRE, Note.
Sort ascending. Group burst activity into a single row with 'count' prefix in Note.
Call out the first-seen indicator and the last-seen indicator in a separate '## Bounds' section.`,
  },
  {
    slug: 'ttp-extractor-from-report',
    title: 'TTP extractor from threat report',
    category: 'threat-intelligence',
    tags: ['mitre', 'att&ck', 'ttp', 'cti'],
    author: 'system',
    body: `You are a CTI analyst. Given a threat report (URL, PDF text, or pasted markdown), extract all MITRE ATT&CK techniques the actor uses.

OUTPUT JSON: { actor: string, first_observed: ISO_DATE, last_observed: ISO_DATE, techniques: [{id: "Txxxx[.yyy]", name: "...", evidence: "one-line quote from report", confidence: 0..100}], software: [string], iocs: {hashes: [], ips: [], domains: []} }.

CONSTRAINTS:
- Only include techniques the report explicitly describes. Do not infer.
- Use sub-technique IDs when the report is specific.
- 'confidence' reflects how directly the report attributes the technique to the actor.`,
  },
  {
    slug: 'sigma-tuning-fp-triage',
    title: 'Sigma rule false-positive triage',
    category: 'detection-engineering',
    tags: ['sigma', 'fp', 'tuning', 'fplens'],
    author: 'system',
    body: `You are a senior SOC detection engineer reviewing a Sigma rule. Given the rule YAML and (optionally) recent sample hits, decide:
1. Is the rule FP-prone in a typical enterprise environment?
2. List the 3 most likely benign scenarios that would trigger it.
3. Suggest 2-3 concrete exclusion filters (process paths, parent processes, user groups, scheduled tasks) that would reduce FP volume without losing TP coverage.
4. Provide a new 'falsepositives:' and 'filter:' block in YAML.

OUTPUT: {fp_risk_level: "HIGH"|"MEDIUM"|"LOW", rationale, exclusions: [...], updated_rule_yaml: "..."}`,
  },
  {
    slug: 'osint-domain-recon',
    title: 'OSINT domain reconnaissance',
    category: 'osint',
    tags: ['osint', 'recon', 'whois', 'dns', 'cert'],
    author: 'system',
    body: `You are an OSINT analyst. Given a single domain, generate a checklist of (1) passive lookups you would run, (2) expected signals of maliciousness, (3) queries to identify phishing / C2 / compromised-redirector, (4) correlations across certificate transparency + passive DNS + WHOIS history.

OUTPUT Markdown with sections:
- ## Passive lookups (table: tool, query, rationale)
- ## Threat signals (bulleted)
- ## Recommended next steps (prioritised)
- ## Pivot points (other domains / IPs / certs to chase)

CONSTRAINTS: Do NOT include active scanning instructions. No port scanning, no exploitation.`,
  },
  {
    slug: 'cloud-iam-least-priv',
    title: 'Cloud IAM least-privilege rewriter',
    category: 'cloud-security',
    tags: ['iam', 'aws', 'azure', 'gcp', 'least-privilege'],
    author: 'system',
    body: `You are a cloud security architect. Given a high-privilege IAM policy (paste below), produce a least-privilege rewrite that retains only the permissions the user / role demonstrably needs (from usage data if provided).

OUTPUT JSON: { original_actions: [...], used_actions_30d: [...], proposed_policy: "...", removed_actions: [...], added_constraints: ["condition keys, mfa_required, source_ip, etc."] }.

CONSTRAINTS:
- Prefer resource-level constraints over wildcard '*' where the usage data supports it.
- If usage data is missing, propose a 7-day CloudTrail / Activity Log observation window before final cutover.`,
  },
  {
    slug: 'malware-yara-from-behavior',
    title: 'YARA rule from malware behaviour',
    category: 'malware-analysis',
    tags: ['yara', 'malware', 'behaviour', 'detection'],
    author: 'system',
    body: `You are a malware analyst. Given a description of malware behaviour (strings, file operations, registry keys, network calls, mutexes), produce a YARA rule that would detect similar samples.

OUTPUT YAML rule with: meta (author, date, description, reference, hash_sample), strings (ascii / wide / hex as appropriate), condition (weighted Boolean for resilience).

CONSTRAINTS:
- Avoid overly generic strings ("Microsoft", "Windows", single-byte hex patterns).
- Use at least 3 distinct strings in the condition.
- Provide one comment line per string explaining why it was chosen.`,
  },
  {
    slug: 'briefing-summary-from-feed',
    title: 'Executive briefing summary from threat feed',
    category: 'threat-intelligence',
    tags: ['briefing', 'exec', 'summary', 'stix'],
    author: 'system',
    body: `You are a CTI briefing writer. Given a list of recent incidents / IOCs / advisories (paste below), produce a 1-paragraph executive summary (max 100 words) and a 5-bullet technical summary (max 25 words each).

CONSTRAINTS:
- Executive summary should be business-impact focused: "What does this mean for our business?"
- Technical summary should be SOC-actionable: which rules to update, which hunts to run, which mitigations to apply.
- Flag any item that warrants an immediate page (criticality, brand impact, regulatory exposure).`,
  },
];

async function ensureSeed(db: D1Database): Promise<void> {
  // Check if seeds are already inserted (idempotent: do nothing on repeat calls).
  const existing = await db.prepare('SELECT COUNT(*) as c FROM promptvault_entries').first();
  if (existing && (existing as { c: number }).c > 0) return;
  await ensureSchema(db);
  const stmt = db.prepare(
    `INSERT OR IGNORE INTO promptvault_entries
      (id, slug, title, category, tags, author, version, body, rating_sum, rating_count, downloads, created_at, updated_at)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, 0, 0, 0, ?8, ?8)`
  );
  const now = new Date().toISOString();
  for (const p of SEED_PROMPTS) {
    await stmt
      .bind(generateId(), p.slug, p.title, p.category, JSON.stringify(p.tags ?? []), p.author, p.body, now)
      .run();
  }
  const after = await db.prepare('SELECT COUNT(*) as c FROM promptvault_entries').first();
}

function rowToEntry(row: Record<string, unknown>): PromptVaultEntry {
  const sum = Number(row.rating_sum ?? 0);
  const cnt = Number(row.rating_count ?? 0);
  const tags = safeJsonArray(row.tags);
  return {
    id: String(row.id),
    slug: String(row.slug),
    title: String(row.title),
    category: String(row.category),
    tags,
    author: String(row.author),
    version: Number(row.version ?? 1),
    body: String(row.body),
    ratingSum: sum,
    ratingCount: cnt,
    downloads: Number(row.downloads ?? 0),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    ratingAvg: cnt > 0 ? Math.round((sum / cnt) * 100) / 100 : 0,
  };
}

function safeJsonArray(v: unknown): string[] {
  if (!v) return [];
  if (typeof v !== 'string') return [];
  try {
    const parsed = JSON.parse(v);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch (_catchErr) {
    console.error('safeJsonArray failed:', errMessage(_catchErr));
    return [];
  }
}

export async function promptVaultList(
  env: EnvWithDb,
  opts: { category?: string; tag?: string; q?: string; limit?: number } = {}
): Promise<PromptVaultEntry[]> {
  const db = env.BRIEFINGS_DB;
  if (!db) throw new Error('BRIEFINGS_DB D1 binding missing');
  await ensureSchema(db);
  await ensureSeed(db);
  const limit = Math.min(100, Math.max(1, opts.limit ?? 50));
  const conds: string[] = [];
  const binds: unknown[] = [];
  if (opts.category) {
    conds.push('category = ?');
    binds.push(opts.category);
  }
  if (opts.tag) {
    conds.push('tags LIKE ?');
    binds.push(`%"${opts.tag}"%`);
  }
  if (opts.q) {
    conds.push('(title LIKE ? OR body LIKE ? OR tags LIKE ?)');
    const q = `%${opts.q}%`;
    binds.push(q, q, q);
  }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const sql = `SELECT id, slug, title, category, tags, author, version, body, rating_sum, rating_count, downloads, created_at, updated_at FROM promptvault_entries ${where} ORDER BY updated_at DESC LIMIT ${limit}`;
  const res = (await db
    .prepare(sql)
    .bind(...binds)
    .all()) as any;
  return (res.results ?? []).map((r: Record<string, unknown>) => rowToEntry(r));
}

export async function promptVaultGet(env: EnvWithDb, slug: string): Promise<PromptVaultEntry | null> {
  const db = env.BRIEFINGS_DB;
  if (!db) throw new Error('BRIEFINGS_DB D1 binding missing');
  await ensureSchema(db);
  await ensureSeed(db);
  const row = await db
    .prepare(
      'SELECT id, slug, title, category, tags, author, version, body, rating_sum, rating_count, downloads, created_at, updated_at FROM promptvault_entries WHERE slug = ?1'
    )
    .bind(slug)
    .first();
  if (!row) return null;
  // Increment downloads (best-effort, fire-and-forget).
  void db
    .prepare('UPDATE promptvault_entries SET downloads = downloads + 1, updated_at = updated_at WHERE slug = ?1')
    .bind(slug)
    .run();
  return rowToEntry(row as Record<string, unknown>);
}

export async function promptVaultCreate(env: EnvWithDb, input: CreatePromptInput): Promise<PromptVaultEntry> {
  const db = env.BRIEFINGS_DB;
  if (!db) throw new Error('BRIEFINGS_DB D1 binding missing');
  if (!ALLOWED_CATEGORIES.includes(input.category)) {
    throw new Error(`Invalid category '${input.category}'. Allowed: ${ALLOWED_CATEGORIES.join(', ')}`);
  }
  if (!input.slug || !/^[a-z0-9][a-z0-9\-_]{1,63}$/.test(input.slug)) {
    throw new Error('slug must match /^[a-z0-9][a-z0-9-_]{1,63}$/');
  }
  if (!input.title || input.title.length > 200) throw new Error('title is required (≤200 chars)');
  if (!input.body || input.body.length > 32000) throw new Error('body is required (≤32KB)');
  if (!input.author || input.author.length > 64) throw new Error('author is required (≤64 chars)');
  await ensureSchema(db);
  const now = new Date().toISOString();
  const id = generateId();
  const tags = (input.tags ?? []).map(String).slice(0, 20);
  await db
    .prepare(
      `INSERT INTO promptvault_entries
        (id, slug, title, category, tags, author, version, body, rating_sum, rating_count, downloads, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, 0, 0, 0, ?8, ?8)`
    )
    .bind(id, input.slug, input.title, input.category, JSON.stringify(tags), input.author, input.body, now)
    .run();
  return {
    id,
    slug: input.slug,
    title: input.title,
    category: input.category,
    tags,
    author: input.author,
    version: 1,
    body: input.body,
    ratingSum: 0,
    ratingCount: 0,
    downloads: 0,
    createdAt: now,
    updatedAt: now,
    ratingAvg: 0,
  };
}

export async function promptVaultRate(env: EnvWithDb, input: RatePromptInput): Promise<PromptVaultEntry | null> {
  const db = env.BRIEFINGS_DB;
  if (!db) throw new Error('BRIEFINGS_DB D1 binding missing');
  if (input.rating < 1 || input.rating > 5 || !Number.isInteger(input.rating)) {
    throw new Error('rating must be an integer 1..5');
  }
  await ensureSchema(db);
  await ensureSeed(db);
  const existing = await db
    .prepare(
      'SELECT id, slug, title, category, tags, author, version, body, rating_sum, rating_count, downloads, created_at, updated_at FROM promptvault_entries WHERE slug = ?1'
    )
    .bind(input.slug)
    .first();
  if (!existing) return null;
  await db
    .prepare(
      'UPDATE promptvault_entries SET rating_sum = rating_sum + ?1, rating_count = rating_count + 1, updated_at = ?2 WHERE slug = ?3'
    )
    .bind(input.rating, new Date().toISOString(), input.slug)
    .run();
  const updated = await db
    .prepare(
      'SELECT id, slug, title, category, tags, author, version, body, rating_sum, rating_count, downloads, created_at, updated_at FROM promptvault_entries WHERE slug = ?1'
    )
    .bind(input.slug)
    .first();
  return updated ? rowToEntry(updated as Record<string, unknown>) : null;
}

export function promptVaultCategories(): string[] {
  return [...ALLOWED_CATEGORIES];
}
