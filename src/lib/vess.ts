/**
 * VESS (Vulnerability Exploitability Scoring System) prototype v4 data model.
 * Ported verbatim from https://www.isitwormable.com/ (inline calculator script,
 * inspected 2026-11-19). The upstream tool is a local-only calculator with no
 * API or CVE feed; this module keeps its question wording, weights, category
 * caps, extreme-restriction groups and scoring rules intact.
 *
 * VESS measures exploit difficulty, not impact or severity.
 */

export type Option = string[];
export type Question = [string, string, Option[]];

export interface Category {
  id: string;
  title: string;
  cap?: number;
  desc: string;
  dynamic?: boolean;
  questions?: Question[];
}

export interface TechnicalFamily {
  name: string;
  barriers: Array<[string, string, number]>;
}

export interface ExtremeGroup {
  id: string;
  title: string;
  description: string;
  fields: Array<[string, string, Option[]]>;
}

export type Answers = Record<string, string>;

export const WORKAROUND = [
  ['1', 'No demonstrated workaround'],
  ['0.75', 'Partial workaround'],
  ['0.5', 'Substantial, unreliable workaround'],
  ['0.25', 'Reliable with residual constraints'],
  ['0', 'Fully neutralized'],
];
export const CATS: Category[] = [
  {
    id: 'attack',
    title: '1. Attack surface and prerequisites',
    cap: 20,
    desc: 'Score only additional restrictions compared with otherwise vulnerable deployments. A normally exposed port or routinely supported configuration contributes zero.',
    questions: [
      [
        'vector',
        'Attack vector',
        [
          ['0', 'Remote / internet'],
          ['3', 'Adjacent network / LAN'],
          ['6', 'Local access'],
          ['8', 'Physical access'],
        ],
      ],
      [
        'auth',
        'Authentication',
        [
          ['0', 'None'],
          ['2', 'Ordinary user'],
          ['5', 'Privileged account'],
          ['7', 'Administrator'],
        ],
      ],
      [
        'config',
        'Additional configuration restriction',
        [
          ['0', 'Default or ordinary for the vulnerable deployment population'],
          ['2', 'Optional setting limits otherwise vulnerable deployments'],
          ['4', 'Rare non-default combination genuinely needed for exploit'],
        ],
      ],
      [
        'interaction',
        'User interaction',
        [
          ['0', 'None'],
          ['2', 'Passive interaction'],
          ['4', 'Active interaction'],
        ],
      ],
      [
        'exposure',
        'Port / service exposure relative to affected deployments',
        [
          ['0', 'Commonly reachable among vulnerable installations (even if the port is unusual)'],
          ['2', 'Unusually exposed / rare accessible deployment subset'],
        ],
      ],
    ],
  },
  {
    id: 'technical',
    title: '2. Vulnerability-specific technical barriers',
    cap: 35,
    desc: 'Only assess barriers essential to the claimed impact. A reliable, demonstrated workaround reduces the remaining points.',
    dynamic: true,
  },
  {
    id: 'reliability',
    title: '3. Exploit reliability',
    cap: 20,
    desc: 'Measure the observed or reasonably evidenced repeatability and failure consequences.',
    questions: [
      [
        'race',
        'Race condition',
        [
          ['0', 'None'],
          ['2', 'Attacker-controlled race'],
          ['5', 'Timing-sensitive race'],
          ['8', 'Unpredictable race'],
        ],
      ],
      [
        'attempts',
        'Attempts required',
        [
          ['0', 'One'],
          ['2', '2–10'],
          ['4', '11–100'],
          ['6', 'More than 100'],
        ],
      ],
      [
        'failure',
        'Failure consequence',
        [
          ['0', 'Request failure / no impact'],
          ['3', 'Process crash'],
          ['5', 'System crash'],
        ],
      ],
      [
        'restart',
        'Restart dependency',
        [
          ['0', 'None'],
          ['1', 'Automatic recovery'],
          ['4', 'Manual restart required'],
        ],
      ],
    ],
  },
  {
    id: 'network',
    title: '4. Network and resource requirements',
    cap: 10,
    desc: 'Ordinary network scoring is capped at 10 points. Extreme volume and throughput requirements receive additional points in Section 7, without double-counting correlated measurements.',
    questions: [
      [
        'protocol',
        'Protocol / request sequence',
        [
          ['0', 'Single request / packet'],
          ['1', 'Multiple ordered requests'],
          ['3', 'Complex protocol state'],
        ],
      ],
      [
        'volume',
        'Traffic volume required',
        [
          ['0', 'Under 1 MB / negligible'],
          ['2', '1–100 MB'],
          ['5', '100 MB–1 GB'],
          ['10', '1–10 GB'],
          ['15', '10–100 GB'],
          ['20', 'Over 100 GB'],
        ],
      ],
      [
        'concurrency',
        'Concurrency',
        [
          ['0', 'No unusual concurrency'],
          ['3', 'Hundreds of simultaneous connections'],
        ],
      ],
      [
        'latency',
        'Network latency sensitivity',
        [
          ['0', 'None'],
          ['3', 'Strict timing requirement'],
        ],
      ],
      [
        'position',
        'Network position',
        [
          ['0', 'Ordinary reachability'],
          ['4', 'Specialized network position required'],
        ],
      ],
    ],
  },
  {
    id: 'target',
    title: '5. Target-specific dependencies',
    cap: 10,
    desc: 'Identify conditions that reduce portability or require special target knowledge.',
    questions: [
      [
        'version',
        'Version specificity',
        [
          ['0', 'Broad vulnerable version range'],
          ['2', 'Exact version needed'],
        ],
      ],
      [
        'build',
        'Build-specific knowledge',
        [
          ['0', 'None'],
          ['3', 'Exact build details needed'],
        ],
      ],
      [
        'secret',
        'Target-specific address / secret',
        [
          ['0', 'None'],
          ['4', 'Specific address or secret required'],
        ],
      ],
      [
        'hardware',
        'Other hardware dependency (excluding CPU/ISA restrictions scored in memory corruption)',
        [
          ['0', 'None'],
          ['3', 'Specific non-CPU hardware configuration'],
        ],
      ],
      [
        'state',
        'Target state',
        [
          ['0', 'Ordinary target state'],
          ['4', 'Rare target state required'],
        ],
      ],
    ],
  },
  {
    id: 'steps',
    title: '6. Additional exploitation steps',
    cap: 5,
    desc: 'Record additional mandatory vulnerabilities or security-boundary crossings; do not count optional escalation.',
    questions: [
      [
        'chain',
        'Exploit chaining',
        [
          ['0', 'Standalone vulnerability'],
          ['3', 'One additional vulnerability required'],
          ['5', 'Multiple additional vulnerabilities required'],
        ],
      ],
      [
        'boundary',
        'Independent boundary crossing',
        [
          ['0', 'None'],
          ['5', 'Additional security boundary must be crossed'],
        ],
      ],
    ],
  },
];
export const TECHNICAL_FAMILIES: Record<string, TechnicalFamily> = {
  memory: {
    name: 'Memory corruption and control-flow defenses',
    barriers: [
      ['canary', 'Stack canaries / cookies', 4],
      ['safeseh', 'SafeSEH (Windows)', 3],
      ['aslr', 'ASLR', 5],
      ['nx', 'NX / DEP', 4],
      ['mte', 'Memory Tagging Extension (MTE)', 7],
      ['pac', 'Pointer Authentication (PAC)', 7],
      ['cfi', 'CFG / CFI / BTI', 5],
      ['cet', 'CET shadow stack', 6],
      ['heap', 'Heap allocator hardening', 5],
      ['primitive', 'Constrained read / write primitive requires additional manipulation', 5],
      ['cpuarch', 'Additional CPU architecture restriction beyond normally supported product CPUs', 3],
      [
        'cpufeature',
        'Selective CPU instruction-set extension needed within otherwise vulnerable targets (e.g., AVX-512 VBMI)',
        5,
      ],
    ],
  },
  disclosure: {
    name: 'Memory disclosure and sensitive-data extraction',
    barriers: [
      ['scope', 'Leak yields only constrained or non-sensitive memory', 6],
      ['placement', 'Target secret must be placed in readable memory region', 7],
      ['repeat', 'Repeated leakage needed to recover useful material', 5],
      ['decode', 'Disclosed memory requires substantial reconstruction / decoding', 5],
      ['bounds', 'Address, buffer size, or allocation boundaries constrain output', 5],
      ['lifetime', 'Sensitive data is present only during narrow timing window', 7],
      ['mitig', 'Memory isolation blocks access to desired data', 7],
    ],
  },
  fileread: {
    name: 'Arbitrary file read and path traversal',
    barriers: [
      ['roots', 'Reader is confined to a restricted directory or mount', 7],
      ['traverse', 'Path traversal / normalization defenses must be bypassed', 7],
      ['perm', 'Process file permissions block desired files', 7],
      ['path', 'Exact target path or identifier must be known', 4],
      ['format', 'File content is transformed, filtered, or truncated', 4],
      ['links', 'Symlink, virtual filesystem, or filesystem policy limits access', 6],
    ],
  },
  filewrite: {
    name: 'File write and arbitrary upload',
    barriers: [
      ['destination', 'Destination path cannot be freely selected', 6],
      ['content', 'Uploaded bytes are validated, rewritten, or restricted', 7],
      ['perm', 'Filesystem permissions prevent writing target file', 7],
      ['extension', 'Filename / extension / content-type restrictions', 5],
      ['execute', 'Executable payload or execution trigger requires separate step', 6],
      ['atomic', 'Existing file cannot be replaced / write is append-only', 4],
      ['quarantine', 'Uploaded file is quarantined or stored outside executable path', 6],
    ],
  },
  idor: {
    name: 'IDOR and broken object-level authorization',
    barriers: [
      ['ids', 'Object identifiers are unguessable or not discoverable', 7],
      ['tenant', 'Tenant isolation must be bypassed', 8],
      ['tokens', 'Per-object capability / signed link required', 8],
      ['binding', 'Ownership checks / secondary authorization constrain access', 7],
      ['enumeration', 'High-volume enumeration or probing required', 4],
      ['workflow', 'Object must reach a narrow application state', 5],
    ],
  },
  sqli: {
    name: 'SQL injection',
    barriers: [
      ['context', 'Injection context restricts statements or expressions', 7],
      ['blind', 'Only blind or inference-based SQL injection is possible', 6],
      ['waf', 'Input filtering / WAF / query validation must be bypassed', 5],
      ['dbpriv', 'Database account privileges restrict target operation', 8],
      ['stacked', 'Multi-statement execution / dangerous DB features unavailable', 5],
      ['extract', 'Significant extraction effort, delays, or output limitations', 5],
      ['dbspecific', 'Engine- or query-specific conditions required', 4],
    ],
  },
  nosqli: {
    name: 'NoSQL and query injection',
    barriers: [
      ['grammar', 'Operator / expression injection constrained by context', 7],
      ['schema', 'Schema validation or parameterized query layer obstructs payload', 7],
      ['perm', 'Database role limits requested operations', 8],
      ['blind', 'Only inference-based data extraction possible', 5],
      ['scope', 'Collection / tenant scope restricted', 7],
      ['format', 'Serialization and JSON shape restrict control', 5],
    ],
  },
  command: {
    name: 'OS command injection',
    barriers: [
      ['context', 'Shell / argument injection context is constrained', 8],
      ['filter', 'Metacharacter, encoding, or input validation restrictions', 7],
      ['blind', 'Blind command execution with no direct output', 5],
      ['sandbox', 'Command runs inside a restrictive sandbox', 7],
      ['priv', 'Execution identity lacks permissions for claimed impact', 7],
      ['egress', 'No usable output or outbound callback channel', 5],
    ],
  },
  ssrf: {
    name: 'Server-side request forgery',
    barriers: [
      ['dest', 'Destination allowlist / hostname restrictions', 8],
      ['scheme', 'Protocol and URL scheme restrictions', 6],
      ['network', 'Internal routing / firewall / egress access barriers', 8],
      ['response', 'Blind SSRF; response cannot be read directly', 6],
      ['redirect', 'Redirects / DNS rebinding constraints', 5],
      ['identity', 'Cloud credentials / identity endpoint access restricted', 7],
      ['method', 'HTTP method, headers, or request body cannot be controlled', 5],
    ],
  },
  xss: {
    name: 'Cross-site scripting',
    barriers: [
      ['context', 'HTML / JavaScript injection context is restrictive', 7],
      ['csp', 'Content Security Policy or Trusted Types must be bypassed', 8],
      ['delivery', 'Payload requires a victim to visit a special page', 4],
      ['origin', 'Origin or frame isolation prevents desired access', 7],
      ['cookies', 'HttpOnly / cookie or token access restrictions', 6],
      ['sink', 'Sanitization / encoding / framework defenses', 8],
      ['priv', 'Requires a specially privileged victim session', 5],
    ],
  },
  auth: {
    name: 'Authentication and session bypass',
    barriers: [
      ['secret', 'Valid secret, token, or session material required', 8],
      ['mfa', 'MFA / step-up authentication blocks the desired action', 8],
      ['binding', 'Session is device-, network-, or channel-bound', 7],
      ['expiry', 'Token lifetime or narrow validity window', 4],
      ['rate', 'Rate limits / lockouts constrain attempts', 5],
      ['state', 'Special login / recovery workflow state required', 6],
      ['proof', 'Additional authorization checks occur after login', 7],
    ],
  },
  deserialization: {
    name: 'Unsafe deserialization',
    barriers: [
      ['gadget', 'Suitable gadget chain must exist in the runtime', 8],
      ['types', 'Class / type allowlist or integrity checks', 8],
      ['format', 'Serialized format restricts attacker-controlled fields', 5],
      ['reach', 'Deserialization sink is reachable only in special workflow', 6],
      ['context', 'Deserialization runs with restricted capabilities', 7],
      ['deps', 'Requires exact library or dependency versions', 5],
    ],
  },
  xxe: {
    name: 'XML external entity',
    barriers: [
      ['dtd', 'DTD / external entity processing disabled or filtered', 8],
      ['resolver', 'Entity resolver restricted to allowlisted paths / schemes', 7],
      ['output', 'No direct channel to return expanded entity data', 6],
      ['perm', 'Parser lacks file or network permissions', 7],
      ['size', 'Expansion limits / parser quotas', 5],
      ['sink', 'User-controlled XML reaches parser only through special flow', 5],
    ],
  },
  csrf: {
    name: 'Cross-site request forgery',
    barriers: [
      ['tokens', 'Unpredictable anti-CSRF token required', 8],
      ['samesite', 'SameSite cookie / origin controls restrict cross-site requests', 8],
      ['headers', 'Custom headers or non-simple request required', 6],
      ['interaction', 'Additional victim confirmation necessary', 5],
      ['session', 'Victim must be authenticated with a specific privileged role', 5],
      ['workflow', 'Multiple state-changing steps must be coordinated', 5],
    ],
  },
  logic: {
    name: 'Business logic and workflow abuse',
    barriers: [
      ['sequence', 'Complex action or transaction ordering', 7],
      ['role', 'Specific object / role / tenant conditions', 8],
      ['limits', 'Quota, balance, or policy checks limit action', 7],
      ['race', 'Cross-service coordination or special state required', 6],
      ['validation', 'Server-side invariant / consistency checks', 8],
      ['rare', 'Rare account, product, or deployment state', 5],
    ],
  },
  crypto: {
    name: 'Cryptographic weakness',
    barriers: [
      ['key', 'Secret material / nonce / key reuse conditions required', 8],
      ['oracle', 'Encryption, signing, or verification oracle required', 8],
      ['samples', 'Large number of samples, ciphertexts, or queries needed', 6],
      ['params', 'Special cryptographic parameters / weak mode required', 7],
      ['compute', 'Substantial computation or specialized hardware required', 7],
      ['sidechannel', 'Precise side-channel measurements / noise reduction required', 8],
    ],
  },
  other: {
    name: 'General technical restrictions',
    barriers: [
      ['input', 'Attacker control over required input is constrained', 8],
      ['output', 'Useful output or feedback is limited', 6],
      ['condition', 'Unusual technical precondition must hold', 8],
      ['protection', 'Technical protection must be circumvented', 8],
      ['primitive', 'Capability is severely constrained', 8],
      ['chain', 'Specific protocol or implementation detail required', 6],
    ],
  },
};
export const METADATA: Category = {
  id: 'metadata',
  title: 'Assessment details',
  desc: 'Record the exploit outcome and the evidence supporting this score.',
  questions: [
    [
      'vclass',
      'Vulnerability class',
      [
        ['memory', 'Memory corruption / unsafe memory'],
        ['disclosure', 'Memory disclosure / Heartbleed-like'],
        ['fileread', 'Arbitrary file read / path traversal'],
        ['filewrite', 'File write / arbitrary upload'],
        ['idor', 'IDOR / broken object authorization'],
        ['sqli', 'SQL injection'],
        ['nosqli', 'NoSQL / query injection'],
        ['command', 'OS command injection'],
        ['ssrf', 'Server-side request forgery (SSRF)'],
        ['xss', 'Cross-site scripting (XSS)'],
        ['auth', 'Authentication / session bypass'],
        ['deserialization', 'Unsafe deserialization'],
        ['xxe', 'XML external entity (XXE)'],
        ['csrf', 'Cross-site request forgery (CSRF)'],
        ['logic', 'Business logic / workflow abuse'],
        ['crypto', 'Cryptographic weakness'],
        ['other', 'Other / unclassified'],
      ],
    ],
    [
      'impact',
      'Target impact',
      [
        ['0', 'Process denial of service'],
        ['1', 'System denial of service'],
        ['2', 'File read / information disclosure'],
        ['3', 'File write'],
        ['4', 'Executable file write'],
        ['5', 'Command execution'],
        ['6', 'Arbitrary code execution'],
        ['7', 'Privilege escalation'],
        ['8', 'Sandbox escape'],
        ['9', 'Other'],
        ['10', 'Credential or session disclosure'],
        ['11', 'Cross-tenant data access'],
        ['12', 'Database access / modification'],
        ['13', 'Arbitrary outbound network request'],
        ['14', 'Authentication / authorization bypass'],
      ],
    ],
    [
      'platform',
      'Platform',
      [
        ['0', 'Server'],
        ['1', 'Browser'],
        ['2', 'Phone / mobile'],
        ['3', 'Desktop'],
        ['4', 'Embedded'],
        ['5', 'Cloud service'],
        ['6', 'Other'],
      ],
    ],
    [
      'evidence',
      'Evidence level',
      [
        ['0', 'Not specified'],
        ['1', 'Demonstrated'],
        ['2', 'Theoretically supported'],
        ['3', 'Unknown'],
      ],
    ],
    [
      'observed',
      'Real-world exploitation evidence (context only; never changes VESS)',
      [
        ['0', 'Not assessed / unknown'],
        ['1', 'No documented successful compromise'],
        ['2', 'Probing or unsuccessful attempts reported'],
        ['3', 'Working exploit on lab / honeypot'],
        ['4', 'Confirmed compromise in real deployment'],
      ],
    ],
    [
      'path',
      'Mandatory exploit path',
      [
        ['0', 'Not specified'],
        ['1', 'Complete / demonstrated'],
        ['2', 'Blocked by unresolved prerequisite'],
        ['3', 'Incomplete assessment'],
      ],
    ],
  ],
};

export const EXTREME_GROUPS: ExtremeGroup[] = [
  {
    id: 'resources',
    title: 'Network, throughput and resource demands',
    description:
      'Use the largest single penalty among traffic, bandwidth, packet/connection counts, concurrency, target memory and heap grooming. These are frequently alternative measurements of the same burden.',
    fields: [
      [
        'minBandwidth',
        'Minimum sustained bandwidth',
        [
          ['0', 'Ordinary / no unusual minimum'],
          ['5', 'Over 100 Mbit/s'],
          ['10', 'Over 300 Mbit/s'],
          ['15', 'Over 1 Gbit/s'],
          ['20', 'Over 10 Gbit/s'],
        ],
      ],
      [
        'packetExtreme',
        'Required packet count',
        [
          ['0', 'Ordinary / unknown'],
          ['5', 'Over 100,000'],
          ['10', 'Over 1 million'],
          ['15', 'Over 10 million'],
          ['20', 'Over 100 million'],
        ],
      ],
      [
        'connectionExtreme',
        'Required connection count',
        [
          ['0', 'Ordinary / unknown'],
          ['5', 'Over 10,000'],
          ['10', 'Over 100,000'],
          ['20', 'Over 1 million'],
        ],
      ],
      [
        'concurrentExtreme',
        'Required simultaneous connections',
        [
          ['0', 'Ordinary / unknown'],
          ['5', 'Over 1,000'],
          ['10', 'Over 10,000'],
          ['20', 'Over 100,000'],
        ],
      ],
      [
        'memoryExtreme',
        'Target memory capacity required',
        [
          ['0', 'Ordinary / unknown'],
          ['5', 'At least 32 GB'],
          ['10', 'At least 128 GB'],
          ['20', 'At least 1 TB'],
        ],
      ],
      [
        'heapExtreme',
        'Required groomed allocations',
        [
          ['0', 'Ordinary / unknown'],
          ['5', 'Over 10,000'],
          ['10', 'Over 1 million'],
          ['20', 'Over 100 million'],
        ],
      ],
    ],
  },
  {
    id: 'timing',
    title: 'Execution time, attempts and race timing',
    description:
      'Use the highest retry, success-rate, timing, or uninterrupted-duration penalty. Correlated time and attempt restrictions are not stacked.',
    fields: [
      [
        'attemptExtreme',
        'Attempts beyond the ordinary range',
        [
          ['0', '100 or fewer / not applicable'],
          ['5', '101–1,000 attempts'],
          ['10', '1,001–10,000 attempts'],
          ['20', 'Over 10,000 attempts'],
        ],
      ],
      [
        'successExtreme',
        'Per-attempt success probability',
        [
          ['0', 'Unknown or at least 10%'],
          ['5', 'Below 10%'],
          ['10', 'Below 1%'],
          ['20', 'Below 0.1%'],
        ],
      ],
      [
        'raceExtreme',
        'Extreme race condition',
        [
          ['0', 'No special timing restriction'],
          ['5', 'Tight but attacker-influenced'],
          ['10', 'Very narrow, partly uncontrollable'],
          ['20', 'Exceptionally narrow, externally uncontrollable'],
        ],
      ],
      [
        'durationExtreme',
        'Uninterrupted execution duration',
        [
          ['0', 'Ordinary / less than 15 minutes'],
          ['5', 'Over 15 minutes'],
          ['10', 'Over 1 hour'],
          ['15', 'Over 6 hours'],
          ['20', 'Over 24 hours'],
        ],
      ],
    ],
  },
  {
    id: 'recovery',
    title: 'Failure and recovery consequences',
    description: 'Apply only when an unsuccessful attempt has a material independent recovery cost.',
    fields: [
      [
        'recoveryExtreme',
        'Recovery after failed attempt',
        [
          ['0', 'Ordinary failure / automatic quick recovery'],
          ['5', 'Extended service disruption'],
          ['10', 'Manual service intervention'],
          ['20', 'Host repair or one practical attempt'],
        ],
      ],
    ],
  },
  {
    id: 'processor',
    title: 'Processor / instruction-set rarity',
    description:
      'Memory-corruption exploit paths only. Processor type / instruction set must exclude some otherwise vulnerable installations, not merely describe the normally supported product. Requires CPU subset selection in Section 2 and actual prevalence evidence.',
    fields: [
      [
        'cpuExtreme',
        'Prevalence of mandatory CPU capability',
        [
          ['0', 'Common / no unusual restriction'],
          ['5', 'Present in approximately 10–50% of affected targets'],
          ['10', 'Present in approximately 1–10%'],
          ['20', 'Present in less than 1%'],
        ],
      ],
    ],
  },
  {
    id: 'calibration',
    title: 'Per-target exploit preparation',
    description:
      'Score the need to specialize or calibrate an exploit, not the original effort to discover the vulnerability.',
    fields: [
      [
        'calibrationExtreme',
        'Target-specific adaptation',
        [
          ['0', 'Reusable across affected installations'],
          ['5', 'Must select a version-specific variant'],
          ['10', 'Separate adjustment per deployment'],
          ['20', 'Unique per-instance calibration or secrets'],
        ],
      ],
    ],
  },
  {
    id: 'conditions',
    title: 'Rare configurations and victim interaction',
    description:
      'Use the higher of the two penalties when unusual settings and user actions describe the same prerequisite.',
    fields: [
      [
        'configExtreme',
        'Configuration rarity',
        [
          ['0', 'Default / ordinary conditions'],
          ['5', 'Uncommon setting combination'],
          ['10', 'Very rare combination'],
          ['20', 'Exceptional multi-factor configuration'],
        ],
      ],
      [
        'interactionExtreme',
        'Victim interaction difficulty',
        [
          ['0', 'No extraordinary interaction'],
          ['5', 'Several explicit steps'],
          ['10', 'Precise multi-step victim coordination'],
          ['20', 'Highly improbable synchronized actions'],
        ],
      ],
    ],
  },
  {
    id: 'chain',
    title: 'Mandatory exploit chaining',
    description:
      'Only count independent vulnerabilities strictly necessary to achieve the stated impact. Do not duplicate the ordinary chaining points.',
    fields: [
      [
        'chainExtreme',
        'Additional independent vulnerabilities',
        [
          ['0', 'None / ordinary'],
          ['5', 'Additional vulnerability with unusual preconditions'],
          ['10', 'Several independent vulnerabilities'],
          ['20', 'Exceptional multi-vulnerability chain'],
        ],
      ],
    ],
  },
];
export const EXTRA_DEFAULTS: Answers = Object.fromEntries(
  EXTREME_GROUPS.flatMap((g) => g.fields.map((f) => [f[0], '0']))
);
Object.assign(EXTRA_DEFAULTS, {
  requiredTrafficGb: '',
  availableMbps: '',
  maxConnectionMinutes: '',
  requiredAttemptsExact: '',
  maxAttemptsAvailable: '',
  cpuCompat: 'unknown',
  manualBlocked: 'no',
  manualReason: '',
  affectedPopulation: '',
  exploitScenario: '',
});

// ── Scoring (pure port of the upstream calculator) ────────────────────

const num = (v: string | undefined): number => Number(v || 0);

export function activeTechnicalFamily(answers: Answers): TechnicalFamily {
  return TECHNICAL_FAMILIES[answers.vclass ?? ''] ?? TECHNICAL_FAMILIES.other!;
}

export function requiredCpuBarrier(answers: Answers): boolean {
  return (
    answers.vclass === 'memory' &&
    answers.cpuScope === 'subset' &&
    ['cpuarch', 'cpufeature'].some((k) => answers[`tech_memory_${k}_required`] === '1')
  );
}

interface CategoryScore {
  id: string;
  title: string;
  cap: number;
  points: number;
  barriers: Record<string, number>;
}

function scoreCategory(cat: Category, answers: Answers): CategoryScore {
  let sum = 0;
  const barriers: Record<string, number> = {};
  if (cat.dynamic) {
    for (const [id, , max] of activeTechnicalFamily(answers).barriers) {
      const key = `tech_${answers.vclass}_${id}`;
      const cpu = id === 'cpuarch' || id === 'cpufeature';
      const active = !cpu || answers.cpuScope === 'subset';
      const points = active ? num(answers[`${key}_required`]) * max * Number(answers[`${key}_residual`] ?? 1) : 0;
      barriers[key] = points;
      sum += points;
    }
  } else {
    for (const [id] of cat.questions ?? []) {
      // Above 1 MB incurs two ordinary points; the nonlinear traffic
      // surcharge is assessed separately after the category caps.
      sum += id === 'volume' ? (num(answers.volume) > 0 ? 2 : 0) : num(answers[id]);
    }
  }
  return { id: cat.id, title: cat.title, cap: cat.cap ?? 0, points: Math.min(cat.cap ?? 0, sum), barriers };
}

export interface GroupScore {
  id: string;
  title: string;
  points: number;
  factors: Array<{ key: string; label: string; points: number }>;
}

function groupResult(group: ExtremeGroup, answers: Answers): GroupScore {
  const candidates: GroupScore['factors'] = [];
  if (group.id === 'resources') {
    candidates.push({
      key: 'volume',
      points: num(answers.volume) >= 5 ? num(answers.volume) : 0,
      label: 'Traffic volume',
    });
  }
  for (const [key, label] of group.fields) {
    let points = num(answers[key]);
    if (group.id === 'processor' && !requiredCpuBarrier(answers)) points = 0;
    if (key === 'raceExtreme' && num(answers.race) === 0) points = 0;
    if (key === 'recoveryExtreme' && num(answers.failure) === 0 && num(answers.restart) === 0) points = 0;
    if (key === 'configExtreme' && num(answers.config) === 0) points = 0;
    if (key === 'interactionExtreme' && num(answers.interaction) === 0) points = 0;
    if (key === 'chainExtreme' && num(answers.chain) === 0) points = 0;
    candidates.push({ key, label, points });
  }
  return {
    id: group.id,
    title: group.title,
    points: Math.max(0, ...candidates.map((c) => c.points)),
    factors: candidates,
  };
}

function parsedPositive(value: string | undefined): number | null {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) return null;
  const n = Number(trimmed);
  return Number.isFinite(n) && n > 0 ? n : null;
}

const fmt = (n: number): string => n.toLocaleString('en-US', { maximumFractionDigits: 1 });

export interface Feasibility {
  status: 'infeasible' | 'not-flagged';
  issues: string[];
  diagnostics: { requiredTransferMinutes?: number };
}

export function feasibility(answers: Answers): Feasibility {
  const issues: string[] = [];
  const diagnostics: Feasibility['diagnostics'] = {};
  const gb = parsedPositive(answers.requiredTrafficGb);
  const mbps = parsedPositive(answers.availableMbps);
  const minutes = parsedPositive(answers.maxConnectionMinutes);
  if (gb !== null && mbps !== null) {
    const transferMin = (gb * 8000) / (mbps * 60);
    diagnostics.requiredTransferMinutes = transferMin;
    if (minutes !== null && transferMin > minutes + 1e-8) {
      issues.push(
        `A ${fmt(gb)} GB transfer requires ${fmt(transferMin)} minutes at ${fmt(mbps)} Mbit/s, exceeding the ${fmt(minutes)}-minute connection window.`
      );
    }
  }
  const attempts = parsedPositive(answers.requiredAttemptsExact);
  const limit = parsedPositive(answers.maxAttemptsAvailable);
  if (attempts !== null && limit !== null && attempts > limit) {
    issues.push(`${fmt(attempts)} required attempts exceed the available ${fmt(limit)} attempts.`);
  }
  if (answers.cpuCompat === 'no' && requiredCpuBarrier(answers)) {
    issues.push('The assessed target lacks a CPU capability mandatory for the chosen exploit path.');
  }
  if (answers.manualBlocked === 'yes') {
    issues.push(
      answers.manualReason
        ? `Mandatory prerequisite cannot be met: ${answers.manualReason}`
        : 'A researcher has identified an impossible mandatory prerequisite (description missing).'
    );
  }
  return { status: issues.length ? 'infeasible' : 'not-flagged', issues, diagnostics };
}

export interface VessResult {
  base: CategoryScore[];
  escalators: GroupScore[];
  baseTotal: number;
  bonus: number;
  rawTotal: number;
  score: number;
  rounded: number;
  feasibility: Feasibility;
}

export function scoreAssessment(answers: Answers): VessResult {
  const base = CATS.map((c) => scoreCategory(c, answers));
  const escalators = EXTREME_GROUPS.map((g) => groupResult(g, answers));
  const baseTotal = base.reduce((a, x) => a + x.points, 0);
  const bonus = escalators.reduce((a, x) => a + x.points, 0);
  const rawTotal = baseTotal + bonus;
  return {
    base,
    escalators,
    baseTotal,
    bonus,
    rawTotal,
    score: Math.min(100, rawTotal),
    rounded: Math.round(Math.min(100, rawTotal)),
    feasibility: feasibility(answers),
  };
}

export function volumeTier(gb: number): string {
  if (gb < 0.001) return '0';
  if (gb < 0.1) return '2';
  if (gb < 1) return '5';
  if (gb < 10) return '10';
  if (gb < 100) return '15';
  return '20';
}

/** Upstream auto-fills the ordinary traffic/attempt tiers from exact values. */
export function syncKnownQuantities(answers: Answers, key: string): Answers {
  const next = { ...answers };
  if (key === 'requiredTrafficGb') {
    const n = parsedPositive(next[key]);
    if (n !== null) next.volume = volumeTier(n);
    else if (String(next[key]).trim() === '0') next.volume = '0';
  }
  if (key === 'requiredAttemptsExact') {
    const n = parsedPositive(next[key]);
    if (n !== null) {
      next.attempts = n <= 1 ? '0' : n <= 10 ? '2' : n <= 100 ? '4' : '6';
      next.attemptExtreme = n <= 100 ? '0' : n <= 1000 ? '5' : n <= 10000 ? '10' : '20';
    } else if (String(next[key]).trim() === '0') {
      next.attempts = '0';
      next.attemptExtreme = '0';
    }
  }
  return next;
}

export function bandFor(score: number): { label: string; range: string; color: string } {
  if (score <= 19) return { label: 'Trivial', range: '0–19', color: '#4dd5a6' };
  if (score <= 39) return { label: 'Easy', range: '20–39', color: '#94ca78' };
  if (score <= 59) return { label: 'Moderate', range: '40–59', color: '#f4c86b' };
  if (score <= 79) return { label: 'Difficult', range: '60–79', color: '#e9a166' };
  return { label: 'Extreme', range: '80–100', color: '#f28e87' };
}
