/**
 * MANTIS infrastructure-hunt planner — faithful TypeScript port of the
 * portable core of fareedfauzi/MANTIS `backend/infra_hunt_service.py`
 * (MIT): extract_features, compose_queries, engine search links, and the
 * built-in signature packs. Host-keyed hunt execution stays in MANTIS (needs
 * SQLite + provider keys); this port covers the deterministic planner so a
 * seed (IP or domain) can be turned into a ranked feature map and a set of
 * engine queries with launch links, running entirely on Cloudflare Workers.
 *
 * Fidelity contract: `api/test/lib/mantis-infra-hunt.test.ts` pins this
 * port against golden outputs generated from the original Python (fixtures
 * in `api/test/fixtures/mantis-hunt-golden.json`).
 */

// ─── Regex constants (ported 1:1) ───────────────────────────────────────────

const DOMAIN_RE = /^[a-zA-Z\d](?:[a-zA-Z\d-]*[a-zA-Z\d])?(?:\.[a-zA-Z\d](?:[a-zA-Z\d-]*[a-zA-Z\d])?)*\.[a-zA-Z]{2,}$/;

const FINGERPRINT_SHA256 = /^[a-f\d]{64}$/;
const JARM_PATTERN = /^[a-f\d]{62}$/;
const JA4X_PATTERN = /^[a-z\d]{12}_[a-z\d]{12}_[a-z\d]{12}$/;

// ─── Signal weights (SIGNAL_WEIGHTS) ────────────────────────────────────────

export const SIGNAL_WEIGHTS: Record<string, number> = {
  certificate_sha256: 35,
  ja4x: 25,
  http_body_hash: 18,
  http_headers_hash: 18,
  favicon_hash: 12,
  certificate_subject: 12,
  certificate_issuer: 10,
  jarm: 7,
  ja3s: 7,
  ja4: 9,
  http_title: 7,
  http_server: 5,
  banner: 8,
  port: 2,
  asn: 2,
  registrar: 4,
  nameserver: 5,
  tld: 2,
};

// ─── MANTIS expansion providers (EXPANSION_PROVIDERS) ───────────────────────

export interface ExpansionProvider {
  label: string;
  role: 'search' | 'pivot' | 'open_dir' | 'validate';
  key_required: boolean;
  description?: string;
}

export const EXPANSION_PROVIDERS: Record<string, ExpansionProvider> = {
  shodan: { label: 'Shodan', role: 'search', key_required: true },
  censys: { label: 'Censys', role: 'search', key_required: true },
  fofa: { label: 'FOFA', role: 'search', key_required: true },
  netlas: { label: 'Netlas', role: 'search', key_required: true },
  silentpush: { label: 'Silent Push', role: 'search', key_required: true },
  driftnet: { label: 'Driftnet', role: 'search', key_required: true },
  validin: { label: 'Validin', role: 'pivot', key_required: true },
  etugen: {
    label: 'Etugen (OpenDir)',
    role: 'open_dir',
    key_required: true,
    description: 'Exposed open directories & leaked files (Trashpile)',
  },
  zoomeye: {
    label: 'ZoomEye',
    role: 'search',
    key_required: true,
    description: 'Global cyberspace search engine by Knownsec',
  },
  greynoise: { label: 'GreyNoise', role: 'validate', key_required: false },
};

// ─── Built-in signature packs (BUILTIN_SIGNATURES + DB row shape) ───────────

export interface SignaturePackSeed {
  slug: string;
  name: string;
  family: string;
  description: string;
  signals: Record<string, string[]>;
  minimum_matches: number;
  false_positive_notes: string;
}

/** Seed definitions — as shipped in MANTIS's BUILTIN_SIGNATURES. */
export const BUILTIN_SIGNATURES: SignaturePackSeed[] = [
  {
    slug: 'asyncrat-default-tls',
    name: 'AsyncRAT default TLS',
    family: 'AsyncRAT',
    description: 'Default AsyncRAT certificate naming observed across public deployments.',
    signals: { certificate_subject: ['AsyncRAT Server'] },
    minimum_matches: 1,
    false_positive_notes: 'Validate with ports, TLS structure, and independent threat telemetry.',
  },
  {
    slug: 'cobalt-strike-default-cert',
    name: 'Cobalt Strike default certificate',
    family: 'Cobalt Strike',
    description: 'Default certificate metadata associated with unmodified Cobalt Strike profiles.',
    signals: { certificate_subject: ['Major Cobalt Strike'], certificate_issuer: ['Major Cobalt Strike'] },
    minimum_matches: 1,
    false_positive_notes: 'Default strings are high-signal but can be copied or used by researchers.',
  },
  {
    slug: 'havoc-default-banner',
    name: 'Havoc default service banner',
    family: 'Havoc',
    description: 'Default X-Havoc service marker.',
    signals: { banner: ['X-Havoc'] },
    minimum_matches: 1,
    false_positive_notes: 'Confirm the service profile and exclude scanners or honeypots.',
  },
  {
    slug: 'mythic-default-title',
    name: 'Mythic default web title',
    family: 'Mythic',
    description: 'Default Mythic web interface title.',
    signals: { http_title: ['Mythic'] },
    minimum_matches: 1,
    false_positive_notes: 'A title alone is mutable; require a second signal for blocking decisions.',
  },
  {
    slug: 'purehvnc-http-profile',
    name: 'PureHVNC/PureLogs HTTP profile',
    family: 'PureHVNC',
    description: 'Research-derived HTTP body and header hash combination.',
    signals: { http_body_hash: ['1929577144'], http_headers_hash: ['707481832'] },
    minimum_matches: 2,
    false_positive_notes: 'Historical profile; validate freshness and malware relations.',
  },
];

/** The row shape MANTIS's SQLite-backed list_signature_packs() emits. */
export interface SignaturePack extends SignaturePackSeed {
  id: number;
  enabled: boolean;
  builtin: boolean;
  updated_at: string;
}

/** Python _utcnow() — seconds-precision UTC with a +00:00 offset suffix. */
export function utcNowIso(now = new Date()): string {
  const floored = new Date(Math.floor(now.getTime() / 1000) * 1000);
  return floored.toISOString().replace('Z', '+00:00');
}

/**
 * The Workers port has no SQLite registry table, so the builtin packs stand
 * in for the seeded rows: ids assigned in seed order (matching MANTIS's
 * init_db ids 1..N), enabled+builtin flags, and a shared update stamp.
 */
export function builtinSignaturePacks(nowIso: string = utcNowIso()): SignaturePack[] {
  return BUILTIN_SIGNATURES.map((seed, index) => ({
    ...seed,
    id: index + 1,
    enabled: true,
    builtin: true,
    updated_at: nowIso,
  }));
}

// ─── Feature extraction (extract_features + _walk + _add) ───────────────────

export interface FeatureRow {
  value: string;
  path: string;
  provider?: string;
}

export interface RankedFeature {
  kind: string;
  value: string;
  path: string;
  provider: string;
  weight: number;
}

export interface FeatureCategories {
  certificates: RankedFeature[];
  web: RankedFeature[];
  network: RankedFeature[];
  hosts: RankedFeature[];
}

export interface ExtractedFeatures {
  by_type: Record<string, FeatureRow[]>;
  ranked: RankedFeature[];
  count: number;
  categories: FeatureCategories;
}

const FEATURE_KINDS = new Set(Object.keys(SIGNAL_WEIGHTS));
const NULLISH_TOKENS = new Set(['true', 'false', 'none', 'unknown', 'n/a']);
const DOMAIN_KEYS = new Set(['domain', 'hostname', 'host', 'name', 'dns_name', 'fqdn']);
const IP_KEYS = new Set(['ip', 'ip_str', 'ip_address', 'address']);
const ASN_KEYS = new Set(['asn', 'as_number']);

/** JSON walk that mirrors Python _walk: dotted path for dicts, [i] for lists, lowercased leaf paths. */
function* walkJson(value: unknown, path = ''): Generator<{ path: string; value: string }> {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      const childPath = path ? `${path}.${key}` : key;
      yield* walkJson(record[key], childPath);
    }
  } else if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index++) {
      yield* walkJson(value[index], `${path}[${index}]`);
    }
  } else if (value !== null && value !== '' && value !== undefined) {
    yield { path: path.toLowerCase(), value: String(value) };
  }
}

function ensureBucket(map: Record<string, FeatureRow[]>, kind: string): FeatureRow[] {
  return map[kind] ?? (map[kind] = []);
}

function addFeature(
  map: Record<string, FeatureRow[]>,
  kind: string,
  value: unknown,
  path: string,
  provider: string
): void {
  const text = String(value ?? '').trim();
  if (!text || text.length > 1000) return;
  const lowered = text.toLowerCase();
  if (NULLISH_TOKENS.has(lowered)) return;
  const bucket = ensureBucket(map, kind);
  const row: FeatureRow = provider ? { value: text, path, provider } : { value: text, path };
  if (!bucket.some((existing) => existing.value.toLowerCase() === lowered)) bucket.push(row);
}

function isIpLike(text: string): string | null {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)) return null;
  // Python's ipaddress.ip_address() both validates octet ranges and emits the
  // canonical dotted form; the base regex alone would accept 999.0.0.1.
  const parts = text.split('.').map((p) => parseInt(p, 10));
  if (!parts.every((n) => n >= 0 && n <= 255)) return null;
  return text;
}

/**
 * extract_features — walks any shapeless JSON payload from provider seed
 * queries (crt.sh certificates, RIPEstat, shodan-style banners) and collects
 * the signal kinds MANTIS's hunt planner acts on.
 */
export function extractFeatures(payload: unknown): ExtractedFeatures {
  const features: Record<string, FeatureRow[]> = {};

  for (const { path, value: raw } of walkJson(payload)) {
    const text = raw.trim();
    const key = path.includes('.') ? path.slice(path.lastIndexOf('.') + 1) : path;
    const provider = path.includes('.') ? path.slice(0, path.indexOf('.')) : '';
    const lowPath = path;

    const ip = isIpLike(text);
    if (IP_KEYS.has(key) && ip) addFeature(features, 'ip', ip, path, provider);

    if (
      (DOMAIN_KEYS.has(key) || lowPath.includes('subject_alternative_name') || lowPath.includes('san')) &&
      DOMAIN_RE.test(text)
    ) {
      addFeature(features, 'domain', text.toLowerCase().replace(/\.$/, ''), path, provider);
    }

    if (key.includes('port') && /^\d+$/.test(text) && parseInt(text, 10) > 0 && parseInt(text, 10) <= 65535) {
      addFeature(features, 'port', text, path, provider);
    } else if (lowPath.includes('port_info.')) {
      const port = lowPath.match(/port_info\.(\d+)/)?.[1];
      if (port && parseInt(port, 10) > 0 && parseInt(port, 10) <= 65535) {
        addFeature(features, 'port', port, path, provider);
      }
    }

    if (ASN_KEYS.has(key) || lowPath.endsWith('autonomous_system.asn')) {
      const m = text.match(/(?:AS)?(\d{1,10})/i);
      if (m) addFeature(features, 'asn', `AS${m[1]}`, path, provider);
    }

    if (key.toLowerCase().includes('jarm') && JARM_PATTERN.test(text.replace(/:/g, ''))) {
      addFeature(features, 'jarm', text.toLowerCase(), path, provider);
    }

    if (key.toLowerCase().includes('ja4x') && JA4X_PATTERN.test(text)) {
      addFeature(features, 'ja4x', text.toLowerCase(), path, provider);
    } else if (key.toLowerCase().includes('ja4t')) {
      addFeature(features, 'ja4t', text, path, provider);
    } else if (key.toLowerCase().includes('ja4')) {
      addFeature(features, 'ja4', text, path, provider);
    }

    if (key.toLowerCase().includes('ja3s')) {
      addFeature(features, 'ja3s', text, path, provider);
    }

    if (
      [
        'fingerprint_sha256',
        'fingerprint.sha256',
        'certificate.sha256',
        'cert_sha256',
        'certificates.leaf_fp_sha_256',
        'thumbprint_sha256',
        'thumbprint',
      ].some((marker) => lowPath.includes(marker))
    ) {
      const cleaned = text.replace(/:/g, '').toLowerCase();
      if (FINGERPRINT_SHA256.test(cleaned)) addFeature(features, 'certificate_sha256', cleaned, path, provider);
    }

    if (
      [
        'subject_dn',
        'subject.common_name',
        'ssl_subject',
        'certificate_subject',
        'cert.subject',
        'subject.cn',
        'subject.o',
      ].some((marker) => lowPath.includes(marker))
    ) {
      addFeature(features, 'certificate_subject', text, path, provider);
    }

    if (
      [
        'issuer_dn',
        'issuer.common_name',
        'ssl_issuer',
        'certificate_issuer',
        'cert.issuer',
        'issuer.cn',
        'issuer.o',
      ].some((marker) => lowPath.includes(marker))
    ) {
      addFeature(features, 'certificate_issuer', text, path, provider);
    }

    if (
      ['favicon', 'icon_hash', 'favicon_hash', 'murmur3'].some((marker) => key.toLowerCase().includes(marker)) ||
      lowPath.includes('favicon')
    ) {
      addFeature(features, 'favicon_hash', text, path, provider);
    }

    if (lowPath.includes('scanning_technologies') && (key === 'product' || key === 'vendor')) {
      addFeature(features, 'http_server', text, path, provider);
    }

    if (['html_hash', 'body_hash', 'body_sha256', 'http_body_hash', 'content_sha1'].includes(key)) {
      addFeature(features, 'http_body_hash', text, path, provider);
    }

    if (['headers_hash', 'header_hash', 'http_headers_hash'].includes(key)) {
      addFeature(features, 'http_headers_hash', text, path, provider);
    }

    if (['title', 'html_title', 'http_title'].includes(key) || lowPath.endsWith('http.title')) {
      addFeature(features, 'http_title', text, path, provider);
    }

    if (['server', 'http_server'].includes(key) || lowPath.endsWith('http.server')) {
      addFeature(features, 'http_server', text, path, provider);
    }

    if (['banner', 'data', 'service_banner'].includes(key)) {
      const server = text.match(/Server:\s*([^\r\n]+)/i)?.[1];
      if (server) addFeature(features, 'http_server', server.trim().slice(0, 100), path, provider);
      else if (text.length <= 90 && !text.startsWith('{') && !text.startsWith('<') && !text.startsWith('[')) {
        addFeature(features, 'banner', text, path, provider);
      }
    }

    if (key.includes('registrar')) {
      addFeature(features, 'registrar', text, path, provider);
    }

    if (['nameserver', 'nameservers', 'name_server', 'name_servers'].includes(key)) {
      const domainRe = /(?:[a-z\d](?:[a-z\d-]*[a-z\d])?(?:\.[a-z\d](?:[a-z\d-]*[a-z\d])?)*\.[a-z]{2,})/gi;
      for (const domain of text.match(domainRe) ?? []) {
        addFeature(features, 'nameserver', domain.toLowerCase(), path, provider);
      }
    }
  }

  for (const row of [...(features['domain'] ?? [])]) {
    const suffix = row.value.slice(row.value.lastIndexOf('.') + 1);
    if (suffix && suffix.length <= 8 && /^[a-zA-Z]+$/.test(suffix)) {
      addFeature(features, 'tld', suffix, row.path, row.provider ?? '');
    }
  }

  const ranked: RankedFeature[] = Object.entries(features).flatMap(([kind, rows]) =>
    rows.map((row) => ({
      kind,
      value: row.value,
      path: row.path,
      provider: row.provider ?? '',
      weight: SIGNAL_WEIGHTS[kind] ?? 1,
    }))
  );
  ranked.sort((a, b) => {
    if (a.weight !== b.weight) return b.weight - a.weight;
    if (a.kind !== b.kind) return a.kind < b.kind ? -1 : 1;
    if (a.value !== b.value) return a.value < b.value ? -1 : 1;
    return 0;
  });

  const isCertKind = (k: string) => k.startsWith('certificate_');
  const isWebKind = (k: string) => ['jarm', 'ja4', 'ja3', 'http_', 'favicon', 'banner'].some((p) => k.startsWith(p));
  const categories: FeatureCategories = {
    certificates: ranked.filter((r) => isCertKind(r.kind)),
    web: ranked.filter((r) => isWebKind(r.kind)),
    network: ranked.filter((r) => ['asn', 'port', 'nameserver', 'registrar', 'tld'].includes(r.kind)),
    hosts: ranked.filter((r) => ['domain', 'ip'].includes(r.kind)),
  };

  return { by_type: features, ranked, count: ranked.length, categories };
}

// ─── Engine search links (_engine_search_url) ───────────────────────────────

function quote(value: string): string {
  return '"' + String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

/** Python-style re.sub with a function replacer (all occurrences). */
function reSub(source: string, pattern: RegExp, replacer: (...groups: string[]) => string): string {
  let last = 0;
  let out = '';
  for (const m of source.matchAll(pattern)) {
    const idx = m.index ?? 0;
    out += source.slice(last, idx) + replacer(...m.slice(1));
    last = idx + m[0].length;
  }
  out += source.slice(last);
  return out;
}

/**
 * _engine_search_url — deterministic deep links per provider for a hunt
 * query. Pure IP/domain queries short-circuit to host pages.
 */
export function engineSearchUrl(provider: string, query: string): string {
  const p = (provider || '').toLowerCase().trim();
  const q = (query || '').trim();
  if (!q) return '';

  const ipMatch = q.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  const isPureIp = /^(?:net:)?(?:ip:)?\s*"?((?:\d{1,3}\.){3}\d{1,3})"?$/.test(q);
  const isPureDomain = /^(?:domain:)?\s*"?([a-zA-Z\d.-]+\.[a-zA-Z]{2,})"?$/.test(q) && !isPureIp;
  const rawIp = ipMatch ? ipMatch[0] : '';

  if (p === 'shodan') {
    if (isPureIp && rawIp) return `https://www.shodan.io/host/${rawIp}`;
    const cleanQ = reSub(
      reSub(q, /\bip:"?([0-9.]+)"?/g, (v) => `net:${v}`),
      /\basn:"?(?:AS)?(\d+)"?/g,
      (v) => `asn:AS${v}`
    );
    return `https://www.shodan.io/search?query=${encodeURIComponent(cleanQ)}`;
  }

  if (p === 'censys') {
    if (isPureIp && rawIp) return `https://search.censys.io/hosts/${rawIp}`;
    const cleanQ = reSub(q, /\bip\s*:\s*"([0-9.]+)"/g, (v) => `ip: ${v}`);
    return `https://search.censys.io/search?resource=hosts&q=${encodeURIComponent(cleanQ)}`;
  }

  if (p === 'fofa') {
    const b64 = btoa(String.fromCharCode(...new TextEncoder().encode(q)));
    return `https://fofa.info/result?qbase64=${b64}`;
  }

  if (p === 'netlas') {
    const cleanQ = reSub(q, /\bip:"([0-9.]+)"/g, (v) => `ip:${v}`);
    return `https://app.netlas.io/responses/?q=${encodeURIComponent(cleanQ)}`;
  }

  if (p === 'urlscan') {
    if (isPureIp && rawIp) return `https://urlscan.io/ip/${rawIp}`;
    if (isPureDomain) {
      const dom = q.replace(/^domain:\s*"?/, '').replace(/"?$/, '');
      return `https://urlscan.io/domain/${dom}`;
    }
    const cleanQ = reSub(q, /files\.sha256:"?([a-f\d]{64})"?/g, (v) => `hash:${v}`);
    // Python: urllib.parse.quote(clean_q, safe=':="/+*') — keep that charset raw.
    const URLSCAN_SAFE = ':="/+*';
    let frag = '';
    for (const ch of cleanQ) {
      frag += URLSCAN_SAFE.includes(ch) ? ch : encodeURIComponent(ch);
    }
    return `https://urlscan.io/search#${frag}`;
  }

  if (p === 'greynoise') {
    if (isPureIp && rawIp) return `https://viz.greynoise.io/ip/${rawIp}`;
    return `https://viz.greynoise.io/query?gnql=${encodeURIComponent(q)}`;
  }

  if (p === 'silentpush') {
    if (rawIp) return `https://explore.silentpush.com/enrichment/ip/${rawIp}`;
    if (isPureDomain) {
      const dom = q.replace(/^domain:\s*"?/, '').replace(/"?$/, '');
      return `https://explore.silentpush.com/enrichment/domain/${dom}`;
    }
    return 'https://explore.silentpush.com/';
  }

  if (p === 'etugen') {
    if (isPureIp && rawIp) return `https://app.etugen.io/trashpile/host/${rawIp}`;
    return `https://app.etugen.io/search?q=${encodeURIComponent(q)}`;
  }

  if (p === 'zoomeye') {
    if (isPureIp && rawIp) return `https://www.zoomeye.ai/searchResult?q=ip%3D%22${rawIp}%22`;
    return `https://www.zoomeye.ai/searchResult?q=${encodeURIComponent(q)}`;
  }

  if (p === 'validin') {
    if (rawIp) return `https://app.validin.com/ip/${rawIp}`;
    if (isPureDomain) {
      const dom = q.replace(/^domain:\s*"?/, '').replace(/"?$/, '');
      return `https://app.validin.com/domain/${dom}`;
    }
    return `https://app.validin.com/search?q=${encodeURIComponent(q)}`;
  }

  return '';
}

// ─── Query composition (compose_queries) ────────────────────────────────────

export interface HuntSignal {
  kind: string;
  value: string;
  weight: number;
}

export interface HuntQuery {
  provider: string;
  query: string;
  signals: HuntSignal[];
  estimated_strength: number;
  mode:
    | 'compound_search'
    | 'passive_search'
    | 'fingerprint_pivot'
    | 'open_dir_host'
    | 'template_search'
    | 'open_dir_search';
  external_url: string;
  dataset?: string;
  pivot_kind?: string;
  focus?: string;
  notes?: string;
}

function stripAsn(value: string): string {
  return value.replace(/^AS/i, '');
}

/**
 * compose_queries — turns the ranked features into per-provider compound
 * queries. Same selection rule as MANTIS: top max_signals (<= 5) distinct
 * signal kinds (port/asn/tld only lead when nothing else is available),
 * then one query per provider with the provider's field map and joiner.
 */
export function composeQueries(features: ExtractedFeatures, maxSignals = 3): HuntQuery[] {
  const selected: RankedFeature[] = [];
  const used = new Set<string>();
  for (const item of features.ranked) {
    if (!FEATURE_KINDS.has(item.kind) || !item.value || used.has(item.kind)) continue;

    if (['port', 'asn', 'tld'].includes(item.kind) && selected.length < 1) continue;

    selected.push(item);
    used.add(item.kind);
    if (selected.length >= Math.max(1, Math.min(maxSignals, 5))) break;
  }

  if (selected.length === 0) {
    for (const item of features.ranked.filter((r) => ['domain', 'ip', 'asn'].includes(r.kind)).slice(0, 2)) {
      selected.push(item);
    }
  }

  const maps: Record<string, Record<string, string>> = {
    shodan: {
      certificate_sha256: 'ssl.cert.fingerprint',
      certificate_subject: 'ssl.cert.subject.cn',
      certificate_issuer: 'ssl.cert.issuer.cn',
      jarm: 'ssl.jarm',
      http_body_hash: 'http.html_hash',
      http_headers_hash: 'http.headers_hash',
      favicon_hash: 'http.favicon.hash',
      http_title: 'http.title',
      http_server: 'http.server',
      port: 'port',
      asn: 'asn',
      ip: 'ip',
    },
    censys: {
      certificate_sha256: 'cert.fingerprint_sha256',
      certificate_subject: 'cert.parsed.subject_dn',
      certificate_issuer: 'cert.parsed.issuer_dn',
      jarm: 'host.services.jarm.fingerprint',
      http_title: 'host.services.http.response.html_title',
      http_server: 'host.services.http.response.headers.server',
      port: 'host.services.port',
      asn: 'host.autonomous_system.asn',
      ip: 'ip',
    },
    fofa: {
      certificate_sha256: 'cert',
      certificate_subject: 'cert.subject',
      certificate_issuer: 'cert.issuer',
      jarm: 'jarm',
      ja3s: 'tls.ja3s',
      http_body_hash: 'body_hash',
      http_headers_hash: 'header_hash',
      favicon_hash: 'icon_hash',
      http_title: 'title',
      http_server: 'server',
      port: 'port',
      asn: 'asn',
      ip: 'ip',
    },
    netlas: {
      certificate_sha256: 'certificate.fingerprint_sha256',
      certificate_subject: 'certificate.subject_dn',
      certificate_issuer: 'certificate.issuer_dn',
      jarm: 'jarm',
      ja3s: 'ja3s',
      favicon_hash: 'http.favicon.hash',
      http_title: 'http.title',
      http_server: 'http.headers.server',
      port: 'port',
      asn: 'whois.asn.number',
      ip: 'ip',
    },
    silentpush: {
      certificate_sha256: 'ssl_sha256',
      certificate_subject: 'ssl_subject',
      certificate_issuer: 'ssl_issuer',
      jarm: 'jarm',
      http_body_hash: 'body_sha256',
      favicon_hash: 'favicon_murmur3',
      http_title: 'htmltitle',
      http_server: 'server',
      port: 'port',
      asn: 'asn',
      ip: 'ip',
    },
    zoomeye: {
      certificate_sha256: 'ssl.cert.fingerprint',
      certificate_subject: 'ssl.cert.subject.cn',
      certificate_issuer: 'ssl.cert.issuer.cn',
      jarm: 'ssl.jarm',
      favicon_hash: 'iconhash',
      http_title: 'title',
      http_server: 'app',
      port: 'port',
      asn: 'asn',
      ip: 'ip',
    },
  };

  const queries: HuntQuery[] = [];
  for (const [provider, fieldMap] of Object.entries(maps)) {
    const clauses: string[] = [];
    const signals: HuntSignal[] = [];
    for (const item of selected) {
      const field = fieldMap[item.kind];
      if (!field) continue;
      const value = item.value;
      const kind = item.kind;

      if (provider === 'shodan') {
        if (kind === 'ip') clauses.push(`net:${value}`);
        else if (kind === 'asn') clauses.push(`asn:AS${stripAsn(value)}`);
        else if (kind === 'port') clauses.push(`port:${value}`);
        else clauses.push(`${field}:${quote(value)}`);
      } else if (provider === 'censys') {
        if (kind === 'ip') clauses.push(`ip: ${value}`);
        else if (kind === 'port' || kind === 'asn')
          clauses.push(`${field} = ${kind === 'asn' ? stripAsn(value) : value}`);
        else clauses.push(`${field} : ${quote(value)}`);
      } else if (provider === 'fofa') {
        const cleanAsn = kind === 'asn' ? stripAsn(value) : value;
        clauses.push(`${field}=${quote(cleanAsn)}`);
      } else if (provider === 'netlas') {
        if (kind === 'ip') clauses.push(`ip:${value}`);
        else if (kind === 'port' || kind === 'asn')
          clauses.push(`${field}:${kind === 'asn' ? stripAsn(value) : value}`);
        else clauses.push(`${field}:${quote(value)}`);
      } else if (provider === 'silentpush') {
        const cleanVal = kind === 'asn' ? stripAsn(value) : value;
        clauses.push(`${field} = ${/^\d+$/.test(String(cleanVal)) ? cleanVal : quote(cleanVal)}`);
      } else if (provider === 'zoomeye') {
        if (kind === 'ip') clauses.push(`ip="${value}"`);
        else if (kind === 'port') clauses.push(`port="${value}"`);
        else if (kind === 'asn') clauses.push(`asn="${stripAsn(value)}"`);
        else clauses.push(`${field}=${quote(value)}`);
      } else {
        clauses.push(`${field}:${quote(value)}`);
      }
      signals.push({ kind: item.kind, value: item.value, weight: item.weight });
    }

    if (clauses.length > 0) {
      const joiner: string = ['fofa', 'zoomeye'].includes(provider)
        ? ' && '
        : ['netlas', 'silentpush'].includes(provider)
          ? ' AND '
          : provider === 'shodan'
            ? ' '
            : ' and ';
      let query = clauses.join(joiner);
      if (provider === 'silentpush') query += ' AND datasource = "webscan"';
      queries.push({
        provider,
        query,
        signals,
        estimated_strength: signals.reduce((sum, s) => sum + s.weight, 0),
        mode: 'compound_search',
        external_url: engineSearchUrl(provider, query),
      });
    }
  }

  const driftnetFields: Record<string, string> = {
    jarm: 'jarm',
    ja4: 'ja4',
    ja4t: 'ja4t',
    favicon_hash: 'favicon',
    certificate_subject: 'subject',
    certificate_issuer: 'issuer',
    http_title: 'title',
    http_body_hash: 'obj-sha1',
    http_server: 'protocol',
    port: 'port-tcp',
  };
  const driftnetSignals = selected.filter((item) => item.kind in driftnetFields);
  if (driftnetSignals.length > 0) {
    const clauses = driftnetSignals.map((item) => `${driftnetFields[item.kind]}:${quote(item.value)}`);
    queries.push({
      provider: 'driftnet',
      query: clauses.join(' AND '),
      signals: driftnetSignals,
      estimated_strength: driftnetSignals.reduce((sum, s) => sum + s.weight, 0),
      mode: 'passive_search',
      dataset: 'protocols',
      external_url: '',
    });
  }

  const validinKinds: Record<string, string> = {
    certificate_sha256: 'cert_hash',
    jarm: 'jarm',
    http_headers_hash: 'header_hash',
    favicon_hash: 'fingerprint',
  };
  const validinSignal = selected.find((item) => item.kind in validinKinds);
  if (validinSignal) {
    const pivotKind = validinKinds[validinSignal.kind];
    queries.push({
      provider: 'validin',
      query: `${pivotKind}:${validinSignal.value}`,
      signals: [validinSignal],
      estimated_strength: validinSignal.weight,
      mode: 'fingerprint_pivot',
      pivot_kind: pivotKind,
      external_url: `https://app.validin.com/search?q=${encodeURIComponent(validinSignal.value)}`,
    });
  }

  // Etugen: exposed open directories (Trashpile) and leaked files.
  // Upstream quirk preserved: the second lookup reads a TOP-LEVEL "ip" key on
  // the features object (extract_features never emits one), so in practice
  // only a selected IP signal can seed the Trashpile host lane.
  const globalIp = (features as { ip?: FeatureRow[] }).ip;
  const ipSignal = selected.find((item) => item.kind === 'ip') ?? (globalIp?.[0] as RankedFeature | undefined);
  let ariaValue = '';
  if (ipSignal) {
    ariaValue = String(ipSignal.value);
    queries.push({
      provider: 'etugen',
      query: ariaValue,
      signals: [ipSignal],
      estimated_strength: 5,
      mode: 'open_dir_host',
      focus: 'open_directory',
      notes: 'Inspect exposed open directory files and leaked artifacts on host (Trashpile)',
      external_url: `https://app.etugen.io/trashpile/host/${encodeURIComponent(ariaValue)}`,
    });
  }
  const portSignal = selected.find(
    (item) => item.kind === 'port' && ['8000', '8080', '8888'].includes(String(item.value))
  );
  const titleSignal = selected.find((item) => item.kind === 'http_title');

  if (titleSignal) {
    const tVal = String(titleSignal.value);
    if (tVal.toLowerCase().includes('phpmyadmin')) {
      queries.push({
        provider: 'etugen',
        query: 'title LIKE %phpMyAdmin%',
        signals: [titleSignal],
        estimated_strength: 4,
        mode: 'template_search',
        notes: 'Etugen template: phpMyAdmin panels',
        external_url: `https://app.etugen.io/search?q=${encodeURIComponent('title LIKE %phpMyAdmin%')}`,
      });
    } else if (tVal.toLowerCase().includes('gophish')) {
      queries.push({
        provider: 'etugen',
        query: 'title LIKE %Gophish%',
        signals: [titleSignal],
        estimated_strength: 5,
        mode: 'template_search',
        notes: 'Etugen template: Gophish phishing consoles',
        external_url: `https://app.etugen.io/search?q=${encodeURIComponent('title LIKE %Gophish%')}`,
      });
    } else if (!ipSignal) {
      queries.push({
        provider: 'etugen',
        query: `title LIKE "%${tVal}%"`,
        signals: [titleSignal],
        estimated_strength: 3,
        mode: 'open_dir_search',
        focus: 'open_directory',
        notes: `Search open directories for title '${tVal}'`,
        external_url: `https://app.etugen.io/search?q=${encodeURIComponent(tVal)}`,
      });
    }
  }

  if (portSignal && String(portSignal.value) === '8000') {
    queries.push({
      provider: 'etugen',
      query: 'title LIKE "Index of%" AND port:8000',
      signals: [portSignal],
      estimated_strength: 4,
      mode: 'template_search',
      focus: 'open_directory',
      notes: 'Etugen template: Open directories on port 8000',
      external_url: `https://app.etugen.io/search?q=${encodeURIComponent('title LIKE "Index of%" AND port:8000')}`,
    });
  }

  if (!ipSignal && !titleSignal) {
    const etugenSignal = selected.find((item) =>
      ['http_server', 'banner', 'domain', 'certificate_subject'].includes(item.kind)
    );
    if (etugenSignal) {
      const sigVal = String(etugenSignal.value);
      queries.push({
        provider: 'etugen',
        query: sigVal,
        signals: [etugenSignal],
        estimated_strength: etugenSignal.weight,
        mode: 'open_dir_search',
        focus: 'open_directory',
        notes: 'Search exposed open directories (Trashpile) for leaked files and paths',
        external_url: `https://app.etugen.io/search?q=${encodeURIComponent(sigVal)}`,
      });
    }
  }

  return queries;
}

/**
 * match_signature_packs — built-in fingerprint packs (AsyncRAT TLS, Cobalt
 * Strike cert, Havoc banner, Mythic title, PureHVNC hashes) checked against
 * the extracted features. User-defined DB packs are a MANTIS feature and
 * intentionally out of scope here (Workers stateless, no registry table).
 */
export function matchSignaturePacks(features: ExtractedFeatures, packs: SignaturePack[] = builtinSignaturePacks()) {
  const available: Record<string, string[]> = {};
  for (const [kind, rows] of Object.entries(features.by_type)) {
    available[kind] = rows.map((row) => String(row.value ?? '').toLowerCase());
  }
  const matches: Array<SignaturePack & { matched_evidence: Array<{ kind: string; value: string }> }> = [];
  for (const pack of packs.filter((p) => p.enabled)) {
    const evidence: Array<{ kind: string; value: string }> = [];
    for (const [kind, values] of Object.entries(pack.signals)) {
      for (const expected of Array.isArray(values) ? values : [values]) {
        const expectedLow = String(expected).toLowerCase();
        if ((available[kind] ?? []).some((observed) => observed.includes(expectedLow))) {
          evidence.push({ kind, value: expected });
        }
      }
    }
    if (evidence.length >= pack.minimum_matches) {
      matches.push({ ...pack, matched_evidence: evidence });
    }
  }
  return matches;
}

/** Seed classification helper: IP, domain, or ASN (route-layer concern). */
export function classifySeed(seed: string): { kind: 'ip' | 'domain' | 'invalid'; value: string } {
  const s = (seed || '').trim().toLowerCase();
  if (isIpLike(s)) return { kind: 'ip', value: s };
  if (DOMAIN_RE.test(s)) return { kind: 'domain', value: s };
  return { kind: 'invalid', value: s };
}
