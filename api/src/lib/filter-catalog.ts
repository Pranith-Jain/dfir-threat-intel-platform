/**
 * Machine-readable filter catalogue + unknown-parameter diagnostics.
 *
 * Two problems this solves, both borrowed from radar.offseq.com's API design:
 *
 *  1. **Typos fail silently.** `GET /api/v1/cve-recent?serity=critical` returns
 *     a full 200 result set with the filter quietly ignored. A caller cannot
 *     tell "no results matched" from "you misspelled the parameter and got
 *     everything back", and the second reading is the dangerous one. Every
 *     handler that declares its accepted filters gets them checked, and
 *     anything unrecognised comes back in an `X-Unknown-Params` response header
 *     plus a `unknownParams` field. The result set is still returned; silently
 *     changing the response would break callers, but the caller is now told.
 *
 *  2. **Nobody can enumerate the filters.** `GET /api/v1/filters` publishes the
 *     whole catalogue so a client can discover what a route accepts instead of
 *     reading the source.
 *
 * The catalogue is hand-declared rather than inferred from Zod because the
 * inference would describe the types but not the semantics. `days` needs a
 * documented meaning and `platform` needs an enum; neither is recoverable from
 * `z.number().optional()`.
 */

/** A single filter parameter as a client sees it. */
export interface FilterParam {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'enum';
  description: string;
  /** For `type: 'enum'`, the accepted values. */
  values?: string[];
  example?: string;
  required?: boolean;
}

export interface FilterEndpoint {
  path: string;
  method: 'GET' | 'POST';
  summary: string;
  params: FilterParam[];
  /**
   * Params the handler reads off `c.req.query()` that are handled somewhere
   * other than the main filter path (auth, caching, pagination shape). Listing
   * them here keeps the unknown-param check from flagging our own plumbing.
   */
  passThrough?: string[];
}

const CVE_ID_PARAMS: FilterParam[] = [
  {
    name: 'cve',
    type: 'string',
    description:
      'CVE identifier. Lenient: CVE-2025-1974, cve-2025-1974 and the bare 2025-1974 all resolve to the same record.',
    example: '2025-1974',
  },
];

/**
 * The catalogue.
 *
 * Kept next to the routes it describes rather than in a separate manifest, so
 * a route change and its filter description land in the same commit and cannot
 * drift silently the way a doc file can.
 */
export const FILTER_CATALOGUE: FilterEndpoint[] = [
  {
    path: '/api/v1/cve-recent',
    method: 'GET',
    summary: 'Recently published and known-exploited CVEs, merged across eight priority sources.',
    params: [
      { name: 'days', type: 'number', description: 'Only CVEs published in the last N days.', example: '7' },
      {
        name: 'severity',
        type: 'enum',
        description: 'Filter by CVSS severity band.',
        values: ['critical', 'high', 'medium', 'low'],
      },
      { name: 'kev', type: 'boolean', description: 'Restrict to CISA Known Exploited Vulnerabilities.' },
      { name: 'limit', type: 'number', description: 'Maximum rows to return.' },
    ],
  },
  {
    path: '/api/v1/cisa-kev',
    method: 'GET',
    summary: 'CISA KEV catalog, CVSS-enriched from NVD.',
    params: [
      {
        name: 'q',
        type: 'string',
        description: 'Free-text match across CVE id, vendor, product and vulnerability name.',
      },
      ...CVE_ID_PARAMS,
      { name: 'vendor', type: 'string', description: 'Substring match on vendor_project.' },
      { name: 'product', type: 'string', description: 'Substring match on product.' },
      { name: 'days', type: 'number', description: 'Only entries added in the last N days.', example: '30' },
      {
        name: 'ransomware_only',
        type: 'boolean',
        description: 'Only entries CISA marks as known ransomware campaign use.',
      },
      {
        name: 'severity',
        type: 'enum',
        description: 'CVSS severity band.',
        values: ['critical', 'high', 'medium', 'low'],
      },
    ],
  },
  {
    path: '/api/v1/detection-coverage',
    method: 'GET',
    summary: 'CVE-to-detection-rule coverage: which known-exploited vulnerabilities have a published rule.',
    params: [
      {
        name: 'platform',
        type: 'enum',
        description: 'Restrict to one rule corpus.',
        values: ['sigma', 'elastic', 'splunk', 'sentinel'],
      },
      { name: 'days', type: 'number', description: 'Only KEV entries added in the last N days.', example: '30' },
      { name: 'ransomware', type: 'boolean', description: 'Only KEV entries with known ransomware campaign use.' },
      { name: 'covered', type: 'boolean', description: 'Only entries that have at least one published rule.' },
      {
        name: 'gaps',
        type: 'boolean',
        description: 'Only entries with no published rule. This is the interesting one.',
      },
      { name: 'limit', type: 'number', description: 'Rows per page. Max 500.' },
      { name: 'offset', type: 'number', description: 'Row offset for paging.' },
    ],
  },
  {
    path: '/api/v1/detection-coverage/library',
    method: 'GET',
    summary: 'The published detection rules behind the coverage numbers, browsable by ATT&CK technique.',
    params: [
      {
        name: 'technique',
        type: 'string',
        description: 'ATT&CK technique id. Sub-technique queries also return the parent.',
        example: 'T1566.001',
      },
      { name: 'source', type: 'enum', description: 'Rule corpus.', values: ['sigma', 'elastic', 'splunk', 'sentinel'] },
      { name: 'q', type: 'string', description: 'Match on rule title or rule path.' },
      { name: 'limit', type: 'number', description: 'Rows to return. Max 500.' },
    ],
  },
  {
    path: '/api/v1/cve/lookup',
    method: 'GET',
    summary: 'Single-CVE record with KEV, EPSS, PoC, SSVC and GHSA enrichment.',
    params: CVE_ID_PARAMS,
  },
  {
    path: '/api/v1/cve/insights',
    method: 'GET',
    summary:
      'CVE feed with facets, detection-latency measurement and a hot/attention ranking. Reads the cve-recent feed rather than fetching its own.',
    params: [
      {
        name: 'cwe',
        type: 'string',
        description: 'Filter by CWE. Accepts 787, CWE-787 and cwe787. Rejects CWE-0 and CWE-9999.',
        example: 'CWE-787',
      },
      {
        name: 'severity',
        type: 'enum',
        description: 'CVSS severity band.',
        values: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'],
      },
      {
        name: 'origin',
        type: 'enum',
        description: 'Source feed that first surfaced the CVE.',
        values: ['nvd', 'kev', 'mti', 'cvefeed', 'tg', 'dbugs', 'exploitgrid'],
      },
      { name: 'kev', type: 'boolean', description: 'Only CISA Known Exploited Vulnerabilities.' },
      { name: 'days', type: 'number', description: 'Only CVEs published in the last N days.' },
      {
        name: 'sort',
        type: 'enum',
        description:
          'newest | oldest | severity | epss (CVSS order) | hot (attention velocity) | latency (slowest detection first).',
        values: ['newest', 'oldest', 'severity', 'epss', 'hot', 'latency'],
      },
      { name: 'limit', type: 'number', description: 'Rows per page. Max 500.' },
      { name: 'offset', type: 'number', description: 'Row offset for paging.' },
    ],
  },
  {
    path: '/api/v1/threat-intel/targeting',
    method: 'GET',
    summary:
      'Victim-side country geography. Where recorded victims are located — NOT attacker attribution and NOT a statement that attacks target that country.',
    params: [
      {
        name: 'band',
        type: 'enum',
        description: 'Evidence-volume band.',
        values: ['elevated', 'moderate', 'low', 'minimal'],
      },
      { name: 'limit', type: 'number', description: 'Rows to return. Max 500.' },
    ],
  },
  {
    path: '/api/v1/glasswing/findings',
    method: 'GET',
    summary: 'Anthropic Project Glasswing AI-disclosed findings.',
    params: [
      {
        name: 'severity',
        type: 'enum',
        description: 'Severity as published by Anthropic.',
        values: ['critical', 'high', 'medium', 'low'],
      },
      {
        name: 'ecosystem',
        type: 'string',
        description: 'Substring match on the project, e.g. torvalds/linux.',
        example: 'twigphp',
      },
      {
        name: 'weakness',
        type: 'string',
        description: 'Substring match on the weakness class.',
        example: 'use-after-free',
      },
      { name: 'q', type: 'string', description: 'Match on CVE id, finding id or title.' },
      { name: 'limit', type: 'number', description: 'Rows to return. Max 500.' },
    ],
  },
];

/** Endpoint lookup by `METHOD /path`, for the diagnostics helper. */
const BY_ROUTE = new Map(FILTER_CATALOGUE.map((e) => [`${e.method} ${e.path}`, e]));

/**
 * Params a route accepts that are NOT in its catalogue entry.
 *
 * Shared across every catalogue endpoint: pagination and auth plumbing that
 * handlers read but that are not domain filters. Anything in this set will
 * never be reported as unknown.
 */
export const UNIVERSAL_PARAMS = new Set(['limit', 'offset', 'page', 'format', 'pretty', 'fields']);

/**
 * Find query keys a route does not accept.
 *
 * Returns an empty array when the route is not in the catalogue: an unlisted
 * route is a documentation gap, not a client error, and flagging its every
 * parameter would produce noise that trains people to ignore the header.
 *
 * `known` can be supplied to widen a route's declared set at the call site for
 * handler-specific extras that are not worth their own catalogue entry.
 */
export function findUnknownParams(
  method: string,
  path: string,
  queryKeys: string[],
  known: Iterable<string> = []
): string[] {
  const entry = BY_ROUTE.get(`${method.toUpperCase()} ${path}`);
  if (!entry) return [];

  const accepted = new Set<string>([
    ...entry.params.map((p) => p.name),
    ...(entry.passThrough ?? []),
    ...UNIVERSAL_PARAMS,
    ...known,
  ]);
  return [...new Set(queryKeys)].filter((k) => !accepted.has(k));
}

/**
 * Response headers describing any ignored parameters.
 *
 * `X-Unknown-Params` carries the comma-separated names. `X-Filter-Catalog`
 * points at the endpoint that documents what this route accepts, so a caller
 * who ignored the first header has somewhere to go from the second.
 *
 * Query-param names are attacker-controlled. `new URL()` percent-decodes
 * them, so a key like `x%0D%0AInjected` arrives containing CR/LF and
 * `Headers.set` throws on the illegal value — turning a harmless typo into
 * a 500. Drop anything that is not a plausible parameter token.
 */
export function unknownParamHeaders(unknown: string[], path: string): Record<string, string> {
  const safe = unknown.filter((name) => SAFE_PARAM_NAME_RE.test(name));
  if (safe.length === 0) return {};
  return {
    'X-Unknown-Params': safe.join(','),
    'X-Filter-Catalog': '/api/v1/filters',
    'X-Note': `${safe.join(', ')} ignored. See /api/v1/filters for accepted parameters on ${path}.`,
  };
}

/** Conservative param-name shape: letters, digits, `_`, `-`, `[`, `]`, `.`. */
const SAFE_PARAM_NAME_RE = /^[A-Za-z0-9_.\-[\]]{1,128}$/;

/** The `/api/v1/filters` payload. */
export function buildFilterCatalogResponse(): Record<string, unknown> {
  return {
    schemaVersion: 'filter-catalog-v1',
    description:
      'Machine-readable catalogue of the filter parameters this API accepts. Any parameter not listed for an endpoint is ignored by that endpoint; GET responses carry an X-Unknown-Params header naming anything they ignored.',
    identifierNormalisation: {
      note: 'CVE identifiers are accepted leniently across the API.',
      equivalentForms: ['CVE-2025-1974', 'cve-2025-1974', 'CVE:2025-1974', '2025-1974'],
      notEquivalent: 'GHSA and EUVD identifiers are NOT auto-translated; look them up through their own routes.',
    },
    endpoints: FILTER_CATALOGUE,
  };
}
