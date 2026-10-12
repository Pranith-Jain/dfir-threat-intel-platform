/**
 * Package URL (purl) parsing and construction.
 *
 * We already emit `pkg:` strings in two places (`depx.ts`, `package-verdict.ts`)
 * by string concatenation, and we already parse CPE 2.3 criteria one-way in
 * `cve-lookup.ts`. Neither can convert between the two, which is what an
 * ecosystem-level question needs: "which CVEs hit npm?" cannot be answered when
 * NVD gives you `cpe:2.3:a:lodash:lodash` and the scanner gives you
 * `pkg:npm/lodash`.
 *
 * Spec: https://github.com/package-url/purl-spec
 *
 * Grammar, in the part that matters here:
 *   pkg:type/namespace/name@version?qualifiers#subpath
 *
 * The parse is deliberately strict about the things that change meaning
 * (type must be a known one, name must not be empty) and forgiving about the
 * things that do not (percent-encoding is normalised, namespace segments are
 * accepted for types that take them and ignored for types that do not).
 */

/** Known purl types. Unknown types are rejected: a `pkg:` string with a typo'd
 * type would otherwise parse "successfully" and silently miss every lookup. */
export const PURL_TYPES = [
  'alpm',
  'apk',
  'bitbucket',
  'cargo',
  'cocoapods',
  'composer',
  'conan',
  'conda',
  'cpan',
  'cran',
  'deb',
  'docker',
  'gem',
  'generic',
  'github',
  'golang',
  'hackage',
  'hex',
  'huggingface',
  'luarocks',
  'maven',
  'mlflow',
  'npm',
  'nuget',
  'oci',
  'pub',
  'pypi',
  'qpkg',
  'rpm',
  'swid',
] as const;

export type PurlType = (typeof PURL_TYPES)[number];

/** Types whose identifier is `namespace/name` rather than a flat name. */
const NAMESPACED = new Set<string>([
  'maven',
  'golang',
  'composer',
  'npm',
  'github',
  'bitbucket',
  'pypi',
  'cargo',
  'gem',
  'cran',
  'huggingface',
  'hex',
  'pub',
  'conan',
  'cocoapods',
  'nuget',
  'generic',
]);

export interface Purl {
  type: PurlType;
  /** Namespace segments, deepest-last. Empty for unnamespaced types. */
  namespace: string[];
  name: string;
  version: string | null;
  /** Qualifier key/value pairs, lowercased keys per spec. */
  qualifiers: Record<string, string>;
  subpath: string | null;
  /** The canonical `pkg:` form, for round-tripping. */
  canonical: string;
}

/**
 * Percent-decode without throwing on a malformed sequence.
 *
 * `decodeURIComponent('%')` throws, and one bad byte in a scraped package name
 * should not take down a scan of a whole lockfile.
 */
function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Lowercase a purl type. The spec requires it; `pkg:NPM/x` is not valid. */
function canonicalType(raw: string): PurlType | null {
  const lower = raw.trim().toLowerCase();
  return (PURL_TYPES as readonly string[]).includes(lower) ? (lower as PurlType) : null;
}

/**
 * Parse a `pkg:` string.
 *
 * Returns null on anything malformed rather than a partially-populated object.
 * A caller that received a Purl with a null name would go on to query a
 * registry with an empty package name, which is a worse outcome than an
 * explicit "not a purl".
 */
export function parsePurl(input: string | null | undefined): Purl | null {
  if (!input) return null;
  const raw = input.trim();
  if (!/^pkg:/i.test(raw)) return null;

  let rest = raw.slice(4);

  let subpath: string | null = null;
  const hash = rest.indexOf('#');
  if (hash >= 0) {
    subpath = safeDecode(rest.slice(hash + 1)).replace(/^\/+|\/+$/g, '') || null;
    rest = rest.slice(0, hash);
  }

  const qualifiers: Record<string, string> = {};
  const qmark = rest.indexOf('?');
  if (qmark >= 0) {
    const qs = rest.slice(qmark + 1);
    rest = rest.slice(0, qmark);
    for (const pair of qs.split('&')) {
      if (!pair) continue;
      const eq = pair.indexOf('=');
      if (eq < 0) continue;
      const key = safeDecode(pair.slice(0, eq)).toLowerCase();
      const value = safeDecode(pair.slice(eq + 1));
      if (key) qualifiers[key] = value;
    }
  }

  let version: string | null = null;
  const at = rest.lastIndexOf('@');
  // Guard against a leading `@` being read as the version separator when the
  // type is missing (`pkg:/@scope/name`).
  if (at > 0) {
    version = safeDecode(rest.slice(at + 1)) || null;
    rest = rest.slice(0, at);
  }

  const slash = rest.indexOf('/');
  if (slash < 0) return null;

  const type = canonicalType(rest.slice(0, slash));
  if (!type) return null;

  const remainder = rest.slice(slash + 1);
  if (!remainder) return null;

  const segments = remainder.split('/').filter(Boolean).map(safeDecode);
  if (segments.length === 0) return null;

  // Namespaced types keep every leading segment as a namespace and the last as
  // the name. Unnamespaced types (deb, rpm, apk, ...) take the whole remainder
  // as the name, because `pkg:deb/debian/curl/amd64` is one name, not three.
  const name = NAMESPACED.has(type) ? segments[segments.length - 1] : remainder;
  const namespace = NAMESPACED.has(type) ? segments.slice(0, -1) : [];
  if (!name) return null;

  return {
    type,
    namespace,
    name,
    version,
    qualifiers,
    subpath,
    canonical: buildPurl({ type, namespace, name, version, qualifiers, subpath }),
  };
}

/** Build the canonical `pkg:` string. Input fields win over any cache. */
export function buildPurl(parts: {
  type: PurlType | string;
  namespace?: string[];
  name: string;
  version?: string | null;
  qualifiers?: Record<string, string>;
  subpath?: string | null;
}): string {
  const type = String(parts.type).toLowerCase();
  const namespace = parts.namespace ?? [];
  const segments = NAMESPACED.has(type) ? [...namespace, parts.name] : [parts.name];
  let out = `pkg:${type}/${segments.map((s) => encodeURIComponent(s)).join('/')}`;
  if (parts.version) out += `@${encodeURIComponent(parts.version)}`;

  const qualifiers = parts.qualifiers ?? {};
  const qs = Object.entries(qualifiers)
    // The spec reserves these keys; emitting them is invalid purl.
    .filter(([k]) => !['checksum', 'file_name', 'repository_url'].includes(k.toLowerCase()))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k.toLowerCase()}=${encodeURIComponent(v)}`)
    .join('&');
  if (qs) out += `?${qs}`;
  if (parts.subpath) out += `#${parts.subpath.split('/').map(encodeURIComponent).join('/')}`;

  return out;
}

/** The package name without namespace, for display or registry lookups. */
export function purlBareName(purl: string): string | null {
  const parsed = parsePurl(purl);
  return parsed ? parsed.name : null;
}

/**
 * The identity used to match two purls to each other.
 *
 * Version is deliberately excluded: coverage questions and lockfile questions
 * both ask "do we have anything for this package", and including the version
 * would make every comparison fail on a patch bump. Callers that do care about
 * the version should compare `version` explicitly.
 */
export function purlIdentity(purl: string): string | null {
  const parsed = parsePurl(purl);
  if (!parsed) return null;
  return [parsed.type, ...parsed.namespace, parsed.name].join('/');
}

/**
 * Ecosystem implied by a CPE 2.3 URI.
 *
 * The mapping is approximate on purpose. CPE names a product in a vendor's own
 * vocabulary; purl names a package in a registry's. There is no exact
 * correspondence, and anything claiming otherwise would be inventing data.
 * Returning null for an unrecognised vendor is the honest answer, and the
 * caller should fall back to a name comparison rather than trust a guess.
 */
const CPE_VENDOR_TO_TYPE: Record<string, PurlType> = {
  npm: 'npm',
  nodejs: 'npm',
  pypi: 'pypi',
  python: 'pypi',
  cargo: 'cargo',
  rust: 'cargo',
  maven: 'maven',
  apache: 'maven',
  golang: 'golang',
  go: 'golang',
  ruby: 'gem',
  gem: 'gem',
  nuget: 'nuget',
  csharp: 'nuget',
  packagist: 'composer',
  composer: 'composer',
  packagist_php: 'composer',
  hex: 'hex',
  elixir: 'hex',
  pub: 'pub',
  dart: 'pub',
  flutter: 'pub',
  cpan: 'cpan',
  perl: 'cpan',
  hackage: 'hackage',
  haskell: 'hackage',
  cocoapods: 'cocoapods',
};

/**
 * Derive a purl from a CPE 2.3 criteria string.
 *
 * Returns null when the vendor is not a recognised registry name, which is most
 * of CPE: NVD's vendor vocabulary is product vendors, not language registries.
 * A caller wanting a best-effort join should treat a null here as "compare the
 * product name directly", not as "no match".
 */
export function purlFromCpe(cpe23: string | null | undefined): Purl | null {
  if (!cpe23 || !cpe23.startsWith('cpe:2.3:')) return null;

  const parts = cpe23.split(':');
  // cpe:2.3:<part>:<vendor>:<product>:<version>:...
  const vendor = parts[3];
  const product = parts[4];
  if (!vendor || !product) return null;

  const type = CPE_VENDOR_TO_TYPE[vendor.toLowerCase()];
  if (!type) return null;

  const version = parts[5] && parts[5] !== '*' && parts[5] !== '-' ? parts[5] : null;
  // A CPE product name is CamelCase or hyphenated (`openssl`, `Zimbra`); purl
  // names are lowercased by convention. Normalise so the two can be compared.
  const name = product.toLowerCase().replace(/[_\s]+/g, '-');

  return parsePurl(buildPurl({ type, name, version }));
}
