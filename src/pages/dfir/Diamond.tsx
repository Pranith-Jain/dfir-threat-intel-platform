import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { Diamond as DiamondIcon, Loader2, RotateCcw, Download, ExternalLink, Wand2 } from 'lucide-react';
import {
  DIAMOND_VERTICES,
  META_FEATURES,
  EXTENDED_AXES,
  SAMPLE_EVENT,
  type EventForm,
  type VertexId,
} from '../../data/diamond';
import { detectIoc as detectIocBase } from '../../lib/dfir/ioc-detect';
import { downloadBlob } from '../../lib/download';

const STORAGE_KEY = 'dfir.diamond.event';
const EMPTY_EVENT: EventForm = {
  adversary: '',
  capability: '',
  infrastructure: '',
  victim: '',
  timestamp: '',
  phase: '',
  result: '',
  direction: '',
  methodology: '',
  resources: '',
  socioPolitical: '',
  technology: '',
};

function loadEvent(): EventForm {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return EMPTY_EVENT;
    const parsed = JSON.parse(raw);
    return { ...EMPTY_EVENT, ...parsed };
  } catch (_catchErr) {
    console.error('loadEvent failed:', errMessage(_catchErr));
    return EMPTY_EVENT;
  }
}

function buildMarkdown(e: EventForm): string {
  const has = (s: string) => s.trim().length > 0;
  const lines: string[] = ['# Diamond Model - Intrusion Event', ''];
  lines.push('## Core features', '');
  if (has(e.adversary)) lines.push(`- **Adversary:** ${e.adversary}`);
  if (has(e.capability)) lines.push(`- **Capability:** ${e.capability}`);
  if (has(e.infrastructure)) lines.push(`- **Infrastructure:** ${e.infrastructure}`);
  if (has(e.victim)) lines.push(`- **Victim:** ${e.victim}`);
  lines.push('', '## Meta-features', '');
  if (has(e.timestamp)) lines.push(`- **Timestamp:** ${e.timestamp}`);
  if (has(e.phase)) lines.push(`- **Phase:** ${e.phase}`);
  if (has(e.result)) lines.push(`- **Result:** ${e.result}`);
  if (has(e.direction)) lines.push(`- **Direction:** ${e.direction}`);
  if (has(e.methodology)) lines.push(`- **Methodology:** ${e.methodology}`);
  if (has(e.resources)) lines.push(`- **Resources:** ${e.resources}`);
  lines.push('', '## Extended', '');
  if (has(e.socioPolitical)) lines.push(`- **Socio-political:** ${e.socioPolitical}`);
  if (has(e.technology)) lines.push(`- **Technology:** ${e.technology}`);
  return lines.join('\n');
}

const VERTEX_KEY: Record<VertexId, keyof EventForm> = {
  adversary: 'adversary',
  capability: 'capability',
  infrastructure: 'infrastructure',
  victim: 'victim',
};

const VERTEX_POS: Record<VertexId, { x: number; y: number }> = {
  adversary: { x: 200, y: 24 },
  capability: { x: 376, y: 200 },
  victim: { x: 200, y: 376 },
  infrastructure: { x: 24, y: 200 },
};

/**
 * Detect IOC type for the auto-fill input. Extended to recognize actor
 * slugs in addition to network/file indicators - actor names trigger a
 * different fetch path (MITRE Group profile → Adversary corner direct).
 */
type DiamondIocType = 'ip' | 'ipv6' | 'domain' | 'url' | 'hash' | 'cve' | 'actor' | null;

const KNOWN_ACTORS_DIAMOND = new Set([
  'lockbit',
  'alphv',
  'blackcat',
  'cl0p',
  'clop',
  'akira',
  'play',
  'playcrypt',
  'black basta',
  'blackbasta',
  'royal',
  'medusa',
  'bianlian',
  'qilin',
  'agenda',
  'conti',
  'revil',
  'sodinokibi',
  'darkside',
  'blackbyte',
  'hive',
  'ryuk',
  'ragnarlocker',
  'ragnar locker',
  'rhysida',
  'volt-typhoon',
  'lazarus-group',
  'fancy-bear',
]);

function detectIoc(raw: string): { type: DiamondIocType; value: string } {
  const v = raw.trim();
  if (!v) return { type: null, value: '' };
  // Shared single-indicator detector (lib/dfir/ioc-detect), mapped onto the
  // coarser set the auto-fill acts on. Types it doesn't handle (email / btc /
  // asn / mitre) collapse to null - the same "unrecognized" result as before,
  // since the old local detector didn't test for them either.
  const base = detectIocBase(v);
  if (base) {
    switch (base.type) {
      case 'cve':
      case 'url':
      case 'ip':
      case 'ipv6':
      case 'domain':
        return { type: base.type, value: base.value };
      case 'hash-md5':
      case 'hash-sha1':
      case 'hash-sha256':
        return { type: 'hash', value: base.value };
      default:
        return { type: null, value: v };
    }
  }
  // Actor-slug fallback - lower-cased value must be in our curated lookup.
  const lower = v.toLowerCase();
  if (KNOWN_ACTORS_DIAMOND.has(lower)) return { type: 'actor', value: lower };
  return { type: null, value: v };
}

function Diamond(): JSX.Element {
  const [event, setEvent] = useState<EventForm>(EMPTY_EVENT);
  const [active, setActive] = useState<VertexId | null>(null);
  const [autoFillIndicator, setAutoFillIndicator] = useState('');
  const [autoFilling, setAutoFilling] = useState(false);
  const [autoFillNote, setAutoFillNote] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    setEvent(loadEvent());
  }, []);

  useEffect(() => () => abortRef.current?.abort(), []);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(event));
    } catch (_catchErr) {
      console.error('Diamond failed:', errMessage(_catchErr));
      /* quota / private mode - non-fatal */
    }
  }, [event]);

  const filledCount = DIAMOND_VERTICES.filter((v) => event[VERTEX_KEY[v.id]].trim()).length;

  const update = (k: keyof EventForm, v: string) => setEvent((e) => ({ ...e, [k]: v }));
  const reset = () => setEvent(EMPTY_EVENT);
  const loadSample = () => setEvent(SAMPLE_EVENT);

  /**
   * Auto-fill the four diamond corners by querying our own APIs for
   * context about the IOC. Conservative - fills only empty fields,
   * appends to existing ones if the user already typed something,
   * and surfaces a short note about what was actually filled vs
   * what we couldn't resolve.
   */
  const autoFill = async () => {
    const { type, value } = detectIoc(autoFillIndicator);
    if (!type) {
      setAutoFillNote('Unrecognized indicator. Expected IP / IPv6 / domain / URL / hash / CVE.');
      return;
    }
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    const signal = AbortSignal.any([ac.signal, AbortSignal.timeout(15_000)]);
    setAutoFilling(true);
    setAutoFillNote(null);
    const filled: string[] = [];
    const skipped: string[] = [];

    try {
      // ─── Actor name: pull Ransomlook profile + recent victims ─────────
      if (type === 'actor') {
        // The actor-timeline endpoint exposes the top-8 active groups; if
        // our input matches one, we get description, raas flag, MITRE ref,
        // and recent-window counts in one fetch.
        const tlRes = await fetch('/api/v1/actor-timeline', { signal });
        if (signal.aborted) return;
        if (tlRes.ok) {
          interface ActorRow {
            slug: string;
            display_name: string;
            description?: string;
            raas?: boolean;
            mitre?: { id: string; name: string; url: string };
            references?: string[];
            posts_in_window?: number;
            all_time_count?: number;
          }
          const body = (await tlRes.json()) as { groups: ActorRow[] };
          if (signal.aborted) return;
          const row = body.groups.find((g) => g.slug === value || g.display_name.toLowerCase() === value);
          if (row) {
            const advParts: string[] = [row.display_name];
            if (row.mitre) advParts.push(`MITRE ${row.mitre.id}`);
            if (row.raas) advParts.push('RaaS operator');
            if (row.all_time_count) advParts.push(`${row.all_time_count} all-time leak-site posts`);
            setEvent((e) => ({
              ...e,
              adversary: e.adversary || advParts.join(' · '),
              capability: e.capability || (row.description ?? `Ransomware group ${row.display_name}`).slice(0, 280),
              methodology:
                e.methodology ||
                (row.mitre
                  ? `MITRE ${row.mitre.id} - ${row.mitre.name}`
                  : `Ransomware operator (RaaS=${row.raas ? 'yes' : 'no'})`),
              direction: e.direction || 'External-to-Internal',
              result: e.result || 'Data exfiltration + encryption',
            }));
            filled.push('Adversary', 'Capability', 'Methodology', 'Direction', 'Result');
          } else {
            setEvent((e) => ({
              ...e,
              adversary: e.adversary || `${value} (not currently in top-8 active actors)`,
            }));
            filled.push('Adversary');
            skipped.push(`${value} not in current active-actor window`);
          }
        }

        // Also pull recent victims of this actor for the Victim corner.
        const rRes = await fetch('/api/v1/ransomware-recent', { signal });
        if (signal.aborted) return;
        if (rRes.ok) {
          interface Victim {
            victim: string;
            group: string;
            discovered: string;
            sector?: string;
          }
          const body = (await rRes.json()) as { victims: Victim[] };
          if (signal.aborted) return;
          const hits = body.victims.filter((v) => v.group === value).slice(0, 3);
          if (hits.length > 0) {
            const victimStr = hits.map((h) => `${h.victim}${h.sector ? ` (${h.sector})` : ''}`).join(', ');
            setEvent((e) => ({ ...e, victim: e.victim || `Recent claims: ${victimStr}` }));
            filled.push('Victim');
          }
        }

        setEvent((e) => ({
          ...e,
          timestamp: e.timestamp || new Date().toISOString(),
          phase: e.phase || 'Actions on objectives',
        }));
        filled.push('Timestamp', 'Phase');
        setAutoFillNote(
          `Filled: ${filled.join(', ')}. ${skipped.length ? `Skipped: ${skipped.join('; ')}. ` : ''}Edit any field to refine.`
        );
        setAutoFilling(false);
        return;
      }

      // ─── CVE: pull actor list + KEV context from cve-recent ────────────
      if (type === 'cve') {
        const res = await fetch('/api/v1/cve-recent', { signal });
        if (signal.aborted) return;
        if (res.ok) {
          const body = (await res.json()) as {
            cves: Array<{
              id: string;
              description: string;
              kev: boolean;
              kev_ransomware?: boolean;
              actors?: Array<{ slug: string; mitre_id?: string; mitre_name?: string }>;
            }>;
          };
          if (signal.aborted) return;
          const cve = body.cves.find((c) => c.id === value);
          if (cve) {
            const adversaryParts: string[] = [];
            if (cve.actors && cve.actors.length > 0) {
              for (const a of cve.actors) {
                adversaryParts.push(`${a.mitre_name ?? a.slug}${a.mitre_id ? ` (${a.mitre_id})` : ''}`);
              }
            } else if (cve.kev_ransomware) {
              adversaryParts.push('Unattributed ransomware operator (CISA KEV ransomware-use flag)');
            } else if (cve.kev) {
              adversaryParts.push('Active in-the-wild exploitation (CISA KEV - actor unknown)');
            }
            if (adversaryParts.length > 0) {
              setEvent((e) => ({ ...e, adversary: e.adversary || adversaryParts.join(', ') }));
              filled.push('Adversary');
            } else skipped.push('Adversary (no actor attribution for this CVE)');

            setEvent((e) => ({
              ...e,
              capability: e.capability || `${value} - ${cve.description.slice(0, 200)}`,
              technology: e.technology || `Vulnerability class: ${cve.description.slice(0, 80)}`,
            }));
            filled.push('Capability', 'Technology');
          } else {
            skipped.push(`${value} not in current cve-recent window`);
          }
        }
      }

      // ─── IP / IPv6: pull GreyNoise + ip-geo + correlation ─────────────
      if (type === 'ip' || type === 'ipv6') {
        const [iocRes, geoRes, corrRes] = await Promise.allSettled([
          fetch(
            `/api/v1/ioc/check?indicator=${encodeURIComponent(value)}&providers=greynoise,abuseipdb,otx,threatfox,cinsarmy`,
            { signal }
          ),
          fetch(`/api/v1/ip-geo?ip=${encodeURIComponent(value)}`, { signal }),
          fetch('/api/v1/ioc-correlation', { signal }),
        ]);
        if (signal.aborted) return;

        // ip-geo → Infrastructure corner
        if (geoRes.status === 'fulfilled' && geoRes.value.ok) {
          const g = (await geoRes.value.json()) as { country?: string; city?: string; org?: string; as?: string };
          if (signal.aborted) return;
          const parts = [g.org ?? g.as, g.country, g.city].filter(Boolean);
          if (parts.length > 0) {
            setEvent((e) => ({
              ...e,
              infrastructure: e.infrastructure || `${value} · ${parts.join(' / ')}`,
            }));
            filled.push('Infrastructure');
          }
        } else skipped.push('Infrastructure (ip-geo unavailable)');

        // Cross-source correlation → Adversary hint
        if (corrRes.status === 'fulfilled' && corrRes.value.ok) {
          const c = (await corrRes.value.json()) as {
            ips: Array<{ value: string; sources: string[]; source_count: number; context?: string }>;
          };
          if (signal.aborted) return;
          const hit = c.ips.find((i) => i.value === value);
          if (hit) {
            const advFromCorr = `Observed in ${hit.source_count} independent feeds (${hit.sources.join(', ')})${hit.context ? ` · context: ${hit.context}` : ''}`;
            setEvent((e) => ({ ...e, adversary: e.adversary || advFromCorr }));
            filled.push('Adversary');
          }
        }

        // ioc-check → Capability hints (any "malicious" verdict tags)
        if (iocRes.status === 'fulfilled' && iocRes.value.ok) {
          // SSE stream - read the whole text and grep for tags. This is a
          // pragmatic shortcut; for a proper read we'd parse event-stream.
          const text = await iocRes.value.text();
          if (signal.aborted) return;
          const tags = new Set<string>();
          for (const line of text.split('\n')) {
            const m = /"tags":\s*\[([^\]]*)\]/.exec(line);
            if (m) {
              for (const t of (m[1] ?? '').split(',')) {
                const cleaned = t.replace(/["\s]/g, '');
                if (cleaned) tags.add(cleaned);
              }
            }
          }
          if (tags.size > 0) {
            const tagStr = [...tags].slice(0, 8).join(', ');
            setEvent((e) => ({ ...e, capability: e.capability || `Reported behaviors: ${tagStr}` }));
            filled.push('Capability');
          }
        }
      }

      // ─── domain / URL: domain-lookup + correlation + victim match ────
      if (type === 'domain' || type === 'url') {
        const lookupTarget = type === 'url' ? new URL(value).hostname : value;
        const [domainRes, corrRes, victimRes] = await Promise.allSettled([
          fetch(`/api/v1/domain/lookup?domain=${encodeURIComponent(lookupTarget)}`, { signal }),
          fetch('/api/v1/ioc-correlation', { signal }),
          fetch('/api/v1/ransomware-recent', { signal }),
        ]);
        if (signal.aborted) return;

        // Victim cross-match: ransomware-recent victim names sometimes ARE
        // domain forms (e.g. "bayareaherbs.com"). If the input domain matches
        // a known victim, fill the Victim corner with the group claiming it.
        if (victimRes.status === 'fulfilled' && victimRes.value.ok) {
          interface Victim {
            victim: string;
            group: string;
            discovered: string;
            sector?: string;
          }
          const vb = (await victimRes.value.json()) as { victims: Victim[] };
          if (signal.aborted) return;
          const target = lookupTarget.toLowerCase();
          const hit = vb.victims.find((v) => {
            const vn = v.victim.trim().toLowerCase();
            if (vn.length < 4) return false;
            return vn === target || vn === 'www.' + target || target === 'www.' + vn;
          });
          if (hit) {
            setEvent((e) => ({
              ...e,
              victim:
                e.victim ||
                `${hit.victim}${hit.sector ? ` (${hit.sector})` : ''} - claimed by ${hit.group} on ${hit.discovered.slice(0, 10)}`,
              adversary: e.adversary || `${hit.group} (ransomware operator)`,
            }));
            filled.push('Victim', 'Adversary (from ransomware claim)');
          }
        }

        if (domainRes.status === 'fulfilled' && domainRes.value.ok) {
          const d = (await domainRes.value.json()) as {
            whois?: { registrar?: string; created?: string };
            dns?: { a?: string[] };
          };
          if (signal.aborted) return;
          const infra: string[] = [lookupTarget];
          if (d.whois?.registrar) infra.push(`registrar: ${d.whois.registrar}`);
          if (d.whois?.created) infra.push(`created: ${d.whois.created.slice(0, 10)}`);
          if (d.dns?.a?.length) infra.push(`A: ${d.dns.a.slice(0, 3).join(', ')}`);
          setEvent((e) => ({ ...e, infrastructure: e.infrastructure || infra.join(' · ') }));
          filled.push('Infrastructure');
        }

        if (corrRes.status === 'fulfilled' && corrRes.value.ok) {
          const c = (await corrRes.value.json()) as {
            domains: Array<{ value: string; sources: string[]; source_count: number; context?: string }>;
            urls: Array<{ value: string; sources: string[]; source_count: number; context?: string }>;
          };
          if (signal.aborted) return;
          const pool = type === 'url' ? c.urls : c.domains;
          const hit = pool.find((i) => i.value === (type === 'url' ? value : lookupTarget));
          if (hit) {
            const adv = `Observed in ${hit.source_count} feeds (${hit.sources.join(', ')})${hit.context ? ` · ${hit.context}` : ''}`;
            setEvent((e) => ({ ...e, adversary: e.adversary || adv }));
            filled.push('Adversary');
          }
        }
      }

      // ─── hash: malware-sample lookup for family signature ─────────────
      if (type === 'hash') {
        const res = await fetch('/api/v1/malware-samples', { signal });
        if (signal.aborted) return;
        if (res.ok) {
          const body = (await res.json()) as {
            samples: Array<{
              sha256?: string;
              md5?: string;
              sha1?: string;
              signature?: string;
              tags?: string[];
              file_type?: string;
            }>;
          };
          if (signal.aborted) return;
          const hit = body.samples.find((s) => s.sha256 === value || s.md5 === value || s.sha1 === value);
          if (hit) {
            const cap = `${hit.signature ?? 'Unknown family'}${hit.file_type ? ` (${hit.file_type})` : ''}${hit.tags?.length ? ` - tags: ${hit.tags.slice(0, 5).join(', ')}` : ''}`;
            setEvent((e) => ({
              ...e,
              capability: e.capability || cap,
              technology: e.technology || `File type: ${hit.file_type ?? 'unknown'}`,
            }));
            filled.push('Capability', 'Technology');
          } else {
            skipped.push(`Hash not in MalwareBazaar recent window - try /dfir/ioc-check for broader hash lookup`);
          }
        }
      }

      // Always stamp the indicator on Infrastructure if nothing else filled it.
      if (signal.aborted) return;
      setEvent((e) => ({
        ...e,
        infrastructure: e.infrastructure || `Observed indicator: ${value} (${type})`,
        timestamp: e.timestamp || new Date().toISOString(),
        phase: e.phase || (type === 'cve' ? 'Exploitation' : 'Delivery'),
      }));
      if (!filled.includes('Infrastructure')) filled.push('Infrastructure');
      filled.push('Timestamp', 'Phase');

      setAutoFillNote(
        `Filled: ${filled.join(', ')}. ${skipped.length ? `Skipped: ${skipped.join('; ')}. ` : ''}Edit any field to refine.`
      );
    } catch (e) {
      logCatch(e);
      if ((e as Error).name === 'AbortError') return;
      setAutoFillNote(`Auto-fill failed: ${(e as Error).message}`);
    } finally {
      if (!signal.aborted) setAutoFilling(false);
    }
  };

  const exportMd = () => {
    const md = buildMarkdown(event);
    const blob = new Blob([md], { type: 'text/markdown' });
    downloadBlob(blob, 'diamond-event.md');
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2 flex items-center gap-3">
          <DiamondIcon size={28} className="text-brand-600 dark:text-brand-400" /> Diamond Model
        </h1>
        <p className="text-muted mb-2 leading-relaxed">
          Caltagirone, Pendergast &amp; Betz, 2013. Every intrusion event is a connected diamond of Adversary,
          Capability, Infrastructure and Victim, plus meta-features describing the event itself.
        </p>
        <p className="text-xs text-muted font-mono mb-8">
          Pairs with the{' '}
          <Link to="/dfir/kill-chain" className="text-brand-600 dark:text-brand-400 hover:underline">
            Cyber Kill Chain
          </Link>{' '}
          (where in the timeline) and{' '}
          <Link to="/threatintel/wiki/mitre" className="text-brand-600 dark:text-brand-400 hover:underline">
            MITRE ATT&amp;CK
          </Link>{' '}
          (which TTPs).
        </p>
      </div>

      {/* Diagram + tabs */}
      <div className="grid gap-6 lg:grid-cols-[400px_1fr] mb-8">
        <div className="surface-card p-4 flex items-center justify-center">
          <svg viewBox="0 0 400 400" className="w-full h-auto max-w-[360px]" role="img" aria-label="Diamond model">
            {/* Connecting edges */}
            <polygon
              points="200,40 360,200 200,360 40,200"
              fill="none"
              className="stroke-slate-300 dark:stroke-slate-700"
              strokeWidth="2"
            />
            {/* Diagonals */}
            <line
              x1="200"
              y1="40"
              x2="200"
              y2="360"
              className="stroke-slate-300 dark:stroke-slate-700"
              strokeWidth="1"
              strokeDasharray="4 4"
            />
            <line
              x1="40"
              y1="200"
              x2="360"
              y2="200"
              className="stroke-slate-300 dark:stroke-slate-700"
              strokeWidth="1"
              strokeDasharray="4 4"
            />
            {DIAMOND_VERTICES.map((v) => {
              const pos = VERTEX_POS[v.id];
              const isActive = active === v.id;
              const isFilled = event[VERTEX_KEY[v.id]].trim().length > 0;
              return (
                <g
                  key={v.id}
                  className="cursor-pointer"
                  onMouseEnter={() => setActive(v.id)}
                  onMouseLeave={() => setActive(null)}
                  onClick={() => setActive(v.id)}
                >
                  <circle
                    cx={pos.x}
                    cy={pos.y}
                    r={isActive ? 50 : 44}
                    className={`transition-all ${
                      isFilled
                        ? 'fill-brand-500/20 stroke-brand-500'
                        : isActive
                          ? 'fill-slate-200 dark:fill-slate-800 stroke-slate-400'
                          : 'fill-white dark:fill-slate-900 stroke-slate-300 dark:stroke-slate-700'
                    }`}
                    strokeWidth="2"
                  />
                  <text
                    x={pos.x}
                    y={pos.y - 4}
                    textAnchor="middle"
                    className="font-display font-semibold fill-slate-900 dark:fill-slate-100"
                    style={{ fontSize: 13 }}
                  >
                    {v.name}
                  </text>
                  <text
                    x={pos.x}
                    y={pos.y + 14}
                    textAnchor="middle"
                    className="font-mono fill-slate-500 dark:fill-slate-500"
                    style={{ fontSize: 9 }}
                  >
                    {isFilled ? '● filled' : '○ empty'}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        <div className="surface-card p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono">
              {active ? `${DIAMOND_VERTICES.find((v) => v.id === active)?.name}` : 'Vertices'}
            </h2>
            <span className="text-xs font-mono text-muted">
              {filledCount} / {DIAMOND_VERTICES.length} filled
            </span>
          </div>
          {active ? (
            (() => {
              const v = DIAMOND_VERTICES.find((x) => x.id === active)!;
              return (
                <div className="space-y-3 text-sm font-mono text-body">
                  <p>{v.description}</p>
                  <div>
                    <h3 className="text-micro font-bold uppercase tracking-[0.2em] text-muted mb-1">Pivot points</h3>
                    <ul className="space-y-1 text-meta list-disc pl-4">
                      {v.pivots.map((p) => (
                        <li key={p}>{p}</li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <h3 className="text-micro font-bold uppercase tracking-[0.2em] text-muted mb-1">Tools</h3>
                    <p className="text-meta">{v.tools.join(' · ')}</p>
                  </div>
                </div>
              );
            })()
          ) : (
            <ul className="space-y-2 text-sm font-mono text-muted">
              {DIAMOND_VERTICES.map((v) => (
                <li key={v.id} className="flex items-baseline gap-2">
                  <span className="text-brand-600 dark:text-brand-400 font-semibold">{v.name}</span>
                  <span className="text-xs">- {v.short}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* Event editor */}
      {/* Auto-fill from IOC */}
      <section className="rounded-xl border border-emerald-500/40 bg-emerald-500/5 dark:bg-emerald-900/10 p-4 mb-6">
        <div className="flex items-center gap-2 mb-2">
          <Wand2 size={14} className="text-emerald-600 dark:text-emerald-400" />
          <h2 className="text-xs font-bold uppercase tracking-[0.2em] text-emerald-700 dark:text-emerald-300 font-mono">
            Auto-fill from indicator
          </h2>
        </div>
        <p className="text-mini font-mono text-muted mb-2">
          Paste any IP / IPv6 / domain / URL / hash / CVE / ransomware-actor-name - we pull context from IOC checker,
          ip-geo, cross-source correlation, KEV+actor mapping, MalwareBazaar, actor-timeline (MITRE Group), and
          ransomware-victim cross-match, then populate empty corners. Won&apos;t overwrite anything you&apos;ve already
          typed.
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void autoFill();
          }}
          className="flex gap-2"
        >
          <input
            type="text"
            value={autoFillIndicator}
            onChange={(e) => setAutoFillIndicator(e.target.value)}
            placeholder="e.g. 1.2.3.4 · evil.example.com · CVE-2024-1709 · sha256 · lockbit / akira / qilin"
            className="flex-1 px-3 py-2 bg-surface-100 border border-line-2 rounded font-mono text-sm focus:outline-none focus:border-emerald-500"
            aria-label="Indicator to auto-fill from"
          />
          <button
            type="submit"
            disabled={autoFilling || !autoFillIndicator.trim()}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded border border-emerald-500/60 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 text-sm font-mono font-semibold hover:bg-emerald-500/25 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {autoFilling ? <Loader2 size={14} className="animate-spin" /> : <Wand2 size={14} />}
            {autoFilling ? 'filling…' : 'Auto-fill'}
          </button>
        </form>
        {autoFillNote && <p className="text-mini font-mono text-body mt-2">{autoFillNote}</p>}
      </section>

      <section className="surface-card p-4 mb-6">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono">Intrusion event</h2>
          <div className="flex flex-wrap gap-2 w-full sm:w-auto">
            <button
              type="button"
              onClick={loadSample}
              className="text-xs font-mono px-3 py-2 sm:px-2 sm:py-1 min-h-[44px] sm:min-h-0 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center transition-colors"
            >
              Load sample
            </button>
            <button
              type="button"
              onClick={exportMd}
              className="text-xs font-mono px-3 py-2 sm:px-2 sm:py-1 min-h-[44px] sm:min-h-0 rounded border border-line-2 hover:border-brand-500/40 hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1.5 transition-colors"
            >
              <Download size={12} /> Export markdown
            </button>
            <button
              type="button"
              onClick={reset}
              className="text-xs font-mono px-3 py-2 sm:px-2 sm:py-1 min-h-[44px] sm:min-h-0 rounded border border-line-2 hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-1.5 transition-colors"
            >
              <RotateCcw size={12} /> Reset
            </button>
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          {DIAMOND_VERTICES.map((v) => {
            const k = VERTEX_KEY[v.id];
            return (
              <label key={v.id} className="block">
                <span className="text-xs font-mono text-body mb-1 block">
                  {v.name} <span className="text-muted">- {v.short}</span>
                </span>
                <textarea
                  value={event[k]}
                  onChange={(e) => update(k, e.target.value)}
                  rows={3}
                  className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs text-heading focus:border-brand-500/60 focus:outline-none"
                  placeholder={v.examples[0]}
                />
              </label>
            );
          })}
        </div>
      </section>

      {/* Meta-features */}
      <section className="surface-card p-4 mb-6">
        <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">Meta-features</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {META_FEATURES.map((m) => {
            const k = m.id as keyof EventForm;
            return (
              <label key={m.id} className="block">
                <span className="text-xs font-mono text-body mb-1 block">{m.name}</span>
                <input
                  type="text"
                  value={event[k]}
                  onChange={(e) => update(k, e.target.value)}
                  className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs text-heading focus:border-brand-500/60 focus:outline-none"
                  placeholder={m.description}
                />
              </label>
            );
          })}
        </div>
      </section>

      {/* Extended axes */}
      <section className="surface-card p-4 mb-6">
        <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">Extended axes</h2>
        <div className="grid gap-3 md:grid-cols-2">
          {EXTENDED_AXES.map((a) => {
            const k = a.id === 'social-political' ? 'socioPolitical' : 'technology';
            return (
              <div key={a.id}>
                <label className="block">
                  <span className="text-xs font-mono text-body mb-1 block">{a.name}</span>
                  <textarea
                    value={event[k as keyof EventForm]}
                    onChange={(e) => update(k as keyof EventForm, e.target.value)}
                    rows={3}
                    className="w-full rounded border border-line-2 bg-surface-200 px-2 py-1.5 font-mono text-xs text-heading focus:border-brand-500/60 focus:outline-none"
                    placeholder={a.description}
                  />
                </label>
                <ul className="mt-1.5 text-mini font-mono text-muted space-y-0.5 list-disc pl-4">
                  {a.questions.map((q) => (
                    <li key={q}>{q}</li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      </section>

      <section className="surface-card p-4">
        <h2 className="text-eyebrow font-mono uppercase tracking-[0.2em] text-muted font-mono mb-3">References</h2>
        <ul className="space-y-1.5 text-sm font-mono text-muted">
          <li>
            <a
              href="https://apps.dtic.mil/sti/citations/ADA586960"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              Caltagirone, Pendergast &amp; Betz - The Diamond Model of Intrusion Analysis (2013)
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
          <li>
            <a
              href="https://www.activeresponse.org/the-diamond-model/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1 transition-colors"
            >
              ActiveResponse - Diamond Model overview &amp; examples
              <ExternalLink size={11} aria-hidden="true" />
            </a>
          </li>
        </ul>
      </section>
    </div>
  );
}

export default Diamond;
