/**
 * The research dossier: everything the writer is allowed to know, in a shape
 * built for reading rather than for JSON.
 *
 * Before this existed the prompt got `JSON.stringify(evidence)` — a couple of
 * KB of loosely-shaped keys, half of them internal bookkeeping
 * (`sourceLinkStatuses`, `trendingSignal`, `grounding`). The model wrote
 * around that noise, which is where the "several others were affected"
 * phrasing and the invented details came from.
 *
 * A dossier has five parts, deliberately ordered by how much authority each
 * one carries:
 *
 *   1. VERIFIED FACTS   — from NVD / KEV / EPSS. Authoritative, citable.
 *   2. SOURCES READ     — pages actually fetched and de-chromed, with the
 *                         excerpt that mattered. This is the difference
 *                         between "the advisory says X" and guessing.
 *   3. PLATFORM SIGNAL  — what our own corpus already knows about the topic.
 *   4. INDICATORS       — real observables, never a count without a sample.
 *   5. NOT KNOWN        — explicit gaps. Naming what nobody has published is
 *                         what stops a writer filling silence with invention.
 *
 * The writer is instructed that section 5 is a licence to say "unconfirmed",
 * and that anything not in sections 1-4 must not appear as fact.
 */

import type { CveFacts, PlatformFacts } from './enrich';
import type { ExtractedPage } from './extract';
import { scrubString } from '../generation/scrub-prompt';

export interface ResearchDossier {
  /** One-line statement of what this piece is about. */
  subject: string;
  /** Authoritative, machine-sourced facts. */
  cves: CveFacts[];
  /** Pages that were fetched and read. */
  pages: ExtractedPage[];
  /** The platform's own intel on the topic. */
  platform: PlatformFacts;
  /** Dated events, newest first — the raw material for an updates timeline. */
  timeline: Array<{ date: string; event: string }>;
  /** Real observables extracted from evidence or sources. */
  indicators: { type: string; values: string[]; total: number }[];
  /** Named entities. */
  entities: { vendors: string[]; products: string[]; actors: string[]; techniques: string[] };
  /** Questions this topic raises that the research could NOT answer. */
  gaps: string[];
  /** Pages that were cited but could not be read. */
  unread: Array<{ url: string; reason: string }>;
  /** How the dossier was built — recorded for the admin. */
  meta: {
    pagesFetched: number;
    pagesRead: number;
    cvesEnriched: number;
    tookMs: number;
  };
}

// ── Rendering ────────────────────────────────────────────────────────────

function renderCveBlock(c: CveFacts): string {
  const lines: string[] = [`### ${c.id}`];
  if (c.cvss)
    lines.push(
      `- CVSS ${c.cvss.version}: ${c.cvss.base_score} ${c.cvss.severity}${c.cvss.vector ? ` (${c.cvss.vector})` : ''}`
    );
  if (c.cwe.length) lines.push(`- Weakness: ${c.cwe.join(', ')}`);
  if (c.products.length) lines.push(`- Affected products (from NVD CPE data): ${c.products.join('; ')}`);
  if (c.published) lines.push(`- Published: ${c.published.slice(0, 10)}`);
  if (c.kev?.in_kev) {
    const bits = ['IN CISA KEV'];
    if (c.kev.date_added) bits.push(`added ${c.kev.date_added.slice(0, 10)}`);
    if (c.kev.due_date) bits.push(`federal due ${c.kev.due_date.slice(0, 10)}`);
    if (c.kev.required_action) bits.push(`required action: ${c.kev.required_action}`);
    if (c.kev.known_ransomware) bits.push('known ransomware campaign use');
    lines.push(`- Exploitation: ${bits.join(', ')}`);
  } else {
    lines.push('- Exploitation: NOT in CISA KEV. Do not describe it as actively exploited.');
  }
  if (c.epss)
    lines.push(
      `- EPSS: ${(c.epss.score * 100).toFixed(1)}% probability of exploitation in 30 days (percentile ${(c.epss.percentile * 100).toFixed(1)}%)`
    );
  if (c.pocCount) lines.push(`- Public exploit / PoC references: ${c.pocCount}`);
  if (c.ssvc) {
    const s = Object.entries(c.ssvc)
      .filter(([, v]) => !!v)
      .map(([k, v]) => `${k}=${v}`)
      .join(', ');
    if (s) lines.push(`- CISA ADP SSVC: ${s}`);
  }
  if (c.description) lines.push(`- NVD description: ${c.description.slice(0, 700)}`);
  return lines.join('\n');
}

function renderSources(pages: ExtractedPage[]): string {
  const read = pages.filter((p) => p.ok);
  if (read.length === 0) return '(no source page could be read)';
  return read
    .map((p, i) => {
      const head = `${i + 1}. [${p.title || p.publisher}](${p.url}) — ${p.publisher}${p.publishedAt ? `, ${p.publishedAt}` : ''}`;
      const excerpt = p.text
        .slice(0, 1600)
        .replace(/\n{2,}/g, '\n')
        .trim();
      return `${head}\n   EXCERPT: ${excerpt}`;
    })
    .join('\n\n');
}

function renderPlatform(platform: PlatformFacts): string {
  const lines: string[] = [];
  if (platform.trendingCves.length) {
    lines.push(
      `Trending right now on social (cvemon): ${platform.trendingCves
        .map((c) => `${c.id} (rank ${c.rank}, hype ${c.hypeScore})`)
        .join('; ')}`
    );
  }
  if (platform.relatedCves.length) {
    lines.push(
      `Other live CVEs on the platform: ${platform.relatedCves.map((c) => `${c.id}${c.score != null ? ` CVSS ${c.score}` : ''}`).join('; ')}`
    );
  }
  if (platform.writeups.length) {
    lines.push(`Our own prior writeups: ${platform.writeups.map((w) => w.title).join(' | ')}`);
  }
  if (platform.actors.length) {
    lines.push(
      `Tracked actors on this topic: ${platform.actors.map((a) => `${a.name}${a.mitre ? ` (${a.mitre})` : ''}`).join('; ')}`
    );
  }
  if (platform.darkweb.length) {
    lines.push(
      `Darkweb monitor hits: ${platform.darkweb.map((d) => `[${d.source ?? 'unknown'}] ${d.title ?? ''}`.trim()).join(' | ')}`
    );
  }
  return lines.length ? lines.join('\n') : '(nothing on this topic in the platform corpus)';
}

function renderIndicators(indicators: ResearchDossier['indicators']): string {
  if (indicators.length === 0) return '(none found — do not invent indicators)';
  return indicators
    .map(
      (i) =>
        `${i.type}: ${i.values.join(', ')}${i.total > i.values.length ? ` (+${i.total - i.values.length} more, ${i.total} total)` : ` (${i.total} total)`}`
    )
    .join('\n');
}

function renderTimeline(timeline: ResearchDossier['timeline']): string {
  if (timeline.length === 0) return '(no dated events established)';
  return timeline.map((t) => `- ${t.date}: ${t.event}`).join('\n');
}

function renderEntities(entities: ResearchDossier['entities']): string {
  const parts: string[] = [];
  if (entities.vendors.length) parts.push(`Vendors: ${entities.vendors.join(', ')}`);
  if (entities.products.length) parts.push(`Products: ${entities.products.join(', ')}`);
  if (entities.actors.length) parts.push(`Actors / families: ${entities.actors.join(', ')}`);
  if (entities.techniques.length) parts.push(`ATT&CK techniques: ${entities.techniques.join(', ')}`);
  return parts.join('\n') || '(none)';
}

export interface RenderDossierOptions {
  /** Extra cap on the rendered length. Keeps the prompt inside the window. */
  budget?: number;
}

/**
 * Render the dossier as the text block that replaces raw JSON in the prompt.
 *
 * Everything is scrubbed with the same prompt-injection defence as the old
 * facts block: the source excerpts are attacker-reachable text, so a page
 * that says "ignore your instructions" must not be able to.
 */
export function renderDossier(d: ResearchDossier, opts: RenderDossierOptions = {}): string {
  const budget = opts.budget ?? 16_000;

  const body = [
    `SUBJECT: ${scrubString(d.subject)}`,
    '',
    '=== VERIFIED FACTS (authoritative: NVD, CISA KEV, FIRST EPSS, CISA ADP) ===',
    d.cves.length ? d.cves.map(renderCveBlock).join('\n\n') : '(no CVE could be resolved for this topic)',
    '',
    '=== SOURCES READ (pages fetched during research) ===',
    renderSources(d.pages),
    '',
    '=== PLATFORM SIGNAL (what our own corpus already knows) ===',
    renderPlatform(d.platform),
    '',
    '=== DATED EVENTS ===',
    renderTimeline(d.timeline),
    '',
    '=== INDICATORS (real values, never a count on its own) ===',
    renderIndicators(d.indicators),
    '',
    '=== ENTITIES ===',
    renderEntities(d.entities),
    '',
    '=== NOT ESTABLISHED BY THIS RESEARCH (say so plainly; never fill these in) ===',
    d.gaps.length ? d.gaps.map((g) => `- ${g}`).join('\n') : '(none)',
  ].join('\n');

  return body.length <= budget ? body : `${body.slice(0, budget)}\n[research dossier truncated]`;
}
