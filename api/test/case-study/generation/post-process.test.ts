import { describe, it, expect } from 'vitest';
import { postProcess } from '../../../src/case-study/generation/post-process';
import type { CaseStudyType } from '../../../src/case-study/types';

/**
 * postProcess is now normalisation + factual checks only.
 *
 * The tests that used to be here pinned the removed QA gate: that a body
 * under 160 words failed, that a score below 45 failed, that a sentence
 * repeated 3x failed, that "serves as a stark reminder" was stripped from
 * the output. Those behaviours are gone on purpose — see the scope note at
 * the top of post-process.ts. What remains worth pinning is the correctness
 * work: markdown repair, empty-section removal, citation-host filtering, and
 * the grounding warnings.
 *
 * NOTE ON FIXTURE IDS. Every CVE id, IP and hash below is a synthetic
 * placeholder, never a real vulnerability or live infrastructure. Fixtures
 * that name real CVEs drift as those records get amended and KEV-listed, and
 * a test that asserts on a specific real id eventually fails for reasons
 * that have nothing to do with this code. `CVE-2099-0001` is well-formed for
 * the regexes and impossible in reality.
 */

/** Well-formed but non-existent CVE id — matches the id regex, resolves nowhere. */
const SYNTHETIC_CVE = 'CVE-2099-0001';
const OTHER_SYNTHETIC_CVE = 'CVE-2099-0002';
/** RFC 5737 documentation address. Never routable, so safe in a fixture. */
const SYNTHETIC_IP = '203.0.113.7';

const FACTS = JSON.stringify({
  cves: [{ id: SYNTHETIC_CVE, products: ['examplecorp gateway'] }],
  pages: [{ url: 'https://blog.talosintelligence.com/vuln/synthetic-fixture', publisher: 'talosintelligence.com' }],
  entities: { vendors: ['examplecorp'], products: ['gateway'], actors: [], techniques: [] },
  indicators: { ipv4: [SYNTHETIC_IP] },
});

const run = (raw: string, type: CaseStudyType = 'vulnfaq', facts = FACTS) =>
  postProcess({ type, raw, factsText: facts });

describe('postProcess — heading depth tolerance', () => {
  // Regression: the structural check used to test /^##\s+.+/ only, so a body
  // whose sections came back as `###` was rejected with "output contained no
  // section headings" — even though `marked.parse` renders h3 fine and the
  // table of contents accepts h2/h3. The prompt actively encourages question
  // shaped headings that models emit at varying depths.

  it('accepts a body whose sections are all h3', () => {
    const out = run(
      '### Which versions are affected?\n\nThe edge gateway build.\n\n### Is it being exploited?\n\nYes, in the wild.'
    );
    expect(out.ok).toBe(true);
    expect(out.errors.join(' ')).not.toMatch(/no section headings/i);
  });

  it('promotes an all-h3 body to top-level h2 so the table of contents fills', () => {
    const out = run('### First question?\n\nBody one.\n\n### Second question?\n\nBody two.');
    expect(out.body).toMatch(/^## First question\?/m);
    expect(out.body).toMatch(/^## Second question\?/m);
  });

  it('preserves genuine nesting when a real h2 is already present', () => {
    const out = run(
      '## Summary\n\nOverview text.\n\n### A deeper detail\n\nNested body.\n\n## References\n\n- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2099-0001)'
    );
    expect(out.body).toMatch(/^## Summary/m);
    expect(out.body).toMatch(/^### A deeper detail/m);
  });

  it('keeps content that follows an h3 subsection attached to its section', () => {
    // stripEmptySections used to break a `##` section body at a `###`, orphaning
    // everything after the subsection as loose lines.
    const out = run('## Summary\n\nLead paragraph.\n\n### Detail\n\nDetail body.\n\n## Fix\n\nUpgrade.');
    expect(out.ok).toBe(true);
    expect(out.body).toContain('Lead paragraph.');
    expect(out.body).toContain('Detail body.');
    expect(out.body).toContain('Upgrade.');
  });

  it('promotes a bold question pseudo-heading when there are no real headings', () => {
    const out = run('**Which versions are affected?**\n\nThe gateway build.\n\n**What should I do?**\n\nUpgrade.');
    expect(out.ok).toBe(true);
    expect(out.body).toMatch(/^## Which versions are affected\?/m);
  });

  it('still fails a body with no headings at all', () => {
    const out = run('Just a paragraph with no headings whatsoever.');
    expect(out.ok).toBe(false);
    expect(out.errors.join(' ')).toMatch(/no section headings/i);
  });

  it('strips untrusted citation hosts when the References section is written as h3', () => {
    // stripUnknownRefHosts finds the References block by /^##\s+(References|…)/.
    // If heading depth is normalised AFTER that call, an h3 References heading
    // is invisible to it and invented citations slip through the allowlist.
    const out = run(
      `### Summary\n\nTwo RCEs.\n\n### References\n\n- [NVD](https://nvd.nist.gov/vuln/detail/${SYNTHETIC_CVE}) — the record\n- [Totally Real Research](https://totally-real-research.example.net/paper) — invented`
    );
    expect(out.body).toContain('nvd.nist.gov');
    expect(out.body).not.toContain('totally-real-research.example.net');
  });

  it('counts sections in the audit consistently with the structural check', () => {
    const out = run('### One?\n\nA.\n\n### Two?\n\nB.');
    expect(out.ok).toBe(true);
    expect(out.audit?.sections).toBe(2);
  });
});

describe('postProcess — heading shapes other than `## text`', () => {
  // Each case below is a shape a model actually emitted that rendered as one
  // undifferentiated paragraph and was then rejected with "output contained no
  // section headings", losing the whole generation. They are all valid
  // markdown that `marked` renders and that a reader would call a section.

  it('promotes Setext headings (underlined titles)', () => {
    const out = run(
      'Which versions are affected?\n---------------------------\n\nThe gateway build.\n\nIs it exploited?\n------------\n\nYes.'
    );
    expect(out.ok).toBe(true);
    expect(out.body).toMatch(/^## Which versions are affected\?/m);
    expect(out.body).toMatch(/^## Is it exploited\?/m);
    expect(out.body).not.toMatch(/^---/m);
  });

  it('promotes a Setext `===` heading', () => {
    const out = run('Summary\n=======\n\nThe vendor shipped two RCEs.');
    expect(out.ok).toBe(true);
    expect(out.body).toMatch(/^## Summary/m);
  });

  it('does not mistake a horizontal rule or front matter for a Setext heading', () => {
    const out = run('## Summary\n\nTwo RCEs.\n\n---\n\nMore detail below the rule.');
    expect(out.ok).toBe(true);
    expect(out.body).toContain('## Summary');
    // The rule must survive as a rule, not become a heading.
    expect(out.body).not.toMatch(/^## -+$/m);
  });

  it('promotes non-question bold pseudo-headings when several of them are present', () => {
    const out = run('**Summary**\n\nTwo RCEs.\n\n**Affected versions**\n\nGateway 14.1.');
    expect(out.ok).toBe(true);
    expect(out.body).toMatch(/^## Summary/m);
    expect(out.body).toMatch(/^## Affected versions/m);
  });

  it('keeps a lone bold lead-in as prose rather than promoting it to a heading', () => {
    // One `**Note:**` in a paragraph is emphasis, not a section. Promoting it
    // would invent structure the model never wrote.
    const out = run(
      '**Note:** vendors should patch the edge appliance. The rest of this body is plain prose with no headings at all.'
    );
    expect(out.body).toContain('**Note:** vendors should patch');
    expect(out.body).not.toMatch(/^## Note/m);
  });

  it('promotes a bold question that shares its line with its answer', () => {
    const out = run(
      '**Which versions are affected?** The gateway build is affected.\n\n**Is it exploited?** Yes, in the wild.'
    );
    expect(out.ok).toBe(true);
    expect(out.body).toMatch(/^## Which versions are affected\?$/m);
    // The answer sentence must be kept, not swallowed by the heading.
    expect(out.body).toContain('The gateway build is affected.');
  });

  it('promotes an ordered list of bare questions used as a section index', () => {
    const out = run(
      '1. Which versions are affected?\n\nThe gateway build.\n\n2. Is it exploited?\n\nYes, in the wild.'
    );
    expect(out.ok).toBe(true);
    expect(out.body).toMatch(/^## Which versions are affected\?/m);
    expect(out.body).toMatch(/^## Is it exploited\?/m);
  });

  it('leaves an ordinary ordered list alone', () => {
    const out = run('## Steps\n\n1. Patch the appliance.\n2. Restart the daemon.\n3. Confirm the fix version.');
    expect(out.ok).toBe(true);
    expect(out.body).toMatch(/^1\. Patch the appliance\./m);
  });

  it('never strips a document down to zero headings', () => {
    // Every section reads as "empty" to the cleaner (its content is a fenced
    // block the heuristic does not see). Stripping must not delete the outline.
    const out = run('## Summary\n\n```\nCVE-2099-0001\n```\n\n## Fix\n\n```\nupgrade\n```');
    expect(out.ok).toBe(true);
    expect(out.audit?.sections).toBe(2);
  });

  it('still fails a plain paragraph with no heading shape at all', () => {
    const out = run('Just a paragraph with no headings whatsoever.');
    expect(out.ok).toBe(false);
    expect(out.errors.join(' ')).toMatch(/no section headings/i);
  });
});

describe('postProcess — structure', () => {
  it('accepts a body with sections', () => {
    const out = run(
      '## Summary\n\nThe vendor shipped two actively exploited RCEs in its edge gateway.\n\n## Fix\n\nUpgrade to the fixed build.'
    );
    expect(out.ok).toBe(true);
    expect(out.body).toContain('## Summary');
    expect(out.body).toContain('## Fix');
  });

  it('fails only when there are no section headings at all', () => {
    // The one structural failure that remains: a body with no headings
    // cannot be rendered as an article.
    const out = run('Just a paragraph with no headings whatsoever.');
    expect(out.ok).toBe(false);
    expect(out.errors.join(' ')).toMatch(/no section headings/i);
  });

  it('promotes a bare section name to a markdown heading', () => {
    const out = run(
      `Summary\n\nSomething happened.\n\nReferences\n\n- [NVD](https://nvd.nist.gov/vuln/detail/${SYNTHETIC_CVE})`
    );
    expect(out.body).toMatch(/^## Summary/m);
  });

  it('drops a section whose body is empty', () => {
    const out = run('## Summary\n\nReal content here.\n\n## Empty\n\n\n## Fix\n\nUpgrade everything.');
    expect(out.body).toContain('## Summary');
    expect(out.body).toContain('## Fix');
    expect(out.body).not.toContain('## Empty');
  });

  it('strips a raw FACTS block the model leaked into the output', () => {
    const out = run(`## Summary\n\nReal content.\n\nFACTS: {"cveId":"${SYNTHETIC_CVE}"}`);
    expect(out.body).not.toMatch(/^FACTS:/m);
  });
});

describe('postProcess — citations', () => {
  it('keeps a reference to a host the research dossier read', () => {
    const out = run(
      '## Summary\n\nTwo RCEs.\n\n## Get more information\n\n- [Talos](https://blog.talosintelligence.com/vuln/synthetic-fixture) — the advisory'
    );
    expect(out.body).toContain('talosintelligence.com');
  });

  it('drops a reference to a host neither the dossier nor the allowlist knows', () => {
    const out = run(
      `## Summary\n\nTwo RCEs.\n\n## Get more information\n\n- [Totally Real Research](https://totally-real-research.example.net/paper) — invented\n- [NVD](https://nvd.nist.gov/vuln/detail/${SYNTHETIC_CVE}) — the record`
    );
    // The fabricated host is a hallucinated citation — a factual error the
    // reader can detect, so it is removed.
    expect(out.body).not.toContain('totally-real-research.example.net');
    expect(out.body).toContain('nvd.nist.gov');
  });

  it('keeps canonical authorities', () => {
    const out = run(
      `## Summary\n\nX.\n\n## References\n\n- [NVD](https://nvd.nist.gov/vuln/detail/${SYNTHETIC_CVE}) — record\n- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — catalog`
    );
    expect(out.body).toContain('nvd.nist.gov');
    expect(out.body).toContain('cisa.gov');
  });
});

describe('postProcess — grounding warnings (never blocking)', () => {
  it('warns about a CVE id absent from the dossier but still returns ok', () => {
    const out = run(`## Summary\n\n${OTHER_SYNTHETIC_CVE} is a remote code execution flaw in a popular appliance.`);
    expect(out.ok).toBe(true);
    expect(out.errors.join(' ')).toMatch(/not in the research dossier/i);
    expect(out.errors.join(' ')).toContain(OTHER_SYNTHETIC_CVE);
  });

  it('does not warn about a CVE id that IS in the dossier', () => {
    const out = run(`## Summary\n\n${SYNTHETIC_CVE} was exploited in the wild before the vendor published a bulletin.`);
    expect(out.errors.join(' ')).not.toMatch(/not in the research dossier/i);
  });

  it('warns about an indicator absent from the dossier', () => {
    const out = run('## Indicators\n\nThe C2 was 45.77.65.211 and the hash was a1b2c3d4.');
    expect(out.ok).toBe(true);
    expect(out.errors.join(' ')).toMatch(/indicator/i);
  });
});

describe('postProcess — indicators', () => {
  it('extracts an IP from the body', () => {
    // 45.77.65.0/24 is Vultr's public range — routable in principle, but this
    // is only exercising the extraction path, never a live lookup.
    const out = run('## Indicators\n\nThe C2 infrastructure was 45.77.65.211.');
    expect(out.iocs.some((i) => i.type === 'ipv4' && i.value === '45.77.65.211')).toBe(true);
  });

  it('drops RFC1918 addresses', () => {
    const out = run('## Indicators\n\n10.0.0.1, 192.168.1.1 and 172.16.0.1 all appeared.');
    const ips = out.iocs.filter((i) => i.type === 'ipv4').map((i) => i.value);
    expect(ips).not.toContain('10.0.0.1');
    expect(ips).not.toContain('192.168.1.1');
    expect(ips).not.toContain('172.16.0.1');
  });

  it('drops the RFC 5737 documentation ranges in full', () => {
    // 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 are all reserved for
    // documentation. A previous version tested the third octet instead of
    // the second, so 203.0.113.5 and 198.51.100.7 leaked through as "real"
    // indicators. Both are /24s — the first two octets are the whole test.
    const out = run('## Indicators\n\n192.0.2.7, 198.51.100.7 and 203.0.113.5 are all documentation addresses.');
    expect(out.iocs.filter((i) => i.type === 'ipv4')).toEqual([]);
  });

  it('never treats a reference host as an indicator', () => {
    const out = run(
      '## References\n\n- [Talos](https://blog.talosintelligence.com/vuln/x) — advisory\n\n## Indicators\n\nNone.'
    );
    expect(out.iocs.some((i) => i.value.includes('talosintelligence'))).toBe(false);
  });
});

describe('postProcess — no scoring, no length gate', () => {
  it('accepts a short but substantive body', () => {
    // The old QA gate failed anything under 160 words, which pushed the model
    // to pad. A terse, factual answer is now fine.
    const out = run('## Answer\n\nTwo actively exploited RCEs. The vendor fixed both on September 27.');
    expect(out.ok).toBe(true);
    expect(out.audit?.words).toBeLessThan(160);
  });

  it('accepts a long body', () => {
    const long = `## Section\n\n${'Real analytical content with specifics. '.repeat(200)}`;
    const out = run(long);
    expect(out.ok).toBe(true);
  });

  it('does not strip sentences for containing a formerly-banned phrase', () => {
    // "serves as a stark reminder" was sentence-stripped by EGREGIOUS_SLOP.
    // If the sentence carries a real fact it must survive.
    const out = run(
      '## Analysis\n\nThis serves as a stark reminder that this appliance sits at the network edge for VPN termination.'
    );
    expect(out.body).toContain('network edge');
  });

  it('does not rewrite or cut a hook that opens on the reader', () => {
    // deyouHook used to delete the first sentence of any "You…" opening.
    const out = run('## Summary\n\nYou should check whether your edge appliances are exposed to this.');
    expect(out.body).toContain('You should check');
  });

  it('reports factual counters rather than a quality score', () => {
    const out = run(
      `## Summary\n\nTwo RCEs.\n\n## References\n\n- [NVD](https://nvd.nist.gov/vuln/detail/${SYNTHETIC_CVE}) — record`
    );
    expect(out.audit).toBeDefined();
    expect(typeof out.audit?.words).toBe('number');
    expect(typeof out.audit?.sections).toBe('number');
    expect(out.audit?.references).toBe(1);
    // No `total` / `breakdown` — those were the scoring fields.
    expect(out.audit).not.toHaveProperty('total');
    expect(out.audit).not.toHaveProperty('breakdown');
  });
});

describe('postProcess — typography', () => {
  it('straightens curly quotes', () => {
    const out = run('## Summary\n\nThe vendor said “we are investigating” in its bulletin.');
    expect(out.body).toContain('"we are investigating"');
    expect(out.body).not.toContain('“');
  });

  it('preserves a table pipe row', () => {
    const out = run('## Versions\n\n| Product | Fixed |\n| --- | --- |\n| Gateway 14.1 | 14.1-73.41 |');
    expect(out.body).toContain('| Gateway 14.1 | 14.1-73.41 |');
  });
});
