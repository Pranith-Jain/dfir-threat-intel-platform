import type { CaseStudyType } from '../types';

const TYPE_LABEL: Record<CaseStudyType, string> = {
  cve: 'CVE',
  actor: 'THREAT ACTOR',
  malware: 'MALWARE',
  vulnfaq: 'VULNERABILITY',
  exploit: 'EXPLOIT',
  darkweb: 'DARKWEB',
  supplychain: 'SUPPLY CHAIN',
  llm: 'LLM SECURITY',
  aisecops: 'AI SECOPS',
  breach: 'BREACH',
  scam: 'SCAM',
  aisec: 'AI SECURITY',
  intel: 'THREAT INTEL',
  osint: 'OSINT',
  methodology: 'METHODOLOGY',
  trend: 'TREND',
  briefing: 'BRIEFING',
  analysis: 'ANALYSIS',
  tool: 'TOOL',
  news: 'NEWS',
  agentic: 'AGENTIC AI',
  hunting: 'THREAT HUNTING',
  report: 'REPORT',
};

const TYPE_HUE: Record<CaseStudyType, number> = {
  cve: 0,
  actor: 30,
  malware: 280,
  vulnfaq: 12,
  exploit: 20,
  darkweb: 290,
  supplychain: 210,
  llm: 185,
  aisecops: 165,
  breach: 350,
  scam: 45,
  aisec: 180,
  intel: 140,
  osint: 90,
  methodology: 260,
  trend: 320,
  briefing: 160,
  analysis: 200,
  tool: 100,
  news: 40,
  agentic: 220,
  hunting: 70,
  report: 120,
};

function xmlEscape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]!);
}

function wrapTitle(title: string, max = 30): string[] {
  const words = title.split(/\s+/);
  const lines: string[] = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > max) {
      if (line) lines.push(line);
      line = w;
    } else {
      line = (line + ' ' + w).trim();
    }
  }
  if (line) lines.push(line);
  return lines.slice(0, 3);
}

export interface RenderHeroSvgInput {
  title: string;
  type: CaseStudyType;
}

export function renderHeroSvg({ title, type }: RenderHeroSvgInput): string {
  const hue = TYPE_HUE[type];
  const label = TYPE_LABEL[type];
  const lines = wrapTitle(title).map(xmlEscape);

  const titleLines = lines
    .map(
      (l, i) =>
        `<text x="80" y="${320 + i * 70}" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="56" fill="#e8e8ea" font-weight="700">${l}</text>`
    )
    .join('');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <pattern id="hex" width="20" height="34" patternUnits="userSpaceOnUse">
      <path d="M10 0 L20 5 L20 17 L10 22 L0 17 L0 5 Z" fill="none" stroke="hsl(${hue} 70% 18%)" stroke-width="0.5"/>
    </pattern>
  </defs>
  <rect width="1200" height="630" fill="#0a0a0c"/>
  <rect width="1200" height="630" fill="url(#hex)"/>
  <rect x="80" y="80" width="170" height="44" rx="6" fill="hsl(${hue} 70% 45%)"/>
  <text x="100" y="110" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="20" fill="#0a0a0c" font-weight="700">${label}</text>
  ${titleLines}
  <text x="80" y="560" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="18" fill="#666">pranithjain.qzz.io / blog</text>
</svg>`;
}
