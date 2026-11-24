/**
 * One-click fix links — pre-filled prompts for coding agents and assistants.
 *
 * Ported from the Global Hack Map pattern (MIT): the prompt carries ONLY a
 * validated CVE id and a link to our own public CVE page. No third-party
 * advisory text is interpolated, so a poisoned advisory cannot inject through
 * the button. Every link just pre-fills a prompt; nothing runs until sent.
 */

import { PORTFOLIO_ORIGIN } from './surface';

export type AgentTarget = 'claude-code' | 'codex' | 'cursor' | 'claude-code-web' | 'claude' | 'chatgpt';

export interface AgentLink {
  target: AgentTarget;
  label: string;
  href: string;
  app: boolean;
  kind: 'repo' | 'chat';
  prompt: string;
}

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

export function cvePageUrl(cve: string, origin = PORTFOLIO_ORIGIN): string {
  return `${origin}/threatintel/cve/${encodeURIComponent(cve)}`;
}

export function fixPrompt(cve: string, origin = PORTFOLIO_ORIGIN): string {
  return `Check whether this repository is affected by ${cve} and fix it if it is.

Fetch ${cvePageUrl(cve, origin)} for the consolidated verdict and source list, then check the vendor's own advisory. Find every place the affected package or product is used, upgrade to a fixed version, run the tests and open a pull request that explains the change. If the repository is not affected, say so and explain why. Ask me before running anything that costs money.`;
}

export function explainPrompt(cve: string, origin = PORTFOLIO_ORIGIN): string {
  return `Explain ${cve} to me in plain English: what is affected, whether it is being exploited, and exactly what I should do today. Start from ${cvePageUrl(cve, origin)} and check the vendor's own advisory before you answer. Be precise about versions and say what is confirmed versus claimed.`;
}

function repoLinks(prompt: string): AgentLink[] {
  const enc = encodeURIComponent;
  return [
    { target: 'claude-code', label: 'Claude Code', href: `claude-cli://open?q=${enc(prompt)}`, app: true, kind: 'repo', prompt },
    { target: 'codex', label: 'Codex', href: `codex://new?prompt=${enc(prompt)}`, app: true, kind: 'repo', prompt },
    { target: 'cursor', label: 'Cursor', href: `https://cursor.com/link/prompt?text=${enc(prompt)}`, app: true, kind: 'repo', prompt },
    { target: 'claude-code-web', label: 'Claude Code (web)', href: `https://claude.ai/code/new?q=${enc(prompt)}`, app: false, kind: 'repo', prompt },
  ];
}

function chatLinks(prompt: string): AgentLink[] {
  const enc = encodeURIComponent;
  return [
    { target: 'claude', label: 'Claude', href: `https://claude.ai/new?q=${enc(prompt)}`, app: false, kind: 'chat', prompt },
    { target: 'chatgpt', label: 'ChatGPT', href: `https://chatgpt.com/?q=${enc(prompt)}`, app: false, kind: 'chat', prompt },
  ];
}

/** All fix links for a CVE. [] for an invalid id — titles never become prompts. */
export function agentLinksForCve(rawCve: string, origin = PORTFOLIO_ORIGIN): AgentLink[] {
  if (typeof rawCve !== 'string') return [];
  const cve = rawCve.trim().toUpperCase();
  if (!CVE_RE.test(cve)) return [];
  return [...repoLinks(fixPrompt(cve, origin)), ...chatLinks(explainPrompt(cve, origin))];
}
