import { useState, type JSX } from 'react';
import { Check, Copy, ExternalLink } from 'lucide-react';
import { agentLinksForCve, type AgentLink } from '../../lib/agent-fix-links';

/**
 * One-click fix links for a CVE. Each href is a fixed template with an
 * encodeURIComponent'd prompt (the prompt carries only a validated CVE id +
 * our own dossier URL), so custom app schemes are safe here — the generic
 * sanitizeUrl allowlist is for attacker-influenced feed URLs, not these.
 */
function LinkButton({ link }: { link: AgentLink }): JSX.Element {
  const web = link.href.startsWith('https:');
  return (
    <a
      href={link.href}
      target={web ? '_blank' : undefined}
      rel={web ? 'noopener noreferrer' : undefined}
      title={link.app ? `Opens ${link.label}. Read the prompt, then press enter.` : `Open ${link.label}`}
      className="inline-flex items-center gap-1 rounded-control border border-line-1 px-2 py-1 font-mono text-mini text-muted transition-colors hover:border-accent/40 hover:text-heading"
    >
      {link.label}
      {web && <ExternalLink size={9} aria-hidden />}
    </a>
  );
}

function CopyPrompt({ prompt }: { prompt: string }): JSX.Element {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(prompt);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1600);
        } catch {
          /* clipboard unavailable — links still work */
        }
      }}
      className="inline-flex items-center gap-1 rounded-control border border-line-1 px-2 py-1 font-mono text-mini text-muted transition-colors hover:border-accent/40 hover:text-heading"
    >
      {copied ? <Check size={10} className="text-emerald-500" aria-hidden /> : <Copy size={10} aria-hidden />}
      {copied ? 'Copied' : 'Copy prompt'}
    </button>
  );
}

export default function AgentFixLinks({ cve }: { cve: string }): JSX.Element | null {
  const links = agentLinksForCve(cve);
  if (!links.length) return null;
  const repo = links.filter((l) => l.kind === 'repo');
  const chat = links.filter((l) => l.kind === 'chat');
  return (
    <div className="mt-4 rounded-xl border border-line-1/70 bg-surface-100 p-3">
      <div className="text-micro font-mono uppercase tracking-wider text-muted mb-2">One-click fix · {cve}</div>
      <div className="flex flex-col gap-2">
        <div>
          <p className="text-micro text-muted mb-1">Fix it in your code</p>
          <div className="flex flex-wrap gap-1.5">
            {repo.map((link) => <LinkButton key={link.target} link={link} />)}
            <CopyPrompt prompt={repo[0]!.prompt} />
          </div>
        </div>
        <div>
          <p className="text-micro text-muted mb-1">Explain it to me</p>
          <div className="flex flex-wrap gap-1.5">
            {chat.map((link) => <LinkButton key={link.target} link={link} />)}
            <CopyPrompt prompt={chat[0]!.prompt} />
          </div>
        </div>
      </div>
      <p className="text-micro text-muted/80 mt-2">
        Links only pre-fill a prompt — nothing runs until you send it. The prompt carries the CVE id and our public
        dossier, never advisory text.
      </p>
    </div>
  );
}
