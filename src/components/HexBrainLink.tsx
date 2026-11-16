import { ExternalLink } from 'lucide-react';

/** Deep link to HexBrain's public CVE page (open data, no key needed). */
function hexbrainCveUrl(cve: string): string {
  return `https://hexbrainai.com/cve/${cve.toUpperCase()}`;
}

interface HexBrainLinkProps {
  cve: string;
  /** Classes for the anchor. Defaults to a bordered inline chip. */
  className?: string;
  label?: string;
  iconSize?: number;
}

export default function HexBrainLink({
  cve,
  className = 'text-xs font-mono text-orange-600 dark:text-orange-300 hover:underline inline-flex items-center gap-1',
  label = 'HexBrain',
  iconSize = 10,
}: HexBrainLinkProps): JSX.Element {
  return (
    <a
      href={hexbrainCveUrl(cve)}
      target="_blank"
      rel="noopener noreferrer"
      title={`Open ${cve.toUpperCase()} on HexBrain - exploitation likelihood, PoCs, detection check`}
      className={className}
    >
      {label} <ExternalLink size={iconSize} />
    </a>
  );
}
