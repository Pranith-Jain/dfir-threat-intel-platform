import { NavLink } from 'react-router-dom';
import { ExternalLink } from 'lucide-react';

/** Shared sub-navigation for the five replicated CyberView pages. */
const CYBERVIEW_LINKS = [
  { to: '/threatintel/cyberview', label: 'Map', end: true },
  { to: '/threatintel/cyberview/vulnerabilities', label: 'Vulnerabilities' },
  { to: '/threatintel/cyberview/archive', label: 'Archive' },
  { to: '/threatintel/cyberview/trends', label: 'Trends' },
  { to: '/threatintel/cyberview/tabletop', label: 'Exercise' },
] as const;

export function CyberViewNav(): JSX.Element {
  return (
    <nav aria-label="CyberView sections" className="mb-5 flex flex-wrap items-center gap-1 border-b border-line-1 pb-2">
      {CYBERVIEW_LINKS.map((link) => (
        <NavLink
          key={link.to}
          to={link.to}
          end={'end' in link ? link.end : false}
          className={({ isActive }) =>
            `rounded px-3 py-1.5 font-mono text-sm font-semibold transition-colors ${
              isActive ? 'bg-brand-600 text-on-fill' : 'text-muted hover:bg-wash hover:text-heading'
            }`
          }
        >
          {link.label}
        </NavLink>
      ))}
      <a
        href="https://xanderhutch.github.io/CyberView/"
        target="_blank"
        rel="noopener noreferrer"
        className="ml-auto inline-flex items-center gap-1 font-mono text-xs text-muted hover:text-accent-text"
      >
        Original CyberView <ExternalLink size={12} aria-hidden="true" />
      </a>
    </nav>
  );
}
