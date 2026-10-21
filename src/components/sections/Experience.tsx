import { useState } from 'react';
import { Search, Zap, Shield, FileText, Monitor, Mail, ChevronDown } from 'lucide-react';
import type { Experience } from '../../core/entities';
import { Badge } from '../Badge';

const iconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  Search,
  Zap,
  Shield,
  FileText,
  Monitor,
  Mail,
};

interface ExperienceProps {
  experiences: Experience[];
}

export function Experience({ experiences }: ExperienceProps) {
  // The first (current) role expands by default - the rest collapse so the
  // list stays scannable. Each card flips on click.
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set([0]));

  const toggle = (index: number): void => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  };

  return (
    <section id="experience" className="scroll-mt-24">
      {/* Header - consistent with the rest of the redesigned sections:
          small caps-mono kicker, display heading, no chrome. */}
      <div className="mb-10 max-w-2xl">
        <div className="mb-3 text-eyebrow font-mono uppercase tracking-[0.2em] text-muted">Experience</div>
        <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight text-heading">
          Experience highlights
        </h2>
      </div>

      {/* Collapsible list - thin-bordered cards, no glass, no glow.
          The chevron alone marks expanded state. */}
      <div className="grid gap-3">
        {experiences.map((exp, index) => {
          const isOpen = expanded.has(index);
          const headerId = `experience-header-${index}`;
          const bodyId = `experience-body-${index}`;
          return (
            <div key={exp.title} className="surface-card">
              <button
                type="button"
                id={headerId}
                aria-expanded={isOpen}
                aria-controls={bodyId}
                onClick={() => toggle(index)}
                className="flex w-full items-start gap-4 px-5 py-4 text-left"
              >
                <div className="flex-1 min-w-0">
                  <div className="text-lg font-semibold text-heading">{exp.title}</div>
                  <div className="text-sm text-body">
                    {exp.company}
                    {exp.location && ` • ${exp.location}`} • {exp.period}
                  </div>
                </div>
                {/* `shrink-0` on this row kept the badge at its full width
                    and pushed the card 35px past the viewport on a phone.
                    The badge now shrinks and wraps; the chevron does not. */}
                <div className="flex min-w-0 items-center gap-3">
                  {exp.badge && (
                    <span className="min-w-0 shrink">
                      <Badge tone="success">{exp.badge}</Badge>
                    </span>
                  )}
                  <ChevronDown
                    className={`h-4 w-4 text-muted transition-transform ${isOpen ? 'rotate-180' : ''}`}
                    aria-hidden="true"
                  />
                </div>
              </button>

              {isOpen && (
                <div
                  id={bodyId}
                  role="region"
                  aria-labelledby={headerId}
                  className="border-t border-line-1/70 px-5 pb-5 pt-4"
                >
                  {/* Sections (for main experience) */}
                  {exp.sections &&
                    exp.sections.map((section, sIndex) => {
                      const IconComponent = iconMap[section.icon];
                      const sectionId = `experience-${section.title
                        .toLowerCase()
                        .replace(/[^\w\s-]/g, '')
                        .replace(/\s+/g, '-')}`;
                      return (
                        <div
                          key={section.title}
                          id={sectionId}
                          className={`scroll-mt-28 ${sIndex < exp.sections!.length - 1 ? 'mb-5' : ''}`}
                        >
                          <h3 className="text-xs font-bold uppercase tracking-wider text-brand-600 dark:text-brand-400 mb-2 flex items-center gap-2">
                            {IconComponent && <IconComponent className="w-4 h-4" aria-hidden="true" />}
                            {section.title}
                          </h3>
                          <ul className="space-y-2 text-sm text-body ml-6">
                            {section.items.map((item, iIndex) => (
                              <li key={iIndex} className="relative pl-4">
                                <span className="absolute left-0 text-brand-600 dark:text-brand-300" aria-hidden="true">
                                  •
                                </span>
                                {item}
                              </li>
                            ))}
                          </ul>
                        </div>
                      );
                    })}

                  {/* Items (for other experiences) */}
                  {exp.items && (
                    <ul className="space-y-2 text-sm text-body">
                      {exp.items.map((item, iIndex) => (
                        <li key={iIndex} className="relative pl-4">
                          <span className="absolute left-0 text-brand-600 dark:text-brand-300" aria-hidden="true">
                            •
                          </span>
                          {item}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
