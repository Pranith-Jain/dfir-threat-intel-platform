/**
 * TabBar - reusable tab navigation.
 *
 * Replaces the pattern of:
 *   <div className="flex gap-1.5 mb-6">
 *     {tabs.map(t => <button className={active === t ? '...' : '...'}>{label}</button>)}
 *   </div>
 *
 * With:
 *   <TabBar
 *     tabs={[{ id: 'stats', label: 'Statistics' }, { id: 'lookup', label: 'Lookup' }]}
 *     active={activeTab}
 *     onChange={setActiveTab}
 *   />
 */

export interface Tab {
  id: string;
  label: string;
  /** Optional badge count shown next to label. */
  count?: number;
  /** Disable this tab. */
  disabled?: boolean;
}

export interface TabBarProps {
  tabs: Tab[];
  active: string;
  onChange: (id: string) => void;
  className?: string;
  /** Accessible name for the tab group. */
  label?: string;
  /** `pills` is the default; `underline` is the quiet, minimal variant. */
  variant?: 'pills' | 'underline';
  /** Called on hover/focus so lazy view chunks can be fetched before a click. */
  onPrefetch?: (id: string) => void;
}

export function TabBar({
  tabs,
  active,
  onChange,
  className,
  label = 'Views',
  variant = 'pills',
  onPrefetch,
}: TabBarProps): JSX.Element {
  const underline = variant === 'underline';

  return (
    // Horizontal scroll rail rather than wrapping: a long tab list (such as
    // ARGUS's six views) never forces a site-wide horizontal scrollbar on
    // narrow viewports. The scrollbar is hidden but the rail stays scrollable
    // by touch, trackpad and keyboard.
    <div
      role="tablist"
      aria-label={label}
      className={`flex ${underline ? 'gap-5' : 'gap-1.5'} mb-6 overflow-x-auto overscroll-x-contain [scrollbar-width:none] [&::-webkit-scrollbar]:hidden ${className ?? ''}`}
    >
      {tabs.map((tab) => {
        const isActive = active === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={isActive}
            disabled={tab.disabled}
            onMouseEnter={() => onPrefetch?.(tab.id)}
            onFocus={() => onPrefetch?.(tab.id)}
            onClick={() => !tab.disabled && onChange(tab.id)}
            className={
              underline
                ? `shrink-0 whitespace-nowrap border-b-2 pb-2 pt-1 text-tool font-medium transition-colors ${
                    isActive
                      ? 'border-brand-500 text-heading'
                      : tab.disabled
                        ? 'border-transparent text-slate-300 dark:text-muted cursor-not-allowed'
                        : 'border-transparent text-muted hover:text-heading'
                  }`
                : `shrink-0 whitespace-nowrap px-3 py-1.5 rounded text-meta font-mono border transition-colors ${
                    isActive
                      ? 'border-brand-500/60 bg-brand-500/10 text-brand-600 dark:text-brand-400'
                      : tab.disabled
                        ? 'border-line-1 text-slate-300 dark:text-muted cursor-not-allowed'
                        : 'border-line-1 text-muted hover:border-brand-500/30'
                  }`
            }
          >
            {tab.label}
            {tab.count !== undefined && <span className="ml-1.5 text-micro opacity-60">{tab.count}</span>}
          </button>
        );
      })}
    </div>
  );
}
