/**
 * The DFIR headline tool count, published as a leaf module with NO imports.
 *
 * ## Why this file exists
 *
 * The sidebar footer and the DFIR hub both used to render a number labelled
 * "tools", and they disagreed on the same screen: the sidebar said 149 while
 * the hero, the search placeholder and the page footer all said 115+.
 *
 * Neither number was a miscount. They measure different things:
 *
 *   - `MAIN_TOOL_COUNT` (derived from `SECTIONS` in `tool-sections.ts`)
 *     excludes `utility: true` entries on purpose, so the front door does not
 *     read as padded, and it does not enumerate every route.
 *   - The sidebar counts every navigable entry in the `dfir-hubs` registry,
 *     which is genuinely larger.
 *
 * Two different statistics sharing one label is what made one of them look
 * broken. The hub's figure is the deliberate marketing number, so the sidebar
 * is the side that moves.
 *
 * ## Why it is a literal and not an import
 *
 * The obvious implementation is for `sidebar-nav.ts` to import
 * `MAIN_TOOL_COUNT` from `tool-sections.ts`. That was tried and reverted:
 * `tool-sections.ts` pulls in ~40 `lucide-react` icons, and `sidebar-nav.ts`
 * is reachable from `AppShell`, which sits on the eager entry path for every
 * tool route. The import added ~34KB to the entry chunk and failed three
 * `npm run check:budgets` limits. A 34KB regression to align a footer label is
 * the wrong trade, so the number is mirrored here instead - a module with no
 * imports costs effectively nothing.
 *
 * ## SECTIONS is the source of truth, not this file
 *
 * This is a guarded mirror, not a second definition. `tool-count.test.ts`
 * asserts this literal equals the value derived from `SECTIONS`, so adding or
 * removing a tool fails CI until this file is updated. Do not "fix" a mismatch
 * by editing this number alone, and do not invert the dependency to make
 * `SECTIONS` import from here - that reintroduces the bundle cost this file
 * exists to avoid.
 */
export const MAIN_TOOL_COUNT = 98;
