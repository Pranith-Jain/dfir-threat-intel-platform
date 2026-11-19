import { describe, it, expect } from 'vitest';
import { filterToolsForQueryType, getToolsForSpecialist } from '../../api/src/lib/agent/specialist-types';
import type { AgentTool } from '../../api/src/lib/agent/types';

/**
 * HI / OH / KP tools are bridged into the agent registry, but the planner
 * and specialist executor both filter tools by allowlist. If a source is
 * missing from the shared allowlist the LLM can never call it, even though
 * it appears in the tool registry and the UI.
 */
const NEW_SOURCE_TOOLS = [
  'hi_list_incidents',
  'hi_get_incident',
  'hi_stats',
  'oh_list_harnesses',
  'oh_get_harness',
  'oh_sources',
  'kp_list_tools',
  'kp_list_exploits',
  'kp_get_feed',
  'kp_stats',
];

const tools = [...NEW_SOURCE_TOOLS, 'get_recipe', 'unified_search', 'not_in_any_allowlist'].map(
  (name) => ({ name, description: '', parameters: {} }) as unknown as AgentTool
);

describe('agent new-source tool allowlist', () => {
  it('exposes HI/OH/KP tools to the planner for generic queries', () => {
    const names = filterToolsForQueryType('generic', undefined, tools).map((t) => t.name);
    for (const name of NEW_SOURCE_TOOLS) expect(names).toContain(name);
    expect(names).not.toContain('not_in_any_allowlist');
  });

  it('accepts the same tools in specialist execution', () => {
    const names = getToolsForSpecialist('ioc-reputation', tools).map((t) => t.name);
    for (const name of NEW_SOURCE_TOOLS) expect(names).toContain(name);
    expect(names).not.toContain('not_in_any_allowlist');
  });
});
