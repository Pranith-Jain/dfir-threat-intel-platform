import { describe, it, expect } from 'vitest';
import {
  createSubrequestBudget,
  SubrequestExhaustedError,
  DISCOVERY_SUBREQUEST_LIMIT,
} from '../../../src/case-study/discovery/subrequest-budget';

describe('createSubrequestBudget', () => {
  it('counts spends and refuses over-limit work without consuming it', () => {
    const budget = createSubrequestBudget(3);
    budget.spend('cve');
    budget.spend('cve', 2);
    expect(budget.used()).toBe(3);
    expect(budget.remaining()).toBe(0);

    expect(() => budget.spend('actor')).toThrow(SubrequestExhaustedError);
    // A refused spend must not be charged — the headroom is still real.
    expect(budget.used()).toBe(3);
    expect(budget.wasStarved('cve')).toBe(false);
    expect(budget.wasStarved('actor')).toBe(true);
    expect(budget.starvedNames()).toEqual(['actor']);
  });

  it('leaves headroom below the Free-plan 50-subrequest ceiling', () => {
    expect(DISCOVERY_SUBREQUEST_LIMIT).toBeLessThan(50);
    expect(createSubrequestBudget().remaining()).toBe(DISCOVERY_SUBREQUEST_LIMIT);
  });
});
