import { describe, expect, it } from 'vitest';
import { formatAlert, shouldDeliver, normaliseChannel, type AlertChannel } from '../../src/lib/feed-delivery';

const BASE: AlertChannel = {
  id: 'ch1',
  job_id: 'job1',
  name: 'SOC alerts',
  type: 'slack',
  target: 'https://hooks.slack.com/services/T/B/X',
  enabled: true,
  match_tags: [],
  min_new_items: 1,
  cooldown_hours: 6,
  last_delivered_at: null,
  last_status: null,
  last_error: null,
  created_at: '2026-01-01T00:00:00Z',
};

const hoursAgo = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();

describe('shouldDeliver', () => {
  it('delivers when there are new items and no blockers', () => {
    expect(shouldDeliver(BASE, ['1.2.3.4']).deliver).toBe(true);
  });

  it('does not deliver when the channel is disabled', () => {
    expect(shouldDeliver({ ...BASE, enabled: false }, ['1.2.3.4'])).toEqual({
      deliver: false,
      reason: 'channel disabled',
    });
  });

  it('suppresses below min_new_items, which is the anti-spam guard', () => {
    const r = shouldDeliver({ ...BASE, min_new_items: 10 }, ['1.2.3.4']);
    expect(r.deliver).toBe(false);
    expect(r.reason).toContain('below threshold 10');
  });

  it('delivers exactly at the threshold', () => {
    expect(shouldDeliver({ ...BASE, min_new_items: 3 }, ['a', 'b', 'c']).deliver).toBe(true);
  });

  it('suppresses during the cooldown window', () => {
    const r = shouldDeliver({ ...BASE, cooldown_hours: 6, last_delivered_at: hoursAgo(1) }, ['1.2.3.4']);
    expect(r.deliver).toBe(false);
    expect(r.reason).toContain('cooldown');
  });

  it('delivers again once the cooldown has elapsed', () => {
    expect(shouldDeliver({ ...BASE, cooldown_hours: 6, last_delivered_at: hoursAgo(7) }, ['1.2.3.4']).deliver).toBe(
      true
    );
  });

  it('does not treat a malformed last_delivered_at as an active cooldown', () => {
    // A bad timestamp must not permanently silence the channel.
    expect(shouldDeliver({ ...BASE, cooldown_hours: 6, last_delivered_at: 'not-a-date' }, ['1.2.3.4']).deliver).toBe(
      true
    );
  });

  it('requires every configured tag to be present (AND, not OR)', () => {
    const channel = { ...BASE, match_tags: ['ransomware', 'apt'] };
    expect(shouldDeliver(channel, ['x'], ['ransomware']).deliver).toBe(false);
    expect(shouldDeliver(channel, ['x'], ['ransomware', 'apt']).deliver).toBe(true);
  });

  it('reads tags off #tag-prefixed items as well as the explicit list', () => {
    const channel = { ...BASE, match_tags: ['ransomware'] };
    expect(shouldDeliver(channel, ['#ransomware 1.2.3.4']).deliver).toBe(true);
  });

  it('delivers with no tag filter configured regardless of tags', () => {
    expect(shouldDeliver({ ...BASE, match_tags: [] }, ['unrelated']).deliver).toBe(true);
  });

  it('checks suppression before tags so a skip reason names the real blocker', () => {
    // A cooldown is the more actionable message; reporting "no tags matched"
    // first would send the operator looking in the wrong place.
    const r = shouldDeliver({ ...BASE, match_tags: ['apt'], last_delivered_at: hoursAgo(1) }, ['1.2.3.4']);
    expect(r.reason).toContain('cooldown');
  });
});

describe('formatAlert', () => {
  it('builds a Slack payload with mrkdwn text', () => {
    const { body } = formatAlert(BASE, 'abuse.ch', ['1.2.3.4']);
    const parsed = JSON.parse(body);
    expect(parsed.text).toContain('abuse.ch');
    expect(parsed.text).toContain('1.2.3.4');
    expect(parsed.text).toContain('1 new indicator');
  });

  it('truncates a large item list instead of failing the payload limit', () => {
    const many = Array.from({ length: 250 }, (_, i) => `10.0.0.${i}`);
    const parsed = JSON.parse(formatAlert(BASE, 'feed', many).body);
    expect(parsed.text).toContain('and 230 more');
  });

  it('sends a structured body for a generic webhook', () => {
    const { body } = formatAlert({ ...BASE, type: 'webhook' }, 'feed', ['1.2.3.4', 'bad.example']);
    const parsed = JSON.parse(body);
    expect(parsed.count).toBe(2);
    expect(parsed.items).toEqual(['1.2.3.4', 'bad.example']);
    expect(parsed.job).toBe('feed');
  });

  it('reports the truncation count on a generic webhook', () => {
    const many = Array.from({ length: 30 }, (_, i) => `10.0.0.${i}`);
    const parsed = JSON.parse(formatAlert({ ...BASE, type: 'webhook' }, 'feed', many).body);
    expect(parsed.truncated).toBe(10);
    expect(parsed.items).toHaveLength(20);
  });

  it('produces an RFC-822 body for email rather than faking a send', () => {
    const { body, headers } = formatAlert({ ...BASE, type: 'email', target: 'soc@example.com' }, 'feed', ['1.2.3.4']);
    expect(headers['content-type']).toBe('text/plain');
    expect(body).toContain('To: soc@example.com');
    expect(body).toContain('Subject:');
  });

  it('pluralises correctly', () => {
    const one = JSON.parse(formatAlert(BASE, 'f', ['a']).body);
    expect(one.text).toContain('1 new indicator');
    expect(one.text).not.toContain('1 new indicators');
  });
});

describe('normaliseChannel', () => {
  it('coerces the D1 integer enabled flag to a boolean', () => {
    expect(normaliseChannel({ ...BASE, enabled: 1 }).enabled).toBe(true);
    expect(normaliseChannel({ ...BASE, enabled: 0 }).enabled).toBe(false);
  });

  it('parses the stored match_tags JSON back into an array', () => {
    const n = normaliseChannel({ ...BASE, match_tags: '["ransomware","apt"]' });
    expect(n.match_tags).toEqual(['ransomware', 'apt']);
  });

  it('degrades a corrupt match_tags to empty rather than throwing', () => {
    expect(normaliseChannel({ ...BASE, match_tags: '{not json' }).match_tags).toEqual([]);
  });

  it('supplies defaults for missing numeric columns', () => {
    const n = normaliseChannel({ id: 'x', job_id: 'y', name: 'n', type: 'slack', target: 'https://x' });
    expect(n.min_new_items).toBe(1);
    expect(n.cooldown_hours).toBe(6);
    expect(n.last_delivered_at).toBeNull();
  });
});
