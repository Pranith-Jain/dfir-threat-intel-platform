import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import type { Env } from '../../src/env';
import { visitorIdentity, visitorOwnerId, visitorVisibilityFilter, visitorOwns } from '../../src/lib/visitor';

function app() {
  const h = new Hono<{ Bindings: Env }>();
  h.use('*', visitorIdentity());
  h.get('/who', (c) =>
    c.json({
      owner: visitorOwnerId(c),
      filter: visitorVisibilityFilter(c),
      ownsOther: visitorOwns(c, 'other-owner'),
      ownsLegacy: visitorOwns(c, null),
    })
  );
  return h;
}

function cookieToken(res: Response): string | null {
  const setCookie = res.headers.get('set-cookie') ?? '';
  return /pj_vid=([0-9a-f]{64})/.exec(setCookie)?.[1] ?? null;
}

describe('visitor identity', () => {
  it('mints an HttpOnly visitor cookie and a namespaced owner', async () => {
    const res = await app().request('/who', {}, {} as Env);
    expect(res.status).toBe(200);

    const setCookie = res.headers.get('set-cookie') ?? '';
    expect(setCookie).toContain('pj_vid=');
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('Secure');
    expect(setCookie).toContain('SameSite=Lax');
    expect(setCookie).toContain('Path=/api');

    const body = (await res.json()) as { owner: string };
    expect(body.owner).toMatch(/^anon:[0-9a-f]{64}$/);
  });

  it('returns the same owner for the same cookie and a different owner for another', async () => {
    const h = app();
    const first = await h.request('/who', {}, {} as Env);
    const token = cookieToken(first);
    expect(token).toBeTruthy();

    const firstBody = (await first.json()) as { owner: string };
    const repeat = await h.request('/who', { headers: { cookie: `pj_vid=${token}` } }, {} as Env);
    const repeatBody = (await repeat.json()) as { owner: string };
    expect(repeatBody.owner).toBe(firstBody.owner);

    const other = await h.request('/who', { headers: { cookie: `pj_vid=${'a'.repeat(64)}` } }, {} as Env);
    const otherBody = (await other.json()) as { owner: string };
    expect(otherBody.owner).not.toBe(firstBody.owner);
  });

  it('scopes listings to the visitor and hides legacy ownerless rows', async () => {
    const res = await app().request('/who', {}, {} as Env);
    const body = (await res.json()) as {
      owner: string;
      filter: { clause: string; bindings: unknown[] };
      ownsOther: boolean;
      ownsLegacy: boolean;
    };

    expect(body.filter.clause).toBe('owner_hash = ?');
    expect(body.filter.bindings).toEqual([body.owner]);
    expect(body.ownsOther).toBe(false);
    expect(body.ownsLegacy).toBe(false);
  });

  it('keeps API-key identity unchanged and does not mint a cookie', async () => {
    const h = new Hono<{ Bindings: Env }>();
    h.use('*', async (c, next) => {
      (c as unknown as { user?: { keyId: string } }).user = { keyId: 'key_123' };
      await next();
    });
    h.use('*', visitorIdentity());
    h.get('/who', (c) => c.json({ owner: visitorOwnerId(c) }));

    const res = await h.request('/who', {}, {} as Env);
    expect(res.headers.get('set-cookie')).toBeNull();
    expect(((await res.json()) as { owner: string }).owner).toBe('key_123');
  });

  it('lets the operator bypass ownership without minting a visitor cookie', async () => {
    const h = app();
    const env = { ADMIN_TOKEN: 'admin-secret' } as Env;
    const res = await h.request('/who', { headers: { authorization: 'Bearer admin-secret' } }, env);
    expect(res.headers.get('set-cookie')).toBeNull();

    const body = (await res.json()) as {
      owner: string | null;
      filter: { clause: string; bindings: unknown[] };
      ownsOther: boolean;
      ownsLegacy: boolean;
    };
    expect(body.owner).toBeNull();
    expect(body.filter.clause).toBe('1 = 1');
    expect(body.ownsOther).toBe(true);
    expect(body.ownsLegacy).toBe(true);
  });
});
