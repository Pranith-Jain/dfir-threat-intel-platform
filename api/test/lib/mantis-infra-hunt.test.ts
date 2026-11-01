import { describe, it, expect } from 'vitest';
import {
  extractFeatures,
  composeQueries,
  matchSignaturePacks,
  builtinSignaturePacks,
  classifySeed,
} from '../../src/lib/mantis-infra-hunt';
import { GOLDEN } from './mantis-hunt-golden';

/**
 * Parity contract against MANTIS's Python planner (see the fixture header).
 * Both "feature extraction must be a faithful port" (character-level query
 * strings matter — analysts paste them straight into engine consoles) and
 * "the planner degrades gracefully on thin payloads".
 */
describe('mantis-infra-hunt (infra_hunt_service.py port)', () => {
  it('extractFeatures matches Python extract_features on the crtsh+ripe seed payload', () => {
    expect(extractFeatures(GOLDEN.domain_payload)).toEqual(GOLDEN.domain_features);
  });

  it('composeQueries matches Python compose_queries on the domain plan', () => {
    const features = extractFeatures(GOLDEN.domain_payload);
    expect(composeQueries(features, 3)).toEqual(GOLDEN.domain_queries);
  });

  it('extractFeatures matches Python extract_features on the TLS/banner-heavy payload', () => {
    expect(extractFeatures(GOLDEN.tls_payload)).toEqual(GOLDEN.tls_features);
  });

  it('composeQueries matches Python compose_queries on the TLS plan (incl. driftnet/validin/etugen lanes)', () => {
    const features = extractFeatures(GOLDEN.tls_payload);
    expect(composeQueries(features, 3)).toEqual(GOLDEN.tls_queries);
  });

  it('matchSignaturePacks flags AsyncRAT, Cobalt Strike and Mythic exactly like upstream', () => {
    const features = extractFeatures(GOLDEN.tls_payload);
    // Pin the seed stamp so the DB-row shape (id/updated_at) is deterministic.
    expect(matchSignaturePacks(features, builtinSignaturePacks('2026-10-31T05:34:14+00:00'))).toEqual(
      GOLDEN.tls_signatures
    );
  });

  it('empty payloads produce empty plans and no matches', () => {
    const features = extractFeatures({});
    expect(features.ranked).toEqual([]);
    expect(features.count).toBe(0);
    expect(composeQueries(features, 3)).toEqual([]);
    expect(matchSignaturePacks(features)).toEqual([]);
  });

  it('classifySeed accepts IPs and domains and rejects junk', () => {
    expect(classifySeed(' 185.216.35.17 ')).toEqual({ kind: 'ip', value: '185.216.35.17' });
    expect(classifySeed('Newsletter-Phish.Com')).toEqual({ kind: 'domain', value: 'newsletter-phish.com' });
    expect(classifySeed('not-a-seed')).toEqual({ kind: 'invalid', value: 'not-a-seed' });
  });

  it('engineSearchUrl short-circuits pure IPs to the Shodan host page (upstream behavior)', () => {
    const qs = composeQueries(extractFeatures({ ip: '185.216.35.17' }), 3) as Array<{
      provider: string;
      query: string;
      external_url: string;
    }>;
    const shodan = qs.find((q) => q.provider === 'shodan');
    // The shodan clause is net:<ip>; upstream maps the pure-IP link to /host/.
    expect(shodan?.query).toBe('net:185.216.35.17');
    expect(shodan?.external_url).toBe('https://www.shodan.io/host/185.216.35.17');
  });
});
