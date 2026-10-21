/**
 * Domain monitor tests.
 *
 * The normalization is the part worth pinning: a watch for "banco" has to
 * catch "BANCO", "bancó" and "banco-seguro.mx", and it has to *not* match
 * a two-letter word that would hit half the domain space.
 */

import { describe, it, expect } from 'vitest';
import { normalizeText, prepareKeywords, matchDomains, isoDaysAgo, dayFeedUrl } from '../../src/lib/domain-monitor';

describe('normalizeText', () => {
  it('strips accents', () => {
    expect(normalizeText('Bancó')).toBe('banco');
    expect(normalizeText('SEGUROS')).toBe('seguros');
    expect(normalizeText('Cuéntame')).toBe('cuentame');
  });

  it('lowercases', () => {
    expect(normalizeText('BANCO')).toBe('banco');
  });

  it('keeps dots and dashes, which are part of a domain', () => {
    expect(normalizeText('banco-seguro.com.mx')).toBe('banco-seguro.com.mx');
  });

  it('drops everything else', () => {
    expect(normalizeText('banco!@#$%')).toBe('banco');
    expect(normalizeText('a b c')).toBe('abc');
  });
});

describe('prepareKeywords', () => {
  it('drops keywords under three characters', () => {
    expect(prepareKeywords(['ab', 'a', 'banco'])).toEqual(['banco']);
  });

  it('deduplicates', () => {
    expect(prepareKeywords(['banco', 'BANCO', 'banco'])).toEqual(['banco']);
  });

  it('sorts longest first so a specific term wins', () => {
    expect(prepareKeywords(['ban', 'banco'])).toEqual(['banco', 'ban']);
  });

  it('normalizes each keyword', () => {
    expect(prepareKeywords(['Bancó'])).toEqual(['banco']);
  });
});

describe('matchDomains', () => {
  const keywords = ['banco'];

  it('matches a domain containing the keyword', () => {
    expect(matchDomains('banco-seguro.com\nwww.banco.mx', keywords)).toEqual(['banco-seguro.com', 'www.banco.mx']);
  });

  it('matches regardless of case and accents', () => {
    expect(matchDomains('BANCO-Seguro.com', keywords)).toEqual(['BANCO-Seguro.com']);
    expect(matchDomains('bancó-seguro.com', keywords)).toEqual(['bancó-seguro.com']);
  });

  it('skips lines that are not domains', () => {
    expect(matchDomains('just a sentence\nbanco.com', keywords)).toEqual(['banco.com']);
  });

  it('returns nothing when no keyword matches', () => {
    expect(matchDomains('example.org\ntest.net', keywords)).toEqual([]);
  });

  it('returns nothing when there are no keywords', () => {
    expect(matchDomains('banco.com', [])).toEqual([]);
  });

  it('deduplicates', () => {
    expect(matchDomains('banco.com\nbanco.com', keywords)).toEqual(['banco.com']);
  });
});

describe('isoDaysAgo', () => {
  it('formats as YYYY-MM-DD', () => {
    const now = new Date('2026-10-21T12:00:00Z');
    expect(isoDaysAgo(0, now)).toBe('2026-10-21');
    expect(isoDaysAgo(3, now)).toBe('2026-10-18');
  });
});

describe('dayFeedUrl', () => {
  it('points at the upstream daily file', () => {
    expect(dayFeedUrl('2026-10-21')).toBe(
      'https://raw.githubusercontent.com/ccas10ca-prog/domain/main/dominios/2026-10-21.txt'
    );
  });
});
