/**
 * Golden outputs generated from the ORIGINAL MANTIS Python
 * (backend/infra_hunt_service.py: extract_features + compose_queries +
 * match_signature_packs) over two synthetic seed payloads. The TS port in
 * api/src/lib/mantis-infra-hunt.ts is pinned to these values so the port
 * stays behavior-identical to upstream.
 *
 * Regenerate: run the generator against the MANTIS bash clone and replace
 * the object literal (python3 + the asserts in the test below).
 */
export interface HuntGoldenFixture {
  domain_payload: unknown;
  tls_payload: unknown;
  domain_features: unknown;
  domain_queries: unknown;
  domain_signatures: unknown;
  tls_features: unknown;
  tls_queries: unknown;
  tls_signatures: unknown;
}

export const GOLDEN = {
  domain_payload: {
    crtsh: {
      source: 'crt.sh',
      domain: 'newsletter-phish.com',
      certificates: [
        {
          certificate_id: 101,
          common_name: 'newsletter-phish.com',
          san: ['newsletter-phish.com', 'mail.newsletter-phish.com', '*.newsletter-phish.com'],
          issuer: "Let's Encrypt Authority X3",
          not_before: '2026-01-05',
          not_after: '2026-04-05',
          serial_number: '0455ef',
          source: 'crt.sh',
        },
        {
          certificate_id: 202,
          common_name: 'cdn.newsletter-phish.com',
          san: ['cdn.newsletter-phish.com', 'assets.newsletter-phish.com'],
          issuer: 'R3',
          not_before: '2026-02-01',
          not_after: '2026-05-01',
          serial_number: '0f11fe',
          source: 'crt.sh',
        },
      ],
      count: 2,
    },
    ripe: {
      source: 'RIPEstat',
      ip: '185.216.35.17',
      prefix: '185.216.35.0/24',
      asns: ['AS201043'],
      asn_overview: {
        asn: 'AS201043',
        announced: true,
        holder: 'SWITCH-YARD',
        block: {
          resource: 'AS201043',
          desc: '...',
        },
      },
      announced_prefixes: ['185.216.35.0/24', '185.216.36.0/24'],
      whois: [
        {
          'abuse-c': 'ABUSE1234-RIPE',
          'org-name': 'Yard Ltd',
        },
      ],
      errors: [],
    },
  },
  tls_payload: {
    shodan: {
      matches: [
        {
          hostnames: ['c2.newsletter-phish.com'],
          ip_str: '185.216.35.17',
          port: 443,
          data: 'HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Havoc: 1.2\r\nContent-Length: 12\r\n',
          title: 'Mythic',
          ssl: {
            jarm: '29d21d20d21d21d00042d43d00041d0f7a5d5a5e8f5f5a5a5a5a5a5a40b1a1b',
            fingerprint: {
              sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
              subject: {
                CN: 'AsyncRAT Server',
              },
              issuer: {
                CN: 'Major Cobalt Strike',
              },
            },
            ja4: 't13d1516h2_8daaf6152771_b186095e22b6',
          },
          scenes: [
            {
              favicon: {
                hash: -859291042,
              },
            },
          ],
        },
        {
          hostnames: [],
          ip_str: '45.153.240.9',
          port: 8443,
          data: 'Generic banner text',
        },
      ],
    },
  },
  domain_features: {
    by_type: {
      domain: [
        {
          value: 'newsletter-phish.com',
          path: 'crtsh.domain',
          provider: 'crtsh',
        },
        {
          value: 'mail.newsletter-phish.com',
          path: 'crtsh.certificates[0].san[1]',
          provider: 'crtsh',
        },
        {
          value: 'cdn.newsletter-phish.com',
          path: 'crtsh.certificates[1].san[0]',
          provider: 'crtsh',
        },
        {
          value: 'assets.newsletter-phish.com',
          path: 'crtsh.certificates[1].san[1]',
          provider: 'crtsh',
        },
      ],
      ip: [
        {
          value: '185.216.35.17',
          path: 'ripe.ip',
          provider: 'ripe',
        },
      ],
      asn: [
        {
          value: 'AS201043',
          path: 'ripe.asn_overview.asn',
          provider: 'ripe',
        },
      ],
      tld: [
        {
          value: 'com',
          path: 'crtsh.domain',
          provider: 'crtsh',
        },
      ],
    },
    ranked: [
      {
        kind: 'asn',
        value: 'AS201043',
        path: 'ripe.asn_overview.asn',
        provider: 'ripe',
        weight: 2,
      },
      {
        kind: 'tld',
        value: 'com',
        path: 'crtsh.domain',
        provider: 'crtsh',
        weight: 2,
      },
      {
        kind: 'domain',
        value: 'assets.newsletter-phish.com',
        path: 'crtsh.certificates[1].san[1]',
        provider: 'crtsh',
        weight: 1,
      },
      {
        kind: 'domain',
        value: 'cdn.newsletter-phish.com',
        path: 'crtsh.certificates[1].san[0]',
        provider: 'crtsh',
        weight: 1,
      },
      {
        kind: 'domain',
        value: 'mail.newsletter-phish.com',
        path: 'crtsh.certificates[0].san[1]',
        provider: 'crtsh',
        weight: 1,
      },
      {
        kind: 'domain',
        value: 'newsletter-phish.com',
        path: 'crtsh.domain',
        provider: 'crtsh',
        weight: 1,
      },
      {
        kind: 'ip',
        value: '185.216.35.17',
        path: 'ripe.ip',
        provider: 'ripe',
        weight: 1,
      },
    ],
    count: 7,
    categories: {
      certificates: [],
      web: [],
      network: [
        {
          kind: 'asn',
          value: 'AS201043',
          path: 'ripe.asn_overview.asn',
          provider: 'ripe',
          weight: 2,
        },
        {
          kind: 'tld',
          value: 'com',
          path: 'crtsh.domain',
          provider: 'crtsh',
          weight: 2,
        },
      ],
      hosts: [
        {
          kind: 'domain',
          value: 'assets.newsletter-phish.com',
          path: 'crtsh.certificates[1].san[1]',
          provider: 'crtsh',
          weight: 1,
        },
        {
          kind: 'domain',
          value: 'cdn.newsletter-phish.com',
          path: 'crtsh.certificates[1].san[0]',
          provider: 'crtsh',
          weight: 1,
        },
        {
          kind: 'domain',
          value: 'mail.newsletter-phish.com',
          path: 'crtsh.certificates[0].san[1]',
          provider: 'crtsh',
          weight: 1,
        },
        {
          kind: 'domain',
          value: 'newsletter-phish.com',
          path: 'crtsh.domain',
          provider: 'crtsh',
          weight: 1,
        },
        {
          kind: 'ip',
          value: '185.216.35.17',
          path: 'ripe.ip',
          provider: 'ripe',
          weight: 1,
        },
      ],
    },
  },
  domain_queries: [
    {
      provider: 'shodan',
      query: 'asn:AS201043',
      signals: [
        {
          kind: 'asn',
          value: 'AS201043',
          weight: 2,
        },
      ],
      estimated_strength: 2,
      mode: 'compound_search',
      external_url: 'https://www.shodan.io/search?query=asn%3AAS201043',
    },
    {
      provider: 'censys',
      query: 'host.autonomous_system.asn = 201043',
      signals: [
        {
          kind: 'asn',
          value: 'AS201043',
          weight: 2,
        },
      ],
      estimated_strength: 2,
      mode: 'compound_search',
      external_url: 'https://search.censys.io/search?resource=hosts&q=host.autonomous_system.asn%20%3D%20201043',
    },
    {
      provider: 'fofa',
      query: 'asn="201043"',
      signals: [
        {
          kind: 'asn',
          value: 'AS201043',
          weight: 2,
        },
      ],
      estimated_strength: 2,
      mode: 'compound_search',
      external_url: 'https://fofa.info/result?qbase64=YXNuPSIyMDEwNDMi',
    },
    {
      provider: 'netlas',
      query: 'whois.asn.number:201043',
      signals: [
        {
          kind: 'asn',
          value: 'AS201043',
          weight: 2,
        },
      ],
      estimated_strength: 2,
      mode: 'compound_search',
      external_url: 'https://app.netlas.io/responses/?q=whois.asn.number%3A201043',
    },
    {
      provider: 'silentpush',
      query: 'asn = 201043 AND datasource = "webscan"',
      signals: [
        {
          kind: 'asn',
          value: 'AS201043',
          weight: 2,
        },
      ],
      estimated_strength: 2,
      mode: 'compound_search',
      external_url: 'https://explore.silentpush.com/',
    },
    {
      provider: 'zoomeye',
      query: 'asn="201043"',
      signals: [
        {
          kind: 'asn',
          value: 'AS201043',
          weight: 2,
        },
      ],
      estimated_strength: 2,
      mode: 'compound_search',
      external_url: 'https://www.zoomeye.ai/searchResult?q=asn%3D%22201043%22',
    },
    {
      provider: 'etugen',
      query: 'assets.newsletter-phish.com',
      signals: [
        {
          kind: 'domain',
          value: 'assets.newsletter-phish.com',
          path: 'crtsh.certificates[1].san[1]',
          provider: 'crtsh',
          weight: 1,
        },
      ],
      estimated_strength: 1,
      mode: 'open_dir_search',
      focus: 'open_directory',
      notes: 'Search exposed open directories (Trashpile) for leaked files and paths',
      external_url: 'https://app.etugen.io/search?q=assets.newsletter-phish.com',
    },
  ],
  domain_signatures: [],
  tls_features: {
    by_type: {
      ip: [
        {
          value: '185.216.35.17',
          path: 'shodan.matches[0].ip_str',
          provider: 'shodan',
        },
        {
          value: '45.153.240.9',
          path: 'shodan.matches[1].ip_str',
          provider: 'shodan',
        },
      ],
      port: [
        {
          value: '443',
          path: 'shodan.matches[0].port',
          provider: 'shodan',
        },
        {
          value: '8443',
          path: 'shodan.matches[1].port',
          provider: 'shodan',
        },
      ],
      http_server: [
        {
          value: 'nginx',
          path: 'shodan.matches[0].data',
          provider: 'shodan',
        },
      ],
      http_title: [
        {
          value: 'Mythic',
          path: 'shodan.matches[0].title',
          provider: 'shodan',
        },
      ],
      certificate_sha256: [
        {
          value: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
          path: 'shodan.matches[0].ssl.fingerprint.sha256',
          provider: 'shodan',
        },
      ],
      certificate_subject: [
        {
          value: 'AsyncRAT Server',
          path: 'shodan.matches[0].ssl.fingerprint.subject.cn',
          provider: 'shodan',
        },
      ],
      certificate_issuer: [
        {
          value: 'Major Cobalt Strike',
          path: 'shodan.matches[0].ssl.fingerprint.issuer.cn',
          provider: 'shodan',
        },
      ],
      ja4: [
        {
          value: 't13d1516h2_8daaf6152771_b186095e22b6',
          path: 'shodan.matches[0].ssl.ja4',
          provider: 'shodan',
        },
      ],
      favicon_hash: [
        {
          value: '-859291042',
          path: 'shodan.matches[0].scenes[0].favicon.hash',
          provider: 'shodan',
        },
      ],
      banner: [
        {
          value: 'Generic banner text',
          path: 'shodan.matches[1].data',
          provider: 'shodan',
        },
      ],
    },
    ranked: [
      {
        kind: 'certificate_sha256',
        value: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
        path: 'shodan.matches[0].ssl.fingerprint.sha256',
        provider: 'shodan',
        weight: 35,
      },
      {
        kind: 'certificate_subject',
        value: 'AsyncRAT Server',
        path: 'shodan.matches[0].ssl.fingerprint.subject.cn',
        provider: 'shodan',
        weight: 12,
      },
      {
        kind: 'favicon_hash',
        value: '-859291042',
        path: 'shodan.matches[0].scenes[0].favicon.hash',
        provider: 'shodan',
        weight: 12,
      },
      {
        kind: 'certificate_issuer',
        value: 'Major Cobalt Strike',
        path: 'shodan.matches[0].ssl.fingerprint.issuer.cn',
        provider: 'shodan',
        weight: 10,
      },
      {
        kind: 'ja4',
        value: 't13d1516h2_8daaf6152771_b186095e22b6',
        path: 'shodan.matches[0].ssl.ja4',
        provider: 'shodan',
        weight: 9,
      },
      {
        kind: 'banner',
        value: 'Generic banner text',
        path: 'shodan.matches[1].data',
        provider: 'shodan',
        weight: 8,
      },
      {
        kind: 'http_title',
        value: 'Mythic',
        path: 'shodan.matches[0].title',
        provider: 'shodan',
        weight: 7,
      },
      {
        kind: 'http_server',
        value: 'nginx',
        path: 'shodan.matches[0].data',
        provider: 'shodan',
        weight: 5,
      },
      {
        kind: 'port',
        value: '443',
        path: 'shodan.matches[0].port',
        provider: 'shodan',
        weight: 2,
      },
      {
        kind: 'port',
        value: '8443',
        path: 'shodan.matches[1].port',
        provider: 'shodan',
        weight: 2,
      },
      {
        kind: 'ip',
        value: '185.216.35.17',
        path: 'shodan.matches[0].ip_str',
        provider: 'shodan',
        weight: 1,
      },
      {
        kind: 'ip',
        value: '45.153.240.9',
        path: 'shodan.matches[1].ip_str',
        provider: 'shodan',
        weight: 1,
      },
    ],
    count: 12,
    categories: {
      certificates: [
        {
          kind: 'certificate_sha256',
          value: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
          path: 'shodan.matches[0].ssl.fingerprint.sha256',
          provider: 'shodan',
          weight: 35,
        },
        {
          kind: 'certificate_subject',
          value: 'AsyncRAT Server',
          path: 'shodan.matches[0].ssl.fingerprint.subject.cn',
          provider: 'shodan',
          weight: 12,
        },
        {
          kind: 'certificate_issuer',
          value: 'Major Cobalt Strike',
          path: 'shodan.matches[0].ssl.fingerprint.issuer.cn',
          provider: 'shodan',
          weight: 10,
        },
      ],
      web: [
        {
          kind: 'favicon_hash',
          value: '-859291042',
          path: 'shodan.matches[0].scenes[0].favicon.hash',
          provider: 'shodan',
          weight: 12,
        },
        {
          kind: 'ja4',
          value: 't13d1516h2_8daaf6152771_b186095e22b6',
          path: 'shodan.matches[0].ssl.ja4',
          provider: 'shodan',
          weight: 9,
        },
        {
          kind: 'banner',
          value: 'Generic banner text',
          path: 'shodan.matches[1].data',
          provider: 'shodan',
          weight: 8,
        },
        {
          kind: 'http_title',
          value: 'Mythic',
          path: 'shodan.matches[0].title',
          provider: 'shodan',
          weight: 7,
        },
        {
          kind: 'http_server',
          value: 'nginx',
          path: 'shodan.matches[0].data',
          provider: 'shodan',
          weight: 5,
        },
      ],
      network: [
        {
          kind: 'port',
          value: '443',
          path: 'shodan.matches[0].port',
          provider: 'shodan',
          weight: 2,
        },
        {
          kind: 'port',
          value: '8443',
          path: 'shodan.matches[1].port',
          provider: 'shodan',
          weight: 2,
        },
      ],
      hosts: [
        {
          kind: 'ip',
          value: '185.216.35.17',
          path: 'shodan.matches[0].ip_str',
          provider: 'shodan',
          weight: 1,
        },
        {
          kind: 'ip',
          value: '45.153.240.9',
          path: 'shodan.matches[1].ip_str',
          provider: 'shodan',
          weight: 1,
        },
      ],
    },
  },
  tls_queries: [
    {
      provider: 'shodan',
      query:
        'ssl.cert.fingerprint:"a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f" ssl.cert.subject.cn:"AsyncRAT Server" http.favicon.hash:"-859291042"',
      signals: [
        {
          kind: 'certificate_sha256',
          value: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
          weight: 35,
        },
        {
          kind: 'certificate_subject',
          value: 'AsyncRAT Server',
          weight: 12,
        },
        {
          kind: 'favicon_hash',
          value: '-859291042',
          weight: 12,
        },
      ],
      estimated_strength: 59,
      mode: 'compound_search',
      external_url:
        'https://www.shodan.io/search?query=ssl.cert.fingerprint%3A%22a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f%22%20ssl.cert.subject.cn%3A%22AsyncRAT%20Server%22%20http.favicon.hash%3A%22-859291042%22',
    },
    {
      provider: 'censys',
      query:
        'cert.fingerprint_sha256 : "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f" and cert.parsed.subject_dn : "AsyncRAT Server"',
      signals: [
        {
          kind: 'certificate_sha256',
          value: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
          weight: 35,
        },
        {
          kind: 'certificate_subject',
          value: 'AsyncRAT Server',
          weight: 12,
        },
      ],
      estimated_strength: 47,
      mode: 'compound_search',
      external_url:
        'https://search.censys.io/search?resource=hosts&q=cert.fingerprint_sha256%20%3A%20%22a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f%22%20and%20cert.parsed.subject_dn%20%3A%20%22AsyncRAT%20Server%22',
    },
    {
      provider: 'fofa',
      query:
        'cert="a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f" && cert.subject="AsyncRAT Server" && icon_hash="-859291042"',
      signals: [
        {
          kind: 'certificate_sha256',
          value: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
          weight: 35,
        },
        {
          kind: 'certificate_subject',
          value: 'AsyncRAT Server',
          weight: 12,
        },
        {
          kind: 'favicon_hash',
          value: '-859291042',
          weight: 12,
        },
      ],
      estimated_strength: 59,
      mode: 'compound_search',
      external_url:
        'https://fofa.info/result?qbase64=Y2VydD0iYTFiMmMzZDRlNWY2MDcxODI5M2E0YjVjNmQ3ZThmOWEwYjFjMmQzZTRmNWE2YjdjOGQ5ZTBmMWEyYjNjNGQ1ZiIgJiYgY2VydC5zdWJqZWN0PSJBc3luY1JBVCBTZXJ2ZXIiICYmIGljb25faGFzaD0iLTg1OTI5MTA0MiI=',
    },
    {
      provider: 'netlas',
      query:
        'certificate.fingerprint_sha256:"a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f" AND certificate.subject_dn:"AsyncRAT Server" AND http.favicon.hash:"-859291042"',
      signals: [
        {
          kind: 'certificate_sha256',
          value: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
          weight: 35,
        },
        {
          kind: 'certificate_subject',
          value: 'AsyncRAT Server',
          weight: 12,
        },
        {
          kind: 'favicon_hash',
          value: '-859291042',
          weight: 12,
        },
      ],
      estimated_strength: 59,
      mode: 'compound_search',
      external_url:
        'https://app.netlas.io/responses/?q=certificate.fingerprint_sha256%3A%22a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f%22%20AND%20certificate.subject_dn%3A%22AsyncRAT%20Server%22%20AND%20http.favicon.hash%3A%22-859291042%22',
    },
    {
      provider: 'silentpush',
      query:
        'ssl_sha256 = "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f" AND ssl_subject = "AsyncRAT Server" AND favicon_murmur3 = "-859291042" AND datasource = "webscan"',
      signals: [
        {
          kind: 'certificate_sha256',
          value: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
          weight: 35,
        },
        {
          kind: 'certificate_subject',
          value: 'AsyncRAT Server',
          weight: 12,
        },
        {
          kind: 'favicon_hash',
          value: '-859291042',
          weight: 12,
        },
      ],
      estimated_strength: 59,
      mode: 'compound_search',
      external_url: 'https://explore.silentpush.com/',
    },
    {
      provider: 'zoomeye',
      query:
        'ssl.cert.fingerprint="a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f" && ssl.cert.subject.cn="AsyncRAT Server" && iconhash="-859291042"',
      signals: [
        {
          kind: 'certificate_sha256',
          value: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
          weight: 35,
        },
        {
          kind: 'certificate_subject',
          value: 'AsyncRAT Server',
          weight: 12,
        },
        {
          kind: 'favicon_hash',
          value: '-859291042',
          weight: 12,
        },
      ],
      estimated_strength: 59,
      mode: 'compound_search',
      external_url:
        'https://www.zoomeye.ai/searchResult?q=ssl.cert.fingerprint%3D%22a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f%22%20%26%26%20ssl.cert.subject.cn%3D%22AsyncRAT%20Server%22%20%26%26%20iconhash%3D%22-859291042%22',
    },
    {
      provider: 'driftnet',
      query: 'subject:"AsyncRAT Server" AND favicon:"-859291042"',
      signals: [
        {
          kind: 'certificate_subject',
          value: 'AsyncRAT Server',
          path: 'shodan.matches[0].ssl.fingerprint.subject.cn',
          provider: 'shodan',
          weight: 12,
        },
        {
          kind: 'favicon_hash',
          value: '-859291042',
          path: 'shodan.matches[0].scenes[0].favicon.hash',
          provider: 'shodan',
          weight: 12,
        },
      ],
      estimated_strength: 24,
      mode: 'passive_search',
      dataset: 'protocols',
      external_url: '',
    },
    {
      provider: 'validin',
      query: 'cert_hash:a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
      signals: [
        {
          kind: 'certificate_sha256',
          value: 'a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
          path: 'shodan.matches[0].ssl.fingerprint.sha256',
          provider: 'shodan',
          weight: 35,
        },
      ],
      estimated_strength: 35,
      mode: 'fingerprint_pivot',
      pivot_kind: 'cert_hash',
      external_url: 'https://app.validin.com/search?q=a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5f',
    },
    {
      provider: 'etugen',
      query: 'AsyncRAT Server',
      signals: [
        {
          kind: 'certificate_subject',
          value: 'AsyncRAT Server',
          path: 'shodan.matches[0].ssl.fingerprint.subject.cn',
          provider: 'shodan',
          weight: 12,
        },
      ],
      estimated_strength: 12,
      mode: 'open_dir_search',
      focus: 'open_directory',
      notes: 'Search exposed open directories (Trashpile) for leaked files and paths',
      external_url: 'https://app.etugen.io/search?q=AsyncRAT%20Server',
    },
  ],
  tls_signatures: [
    {
      id: 1,
      slug: 'asyncrat-default-tls',
      name: 'AsyncRAT default TLS',
      family: 'AsyncRAT',
      description: 'Default AsyncRAT certificate naming observed across public deployments.',
      minimum_matches: 1,
      false_positive_notes: 'Validate with ports, TLS structure, and independent threat telemetry.',
      enabled: true,
      builtin: true,
      updated_at: '2026-10-31T05:34:14+00:00',
      signals: {
        certificate_subject: ['AsyncRAT Server'],
      },
      matched_evidence: [
        {
          kind: 'certificate_subject',
          value: 'AsyncRAT Server',
        },
      ],
    },
    {
      id: 2,
      slug: 'cobalt-strike-default-cert',
      name: 'Cobalt Strike default certificate',
      family: 'Cobalt Strike',
      description: 'Default certificate metadata associated with unmodified Cobalt Strike profiles.',
      minimum_matches: 1,
      false_positive_notes: 'Default strings are high-signal but can be copied or used by researchers.',
      enabled: true,
      builtin: true,
      updated_at: '2026-10-31T05:34:14+00:00',
      signals: {
        certificate_issuer: ['Major Cobalt Strike'],
        certificate_subject: ['Major Cobalt Strike'],
      },
      matched_evidence: [
        {
          kind: 'certificate_issuer',
          value: 'Major Cobalt Strike',
        },
      ],
    },
    {
      id: 4,
      slug: 'mythic-default-title',
      name: 'Mythic default web title',
      family: 'Mythic',
      description: 'Default Mythic web interface title.',
      minimum_matches: 1,
      false_positive_notes: 'A title alone is mutable; require a second signal for blocking decisions.',
      enabled: true,
      builtin: true,
      updated_at: '2026-10-31T05:34:14+00:00',
      signals: {
        http_title: ['Mythic'],
      },
      matched_evidence: [
        {
          kind: 'http_title',
          value: 'Mythic',
        },
      ],
    },
  ],
} satisfies HuntGoldenFixture;
