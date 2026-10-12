import type { Context } from 'hono';
import type { Env } from '../env';
import { logError } from '../lib/logger';
import { safeErrorMessage } from '../lib/error';
import { badGateway, tooManyRequests, badRequest, forbidden } from '../lib/api-error';

const TIMEOUT_MS = 10_000;

const ALLOWED_HOSTS = new Set([
  // Government and CERT
  'ip-api.com',
  'www.cisa.gov',
  'cisa.gov',
  'nvd.nist.gov',
  'isc.sans.edu',
  'us-cert.cisa.gov',
  'cert.europa.eu',
  'ccb.belgium.be',
  // Aggregators
  'feeds.feedburner.com',
  // News and journalism
  'threatpost.com',
  'www.threatpost.com',
  'krebsonsecurity.com',
  'thehackernews.com',
  'www.bleepingcomputer.com',
  'bleepingcomputer.com',
  'www.securityweek.com',
  'securityweek.com',
  'www.darkreading.com',
  'darkreading.com',
  'www.zdnet.com',
  'feeds.arstechnica.com',
  'arstechnica.com',
  'www.vice.com',
  'www.wired.com',
  'www.theregister.com',
  'www.schneier.com',
  // abuse.ch
  'threatfox.abuse.ch',
  'urlhaus.abuse.ch',
  'bazaar.abuse.ch',
  'mb-api.abuse.ch',
  'sslbl.abuse.ch',
  'openphish.com',
  'www.openphish.com',
  // DFIR Lab and Radar
  'dfir-lab.ch',
  'www.dfir-lab.ch',
  'falhumaid.github.io',
  // Vendor research
  'blog.talosintelligence.com',
  'talosintelligence.com',
  'unit42.paloaltonetworks.com',
  'blog.trailofbits.com',
  'www.welivesecurity.com',
  'welivesecurity.com',
  'securelist.com',
  'www.securelist.com',
  'www.crowdstrike.com',
  'crowdstrike.com',
  'www.sentinelone.com',
  'sentinelone.com',
  'flashpoint.io',
  'www.flashpoint.io',
  'feeds.fireeye.com',
  'www.microsoft.com',
  'msrc-blog.microsoft.com',
  'googleprojectzero.blogspot.com',
  'cloud.google.com',
  'research.checkpoint.com',
  'www.trendmicro.com',
  'news.sophos.com',
  'blog.malwarebytes.com',
  'www.volexity.com',
  'www.huntress.com',
  'redcanary.com',
  // Researcher blogs
  'www.malware-traffic-analysis.net',
  'www.hackmageddon.com',
  'www.infostealers.com',
  'medium.com',
  // Dark web and ransomware trackers
  'darkwebinformer.com',
  'ransomware.live',
  'www.databreaches.net',
  'thedfirreport.com',
  'therecord.media',
  'www.curatedintel.org',
  'www.cyfirma.com',
  // Reddit RSS
  'www.reddit.com',
  'reddit.com',
  'old.reddit.com',
  // Hacker News and YC
  'hnrss.org',
  'news.ycombinator.com',
  'www.ycombinator.com',
  'ycombinator.com',
  // Late additions: probed and confirmed accessible
  'rss.packetstormsecurity.com',
  'otx.alienvault.com',
  'www.helpnetsecurity.com',
  'www.csoonline.com',
  'www.cvedetails.com',
  'www.exploit-db.com',
  'raw.githubusercontent.com',
  // Scam Watch sources
  'consumer.ftc.gov',
  'www.ic3.gov',
  'ic3.gov',
  'www.snopes.com',
  'snopes.com',
  'news.google.com',
  'rekt.news',
  'www.web3isgoinggreat.com',
  'web3isgoinggreat.com',
  // Industry / fundraising / Tech & AI
  'techcrunch.com',
  'www.techcrunch.com',
  'venturebeat.com',
  'www.venturebeat.com',
  'www.theverge.com',
  'theverge.com',
  'www.technologyreview.com',
  'technologyreview.com',
  'openai.com',
  'www.openai.com',
  'blog.google',
  // Breach-focused feeds (added 2026-05-11) — used by /threatintel/breach
  'www.vpnmentor.com',
  'vpnmentor.com',
  'grcsolutions.io',
  'www.grcsolutions.io',
  'www.comparitech.com',
  'comparitech.com',
  'www.troyhunt.com',
  'troyhunt.com',
  'www.idtheftcenter.org',
  'idtheftcenter.org',
  // Feed expansion 2026-05-18 (kept in sync with feeds-aggregate.ts)
  'cyble.com',
  'www.cyble.com',
  'socradar.io',
  'www.socradar.io',
  'blog.bushidotoken.net',
  'www.rapid7.com',
  'rapid7.com',
  'blogs.jpcert.or.jp',
  'www.ncsc.gov.uk',
  'asec.ahnlab.com',
  'huggingface.co',
  'the-decoder.com',
  'importai.substack.com',
  'blog.fox-it.com',
  // AI lab blogs (2026-06) — kept in sync with feeds-aggregate.ts
  'www.anthropic.com',
  'anthropic.com',
  'deepmind.google',
  // Finance & banking (2026-06) — kept in sync with feeds-aggregate.ts
  'www.finextra.com',
  'finextra.com',
  'www.paymentsdive.com',
  'paymentsdive.com',
  'www.bankingdive.com',
  'bankingdive.com',
  // Same-origin synthesised feeds (e.g. MyThreatIntel ransomware → RSS)
  'pranithjain.qzz.io',
  // Sync with feeds-aggregate.ts ALLOWED_HOSTS (2026-05-24 additions)
  'www.akamai.com',
  'akamai.com',
  'github.com',
  'osv.dev',
  'www.osv.dev',
  // Dead-feed fixes 2026-06 (sync w/ feeds-aggregate.ts)
  'projectzero.google',
  'www.malwarebytes.com',
  'malwarebytes.com',
  'api.theregister.com',
  'theregister.com',
  'databreaches.net',
  'hackread.com',
  'redhuntlabs.com',
  'www.redhuntlabs.com',
  'www.recordedfuture.com',
  'recordedfuture.com',
  'cyberscoop.com',
  'www.cyberscoop.com',
  'grahamcluley.com',
  'www.grahamcluley.com',
  // Lyrie Research — autonomous CTI platform with JSON Feed v1.1
  'lyrie.ai',
  // supplychainattack.org — supply-chain incident catalog RSS (change-detection)
  'supplychainattack.org',
  // Wiz Research cloud-threat-landscape RSS (cloud/SaaS/identity incidents)
  'www.wiz.io',
  'wiz.io',
  // Feedspot high-quality feeds 2026-06 — curated from rss.feedspot.com/hacker_rss_feeds/
  'tisiphone.net',
  'thehackerblog.com',
  'blog.detectify.com',
  'hackerone.com',
  'www.hackerone.com',
  'bugcrowd.com',
  'www.bugcrowd.com',
  'yeswehack.com',
  'www.yeswehack.com',
  'synack.com',
  'www.synack.com',
  'hackthebox.com',
  'www.hackthebox.com',
  'pentestlab.blog',
  'hackers-arise.com',
  'www.hackers-arise.com',
  'embracethered.com',
  'blog.knowbe4.com',
  'darknet.org.uk',
  'cqureacademy.com',
  'hackingarticles.in',
  // www-prefixed variants used by some feeds
  'www.hackingarticles.in',
  'www.darknet.org.uk',
  // 2026-06: direct-fetch host for The Hacker News (was FeedBurner)
  'thehackernews.com',
  'www.thehackernews.com',
  // Dead-feed redirect fixes 2026-06-23: feeds that moved hosts — add
  // the redirect targets so the per-hop host check doesn't reject them.
  'www.withsecure.com',
  'withsecure.com',
  'www.sophos.com',
  'sophos.com',
  'security.googleblog.com',
  // 2026-06-23: threat-intel allowlist gaps — 16 feeds were silently dropped
  'aws.amazon.com',
  'chronicle.security',
  'countercept.com',
  'feeds.trendmicro.com',
  'intel471.com',
  'labs.withsecure.com',
  'objective-see.org',
  'securitylabs.datadoghq.com',
  'the-hunters-ledger.com',
  'vxdb.sh',
  'www.elastic.co',
  'www.hexacorn.com',
  'www.malwaretech.com',
  'www.netskope.com',
  'www.wordfence.com',
  // Redirect-target variants for the above (www ↔ apex)
  'elastic.co',
  'hexacorn.com',
  'malwaretech.com',
  'netskope.com',
  'wordfence.com',
  'www.chronicle.security',
  'www.countercept.com',
  'www.intel471.com',
  'www.objective-see.org',
  'www.the-hunters-ledger.com',
  'www.vxdb.sh',
  // Additional common www ↔ apex redirect targets across the full set
  'csoonline.com',
  'curatedintel.org',
  'cyfirma.com',
  'exploit-db.com',
  'helpnetsecurity.com',
  'huntress.com',
  'infostealers.com',
  'malware-traffic-analysis.net',
  'microsoft.com',
  'ncsc.gov.uk',
  'schneier.com',
  'trendmicro.com',
  'volexity.com',
  'wired.com',
  'zdnet.com',
  'www.arstechnica.com',
  'www.krebsonsecurity.com',
  'www.socradar.io',
  'www.the-decoder.com',
  'www.thedfirreport.com',
  'www.therecord.media',
  'www.tisiphone.net',
  'www.venturebeat.com',
]);

export async function feedProxyHandler(c: Context<{ Bindings: Env }>) {
  const url = c.req.query('url');
  if (!url) return badRequest(c, 'missing url');

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (_catchErr) {
    logError('feedProxyHandler failed', _catchErr);
    return badRequest(c, 'invalid url');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return badRequest(c, 'unsupported protocol');
  }
  // Allow-list to prevent SSRF / abuse
  if (!ALLOWED_HOSTS.has(parsed.hostname.toLowerCase())) {
    return forbidden(c, `host not in allow-list: ${parsed.hostname}`);
  }

  // BleepingComputer 403s datacenter egress (Cloudflare bot challenge).
  // Fetch its Google News mirror instead; news.google.com is allowlisted
  // above. Mirrors the same alias in feeds-aggregate.ts fetchOne.
  const BLEEPING_COMPUTER_HOST_RE = /^(?:www\.)?bleepingcomputer\.com$/i;
  if (BLEEPING_COMPUTER_HOST_RE.test(parsed.hostname)) {
    parsed = new URL('https://news.google.com/rss/search?q=site:bleepingcomputer.com&hl=en-US&gl=US&ceid=US:en');
    if (!ALLOWED_HOSTS.has(parsed.hostname.toLowerCase())) {
      return forbidden(c, `mirror host not in allow-list: ${parsed.hostname}`);
    }
  }

  // Cache-API first (free, no KV quota). Keyed on the full URL so repeated
  // requests for the same feed skip the upstream fetch entirely.
  const CACHE_TTL = 300; // 5min
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheReq = new Request(`https://feed-proxy-cache.internal/v1?u=${encodeURIComponent(url)}`);
  const cached = await cache.match(cacheReq);
  if (cached) {
    // SWR: serve immediately, refresh in background if older than 80%.
    const cacheDate = cached.headers.get('date');
    const age = cacheDate ? (Date.now() - new Date(cacheDate).getTime()) / 1000 : 0;
    if (age > CACHE_TTL * 0.8) {
      c.executionCtx.waitUntil(
        (async () => {
          try {
            // Re-fetch in background — same redirect/validation logic.
            // We don't re-run the full handler; just re-fetch the upstream
            // and update the cache. If it fails, the stale copy stays.
            const res = await fetch(parsed.toString(), {
              redirect: 'manual',
              headers: {
                'user-agent':
                  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) pranithjain-rss/1.0 Safari/537.36',
                accept: 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.5',
              },
              signal: AbortSignal.timeout(TIMEOUT_MS),
            });
            if (res.ok) {
              const body = await res.text();
              if (body.length <= 512 * 1024) {
                const upstreamCt = (res.headers.get('content-type') ?? '').toLowerCase();
                const safeCt = /(?:xml|rss|atom|json)/.test(upstreamCt)
                  ? (upstreamCt.split(';')[0]?.trim() ?? 'text/plain; charset=utf-8')
                  : 'text/plain; charset=utf-8';
                await cache.put(
                  cacheReq,
                  new Response(body, {
                    headers: {
                      'content-type': safeCt,
                      'x-content-type-options': 'nosniff',
                      'cache-control': `public, max-age=${CACHE_TTL}`,
                    },
                  })
                );
              }
            }
          } catch {
            /* non-fatal */
          }
        })()
      );
    }
    return new Response(cached.body, cached);
  }

  try {
    // Manual redirect handling: an allow-listed host with an open redirect
    // (Google News, Reddit, raw.githubusercontent, …) could otherwise bounce
    // `redirect: 'follow'` to an arbitrary internal/external target,
    // defeating the allow-list. Re-validate every hop's host.
    const reqHeaders = {
      // Many feed origins (Akamai/Cloudflare-fronted, Reddit, etc.) block
      // generic bot UAs. Use a browser-like UA to maximise compatibility.
      'user-agent':
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) pranithjain-rss/1.0 Safari/537.36',
      accept: 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.5',
      'accept-language': 'en-US,en;q=0.9',
    };
    let current = parsed;
    let upstream: Response | null = null;
    for (let hop = 0; hop < 5; hop += 1) {
      upstream = await fetch(current.toString(), {
        redirect: 'manual',
        headers: reqHeaders,
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (upstream.status < 300 || upstream.status >= 400) break;
      const location = upstream.headers.get('location');
      if (!location) break;
      let next: URL;
      try {
        next = new URL(location, current);
      } catch (_catchErr) {
        logError('handler failed', _catchErr);
        return badGateway(c, 'upstream redirect to malformed url');
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        return forbidden(c, `upstream redirect to unsupported protocol: ${next.protocol}`);
      }
      if (!ALLOWED_HOSTS.has(next.hostname.toLowerCase())) {
        return forbidden(c, `upstream redirect to non-allow-listed host: ${next.hostname}`);
      }
      current = next;
      if (hop === 4) return badGateway(c, 'too many redirects');
    }
    if (!upstream) return badGateway(c, 'upstream fetch failed');
    if (upstream.status === 429) {
      const retryAfter = upstream.headers.get('retry-after') ?? '60';
      return tooManyRequests(c, 'upstream_rate_limited', { windowSeconds: parseInt(retryAfter, 10) || 60 });
    }
    if (!upstream.ok) {
      return badGateway(c, `upstream ${upstream.status}`);
    }
    const MAX_FEED_BYTES = 512 * 1024;
    const contentLength = Number(upstream.headers.get('content-length') ?? '0');
    if (contentLength > MAX_FEED_BYTES) {
      return badGateway(c, 'upstream response too large');
    }
    const body = await upstream.text();
    if (body.length > MAX_FEED_BYTES) {
      return badGateway(c, 'upstream response too large');
    }
    // Never echo the upstream content-type verbatim: this endpoint is
    // same-origin, and an allow-listed raw-content host (e.g.
    // raw.githubusercontent.com) returning text/html would render as an
    // attacker page on our origin. Only pass through XML/JSON feed types;
    // anything else is served as inert text/plain.
    const upstreamCt = (upstream.headers.get('content-type') ?? '').toLowerCase();
    const safeCt = /(?:xml|rss|atom|json)/.test(upstreamCt)
      ? (upstreamCt.split(';')[0]?.trim() ?? 'text/plain; charset=utf-8')
      : 'text/plain; charset=utf-8';
    const response = new Response(body, {
      status: 200,
      headers: {
        'content-type': safeCt,
        'x-content-type-options': 'nosniff',
        'cache-control': `public, max-age=${CACHE_TTL}`,
      },
    });
    // Write-through to the Cache-API so the next request for the same URL
    // is a cache hit (free, no KV).
    c.executionCtx.waitUntil(cache.put(cacheReq, response.clone()));
    return response;
  } catch (err) {
    logError('handler failed', err);
    return badGateway(c, safeErrorMessage(c.env as unknown as Record<string, unknown>, err));
  }
}
