import type { PulseEvent } from './types';
import { COUNTRY_COORDS } from './geo';
import { logError } from '../../lib/logger';
import { advisoriesUrl, githubHeaders, type GithubEnv } from '../../lib/github-api';

/* ─── USGS Earthquakes ──────────────────────────────────────────────────── */

export async function fetchEarthquakes(): Promise<PulseEvent[]> {
  try {
    const res = await fetch('https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_day.geojson', {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as {
      features?: Array<{
        properties: { mag: number; place: string; time: number; url: string; alert?: string };
        geometry: { coordinates: [number, number, number] };
      }>;
    };
    return (data.features ?? []).slice(0, 50).map((f, idx) => {
      const [lng, lat] = f.geometry.coordinates;
      const mag = f.properties.mag;
      return {
        id: `quake-${idx}-${f.properties.time}`,
        kind: 'earthquake' as const,
        title: `M${mag.toFixed(1)} — ${f.properties.place}`,
        description:
          `Magnitude ${mag.toFixed(1)} earthquake` + (f.properties.alert ? ` · Alert: ${f.properties.alert}` : ''),
        lat,
        lng,
        magnitude: mag,
        timestamp: new Date(f.properties.time).toISOString(),
        severity: mag >= 6 ? ('critical' as const) : mag >= 4.5 ? ('high' as const) : ('medium' as const),
        source: 'USGS',
        url: f.properties.url,
      };
    });
  } catch (_catchErr) {
    logError('fetchEarthquakes failed', _catchErr);
    return [];
  }
}

/* ─── NASA EONET (Natural Events — storms, volcanoes, floods, fires) ──── */

export async function fetchNaturalEvents(): Promise<PulseEvent[]> {
  try {
    const res = await fetch('https://eonet.gsfc.nasa.gov/api/v3/events?status=open&limit=50', {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as {
      events?: Array<{
        id: string;
        title: string;
        categories: Array<{ id: string; title: string }>;
        geometry: Array<{ date: string; coordinates: [number, number] }>;
        sources: Array<{ url: string }>;
      }>;
    };
    const events: PulseEvent[] = [];
    for (const evt of data.events ?? []) {
      const cat = evt.categories[0];
      if (!cat) continue;
      const latestGeo = evt.geometry[evt.geometry.length - 1];
      if (!latestGeo) continue;
      const [lng, lat] = latestGeo.coordinates;
      const isWildfire = cat.id === 'wildfires';
      const isVolcano = cat.id === 'volcanoes';
      const isStorm = cat.id === 'severeStorms';
      events.push({
        id: `eonet-${evt.id}`,
        kind: isWildfire ? 'war_room' : 'geopolitical',
        title: evt.title,
        description: cat.title,
        lat,
        lng,
        timestamp: latestGeo.date || new Date().toISOString(),
        severity: isVolcano || isStorm ? ('high' as const) : isWildfire ? ('medium' as const) : ('low' as const),
        source: 'NASA EONET',
        url: evt.sources[0]?.url,
      });
    }
    return events;
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return [];
  }
}

/* ─── OpenSky Network (Live Flight Data — ADS-B) ─────────────────────── */

export async function fetchFlights(): Promise<PulseEvent[]> {
  try {
    // OpenSky may block Cloudflare Workers - use timeout and fallback
    const res = await fetch('https://opensky-network.org/api/states/all?lamin=20&lomin=-130&lamax=70&lomax=50', {
      signal: AbortSignal.timeout(8000),
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) return getStaticFlights();
    const data = (await res.json()) as {
      states?: Array<
        [
          string,
          string,
          number,
          number,
          number | null,
          number | null,
          number | null,
          boolean,
          number,
          number,
          number | null,
          number | null,
          string | null,
          number | null,
          string | null,
        ]
      >;
    };
    if (!data.states?.length) return getStaticFlights();
    const sampled = data.states.filter((_, i) => i % 30 === 0).slice(0, 25);
    return sampled
      .map((s, idx) => {
        const [icao24, callsign, , , , lon, lat, , , , , , originCountry] = s;
        return {
          id: `flight-${icao24}-${idx}`,
          kind: 'aircraft' as const,
          title: `${(callsign ?? '').trim() || icao24} — ${originCountry ?? 'Unknown'}`,
          description: `Aircraft from ${originCountry ?? 'Unknown origin'}`,
          lat: lat ?? 0,
          lng: lon ?? 0,
          timestamp: new Date().toISOString(),
          severity: 'low' as const,
          source: 'OpenSky',
        };
      })
      .filter((f) => f.lat !== 0 || f.lng !== 0);
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return getStaticFlights();
  }
}

/* ─── Static Flight Data (Fallback) ───────────────────────────────────── */

function getStaticFlights(): PulseEvent[] {
  // Major airports worldwide for fallback visualization
  const airports = [
    { code: 'JFK', lat: 40.64, lng: -73.78, city: 'New York' },
    { code: 'LAX', lat: 33.94, lng: -118.41, city: 'Los Angeles' },
    { code: 'LHR', lat: 51.47, lng: -0.46, city: 'London' },
    { code: 'CDG', lat: 49.01, lng: 2.55, city: 'Paris' },
    { code: 'FRA', lat: 50.03, lng: 8.57, city: 'Frankfurt' },
    { code: 'DXB', lat: 25.25, lng: 55.36, city: 'Dubai' },
    { code: 'HND', lat: 35.55, lng: 139.78, city: 'Tokyo' },
    { code: 'SIN', lat: 1.35, lng: 103.99, city: 'Singapore' },
    { code: 'SYD', lat: -33.95, lng: 151.18, city: 'Sydney' },
    { code: 'GRU', lat: -23.43, lng: -46.47, city: 'São Paulo' },
    { code: 'JNB', lat: -26.13, lng: 28.24, city: 'Johannesburg' },
    { code: 'PEK', lat: 40.08, lng: 116.58, city: 'Beijing' },
    { code: 'ICN', lat: 37.46, lng: 126.44, city: 'Seoul' },
    { code: 'BOM', lat: 19.09, lng: 72.87, city: 'Mumbai' },
    { code: 'ORD', lat: 41.97, lng: -87.91, city: 'Chicago' },
  ];
  return airports.map((a, idx) => ({
    id: `airport-${a.code}-${idx}`,
    kind: 'aircraft' as const,
    title: `${a.code} — ${a.city}`,
    description: `Major airport hub`,
    lat: a.lat,
    lng: a.lng,
    timestamp: new Date().toISOString(),
    severity: 'low' as const,
    source: 'Airport Data',
  }));
}

/* ─── GDACS (Global Disaster Alerts) ──────────────────────────────────── */

export async function fetchGdacsAlerts(): Promise<PulseEvent[]> {
  try {
    const res = await fetch(
      'https://www.gdacs.org/gdacsapi/api/events/geteventlist/MAP?alertlevel=Orange;Red&eventtype=TC;EQ;FL;VO;DR;WF',
      { signal: AbortSignal.timeout(8000) }
    );
    if (!res.ok) return [];
    const data = (await res.json()) as {
      features?: Array<{
        properties: {
          eventid: string;
          eventtype: string;
          alertlevel: string;
          country: string;
          title: string;
          fromdate: string;
        };
        geometry: { coordinates: [number, number] };
      }>;
    };
    return (data.features ?? [])
      .filter((f) => f.properties.alertlevel !== 'Green')
      .slice(0, 30)
      .map((f) => {
        const [lng, lat] = f.geometry.coordinates;
        const p = f.properties;
        const typeMap: Record<string, string> = {
          TC: 'Tropical Cyclone',
          EQ: 'Earthquake',
          FL: 'Flood',
          VO: 'Volcano',
          DR: 'Drought',
          WF: 'Wildfire',
        };
        return {
          id: `gdacs-${p.eventid}`,
          kind: 'geopolitical' as const,
          title: p.title || `${typeMap[p.eventtype] ?? p.eventtype} — ${p.country}`,
          description: `${typeMap[p.eventtype] ?? p.eventtype} · Alert: ${p.alertlevel} · ${p.country}`,
          lat,
          lng,
          timestamp: p.fromdate || new Date().toISOString(),
          severity: p.alertlevel === 'Red' ? ('critical' as const) : ('high' as const),
          source: 'GDACS',
        };
      });
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return [];
  }
}

/* ─── Feodo Tracker (Botnet C2 Infrastructure) ─────────────────────────── */

// Multi-source live C2 infrastructure. Was Feodo-only (~1 online geo-located
// host); now also pulls live Cobalt Strike beacons (CriticalPathSecurity) and
// the C2IntelFeeds 30-day IP:port+framework set so the C2 layer reflects the
// real C2 surface. Feodo carries a country → globe markers; the IP-only feeds
// are non-geo → CTI feed panel. Deduped by IP across all sources.
//
// Caps are deliberately tight (25/15/15): every row here is stamped at fetch
// time and severity critical/high, so an uncapped C2 triple-source permanently
// tops any severity-first sort above ransomware victims and 0-day CVEs with
// real (older) timestamps. Volume discipline here is what keeps the pulse
// about threats, not infrastructure inventory.
export async function fetchBotnetC2(): Promise<PulseEvent[]> {
  const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
  const get = (url: string, ms = 8000) =>
    fetch(url, { signal: AbortSignal.timeout(ms), headers: { 'user-agent': 'pranithjain-dfir/1.0' } });
  const events: PulseEvent[] = [];
  const seen = new Set<string>();

  // 1) Feodo Tracker — geo-located → globe markers.
  try {
    const res = await get('https://feodotracker.abuse.ch/downloads/ipblocklist.json');
    if (res.ok) {
      const data = (await res.json()) as Array<{
        ip_address: string;
        port: number;
        status: string;
        hostname: string | null;
        as_name: string;
        country: string;
        first_seen: string;
        last_online: string;
        malware: string;
      }>;
      for (const c of data.filter((c) => c.status === 'online').slice(0, 25)) {
        const coords = COUNTRY_COORDS[c.country];
        if (!coords || seen.has(c.ip_address)) continue;
        seen.add(c.ip_address);
        events.push({
          id: `c2-feodo-${c.ip_address}-${c.port}`,
          kind: 'c2_tracker' as const,
          title: `${c.malware} C2 — ${c.ip_address}:${c.port}`,
          description: `${c.as_name} · ${c.country} · ${c.hostname || 'No hostname'}`,
          lat: coords[0] + (Math.random() - 0.5) * 2,
          lng: coords[1] + (Math.random() - 0.5) * 3,
          timestamp: c.last_online || c.first_seen || new Date().toISOString(),
          severity: 'critical' as const,
          source: 'Feodo Tracker',
          url: `https://feodotracker.abuse.ch/host/${c.ip_address}/`,
          country: c.country,
        });
      }
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    /* skip source */
  }

  // 2) CriticalPathSecurity — live Cobalt Strike beacon IPs (non-geo → feed).
  try {
    const res = await get(
      'https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/cobaltstrike_ips.txt'
    );
    if (res.ok) {
      const ips = [
        ...new Set(
          (await res.text())
            .split('\n')
            .map((l) => l.trim())
            .filter((l) => IPV4.test(l))
        ),
      ];
      for (const ip of ips.slice(0, 15)) {
        if (seen.has(ip)) continue;
        seen.add(ip);
        events.push({
          id: `c2-cs-${ip}`,
          kind: 'c2_tracker' as const,
          title: `Cobalt Strike C2 — ${ip}`,
          description: 'Live Cobalt Strike beacon · CriticalPathSecurity',
          lat: 0,
          lng: 0,
          timestamp: new Date().toISOString(),
          severity: 'critical' as const,
          source: 'CriticalPathSecurity',
          url: `https://www.shodan.io/host/${ip}`,
        });
      }
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    /* skip source */
  }

  // 3) C2IntelFeeds (drb-ra) — IP,port,framework over a 30-day window (non-geo → feed).
  try {
    const res = await get(
      'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPPortC2s-30day.csv',
      10000
    );
    if (res.ok) {
      let added = 0;
      for (const line of (await res.text()).split('\n').slice(1)) {
        if (added >= 15) break;
        const [ip, port, ...rest] = line.split(',');
        if (!ip || !IPV4.test(ip) || seen.has(ip)) continue;
        seen.add(ip);
        const framework =
          (rest.join(',') || 'C2')
            .replace(/^Possible\s+/i, '')
            .replace(/\s*C2 IP\s*$/i, '')
            .trim() || 'C2';
        events.push({
          id: `c2-intel-${ip}-${port || '0'}`,
          kind: 'c2_tracker' as const,
          title: `${framework} C2 — ${ip}${port ? `:${port}` : ''}`,
          description: 'C2IntelFeeds · 30-day',
          lat: 0,
          lng: 0,
          timestamp: new Date().toISOString(),
          severity: 'high' as const,
          source: 'C2IntelFeeds',
          url: `https://www.shodan.io/host/${ip}`,
        });
        added++;
      }
    }
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    /* skip source */
  }

  return events;
}

/* ─── SANS DShield Top Attackers ───────────────────────────────────────── */

export async function fetchDShieldAttackers(): Promise<PulseEvent[]> {
  try {
    const res = await fetch('https://isc.sans.edu/api/sources/attacks/20?json', {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as Array<{
      ip: string;
      attacks: number;
      count: number;
      firstseen: string;
      lastseen: string;
    }>;
    return data.slice(0, 20).map((a) => {
      // Use a deterministic "random" based on IP for consistent positioning
      const ipHash = a.ip.split('.').reduce((h, o) => (h * 11 + parseInt(o)) % 360, 0);
      const lat = 20 + (ipHash % 50);
      const lng = -180 + ((ipHash * 7) % 360);
      return {
        id: `dshield-${a.ip}`,
        kind: 'cyber_attack' as const,
        title: `Mass Scanner — ${a.ip}`,
        description: `${a.attacks.toLocaleString()} attacks · ${a.count.toLocaleString()} targets · Since ${a.firstseen}`,
        lat,
        lng,
        timestamp: a.lastseen || new Date().toISOString(),
        severity: a.attacks > 5000 ? ('critical' as const) : a.attacks > 1000 ? ('high' as const) : ('medium' as const),
        source: 'SANS DShield',
        url: `https://isc.sans.edu/ipinfo.html?ip=${a.ip}`,
      };
    });
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return [];
  }
}

/* ─── Emerging Threats Compromised IPs ─────────────────────────────────── */

export async function fetchCompromisedIPs(): Promise<PulseEvent[]> {
  try {
    const res = await fetch('https://rules.emergingthreats.net/blockrules/compromised-ips.txt', {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const text = await res.text();
    const ips = text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))
      .slice(0, 30);
    return ips.map((ip, idx) => {
      const ipHash = ip.split('.').reduce((h, o) => (h * 11 + parseInt(o || '0')) % 360, 0);
      const lat = 20 + (ipHash % 50);
      const lng = -180 + ((ipHash * 7) % 360);
      return {
        id: `compromised-${ip}-${idx}`,
        kind: 'cyber_attack' as const,
        title: `Compromised Host — ${ip}`,
        description: 'Listed by Emerging Threats (Proofpoint) as compromised',
        lat,
        lng,
        timestamp: new Date().toISOString(),
        severity: 'high' as const,
        source: 'Emerging Threats',
      };
    });
  } catch (_catchErr) {
    logError('fetchCompromisedIPs failed', _catchErr);
    return [];
  }
}

/* ─── Blocklist.de Attackers ───────────────────────────────────────────── */

export async function fetchBlocklistAttackers(): Promise<PulseEvent[]> {
  try {
    const res = await fetch('https://lists.blocklist.de/lists/all.txt', {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const text = await res.text();
    const ips = text
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))
      .slice(0, 30);
    return ips.map((ip, idx) => {
      const ipHash = ip.split('.').reduce((h, o) => (h * 11 + parseInt(o || '0')) % 360, 0);
      const lat = 20 + (ipHash % 50);
      const lng = -180 + ((ipHash * 7) % 360);
      return {
        id: `blocklist-${ip}-${idx}`,
        kind: 'cyber_attack' as const,
        title: `Attacker — ${ip}`,
        description: 'Listed by Blocklist.de for malicious activity',
        lat,
        lng,
        timestamp: new Date().toISOString(),
        severity: 'high' as const,
        source: 'Blocklist.de',
      };
    });
  } catch (_catchErr) {
    logError('fetchBlocklistAttackers failed', _catchErr);
    return [];
  }
}

/* ─── CISA Known Exploited Vulnerabilities ─────────────────────────────── */

export async function fetchCisaKev(): Promise<PulseEvent[]> {
  try {
    const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as {
      vulnerabilities?: Array<{
        cveID: string;
        vendorProject: string;
        product: string;
        vulnerabilityName: string;
        dateAdded: string;
        shortDescription: string;
        requiredAction: string;
        dueDate: string;
      }>;
    };
    // Get recently added KEVs (last 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString().split('T')[0] ?? '';
    return (data.vulnerabilities ?? [])
      .filter((v) => v.dateAdded >= thirtyDaysAgo)
      .slice(0, 20)
      .map((v) => ({
        id: `kev-${v.cveID}`,
        kind: 'cisa_advisory' as const,
        title: `${v.cveID} — ${v.vendorProject} ${v.product}`,
        description: v.vulnerabilityName + '. ' + v.shortDescription.slice(0, 100),
        lat: 38.9, // Washington DC area (CISA)
        lng: -77.05,
        timestamp: v.dateAdded,
        severity: 'critical' as const,
        source: 'CISA KEV',
        url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      }));
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return [];
  }
}

/* ─── URLhaus Malware URLs ─────────────────────────────────────────────── */

export async function fetchUrlhaus(): Promise<PulseEvent[]> {
  try {
    // URLhaus API may require auth or be rate-limited — fail gracefully
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/30/', {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as {
      query_status?: string;
      urls?: Array<{
        id: number;
        url: string;
        url_status: string;
        date_added: string;
        threat: string;
        tags?: string[];
        report?: {
          country?: string;
        };
      }>;
    };
    if (data.query_status !== 'ok' || !data.urls?.length) return [];
    return data.urls
      .filter((u) => u.url_status === 'online')
      .slice(0, 20)
      .map((u) => {
        const cc = u.report?.country;
        const coords = cc ? COUNTRY_COORDS[cc] : null;
        return {
          id: `urlhaus-${u.id}`,
          kind: 'malware' as const,
          title: u.url.slice(0, 80),
          description: `Malware URL · ${u.threat} · Tags: ${(u.tags ?? []).join(', ') || 'none'}`,
          lat: coords ? coords[0] + (Math.random() - 0.5) * 2 : 0,
          lng: coords ? coords[1] + (Math.random() - 0.5) * 3 : 0,
          timestamp: u.date_added || new Date().toISOString(),
          severity: u.threat === 'malware_download' ? ('critical' as const) : ('high' as const),
          source: 'URLhaus',
          url: u.url,
          country: cc,
        };
      });
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return [];
  }
}

/* ─── Supply Chain Attacks (supplychainattack.org primary, GHSA fallback) ─ */

export async function fetchSupplyChain(env?: GithubEnv): Promise<PulseEvent[]> {
  // PRIMARY: supplychainattack.org incident catalog (npm/PyPI/container/
  // AI-agents). Currently 402-gated; on any failure fall back to the GitHub
  // malware advisory set below. Non-geo (lat/lng 0) — surfaces in the
  // feed/ticker, not the globe. At most two direct fetches.
  try {
    const res = await fetch('https://supplychainattack.org/incidents.json', {
      signal: AbortSignal.timeout(8000),
      headers: { 'user-agent': 'pranithjain-dfir/1.0', accept: 'application/json' },
    });
    if (res.ok) {
      const data = (await res.json()) as {
        incidents?: Array<{
          id?: string;
          title?: string;
          summary?: string;
          status?: string;
          severity?: string;
          ecosystems?: string[];
          disclosedDate?: string;
          url?: string;
          iocs?: { packages?: string[] };
        }>;
      };
      const incidents = Array.isArray(data.incidents) ? data.incidents : [];
      if (incidents.length > 0) {
        const SEV = new Set(['critical', 'high', 'medium', 'low']);
        return incidents.slice(0, 30).map((i, idx) => {
          const sevRaw = typeof i.severity === 'string' ? i.severity.toLowerCase() : '';
          const severity = (SEV.has(sevRaw) ? sevRaw : 'high') as PulseEvent['severity'];
          const eco = Array.isArray(i.ecosystems) ? i.ecosystems.join(', ') : '';
          const pkgs = i.iocs?.packages?.length ?? 0;
          const desc =
            `${eco}${eco && pkgs ? ' · ' : ''}${pkgs ? `${pkgs} package${pkgs === 1 ? '' : 's'}` : ''}${i.status ? ` · ${i.status}` : ''}`.trim() ||
            (typeof i.summary === 'string' ? i.summary.slice(0, 200) : '');
          return {
            id: `sca-${i.id ?? idx}`,
            kind: 'supply_chain_attacks' as const,
            title: (i.title ?? 'Supply-chain incident').slice(0, 140),
            description: desc,
            lat: 0,
            lng: 0,
            timestamp: i.disclosedDate || new Date().toISOString(),
            severity,
            source: 'supplychainattack.org',
            url: typeof i.url === 'string' && /^https?:\/\//.test(i.url) ? i.url : undefined,
            cti: 'other' as const,
          };
        });
      }
    }
  } catch (_catchErr) {
    logError('primary supplychainattack.org failed', _catchErr);
  }
  return fetchSupplyChainGhsaFallback(env);
}

/** FALLBACK: GitHub malware advisories when the primary catalog is down. */
async function fetchSupplyChainGhsaFallback(env?: GithubEnv): Promise<PulseEvent[]> {
  try {
    const res = await fetch(advisoriesUrl({ type: 'malware', per_page: 30, sort: 'published', direction: 'desc' }), {
      signal: AbortSignal.timeout(8000),
      // Authenticated when GITHUB_TOKEN is set: this is the dashboard's
      // only malware-advisory source once supplychainattack.org stays 402-gated,
      // and an anonymous 403 empties the supply-chain card silently.
      headers: githubHeaders(env),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as Array<{
      ghsa_id?: string;
      summary?: string;
      severity?: string;
      html_url?: string;
      published_at?: string;
      vulnerabilities?: Array<{ package?: { ecosystem?: string; name?: string } }>;
    }>;
    const SEV = new Set(['critical', 'high', 'medium', 'low']);
    return (Array.isArray(data) ? data : []).slice(0, 30).map((a, idx) => {
      const sevRaw = typeof a.severity === 'string' ? a.severity.toLowerCase() : '';
      const severity = (SEV.has(sevRaw) ? sevRaw : 'high') as PulseEvent['severity'];
      const vulns = Array.isArray(a.vulnerabilities) ? a.vulnerabilities : [];
      const ecos = [...new Set(vulns.map((v) => v.package?.ecosystem).filter(Boolean))].join(', ');
      const pkgs = [...new Set(vulns.map((v) => v.package?.name).filter(Boolean))];
      const desc =
        `${ecos}${ecos && pkgs.length ? ' · ' : ''}${pkgs.length ? `${pkgs.length} package${pkgs.length === 1 ? '' : 's'}: ${pkgs.slice(0, 3).join(', ')}` : ''}`.trim() ||
        (typeof a.summary === 'string' ? a.summary.slice(0, 200) : '');
      const ghsaId = typeof a.ghsa_id === 'string' ? a.ghsa_id : '';
      const url =
        typeof a.html_url === 'string' && /^https?:\/\//.test(a.html_url)
          ? a.html_url
          : ghsaId
            ? `https://github.com/advisories/${ghsaId}`
            : undefined;
      return {
        id: `sca-${ghsaId || idx}`,
        kind: 'supply_chain_attacks' as const,
        title: (a.summary ?? 'Supply-chain incident').slice(0, 140),
        description: desc,
        lat: 0,
        lng: 0,
        timestamp: a.published_at || new Date().toISOString(),
        severity,
        source: 'GitHub Security Advisories',
        url,
        cti: 'other' as const,
      };
    });
  } catch (_catchErr) {
    logError('handler failed', _catchErr);
    return [];
  }
}
