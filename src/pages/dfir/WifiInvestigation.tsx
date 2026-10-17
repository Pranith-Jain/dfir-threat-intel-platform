import { errMessage, logCatch } from '../../lib/log';
import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Wifi, Search, ExternalLink, Globe, Radio, AlertTriangle, CheckCircle } from 'lucide-react';

const MAC_REGEX = /^([0-9A-Fa-f]{2}[:\-\.]){5}[0-9A-Fa-f]{2}$/;

function detectInputType(value: string): 'bssid' | 'ssid' | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  return MAC_REGEX.test(trimmed) ? 'bssid' : 'ssid';
}

function formatMac(raw: string): string {
  return raw.replace(/[:-]/g, ':').toUpperCase();
}

function buildWifiLookups(
  type: 'bssid' | 'ssid',
  value: string
): { service: string; url: string; description: string; category: string }[] {
  const lookups: { service: string; url: string; description: string; category: string }[] = [];

  if (type === 'bssid') {
    const mac = formatMac(value);
    lookups.push(
      {
        service: 'WiGLE.net',
        url: `https://wigle.net/search?query=${encodeURIComponent(mac)}`,
        description: 'Wireless network mapping - location, SSID history, signal strength',
        category: 'wireless',
      },
      {
        service: 'MAC Vendor Lookup',
        url: `https://macvendors.io/${mac}`,
        description: 'Identify hardware manufacturer from OUI prefix',
        category: 'vendor',
      },
      {
        service: 'MACVendors.com',
        url: `https://macvendors.com/${mac}`,
        description: 'Alternative MAC vendor lookup with detailed vendor info',
        category: 'vendor',
      },
      {
        service: 'Google',
        url: `https://www.google.com/search?q=%22${encodeURIComponent(mac)}%22`,
        description: 'Broad search for the BSSID across indexed pages',
        category: 'search',
      },
      {
        service: 'Censys',
        url: `https://search.censys.io/search?resource=hosts&q=${encodeURIComponent(mac)}`,
        description: 'Internet-wide scan data - check for exposed services on this MAC',
        category: 'search',
      },
      {
        service: 'Shodan',
        url: `https://www.shodan.io/search?query=${encodeURIComponent(mac)}`,
        description: 'IoT device search engine - look for the BSSID in device databases',
        category: 'search',
      }
    );
  } else {
    const ssid = value.trim();
    lookups.push(
      {
        service: 'WiGLE.net',
        url: `https://wigle.net/search?query=${encodeURIComponent(ssid)}`,
        description: 'Search for SSID across global wireless networks',
        category: 'wireless',
      },
      {
        service: 'Google',
        url: `https://www.google.com/search?q=%22${encodeURIComponent(ssid)}%22+wifi`,
        description: 'Search for the SSID across the web',
        category: 'search',
      },
      {
        service: 'Wi-Fi Alliance',
        url: `https://www.wi-fi.org/discover-wi-fi`,
        description: 'Official Wi-Fi Alliance resources',
        category: 'wireless',
      },
      {
        service: 'Router Default Passwords',
        url: `https://www.routerpasswords.com/`,
        description: 'Check common default passwords for this SSID/model',
        category: 'security',
      }
    );
  }

  return lookups;
}

interface SecurityFlag {
  type: 'danger' | 'warning' | 'info';
  label: string;
  description: string;
}

function analyzeSecurityFlags(type: 'bssid' | 'ssid', value: string): SecurityFlag[] {
  const flags: SecurityFlag[] = [];

  if (type === 'bssid') {
    const mac = formatMac(value);
    const firstByte = parseInt(mac.substring(0, 2), 16);
    if (firstByte & 0x02) {
      flags.push({
        type: 'info',
        label: 'Locally Administered',
        description:
          'Bit 1 of first octet is set - this MAC was manually assigned or randomized, not from the manufacturer.',
      });
    }
    if (firstByte & 0x01) {
      flags.push({
        type: 'info',
        label: 'Multicast',
        description: 'Bit 0 of first octet is set - this is a multicast address, not assigned to a single device.',
      });
    }
    if (/^(AA:BB:CC|00:00:00|FF:FF:FF)/i.test(mac)) {
      flags.push({
        type: 'warning',
        label: 'Suspicious OUI',
        description: 'This OUI prefix is commonly used for spoofed or test MAC addresses.',
      });
    }
  }

  if (type === 'ssid') {
    const ssid = value.trim();
    if (/^(linksys|netgear|dlink|tp-link|tplink|belkin|asus|cisco)/i.test(ssid)) {
      flags.push({
        type: 'warning',
        label: 'Default SSID Pattern',
        description: 'SSID starts with a common router brand name - may be using default configuration.',
      });
    }
    if (/^(mywifi|wifi|network|internet|home|admin)/i.test(ssid)) {
      flags.push({
        type: 'warning',
        label: 'Generic SSID',
        description: 'SSID is generic and could be a honeypot or rogue access point impersonating a default network.',
      });
    }
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/i.test(ssid)) {
      flags.push({
        type: 'danger',
        label: 'IP-Like SSID',
        description:
          'SSID looks like an IP address - this is highly unusual and may indicate a captive portal or attack.',
      });
    }
    if (ssid.length > 32) {
      flags.push({
        type: 'info',
        label: 'Long SSID',
        description: 'SSID exceeds 32 characters - some devices may not display or connect to this network properly.',
      });
    }
  }

  return flags;
}

export default function WifiInvestigation(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [input, setInput] = useState(searchParams.get('q') ?? '');
  const [result, setResult] = useState<{ type: 'bssid' | 'ssid'; value: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [apiResult, setApiResult] = useState<Record<string, unknown> | null>(null);

  const inputType = useMemo(() => detectInputType(input), [input]);
  const lookups = useMemo(() => (result ? buildWifiLookups(result.type, result.value) : []), [result]);
  const securityFlags = useMemo(() => (result ? analyzeSecurityFlags(result.type, result.value) : []), [result]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = input.trim();
    if (!trimmed) return;

    const type = detectInputType(trimmed);
    if (!type) return;

    setSearchParams((prev) => {
      const out = new URLSearchParams(prev);
      out.set('q', trimmed);
      return out;
    });

    setResult({ type, value: trimmed });
    setLoading(true);
    setApiError(null);
    setApiResult(null);

    try {
      const param =
        type === 'bssid' ? `bssid=${encodeURIComponent(formatMac(trimmed))}` : `ssid=${encodeURIComponent(trimmed)}`;
      const res = await fetch(`/api/v1/wifi-investigation?${param}`);
      if (!res.ok) throw new Error(`API returned ${res.status}`);
      const data = await res.json();
      setApiResult(data);
    } catch (err) {
      logCatch(err);
      setApiError(errMessage(err, 'Failed to fetch investigation data'));
    } finally {
      setLoading(false);
    }
  };

  const FLAG_ICONS: Record<string, typeof AlertTriangle> = {
    danger: AlertTriangle,
    warning: AlertTriangle,
    info: CheckCircle,
  };

  const FLAG_STYLES: Record<string, string> = {
    danger: 'border-red-500/40 bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300',
    warning: 'border-amber-500/40 bg-amber-50 dark:bg-amber-950/30 text-amber-700 dark:text-amber-300',
    info: 'border-line-1 bg-slate-50 dark:bg-surface-200 text-body',
  };

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Wifi size={28} />}
      title="Wi-Fi / BSSID Investigation"
      description={
        <span className="block max-w-3xl">
          Investigate a wireless network - BSSID vendor lookup, SSID analysis, security flags, and investigation
          resources. Enter a MAC address (BSSID) or network name (SSID) and hit enter.
        </span>
      }
    >
      <form onSubmit={handleSubmit} className="mb-6">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Wifi size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="AA:BB:CC:DD:EE:FF or MyWiFiNetwork"
              className="w-full pl-9 pr-4 py-2.5 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
              aria-label="BSSID or SSID"
            />
          </div>
          <button
            aria-label="Search"
            type="submit"
            disabled={!input.trim()}
            className="px-4 py-2.5 bg-brand-600 dark:bg-brand-500 text-on-fill rounded font-mono text-sm font-semibold hover:bg-brand-700 dark:hover:bg-brand-400 disabled:opacity-40 transition-colors"
          >
            <Search size={16} />
          </button>
        </div>
        {input.trim() && inputType && (
          <p className="text-mini font-mono text-muted mt-2">
            Detected as:{' '}
            <span className="text-body">{inputType === 'bssid' ? 'BSSID (MAC address)' : 'SSID (network name)'}</span>
          </p>
        )}
        {input.trim() && !inputType && (
          <p className="text-mini font-mono text-amber-500 mt-2">
            Could not detect input type - enter a MAC address (AA:BB:CC:DD:EE:FF) or network name
          </p>
        )}
      </form>

      {result && result.type === 'bssid' && (
        <div className="mb-6 surface-card p-4">
          <h3 className="font-display font-semibold text-sm text-heading mb-3 flex items-center gap-2">
            <Radio size={14} /> MAC Address Analysis
          </h3>
          <div className="grid gap-3 sm:grid-cols-2 font-mono text-sm">
            <div>
              <span className="text-muted">BSSID:</span>{' '}
              <span className="text-heading font-semibold">{formatMac(result.value)}</span>
            </div>
            <div>
              <span className="text-muted">OUI Prefix:</span>{' '}
              <span className="text-heading">{formatMac(result.value).substring(0, 8)}</span>
            </div>
            <div>
              <span className="text-muted">First Octet:</span>{' '}
              <span className="text-heading">{formatMac(result.value).substring(0, 2)}</span>
              <span className="text-muted ml-2">
                (
                {parseInt(formatMac(result.value).substring(0, 2), 16) & 0x02
                  ? 'locally administered'
                  : 'globally unique'}
                ,{parseInt(formatMac(result.value).substring(0, 2), 16) & 0x01 ? ' multicast' : ' unicast'})
              </span>
            </div>
            <div>
              <span className="text-muted">Format:</span>{' '}
              <span className="text-heading">Colon-separated, uppercase</span>
            </div>
          </div>
          {!!apiResult?.mac && (
            <div className="mt-3 pt-3 border-t border-line-1">
              <p className="text-mini font-mono text-muted mb-2">Server Vendor Lookup:</p>
              <div className="grid gap-2 sm:grid-cols-2 font-mono text-sm">
                <div>
                  <span className="text-muted">Vendor:</span>{' '}
                  <span className="text-heading font-semibold">
                    {(apiResult.mac as Record<string, unknown>).vendor as string}
                  </span>
                </div>
                <div>
                  <span className="text-muted">OUI:</span>{' '}
                  <span className="text-heading">{(apiResult.mac as Record<string, unknown>).oui as string}</span>
                </div>
              </div>
            </div>
          )}
          {Array.isArray(apiResult?.lookups) && (
            <div className="mt-3 pt-3 border-t border-line-1">
              <p className="text-mini font-mono text-muted mb-2">Server Lookups:</p>
              <div className="flex flex-wrap gap-2">
                {(apiResult.lookups as Array<{ service: string; url: string }>).map((l) => (
                  <a
                    key={l.service + l.url}
                    href={l.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-mini font-mono px-2 py-1 rounded border border-line-2 hover:border-brand-500/40 inline-flex items-center gap-1 transition-colors"
                  >
                    {l.service} <ExternalLink size={9} className="opacity-60" />
                  </a>
                ))}
              </div>
            </div>
          )}
          {Array.isArray(apiResult?.flags) && apiResult.flags.length > 0 && (
            <div className="mt-3 pt-3 border-t border-line-1">
              <p className="text-mini font-mono text-muted mb-2">Server Flags:</p>
              <ul className="text-meta font-mono text-muted space-y-1">
                {(apiResult.flags as string[]).map((f, i) => (
                  <li key={i}>- {f}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {result && result.type === 'ssid' && (
        <div className="mb-6 surface-card p-4">
          <h3 className="font-display font-semibold text-sm text-heading mb-3 flex items-center gap-2">
            <Radio size={14} /> SSID Analysis
          </h3>
          <div className="font-mono text-sm">
            <div>
              <span className="text-muted">Network Name:</span>{' '}
              <span className="text-heading font-semibold">{result.value}</span>
            </div>
            <div className="mt-2">
              <span className="text-muted">Length:</span>{' '}
              <span className="text-heading">{result.value.length} characters</span>
            </div>
          </div>
          {Array.isArray(apiResult?.lookups) && (
            <div className="mt-3 pt-3 border-t border-line-1">
              <p className="text-mini font-mono text-muted mb-2">Server Lookups:</p>
              <div className="flex flex-wrap gap-2">
                {(apiResult.lookups as Array<{ service: string; url: string }>).map((l) => (
                  <a
                    key={l.service + l.url}
                    href={l.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-mini font-mono px-2 py-1 rounded border border-line-2 hover:border-brand-500/40 inline-flex items-center gap-1 transition-colors"
                  >
                    {l.service} <ExternalLink size={9} className="opacity-60" />
                  </a>
                ))}
              </div>
            </div>
          )}
          {Array.isArray(apiResult?.flags) && apiResult.flags.length > 0 && (
            <div className="mt-3 pt-3 border-t border-line-1">
              <p className="text-mini font-mono text-muted mb-2">Server Flags:</p>
              <ul className="text-meta font-mono text-muted space-y-1">
                {(apiResult.flags as string[]).map((f, i) => (
                  <li key={i}>- {f}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {loading && (
        <div className="mb-6 surface-card p-4 text-center">
          <p className="text-sm font-mono text-muted">Investigating...</p>
        </div>
      )}

      {apiError && (
        <div className="mb-6 rounded-xl border border-amber-500/40 bg-amber-50 dark:bg-amber-950/30 p-4 text-sm font-mono text-amber-700 dark:text-amber-300">
          {apiError}
        </div>
      )}

      {securityFlags.length > 0 && (
        <div className="mb-6 space-y-2">
          <h3 className="font-display font-semibold text-sm text-heading mb-2">Security Flags</h3>
          {securityFlags.map((flag) => {
            const Icon = FLAG_ICONS[flag.type] ?? AlertTriangle;
            return (
              <div
                key={flag.label}
                className={`rounded-xl border p-3 flex items-start gap-3 text-sm font-mono ${FLAG_STYLES[flag.type]}`}
              >
                <Icon size={14} className="mt-0.5 shrink-0" />
                <div>
                  <span className="font-semibold">{flag.label}</span>
                  <p className="text-xs mt-0.5 opacity-80">{flag.description}</p>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {lookups.length > 0 && (
        <div className="mb-6">
          <h3 className="font-display font-semibold text-sm text-heading mb-3">Lookup Links</h3>
          <ul className="grid gap-3 md:grid-cols-2">
            {lookups.map((l) => (
              <li key={l.service + l.url} className="surface-card p-4">
                <a
                  href={l.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-display font-semibold text-base text-heading hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1 min-w-0 break-words transition-colors"
                >
                  {l.service} <ExternalLink size={12} className="opacity-60 shrink-0" />
                </a>
                <p className="text-meta font-mono text-muted leading-relaxed break-words mt-1">{l.description}</p>
                <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-line-2 text-muted mt-2 inline-flex items-center gap-1">
                  <Globe size={9} /> {l.category}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-8 surface-card p-4">
        <h3 className="font-display font-semibold text-sm text-heading mb-2">Investigation Tips</h3>
        <ul className="text-meta font-mono text-muted space-y-1.5">
          <li>
            <strong>BSSID to location:</strong> WiGLE.net maintains a global database of wireless access points - a
            BSSID search often returns GPS coordinates, SSID history, and first/last seen dates.
          </li>
          <li>
            <strong>Vendor identification:</strong> The first 3 octets (OUI) of a MAC address identify the manufacturer.
            Use this to narrow down the device type - AP, router, IoT device, or phone hotspot.
          </li>
          <li>
            <strong>Locally administered bit:</strong> If bit 1 of the first octet is set, the MAC was manually set or
            randomized - common for privacy features but also used by attackers to spoof APs.
          </li>
          <li>
            <strong>Rogue AP detection:</strong> Look for duplicate SSIDs with different BSSIDs, or known brand SSIDs
            with unexpected OUI vendors - these may indicate evil twin attacks.
          </li>
          <li>
            <strong>SSID default check:</strong> If the SSID matches a router brand default (e.g., "NETGEARXX",
            "Linksys"), the network may be using factory credentials - check router default passwords.
          </li>
          <li>
            <strong>Cross-reference:</strong> Combine BSSID and SSID data - if a known BSSID is broadcasting an
            unexpected SSID, the device may have been reconfigured or compromised.
          </li>
        </ul>
      </div>
    </DataPageLayout>
  );
}
