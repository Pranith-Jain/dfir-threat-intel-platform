import { errMessage, logCatch } from '../../lib/log';
import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Phone, Search, ExternalLink, Globe, Shield, Users, MapPin, Building2, Wifi } from 'lucide-react';
import { CopyChip } from '../../components/dfir/CopyButton';

interface PhoneLookup {
  service: string;
  url: string;
  category: string;
  description: string;
  free: boolean;
  icon?: string;
}

const CATEGORY_ICONS: Record<string, typeof Globe> = {
  'reverse-lookup': Search,
  carrier: Wifi,
  geolocation: MapPin,
  breach: Shield,
  social: Users,
  business: Building2,
  messaging: Phone,
  directory: Globe,
};

const CATEGORY_LABELS: Record<string, string> = {
  'reverse-lookup': 'Reverse Lookup',
  carrier: 'Carrier Info',
  geolocation: 'Geolocation',
  breach: 'Breach / Leak',
  social: 'Social Media',
  business: 'Business / Corp',
  messaging: 'Messaging Apps',
  directory: 'Directories',
};

function parsePhone(raw: string): { e164: string; digits: string; countryHint: string } | null {
  const cleaned = raw.replace(/[\s\-().]/g, '');
  if (!/^\+?\d{7,15}$/.test(cleaned)) return null;
  const e164 = cleaned.startsWith('+') ? cleaned : `+${cleaned}`;
  const digits = e164.replace(/\D/g, '');
  // rough country hint from leading digits
  let countryHint = '';
  if (digits.startsWith('1')) countryHint = 'US/CA';
  else if (digits.startsWith('44')) countryHint = 'UK';
  else if (digits.startsWith('49')) countryHint = 'DE';
  else if (digits.startsWith('33')) countryHint = 'FR';
  else if (digits.startsWith('81')) countryHint = 'JP';
  else if (digits.startsWith('86')) countryHint = 'CN';
  else if (digits.startsWith('91')) countryHint = 'IN';
  else if (digits.startsWith('61')) countryHint = 'AU';
  else if (digits.startsWith('55')) countryHint = 'BR';
  else if (digits.startsWith('7')) countryHint = 'RU';
  else if (digits.startsWith('82')) countryHint = 'KR';
  else if (digits.startsWith('39')) countryHint = 'IT';
  else if (digits.startsWith('34')) countryHint = 'ES';
  else if (digits.startsWith('31')) countryHint = 'NL';
  else if (digits.startsWith('46')) countryHint = 'SE';
  else if (digits.startsWith('47')) countryHint = 'NO';
  else if (digits.startsWith('45')) countryHint = 'DK';
  else if (digits.startsWith('48')) countryHint = 'PL';
  else if (digits.startsWith('351')) countryHint = 'PT';
  else if (digits.startsWith('352')) countryHint = 'LU';
  else if (digits.startsWith('353')) countryHint = 'IE';
  else if (digits.startsWith('354')) countryHint = 'IS';
  else if (digits.startsWith('358')) countryHint = 'FI';
  else if (digits.startsWith('370')) countryHint = 'LT';
  else if (digits.startsWith('371')) countryHint = 'LV';
  else if (digits.startsWith('372')) countryHint = 'EE';
  return { e164, digits, countryHint };
}

function buildLookups(phone: string): PhoneLookup[] {
  const p = parsePhone(phone);
  if (!p) return [];
  const { e164, digits } = p;
  const international = e164.substring(1);

  return [
    // Reverse Lookups
    {
      service: 'TrueCaller',
      url: `https://www.truecaller.com/search/${digits}`,
      category: 'reverse-lookup',
      description: 'Global caller ID & spam database - name, carrier, spam score',
      free: true,
    },
    {
      service: 'NumLookup',
      url: `https://www.numlookup.com/phone/${international}`,
      category: 'reverse-lookup',
      description: 'Reverse phone lookup - carrier, location, line type',
      free: true,
    },
    {
      service: 'CallerID Test',
      url: `https://calleridtest.com/Phone/${digits}`,
      category: 'reverse-lookup',
      description: 'Caller ID verification and line-type detection',
      free: true,
    },
    {
      service: 'Sync.me',
      url: `https://sync.me/search/?number=${digits}`,
      category: 'reverse-lookup',
      description: 'Caller ID & contact sync service - name & photo lookup',
      free: true,
    },
    {
      service: 'SpyDialer',
      url: `https://www.spydialer.com/default.aspx?r=${digits}`,
      category: 'reverse-lookup',
      description: 'US-focused reverse lookup - name, voicemail, address',
      free: true,
    },
    {
      service: 'WhitePages',
      url: `https://www.whitepages.com/phone/${digits}`,
      category: 'reverse-lookup',
      description: 'US phone directory - name, address, carrier, line type',
      free: true,
    },
    {
      service: 'BeenVerified',
      url: `https://www.beenverified.com/phone/${digits}/`,
      category: 'reverse-lookup',
      description: 'People search - name, address, email, social profiles',
      free: false,
    },
    // Carrier & Line Type
    {
      service: 'NumVerify',
      url: `https://numverify.com/`,
      category: 'carrier',
      description: 'Number validation API - carrier, line type, location, country',
      free: true,
    },
    {
      service: 'Twilio Lookup',
      url: `https://www.twilio.com/lookup`,
      category: 'carrier',
      description: 'Phone number intelligence - carrier, line type, caller name',
      free: false,
    },
    // Geolocation
    {
      service: 'PhoneLocation.io',
      url: `https://www.phonelocation.io/phone/${international}`,
      category: 'geolocation',
      description: 'Phone number geolocation - country, city, coordinates',
      free: true,
    },
    {
      service: 'Map-It (Phone)',
      url: `https://www.mapit.co.uk/results.asp?phone=${digits}`,
      category: 'geolocation',
      description: 'Phone number location on map',
      free: true,
    },
    // Social Media / Messenger
    {
      service: 'WhatsApp Check',
      url: `https://wa.me/${digits}`,
      category: 'messaging',
      description: 'Check if number is on WhatsApp - profile pic & status visible',
      free: true,
    },
    {
      service: 'Telegram Check',
      url: `https://t.me/+${digits}`,
      category: 'messaging',
      description: 'Check if number has a Telegram account',
      free: true,
    },
    {
      service: 'Viber Check',
      url: `viber://add?number=${digits}`,
      category: 'messaging',
      description: 'Check if number is on Viber',
      free: true,
    },
    // Breach / Leak
    {
      service: 'Hudson Rock',
      url: `https://www.hudsonrock.com/free-tools`,
      category: 'breach',
      description: 'Infostealer credential check - search by phone for stealer-log exposure',
      free: true,
    },
    // Google Dorks
    {
      service: 'Google: Phone Dork',
      url: `https://www.google.com/search?q=%22${digits}%22+OR+%22${international}%22`,
      category: 'directory',
      description: 'Broad Google search for the phone number across indexed pages',
      free: true,
    },
    {
      service: 'Google: Site Dork',
      url: `https://www.google.com/search?q=site:linkedin.com+OR+site:facebook.com+OR+site:twitter.com+%22${digits}%22`,
      category: 'social',
      description: 'Search social platforms for the phone number',
      free: true,
    },
    // Business / Corporate
    {
      service: 'LinkedIn Search',
      url: `https://www.google.com/search?q=site:linkedin.com+%22${digits}%22`,
      category: 'business',
      description: 'Search LinkedIn for phone number mentions in profiles/posts',
      free: true,
    },
  ];
}

export default function PhoneOsint(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [input, setInput] = useState(searchParams.get('q') ?? '');
  const [activeCategory, setActiveCategory] = useState<string | null>(null);
  const [apiResult, setApiResult] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const parsed = useMemo(() => parsePhone(input.trim()), [input]);
  const lookups = useMemo(() => buildLookups(input.trim()), [input]);

  const categories = useMemo(() => {
    const cats = new Map<string, number>();
    for (const l of lookups) cats.set(l.category, (cats.get(l.category) ?? 0) + 1);
    return cats;
  }, [lookups]);

  const filtered = useMemo(
    () => (activeCategory ? lookups.filter((l) => l.category === activeCategory) : lookups),
    [lookups, activeCategory]
  );

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const phone = input.trim();
    setSearchParams((prev) => {
      const out = new URLSearchParams(prev);
      if (phone) out.set('q', phone);
      else out.delete('q');
      return out;
    });
    if (!phone || !parsePhone(phone)) return;
    setLoading(true);
    setApiError(null);
    setApiResult(null);
    try {
      const res = await fetch(`/api/v1/phone-osint?phone=${encodeURIComponent(phone)}`);
      if (!res.ok) throw new Error(`API returned ${res.status}`);
      setApiResult(await res.json());
    } catch (err) {
      logCatch(err);
      setApiError(errMessage(err, 'Failed to fetch phone intel'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<Phone size={28} />}
      title="Phone OSINT"
      description={
        <span className="block max-w-3xl">
          Investigate a phone number - reverse lookup, carrier info, geolocation, social/messaging presence, and breach
          exposure. Paste a number in E.164 or local format and hit enter.
        </span>
      }
    >
      {/* Input */}
      <form onSubmit={handleSubmit} className="mb-6">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Phone size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="tel"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="+1 555 123 4567 or 5551234567"
              className="w-full pl-9 pr-4 py-2.5 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-brand-500 dark:focus:border-brand-400"
              aria-label="Phone number"
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
      </form>

      {/* Parsed info */}
      {parsed && (
        <div className="mb-6 surface-card p-4">
          <div className="flex flex-wrap items-center gap-4 text-sm font-mono">
            <div>
              <span className="text-muted">E.164:</span>{' '}
              <span className="text-heading font-semibold">{parsed.e164}</span>
              <CopyChip value={parsed.e164} className="ml-1" />
            </div>
            {parsed.countryHint && (
              <div>
                <span className="text-muted">Country:</span> <span className="text-heading">{parsed.countryHint}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="mb-6 surface-card p-4 text-center">
          <p className="text-sm font-mono text-muted">Investigating phone number...</p>
        </div>
      )}

      {/* API Error */}
      {apiError && (
        <div className="mb-6 rounded-xl border border-amber-500/40 bg-amber-50 dark:bg-amber-950/30 p-4 text-sm font-mono text-amber-700 dark:text-amber-300">
          {apiError}
        </div>
      )}

      {/* API Result - carrier + breach details */}
      {apiResult && (
        <div className="mb-6 surface-card p-4">
          <h3 className="font-display font-semibold text-sm text-heading mb-3">Server-Side Intel</h3>

          {!!apiResult.carrier && (
            <div className="mb-3 pb-3 border-b border-line-1">
              <p className="text-mini font-mono text-muted mb-1">Carrier / Line Type</p>
              <div className="flex flex-wrap gap-3 text-sm font-mono">
                <span className="px-2 py-0.5 rounded bg-brand-500/10 text-brand-700 dark:text-brand-300 border border-brand-500/30">
                  {(apiResult.carrier as Record<string, string>).type}
                </span>
                <span className="text-body">{(apiResult.carrier as Record<string, string>).carrier}</span>
                <span className="text-muted">
                  confidence: {(apiResult.carrier as Record<string, string>).confidence}
                </span>
              </div>
            </div>
          )}

          {!!apiResult.numverify && (
            <div className="mb-3 pb-3 border-b border-line-1">
              <p className="text-mini font-mono text-muted mb-1">NumVerify API</p>
              <div className="grid gap-1 sm:grid-cols-2 text-sm font-mono">
                {Object.entries(apiResult.numverify as Record<string, string>).map(([k, v]) =>
                  v ? (
                    <div key={k}>
                      <span className="text-muted">{k}:</span> <span className="text-heading">{v}</span>
                    </div>
                  ) : null
                )}
              </div>
            </div>
          )}

          {!!apiResult.breach && (
            <div className="mb-3 pb-3 border-b border-line-1">
              <p className="text-mini font-mono text-muted mb-1">Breach Exposure</p>
              <div className="text-sm font-mono">
                {(apiResult.breach as Record<string, string>).checked ? (
                  <span className="text-green-600 dark:text-green-400">Checked via Hudson Rock</span>
                ) : (
                  <span className="text-muted">{(apiResult.breach as Record<string, string>).reason}</span>
                )}
              </div>
            </div>
          )}

          {Array.isArray(apiResult.dorks) && apiResult.dorks.length > 0 && (
            <div className="mt-2">
              <p className="text-mini font-mono text-muted mb-2">Generated Dorks</p>
              <div className="flex flex-wrap gap-1.5">
                {(apiResult.dorks as Array<{ engine: string; query: string; url: string }>).map((d, i) => (
                  <a
                    key={i}
                    href={d.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-mini font-mono px-2 py-0.5 rounded border border-line-2 hover:border-brand-500/40 inline-flex items-center gap-1 transition-colors"
                  >
                    {d.engine}: {d.query.slice(0, 30)}
                    {d.query.length > 30 ? '...' : ''} <ExternalLink size={9} className="opacity-60" />
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Category pills */}
      {categories.size > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 mb-4">
          <span className="text-mini font-mono text-muted mr-1">category:</span>
          {[...categories.entries()].map(([cat, count]) => {
            const Icon = CATEGORY_ICONS[cat] ?? Globe;
            const active = activeCategory === cat;
            return (
              <button
                key={cat}
                type="button"
                onClick={() => setActiveCategory(active ? null : cat)}
                className={`text-mini font-mono px-2 py-1 rounded border transition-colors flex items-center gap-1 ${
                  active
                    ? 'border-brand-500/50 bg-brand-500/10 text-brand-700 dark:text-brand-300'
                    : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-brand-500/40'
                }`}
                aria-pressed={active}
              >
                <Icon size={10} /> {CATEGORY_LABELS[cat] ?? cat} <span className="opacity-70">· {count}</span>
              </button>
            );
          })}
          {activeCategory && (
            <button
              type="button"
              onClick={() => setActiveCategory(null)}
              className="text-mini font-mono px-2 py-1 rounded border border-line-2 text-muted hover:border-brand-500/40 transition-colors"
            >
              clear
            </button>
          )}
        </div>
      )}

      {/* Results */}
      {input.trim() && parsed && (
        <>
          <p className="text-mini font-mono text-muted mb-4">
            {filtered.length} lookup{filtered.length !== 1 ? 's' : ''} available
          </p>
          <ul className="grid gap-3 md:grid-cols-2">
            {filtered.map((l) => {
              const Icon = CATEGORY_ICONS[l.category] ?? Globe;
              return (
                <li key={l.service + l.url} className="surface-card p-4">
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <a
                      href={l.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-display font-semibold text-base text-heading hover:text-brand-600 dark:hover:text-brand-400 inline-flex items-center gap-1 min-w-0 break-words transition-colors"
                    >
                      {l.service} <ExternalLink size={12} className="opacity-60 shrink-0" />
                    </a>
                    <div className="flex items-center gap-1 shrink-0">
                      <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-line-2 text-muted flex items-center gap-1">
                        <Icon size={9} /> {CATEGORY_LABELS[l.category] ?? l.category}
                      </span>
                      {!l.free && (
                        <span className="text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded bg-amber-500/10 text-amber-700 dark:text-amber-300 border border-amber-500/30">
                          paid
                        </span>
                      )}
                    </div>
                  </div>
                  <p className="text-meta font-mono text-muted leading-relaxed break-words">{l.description}</p>
                </li>
              );
            })}
          </ul>
        </>
      )}

      {input.trim() && !parsed && (
        <div className="rounded-xl border border-amber-500/40 bg-amber-50 dark:bg-amber-950/30 p-4 text-sm font-mono text-amber-700 dark:text-amber-300">
          Could not parse phone number. Try E.164 format (e.g. +15551234567) or a plain 7-15 digit number.
        </div>
      )}

      {/* Tips */}
      <div className="mt-8 surface-card p-4">
        <h3 className="font-display font-semibold text-sm text-heading mb-2">Investigation Tips</h3>
        <ul className="text-meta font-mono text-muted space-y-1.5">
          <li>
            <strong>WhatsApp check:</strong> Click the WhatsApp link - if a profile photo appears, the number is active.
            Screenshot it before they change it.
          </li>
          <li>
            <strong>Google dork:</strong> The broad search dork often surfaces old forum posts, leaked databases, or
            LinkedIn profiles mentioning the number.
          </li>
          <li>
            <strong>Carrier info:</strong> NumVerify and Twilio Lookup can tell you if the line is mobile, landline, or
            VoIP - VoIP numbers are often used for scamming.
          </li>
          <li>
            <strong>Breach check:</strong> Infostealer logs frequently contain phone numbers from saved contacts. Hudson
            Rock can surface this exposure.
          </li>
          <li>
            <strong>Multiple formats:</strong> Try different formats (+country code, local format, with/without spaces)
            - some services index differently.
          </li>
        </ul>
      </div>
    </DataPageLayout>
  );
}
