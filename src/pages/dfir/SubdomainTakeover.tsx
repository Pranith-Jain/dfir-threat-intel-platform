import { errMessage, logCatch } from '../../lib/log';
import { useState } from 'react';
import { Search, AlertTriangle, CheckCircle, ExternalLink, Loader2, Link2 } from 'lucide-react';
import { BackLink } from '../../components/BackLink';
import { api } from '../../lib/api-client';

interface TakeoverResult {
  subdomain: string;
  cname: string;
  status: 'vulnerable' | 'safe' | 'error';
  provider: string;
  evidence: string;
}

const PROVIDER_DB: Record<string, { name: string; verifyUrl: string }> = {
  'amazonaws.com': {
    name: 'AWS S3/CloudFront',
    verifyUrl: 'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/website-hosting-custom-domain-walkthrough.html',
  },
  'azurewebsites.net': { name: 'Azure App Service', verifyUrl: 'https://learn.microsoft.com/en-us/azure/app-service/' },
  'herokuapp.com': { name: 'Heroku', verifyUrl: 'https://devcenter.heroku.com/articles/custom-domains' },
  'github.io': { name: 'GitHub Pages', verifyUrl: 'https://docs.github.com/en/pages' },
  'bitbucket.io': {
    name: 'Bitbucket Pages',
    verifyUrl: 'https://support.atlassian.com/bitbucket-cloud/docs/publishing-a-website/',
  },
  'shopify.com': { name: 'Shopify', verifyUrl: 'https://shopify.dev/' },
  'squarespace.com': { name: 'Squarespace', verifyUrl: 'https://support.squarespace.com/' },
  'pantheon.io': { name: 'Pantheon', verifyUrl: 'https://pantheon.io/' },
  'surge.sh': { name: 'Surge.sh', verifyUrl: 'https://surge.sh/' },
  'fly.dev': { name: 'Fly.io', verifyUrl: 'https://fly.io/' },
  'vercel.app': { name: 'Vercel', verifyUrl: 'https://vercel.com/' },
  'netlify.app': { name: 'Netlify', verifyUrl: 'https://www.netlify.com/' },
  'fastly.net': { name: 'Fastly', verifyUrl: 'https://www.fastly.com/' },
  'cloudfront.net': { name: 'CloudFront', verifyUrl: 'https://aws.amazon.com/cloudfront/' },
  'firebaseapp.com': { name: 'Firebase', verifyUrl: 'https://firebase.google.com/' },
  'ghost.io': { name: 'Ghost', verifyUrl: 'https://ghost.org/' },
  'helpjuice.com': { name: 'Helpjuice', verifyUrl: 'https://helpjuice.com/' },
  'helpscoutdocs.com': { name: 'Help Scout', verifyUrl: 'https://www.helpscout.com/' },
  'readme.io': { name: 'ReadMe', verifyUrl: 'https://readme.com/' },
  'landingi.com': { name: 'Landingi', verifyUrl: 'https://landingi.com/' },
  'launchrock.com': { name: 'LaunchRock', verifyUrl: 'https://www.launchrock.com/' },
  'mashery.com': { name: 'Mashery', verifyUrl: 'https://www.mashery.com/' },
  'ngrok.io': { name: 'ngrok', verifyUrl: 'https://ngrok.com/' },
  'pingdom.com': { name: 'Pingdom', verifyUrl: 'https://www.pingdom.com/' },
  'proposify.biz': { name: 'Proposify', verifyUrl: 'https://www.proposify.biz/' },
  'simplebooklet.com': { name: 'SimpleBooklet', verifyUrl: 'https://simplebooklet.com/' },
  'smartling.com': { name: 'Smartling', verifyUrl: 'https://www.smartling.com/' },
  'statuspage.io': { name: 'Statuspage', verifyUrl: 'https://www.atlassian.com/software/statuspage' },
  'strikingly.com': { name: 'Strikingly', verifyUrl: 'https://www.strikingly.com/' },
  'stringee.com': { name: 'Stringee', verifyUrl: 'https://stringee.com/' },
  'tave.com': { name: 'Tave', verifyUrl: 'https://www.tave.com/' },
  'thinkific.com': { name: 'Thinkific', verifyUrl: 'https://www.thinkific.com/' },
  'tictail.com': { name: 'Tictail', verifyUrl: 'https://www.tictail.com/' },
  'tumblr.com': { name: 'Tumblr', verifyUrl: 'https://www.tumblr.com/' },
  'uberflip.com': { name: 'Uberflip', verifyUrl: 'https://www.uberflip.com/' },
  'uservoice.com': { name: 'UserVoice', verifyUrl: 'https://www.uservoice.com/' },
  'valuespark.io': { name: 'ValueSpark', verifyUrl: 'https://valuespark.io/' },
  'webflow.com': { name: 'Webflow', verifyUrl: 'https://webflow.com/' },
  'wishpond.com': { name: 'Wishpond', verifyUrl: 'https://www.wishpond.com/' },
  'wordpress.com': { name: 'WordPress.com', verifyUrl: 'https://wordpress.com/' },
  'zendesk.com': { name: 'Zendesk', verifyUrl: 'https://www.zendesk.com/' },
};

function detectProvider(cname: string): string {
  const lower = cname.toLowerCase();
  for (const [pattern, info] of Object.entries(PROVIDER_DB)) {
    if (lower.includes(pattern)) return info.name;
  }
  return 'Unknown';
}

export default function SubdomainTakeover() {
  const [domain, setDomain] = useState('');
  const [results, setResults] = useState<TakeoverResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ctSubdomains, setCtSubdomains] = useState<string[]>([]);

  const handleScan = async () => {
    const d = domain.trim().toLowerCase();
    if (!d) return;
    setLoading(true);
    setError(null);
    setResults([]);
    setCtSubdomains([]);

    try {
      // Phase 1: Enumerate subdomains via cert transparency (crt.sh)
      let subdomains: string[] = [];
      try {
        const ct = await api.get<{ subdomains: string[] }>(`/api/v1/cert-transparency?domain=${encodeURIComponent(d)}`);
        subdomains = ct.subdomains ?? [];
        setCtSubdomains(subdomains);
      } catch (_catchErr) {
        console.error('SubdomainTakeover failed:', errMessage(_catchErr));
        // crt.sh may be slow/down - continue with just the base domain
      }

      // Phase 2: Check CNAMEs for the base domain + discovered subdomains
      const allTargets = [d, ...subdomains.filter((s) => s !== d && s.endsWith(`.${d}`))];
      const newResults: TakeoverResult[] = [];

      // Check base domain first
      const baseData = await api.get<{ records: Record<string, { data: string }[]> }>(
        `/api/v1/dns/lookup?hostname=${d}`
      );
      const baseCnames = (baseData.records?.CNAME ?? []).map((r) => r.data);
      const baseARecords = (baseData.records?.A ?? []).map((r) => r.data);

      if (baseCnames.length === 0 && baseARecords.length > 0) {
        newResults.push({
          subdomain: d,
          cname: 'Direct A record (no CNAME)',
          status: 'safe',
          provider: 'N/A',
          evidence: 'Domain resolves directly - no dangling CNAME',
        });
      } else {
        for (const cname of baseCnames) {
          const provider = detectProvider(cname);
          const isKnownProvider = provider !== 'Unknown';
          newResults.push({
            subdomain: d,
            cname,
            status: isKnownProvider ? 'vulnerable' : 'safe',
            provider,
            evidence: isKnownProvider
              ? `CNAME points to ${provider} - verify claim status`
              : 'CNAME not in known vulnerable provider list',
          });
        }
      }

      // Check discovered subdomains (up to 20 to avoid rate limits)
      const subTargets = allTargets.filter((s) => s !== d).slice(0, 20);
      for (const sub of subTargets) {
        try {
          const subData = await api.get<{ records: Record<string, { data: string }[]> }>(
            `/api/v1/dns/lookup?hostname=${sub}`
          );
          const subCnames = (subData.records?.CNAME ?? []).map((r) => r.data);
          if (subCnames.length === 0) continue; // skip subdomains without CNAMEs

          for (const cname of subCnames) {
            const provider = detectProvider(cname);
            const isKnownProvider = provider !== 'Unknown';
            newResults.push({
              subdomain: sub,
              cname,
              status: isKnownProvider ? 'vulnerable' : 'safe',
              provider,
              evidence: isKnownProvider
                ? `CNAME points to ${provider} - verify claim status`
                : 'CNAME not in known vulnerable provider list',
            });
          }
        } catch (_catchErr) {
          logCatch(_catchErr);
          // skip individual subdomain failures
        }
      }

      setResults(newResults);
    } catch (e) {
      logCatch(e);
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  };

  const vulnerableCount = results.filter((r) => r.status === 'vulnerable').length;

  return (
    <div className="min-h-screen [background:rgb(var(--surface-100))] text-heading">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-6">
        <BackLink to="/dfir">back</BackLink>
        <header className="mb-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-2 h-6 bg-brand-500 rounded" />
            <h1 className="text-lg font-bold tracking-wider text-heading">SUBDOMAIN TAKEOVER SCANNER</h1>
          </div>
          <p className="text-[0.65rem] font-semibold tracking-widest uppercase text-muted">
            Detect dangling CNAMEs pointing to expired or unclaimed third-party services
          </p>
        </header>

        <div className="flex gap-3 mb-6">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
            <input
              type="text"
              placeholder="Enter domain (e.g. example.com)"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              className="w-full pl-9 pr-4 py-2.5 rounded-xl text-sm bg-wash border border-line-1 text-heading placeholder:text-muted dark:placeholder:text-muted focus:outline-none focus:border-brand-500"
            />
          </div>
          <button
            onClick={handleScan}
            disabled={loading || !domain.trim()}
            className="px-5 py-2.5 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-on-fill rounded-xl text-sm font-medium transition-colors"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Scan'}
          </button>
        </div>

        {error && (
          <div className="surface-card p-4 border-red-800 bg-red-900/20 text-red-700 dark:text-red-300 text-sm mb-4">
            {error}
          </div>
        )}

        {results.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center gap-3 text-sm">
              <span className="text-muted">
                {results.length} record{results.length !== 1 ? 's' : ''} checked
              </span>
              {ctSubdomains.length > 0 && (
                <span className="flex items-center gap-1 text-sky-700 dark:text-sky-400 font-medium text-xs">
                  <Link2 className="w-3 h-3" />
                  {ctSubdomains.length} subdomain{ctSubdomains.length !== 1 ? 's' : ''} via crt.sh
                </span>
              )}
              {vulnerableCount > 0 && (
                <span className="flex items-center gap-1 text-red-700 dark:text-red-400 font-medium">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  {vulnerableCount} potential takeover{vulnerableCount !== 1 ? 's' : ''}
                </span>
              )}
              {vulnerableCount === 0 && (
                <span className="flex items-center gap-1 text-green-700 dark:text-green-400 font-medium">
                  <CheckCircle className="w-3.5 h-3.5" />
                  No dangling CNAMEs detected
                </span>
              )}
            </div>

            {results.map((r, i) => (
              <div
                key={i}
                className={`surface-card p-4 border-l-4 ${r.status === 'vulnerable' ? 'border-l-red-500' : 'border-l-green-500'}`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-sm text-heading">{r.subdomain}</span>
                      {r.status === 'vulnerable' && (
                        <span className="px-1.5 py-0.5 text-[0.6rem] font-semibold uppercase rounded bg-red-100 text-red-700 dark:bg-red-900/60 dark:text-red-300">
                          Vulnerable
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-muted mb-1">
                      CNAME: <span className="font-mono text-muted">{r.cname}</span>
                    </p>
                    <p className="text-xs text-muted">
                      Provider: <span className="text-body">{r.provider}</span> - {r.evidence}
                    </p>
                  </div>
                  {r.status === 'vulnerable' && (
                    <a
                      href={`https://${r.subdomain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="shrink-0 p-1.5 text-muted hover:text-body dark:hover:text-inverted transition-colors"
                      title="Test subdomain"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {!loading && results.length === 0 && !error && (
          <div className="surface-card p-8 text-center text-muted text-sm">
            Enter a domain above to scan for dangling CNAME records that may be vulnerable to subdomain takeover.
          </div>
        )}
      </div>
    </div>
  );
}
