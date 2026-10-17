import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../env';
import { pinnedFetchFollow } from '../../api/src/lib/ssrf-guard';
import { errMessage } from '../lib/err';

const MAX_CRAWL_PAGES = 100;
const MAX_JS_ANALYSIS = 50;
const MAX_WS_CONNECTIONS = 5;
const ALARM_INTERVAL_MS = 150;
const DEFAULT_DELAY_MS = 200;
// Upper bound on any single .text() buffer from a crawled/external response.
// The Worker memory limit is 128 MB; a malicious or huge page could OOM the
// isolate before parsing. 5 MB is well above any legitimate HTML/JS/sitemap
// while keeping a hard ceiling. Checked against Content-Length when present
// and enforced by reading the stream with a cap otherwise.
const MAX_FETCH_BYTES = 5_000_000;

/**
 * Read a response body as text with a hard byte ceiling. Guards against
 * unbounded `await res.text()` on crawled/external responses (radar scans
 * arbitrary user-supplied URLs). If Content-Length exceeds the cap the
 * response is rejected without buffering; otherwise the stream is read with
 * a running byte count and truncated/aborted at the cap.
 */
async function fetchTextBounded(res: Response, max = MAX_FETCH_BYTES): Promise<string> {
  const cl = Number(res.headers.get('content-length') ?? 0);
  if (cl && cl > max) {
    throw new Error(`response too large: Content-Length ${cl} > ${max}`);
  }
  // Stream-read with a cap so chunked/unknown-length responses are bounded too.
  const reader = res.body?.getReader();
  if (!reader) return '';
  const decoder = new TextDecoder();
  let received = 0;
  let out = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > max) {
      // Truncate the final chunk to the cap and stop reading.
      const keep = value.subarray(0, max - (received - value.byteLength));
      out += decoder.decode(keep, { stream: false });
      try {
        await reader.cancel();
      } catch {
        /* ignore */
      }
      break;
    }
    out += decoder.decode(value, { stream: true });
  }
  out += decoder.decode();
  return out;
}

interface CrawlState {
  id: string;
  target: string;
  hostname: string;
  status: 'pending' | 'crawling' | 'analyzing' | 'done' | 'error';
  crawledCount: number;
  maxPages: number;
  visited: string[];
  queue: string[];
  scannedUrls: string[];
  apiPaths: string[];
  parameters: string[];
  queryParameters: string[];
  domains: string[];
  emails: string[];
  guids: string[];
  socialMediaUrls: string[];
  fileExtensionUrls: string[];
  filteredPortUrls: string[];
  localhostRefs: string[];
  nodeModules: string[];
  awsAssets: { type: string; url: string; status?: number }[];
  s3Takeovers: string[];
  npmConfusion: string[];
  vulnerabilities: { type: string; detail: string; severity: string }[];
  graphql: { queries: string[]; mutations: string[]; fragments: string[] };
  jsFilesToAnalyze: string[];
  jsAnalysisDone: number;
  error?: string;
  startedAt: string;
  completedAt?: string;
  jsFileUrls: string[];
  robotsDisallow: string[];
  sitemapUrls: string[];
  directoryListings: string[];
  backupFiles: string[];
  debugEndpoints: string[];
  openRedirects: string[];
  sensitiveFiles: string[];
  sourceMaps: string[];
  corsIssues: string[];
  cookieIssues: string[];
  wafDetected: string[];
  jwtTokens: string[];
  htmlComments: string[];
  hiddenForms: string[];
  techHints: string[];
  backupPatterns: string[];
}

export class RadarCrawlerDO extends DurableObject<Env> {
  private sessions = new Set<WebSocket>();
  private ipConnections = new Map<string, number>();

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.headers.get('upgrade') === 'websocket') {
      return this.handleWebSocketUpgrade(request);
    }

    if (url.pathname === '/start' && request.method === 'POST') {
      const body = (await request.json()) as { id: string; target: string; hostname: string };
      const initialState: CrawlState = {
        id: body.id,
        target: body.target,
        hostname: body.hostname,
        status: 'pending',
        crawledCount: 0,
        maxPages: MAX_CRAWL_PAGES,
        visited: [],
        queue: [body.target],
        scannedUrls: [],
        apiPaths: [],
        parameters: [],
        queryParameters: [],
        domains: [],
        emails: [],
        guids: [],
        socialMediaUrls: [],
        fileExtensionUrls: [],
        filteredPortUrls: [],
        localhostRefs: [],
        nodeModules: [],
        awsAssets: [],
        s3Takeovers: [],
        npmConfusion: [],
        vulnerabilities: [],
        graphql: { queries: [], mutations: [], fragments: [] },
        jsFilesToAnalyze: [],
        jsAnalysisDone: 0,
        startedAt: new Date().toISOString(),
        jsFileUrls: [],
        robotsDisallow: [],
        sitemapUrls: [],
        directoryListings: [],
        backupFiles: [],
        debugEndpoints: [],
        openRedirects: [],
        sensitiveFiles: [],
        sourceMaps: [],
        corsIssues: [],
        cookieIssues: [],
        wafDetected: [],
        jwtTokens: [],
        htmlComments: [],
        hiddenForms: [],
        techHints: [],
        backupPatterns: [],
      };
      await this.ctx.storage.put('state', initialState);
      await this.ctx.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
      return Response.json({ ok: true, id: body.id });
    }

    if (url.pathname === '/state') {
      const state = await this.ctx.storage.get<CrawlState>('state');
      return state ? Response.json(state) : Response.json({ error: 'not found' }, { status: 404 });
    }

    if (url.pathname === '/result') {
      const state = await this.ctx.storage.get<CrawlState>('state');
      if (!state) return Response.json({ error: 'not found' }, { status: 404 });
      if (state.status !== 'done') return Response.json({ status: state.status, crawledCount: state.crawledCount });
      return Response.json({
        scannedUrls: state.scannedUrls,
        apiPaths: state.apiPaths,
        parameters: state.parameters,
        queryParameters: state.queryParameters,
        domains: state.domains,
        emails: state.emails,
        guids: state.guids,
        socialMediaUrls: state.socialMediaUrls,
        fileExtensionUrls: state.fileExtensionUrls,
        filteredPortUrls: state.filteredPortUrls,
        localhostRefs: state.localhostRefs,
        nodeModules: state.nodeModules,
        awsAssets: state.awsAssets,
        s3Takeovers: state.s3Takeovers,
        npmConfusion: state.npmConfusion,
        vulnerabilities: state.vulnerabilities,
        graphql: state.graphql,
        robotsDisallow: state.robotsDisallow,
        sitemapUrls: state.sitemapUrls,
        directoryListings: state.directoryListings,
        backupFiles: state.backupFiles,
        debugEndpoints: state.debugEndpoints,
        openRedirects: state.openRedirects,
        sensitiveFiles: state.sensitiveFiles,
        sourceMaps: state.sourceMaps,
        corsIssues: state.corsIssues,
        cookieIssues: state.cookieIssues,
        wafDetected: state.wafDetected,
        jwtTokens: state.jwtTokens,
        htmlComments: state.htmlComments,
        hiddenForms: state.hiddenForms,
        techHints: state.techHints,
        backupPatterns: state.backupPatterns,
      });
    }

    return new Response('not found', { status: 404 });
  }

  private handleWebSocketUpgrade(request: Request): Response {
    if (this.sessions.size >= MAX_WS_CONNECTIONS) {
      return new Response('Too many connections', { status: 429 });
    }
    const clientIp = request.headers.get('cf-connecting-ip') ?? 'unknown';
    const ipCount = this.ipConnections.get(clientIp) ?? 0;
    if (ipCount >= 3) {
      return new Response('Too many connections from this IP', { status: 429 });
    }
    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    this.ctx.acceptWebSocket(server);
    this.sessions.add(server);
    this.ipConnections.set(clientIp, ipCount + 1);
    server.addEventListener('close', () => {
      this.sessions.delete(server);
      const remaining = this.ipConnections.get(clientIp) ?? 1;
      if (remaining <= 1) this.ipConnections.delete(clientIp);
      else this.ipConnections.set(clientIp, remaining - 1);
    });
    return new Response(null, { status: 101, webSocket: client });
  }

  private broadcast(msg: Record<string, unknown>) {
    const data = JSON.stringify(msg);
    for (const ws of this.sessions) {
      try {
        ws.send(data);
      } catch (_catchErr) {
        console.error('handler failed:', errMessage(_catchErr));
        this.sessions.delete(ws);
      }
    }
  }

  override async alarm(): Promise<void> {
    const state = await this.ctx.storage.get<CrawlState>('state');
    if (!state || state.status === 'done' || state.status === 'error') return;

    try {
      if (state.status === 'pending' || state.status === 'crawling') {
        await this.crawlStep(state);
      } else if (state.status === 'analyzing') {
        await this.analyzeJsStep(state);
      }
    } catch (err) {
      console.error('handler failed:', errMessage(err));
      state.status = 'error';
      state.error = errMessage(err);
      await this.ctx.storage.put('state', state);
      this.broadcast({ type: 'error', error: state.error });
      return;
    }

    await this.ctx.storage.put('state', state);

    const finalStatus = state.status as string;
    if (finalStatus === 'done' || finalStatus === 'error') {
      this.broadcast({ type: 'done', state });
    } else {
      await this.ctx.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
    }
  }

  private async crawlStep(state: CrawlState): Promise<void> {
    if (state.queue.length === 0 || state.crawledCount >= state.maxPages) {
      state.status = 'analyzing';
      state.jsFilesToAnalyze = this.extractJsFromVisited(state);
      return;
    }

    // Pre-scan: robots.txt + sitemap.xml on first page
    if (state.crawledCount === 0) {
      await this.fetchRobotsTxt(state);
      await this.fetchSitemap(state);
    }

    const url = state.queue.shift()!;
    if (state.visited.includes(url)) {
      return;
    }

    state.visited.push(url);
    state.status = 'crawling';
    state.crawledCount++;

    this.broadcast({ type: 'progress', crawled: state.crawledCount, max: state.maxPages, current: url });

    try {
      const res = await pinnedFetchFollow(url, {
        headers: {
          'user-agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'accept-language': 'en-US,en;q=0.9',
        },
      });

      const contentType = res.headers.get('content-type') ?? '';
      if (!contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
        return; // non-HTML, skip silently
      }

      const html = await fetchTextBounded(res);
      const respHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        respHeaders[k.toLowerCase()] = v;
      });
      state.scannedUrls.push(url);

      // Extract JS file URLs from script tags
      const scriptRe = /<script[^>]*src=["']([^"']+\.js[^"']*)["'][^>]*>/gi;
      let sm;
      const skipDomains = [
        'cloudflareinsights.com',
        'googletagmanager.com',
        'google-analytics.com',
        'hotjar.com',
        'segment.com',
        'sentry.io',
        'newrelic.com',
        'ampproject.org',
      ];
      while ((sm = scriptRe.exec(html)) !== null) {
        const src = sm[1];
        if (src) {
          try {
            const jsUrl = new URL(src, url).href;
            const host = new URL(jsUrl).hostname;
            const shouldSkip = skipDomains.some((d) => host.includes(d));
            if (!shouldSkip) {
              state.jsFileUrls.push(jsUrl);
            }
          } catch (_catchErr) {
            console.error('handler failed:', errMessage(_catchErr));
            /* skip */
          }
        }
      }

      this.extractLinksForQueue(html, url, state);
      this.extractReconData(html, url, state);
      this.extractAttackSurface(html, url, respHeaders, state);
    } catch (err) {
      console.error('handler failed:', errMessage(err));
      state.error = `crawl fetch failed: ${errMessage(err)}`;
    }

    // Polite delay between requests
    await new Promise((r) => setTimeout(r, DEFAULT_DELAY_MS));
  }

  private async fetchRobotsTxt(state: CrawlState): Promise<void> {
    try {
      const robotsUrl = new URL('/robots.txt', state.target).href;
      const res = await pinnedFetchFollow(robotsUrl, {
        headers: { 'user-agent': 'Mozilla/5.0 (compatible; security-research)' },
      });
      if (!res.ok) return;
      const content = await fetchTextBounded(res);
      state.visited.push(robotsUrl);

      // Extract Disallow paths
      const disallowRe = /Disallow:\s*(.+)/gi;
      let m;
      while ((m = disallowRe.exec(content)) !== null) {
        const path = m[1]?.trim();
        if (path && path !== '/') {
          state.robotsDisallow.push(path);
          try {
            const fullUrl = new URL(path, state.target).href;
            if (!state.visited.includes(fullUrl) && !state.queue.includes(fullUrl)) {
              state.queue.push(fullUrl);
            }
          } catch (_catchErr) {
            console.error('handler failed:', errMessage(_catchErr));
            /* skip */
          }
        }
      }

      // Extract Sitemap references
      const sitemapRe = /Sitemap:\s*(\S+)/gi;
      while ((m = sitemapRe.exec(content)) !== null) {
        const sitemapUrl = m[1];
        if (sitemapUrl) {
          state.sitemapUrls.push(sitemapUrl);
          await this.fetchSitemapContent(sitemapUrl, state);
        }
      }
    } catch (_catchErr) {
      console.error('handler failed:', errMessage(_catchErr));
      /* robots.txt fetch failed, skip */
    }
  }

  private async fetchSitemap(state: CrawlState): Promise<void> {
    try {
      const sitemapUrl = new URL('/sitemap.xml', state.target).href;
      await this.fetchSitemapContent(sitemapUrl, state);
    } catch (_catchErr) {
      console.error('handler failed:', errMessage(_catchErr));
      /* skip */
    }
  }

  private async fetchSitemapContent(sitemapUrl: string, state: CrawlState): Promise<void> {
    try {
      const res = await pinnedFetchFollow(sitemapUrl, {
        headers: { 'user-agent': 'Mozilla/5.0 (compatible; security-research)' },
      });
      if (!res.ok) return;
      const content = await fetchTextBounded(res);
      state.visited.push(sitemapUrl);

      // Extract <loc> URLs
      const locRe = /<loc>\s*(.*?)\s*<\/loc>/gi;
      let m;
      let queued = 0;
      while ((m = locRe.exec(content)) !== null) {
        const locUrl = m[1]?.trim();
        if (!locUrl) continue;
        try {
          const parsed = new URL(locUrl);
          if (parsed.hostname === state.hostname && !state.visited.includes(locUrl) && !state.queue.includes(locUrl)) {
            state.queue.push(locUrl);
            queued++;
          }
        } catch (_catchErr) {
          console.error('handler failed:', errMessage(_catchErr));
          /* skip invalid URLs */
        }
        if (queued >= 200) break;
      }
    } catch (_catchErr) {
      console.error('handler failed:', errMessage(_catchErr));
      /* skip */
    }
  }

  private extractLinksForQueue(html: string, baseUrl: string, state: CrawlState): void {
    const re = /href=["']([^"']+)["']/gi;
    let m;
    while ((m = re.exec(html)) !== null) {
      const raw = m[1];
      if (!raw || raw.startsWith('#') || raw.startsWith('javascript:') || raw.startsWith('mailto:')) continue;
      try {
        const u = new URL(raw, baseUrl);
        if (u.hostname === state.hostname && !state.visited.includes(u.href) && !state.queue.includes(u.href)) {
          const path = u.pathname;
          if (path.match(/\.(jpg|jpeg|png|gif|svg|css|woff|ttf|ico|mp4|mp3|zip|pdf)$/i)) continue;
          state.queue.push(u.href);
        }
      } catch (_catchErr) {
        console.error('handler failed:', errMessage(_catchErr));
        /* skip invalid URLs */
      }
    }
  }

  private extractReconData(html: string, url: string, state: CrawlState): void {
    const emailRe = /(?:mailto:)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi;
    let m;
    while ((m = emailRe.exec(html)) !== null) {
      if (m[1] && !m[1].includes('example.') && !m[1].includes('email@')) {
        state.emails.push(m[1].toLowerCase());
      }
    }

    const guidsRe = /["'=\s]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi;
    while ((m = guidsRe.exec(html)) !== null) {
      if (m[1]) state.guids.push(m[1]);
    }

    const localhostRe = /(?:https?:\/\/)?localhost(?::\d+)?(?:\/[^\s"'<>]*)?/gi;
    while ((m = localhostRe.exec(html)) !== null) {
      if (m[0]) state.localhostRefs.push(m[0]);
    }

    const socialPatterns = [
      /https?:\/\/(?:www\.)?facebook\.com\/[^\s"'<>]+/gi,
      /https?:\/\/(?:www\.)?twitter\.com\/[^\s"'<>]+/gi,
      /https?:\/\/(?:www\.)?x\.com\/[^\s"'<>]+/gi,
      /https?:\/\/(?:www\.)?instagram\.com\/[^\s"'<>]+/gi,
      /https?:\/\/(?:www\.)?linkedin\.com\/[^\s"'<>]+/gi,
      /https?:\/\/(?:www\.)?youtube\.com\/[^\s"'<>]+/gi,
      /https?:\/\/t\.me\/[^\s"'<>]+/gi,
      /https?:\/\/(?:www\.)?github\.com\/[^\s"'<>]+/gi,
    ];
    for (const re of socialPatterns) {
      while ((m = re.exec(html)) !== null) {
        if (m[0]) state.socialMediaUrls.push(m[0].replace(/[.,;:!?)]+$/, ''));
      }
    }

    const fileExtRe =
      /["'](https?:\/\/[^"']+?\.(?:pdf|doc|docx|xls|xlsx|csv|zip|tar\.gz|rar|sql|db|log|conf|env|bak|pem|key|crt))["']/gi;
    while ((m = fileExtRe.exec(html)) !== null) {
      if (m[1]) state.fileExtensionUrls.push(m[1]);
    }

    const portRe = /["'](https?:\/\/[^"'\s<>]*:\d{2,5}[^"'\s<>]*)["']/gi;
    while ((m = portRe.exec(html)) !== null) {
      if (m[1]) state.filteredPortUrls.push(m[1]);
    }

    const paramRe = /[?&](\w+)=/g;
    while ((m = paramRe.exec(html)) !== null) {
      if (m[1] && m[1].length > 1) state.parameters.push(m[1]);
    }

    const urlParamRe = /["'](https?:\/\/[^"'\s<>]+?\?[^"'\s<>]+)["']/gi;
    while ((m = urlParamRe.exec(html)) !== null) {
      const raw = m[1];
      if (!raw) continue;
      try {
        const u = new URL(raw);
        u.searchParams.forEach((_v, k) => state.queryParameters.push(k));
      } catch (_catchErr) {
        console.error('handler failed:', errMessage(_catchErr));
        /* skip */
      }
    }

    const domainRe = /https?:\/\/([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}/gi;
    while ((m = domainRe.exec(html)) !== null) {
      try {
        const u = new URL(m[0]);
        const host = u.hostname.toLowerCase();
        if (host && !host.endsWith(state.hostname) && !host.includes('example.') && !host.includes('email@')) {
          state.domains.push(host);
        }
      } catch (_catchErr) {
        console.error('handler failed:', errMessage(_catchErr));
        /* skip */
      }
    }

    const nodeModRe = /["'](\/node_modules\/[^"']+)["']/gi;
    while ((m = nodeModRe.exec(html)) !== null) {
      if (m[1]) state.nodeModules.push(m[1]);
    }

    const apiPathRe = /["'`](\/api\/v\d+\/[a-zA-Z0-9/_-{}:.]+)["'`]/g;
    while ((m = apiPathRe.exec(html)) !== null) {
      if (m[1]) state.apiPaths.push(m[1]);
    }

    const portUrlRe = /["'](https?:\/\/[^"'\s<>]*:\d{2,5}[^"'\s<>]*)["']/gi;
    while ((m = portUrlRe.exec(html)) !== null) {
      if (m[1]) state.filteredPortUrls.push(m[1]);
    }
  }

  private extractJsFromVisited(state: CrawlState): string[] {
    return [...new Set(state.jsFileUrls)].slice(0, MAX_JS_ANALYSIS);
  }

  private extractAttackSurface(html: string, url: string, headers: Record<string, string>, state: CrawlState): void {
    let m: RegExpExecArray | null;

    // ── Directory listing detection ──
    const dirListPatterns = [
      /<title>Index of \//i,
      /<h1>Index of \//i,
      /Parent Directory<\/a>/i,
      /<pre><a href=.*?>\.\.\/<\/a>/i,
      /Directory listing for/i,
    ];
    for (const re of dirListPatterns) {
      if (re.test(html)) {
        state.directoryListings.push(url);
        break;
      }
    }

    // ── Backup file detection ──
    const backupExts = [
      '.bak',
      '.backup',
      '.old',
      '.orig',
      '.save',
      '.swp',
      '.tmp',
      '.sql',
      '.sql.gz',
      '.dump',
      '.export',
    ];
    const backupNames = [
      'backup.sql',
      'dump.sql',
      'database.sql',
      'backup.zip',
      'backup.tar.gz',
      'site.zip',
      'www.zip',
      'config.php.bak',
      'wp-config.php.bak',
      '.env.backup',
      '.env.old',
      '.env.local',
      '.env.production',
      'credentials.json',
      'secrets.json',
      'service-account.json',
    ];
    const backupRe = new RegExp(
      `href=["']([^"']*(?:${backupExts.map((e) => e.replace(/\./g, '\\.')).join('|')})[^"']*)["']`,
      'gi'
    );
    while ((m = backupRe.exec(html)) !== null) {
      if (m[1]) state.backupFiles.push(new URL(m[1], url).href);
    }
    for (const name of backupNames) {
      if (html.toLowerCase().includes(name)) {
        const nameRe = new RegExp(`["']([^"']*(?:${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})[^"']*)["']`, 'gi');
        const nameMatch = nameRe.exec(html);
        if (nameMatch?.[1]) state.backupPatterns.push(new URL(nameMatch[1], url).href);
      }
    }

    // ── Debug/admin endpoint detection ──
    const debugEndpoints = [
      '/debug',
      '/debug/vars',
      '/debug/pprof',
      '/admin',
      '/adminer.php',
      '/phpinfo.php',
      '/info.php',
      '/.env',
      '/.env.local',
      '/.env.production',
      '/actuator',
      '/actuator/env',
      '/actuator/health',
      '/swagger-ui',
      '/swagger-ui.html',
      '/api-docs',
      '/swagger.json',
      '/graphql',
      '/graphiql',
      '/playground',
      '/console',
      '/manage',
      '/phpmyadmin',
      '/wp-admin',
      '/wp-login.php',
    ];
    for (const ep of debugEndpoints) {
      const escaped = ep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const epRe = new RegExp(`["'][^"']*${escaped}[^"']*["']`, 'i');
      if (epRe.test(html)) {
        state.debugEndpoints.push(new URL(ep, url).href);
      }
    }

    // ── Open redirect detection ──
    const redirectParams = [
      'redirect',
      'redirect_url',
      'redirect_uri',
      'return_url',
      'return_to',
      'next',
      'continue',
      'dest',
      'destination',
      'goto',
      'url',
      'ref',
    ];
    for (const param of redirectParams) {
      const esc = param.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const redirRe = new RegExp(`action=["'][^"']*${esc}[^"']*["']`, 'i');
      if (redirRe.test(html)) {
        state.openRedirects.push(`form:${param} on ${url}`);
      }
      const jsRedirRe = new RegExp(
        `(?:window\\.location|location\\.href|location\\.replace)\\s*[=(]\\s*['"\`][^'"]*${esc}`,
        'i'
      );
      if (jsRedirRe.test(html)) {
        state.openRedirects.push(`js:${param} on ${url}`);
      }
    }

    // ── Sensitive file detection ──
    const sensitivePaths = [
      '/.env',
      '/.git/config',
      '/.git/HEAD',
      '/.htaccess',
      '/.htpasswd',
      '/wp-config.php.bak',
      '/config.php.bak',
      '/database.sql',
      '/backup.sql',
      '/docker-compose.yml',
      '/Dockerfile',
      '/package-lock.json',
      '/.npmrc',
      '/server.key',
      '/server.crt',
      '/.well-known/security.txt',
      '/robots.txt',
      '/sitemap.xml',
      '/swagger.json',
      '/openapi.json',
      '/graphql',
      '/web.config',
    ];
    for (const path of sensitivePaths) {
      if (html.toLowerCase().includes(path)) {
        state.sensitiveFiles.push(`${path} referenced on ${url}`);
      }
    }

    // ── Source map discovery ──
    const sourceMapRe = /\/\/#\s*sourceMappingURL=(\S+)/gi;
    while ((m = sourceMapRe.exec(html)) !== null) {
      const mapUrl = m[1];
      if (mapUrl) {
        try {
          state.sourceMaps.push(mapUrl.startsWith('http') ? mapUrl : new URL(mapUrl, url).href);
        } catch (_catchErr) {
          console.error('handler failed:', errMessage(_catchErr));
          /* skip */
        }
      }
    }
    const mapFileRe = /["']([^"']*\.js\.map)["']/gi;
    while ((m = mapFileRe.exec(html)) !== null) {
      if (m[1]) {
        try {
          state.sourceMaps.push(m[1].startsWith('http') ? m[1] : new URL(m[1], url).href);
        } catch (_catchErr) {
          console.error('handler failed:', errMessage(_catchErr));
          /* skip */
        }
      }
    }

    // ── CORS analysis ──
    const acao = headers['access-control-allow-origin'] ?? '';
    if (acao === '*') {
      state.corsIssues.push(`CORS wildcard on ${url}`);
    } else if (acao) {
      const acac = headers['access-control-allow-credentials'] ?? '';
      if (acac.toLowerCase() === 'true') {
        state.corsIssues.push(`CORS credentials+origin reflection on ${url}: ${acao}`);
      }
    }

    // ── Cookie analysis ──
    const setCookie = headers['set-cookie'] ?? '';
    if (setCookie) {
      const cookies = setCookie.split('\n').filter((c) => c.trim());
      for (const cookie of cookies) {
        const name = cookie.split('=')[0]?.trim() ?? '';
        const lc = cookie.toLowerCase();
        const issues: string[] = [];
        if (!lc.includes('secure')) issues.push('no Secure');
        if (!lc.includes('httponly')) issues.push('no HttpOnly');
        if (!lc.includes('samesite')) issues.push('no SameSite');
        const isSession = ['session', 'sid', 'token', 'auth', 'jwt', 'sess'].some((w) =>
          name.toLowerCase().includes(w)
        );
        if (issues.length > 0 && (isSession || issues.length >= 2)) {
          state.cookieIssues.push(`Cookie ${name}: ${issues.join(', ')} on ${url}`);
        }
      }
    }

    // ── WAF detection ──
    const wafPatterns: [RegExp, string][] = [
      [/cloudflare/i, 'Cloudflare'],
      [/incapsula|imperva/i, 'Incapsula/Imperva'],
      [/akamaighost/i, 'Akamai'],
      [/awselb|aws.*waf/i, 'AWS WAF'],
      [/Sucuri/i, 'Sucuri'],
      [/ModSecurity/i, 'ModSecurity'],
      [/server.*bigip|BIGip/i, 'F5 BIG-IP'],
    ];
    const combined =
      Object.entries(headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n') +
      '\n' +
      html;
    for (const [pattern, name] of wafPatterns) {
      if (pattern.test(combined)) {
        state.wafDetected.push(name);
        break;
      }
    }

    // ── JWT detection ──
    const jwtRe = /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g;
    while ((m = jwtRe.exec(html)) !== null) {
      const token = m[0];
      if (!state.jwtTokens.includes(token)) {
        state.jwtTokens.push(token);
        // Decode header to check alg
        try {
          const parts = token.split('.');
          const headerPad = (parts[0] ?? '') + '='.repeat((4 - ((parts[0]?.length ?? 0) % 4)) % 4);
          const header = JSON.parse(atob(headerPad));
          if (header.alg === 'none') {
            state.vulnerabilities.push({
              type: 'JWT alg=none',
              detail: `JWT with alg=none on ${url} — signature bypass possible`,
              severity: 'critical',
            });
          }
        } catch (_catchErr) {
          console.error('handler failed:', errMessage(_catchErr));
          /* skip */
        }
      }
    }

    // ── HTML comment analysis ──
    const commentRe = /<!--([\s\S]*?)-->/gi;
    const interestingKw = [
      'todo',
      'fixme',
      'hack',
      'password',
      'secret',
      'token',
      'api',
      'admin',
      'debug',
      'internal',
      'staging',
    ];
    while ((m = commentRe.exec(html)) !== null) {
      const comment = m[1]?.trim();
      if (comment && comment.length >= 5) {
        const lower = comment.toLowerCase();
        if (interestingKw.some((kw) => lower.includes(kw))) {
          state.htmlComments.push(`[${url}] ${comment.slice(0, 120)}`);
        }
      }
    }

    // ── Hidden form analysis ──
    if (/type=["']?file["']?/i.test(html)) {
      state.hiddenForms.push(`File upload form on ${url}`);
    }
    if (/name=["'](?:csrf|_token|csrf_token|authenticity_token)["']/i.test(html)) {
      state.hiddenForms.push(`CSRF token on ${url}`);
    }
    const formCount = (html.match(/<form/gi) ?? []).length;
    if (formCount > 3) {
      state.hiddenForms.push(`${formCount} forms on ${url} — test each endpoint`);
    }

    // ── Missing security headers → tech hints ──
    const missingHeaders = [
      'content-security-policy',
      'x-content-type-options',
      'strict-transport-security',
      'x-frame-options',
    ];
    for (const h of missingHeaders) {
      if (!headers[h]) {
        state.techHints.push(`Missing ${h} on ${url}`);
      }
    }

    // ── Information disclosure headers ──
    for (const h of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-debug-token', 'x-generated-by']) {
      if (headers[h]) {
        state.techHints.push(`${h}: ${headers[h]} on ${url}`);
      }
    }

    // ── process.env references ──
    const envRe = /(?:process\.env\.|import\.meta\.env\.)(\w+)/g;
    while ((m = envRe.exec(html)) !== null) {
      if (m[1]) state.techHints.push(`process.env.${m[1]} on ${url}`);
    }

    // ── Subdomain hints from HTML ──
    const targetBase = state.hostname.split('.').slice(-2).join('.');
    const targetBaseLabel = targetBase.split('.')[0] ?? '';
    const subdomainRe = /https?:\/\/([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/gi;
    while ((m = subdomainRe.exec(html)) !== null) {
      try {
        const host = new URL(m[0]).hostname;
        if (
          host !== state.hostname &&
          targetBaseLabel !== '' &&
          host.includes(targetBaseLabel) &&
          host.endsWith(targetBase) &&
          !host.includes('example.com')
        ) {
          if (!state.domains.includes(host)) state.domains.push(host);
        }
      } catch (_catchErr) {
        console.error('handler failed:', errMessage(_catchErr));
        /* skip */
      }
    }
  }

  private async analyzeJsStep(state: CrawlState): Promise<void> {
    if (state.jsAnalysisDone >= state.jsFilesToAnalyze.length) {
      state.status = 'done';
      state.completedAt = new Date().toISOString();
      state.emails = [...new Set(state.emails)];
      state.guids = [...new Set(state.guids)];
      state.localhostRefs = [...new Set(state.localhostRefs)];
      state.socialMediaUrls = [...new Set(state.socialMediaUrls)];
      state.fileExtensionUrls = [...new Set(state.fileExtensionUrls)];
      state.parameters = [...new Set(state.parameters)];
      state.queryParameters = [...new Set(state.queryParameters)];
      state.domains = [...new Set(state.domains)];
      state.apiPaths = [...new Set(state.apiPaths)];
      state.nodeModules = [...new Set(state.nodeModules)];
      state.filteredPortUrls = [...new Set(state.filteredPortUrls)];
      state.robotsDisallow = [...new Set(state.robotsDisallow)];
      state.sitemapUrls = [...new Set(state.sitemapUrls)];
      state.directoryListings = [...new Set(state.directoryListings)];
      state.backupFiles = [...new Set(state.backupFiles)];
      state.backupPatterns = [...new Set(state.backupPatterns)];
      state.debugEndpoints = [...new Set(state.debugEndpoints)];
      state.openRedirects = [...new Set(state.openRedirects)];
      state.sensitiveFiles = [...new Set(state.sensitiveFiles)];
      state.sourceMaps = [...new Set(state.sourceMaps)];
      state.corsIssues = [...new Set(state.corsIssues)];
      state.cookieIssues = [...new Set(state.cookieIssues)];
      state.wafDetected = [...new Set(state.wafDetected)];
      state.jwtTokens = [...new Set(state.jwtTokens)];
      state.htmlComments = [...new Set(state.htmlComments)];
      state.hiddenForms = [...new Set(state.hiddenForms)];
      state.techHints = [...new Set(state.techHints)];
      return;
    }

    state.status = 'analyzing';
    const BATCH_SIZE = 10;
    const batchEnd = Math.min(state.jsAnalysisDone + BATCH_SIZE, state.jsFilesToAnalyze.length);

    for (let i = state.jsAnalysisDone; i < batchEnd; i++) {
      const jsUrl = state.jsFilesToAnalyze[i];
      if (!jsUrl) continue;

      try {
        const res = await pinnedFetchFollow(jsUrl, {
          headers: { 'user-agent': 'Mozilla/5.0', accept: '*/*' },
        });
        const js = await fetchTextBounded(res);
        this.analyzeJsContent(js, jsUrl, state);
      } catch (_catchErr) {
        console.error('handler failed:', errMessage(_catchErr));
        /* skip failed JS */
      }
    }

    state.jsAnalysisDone = batchEnd;
    this.broadcast({ type: 'js_progress', done: state.jsAnalysisDone, total: state.jsFilesToAnalyze.length });
  }

  private analyzeJsContent(js: string, jsUrl: string, state: CrawlState): void {
    let m: RegExpExecArray | null;

    // ── API paths: REST, GraphQL, internal routes ──────────────
    const apiPatterns = [
      // Explicit /api/v1/... paths
      /["'`](\/api\/v\d+\/[a-zA-Z0-9/_-{}:.]+)["'`]/g,
      // /api/... without version
      /["'`](\/api\/[a-zA-Z0-9/_-{}:.]+)["'`]/g,
      // Next.js API routes: pages/api/... or app/api/...
      /["'`](\/(?:pages|app)\/api\/[a-zA-Z0-9/_-{}:.]+)["'`]/g,
      // fetch/axios with path
      /(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*["'`](\/[a-zA-Z0-9/_-{}:.]+)["'`]/g,
      // Route definitions: path: "/..." or route: "/..."
      /(?:path|route|endpoint|url)\s*[:=]\s*["'`](\/[a-zA-Z0-9/_-{}:.]+)["'`]/g,
      // Express-style: app.get("/..."), router.post("/...")
      /(?:app|router)\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*["'`](\/[a-zA-Z0-9/_-{}:.]+)["'`]/g,
      // Hono-style: c.get("/..."), c.post("/...")
      /c\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*["'`](\/[a-zA-Z0-9/_-{}:.]+)["'`]/g,
      // Generic: any quoted path that looks like an endpoint
      /["'`](\/(?:auth|login|register|signup|signin|logout|dashboard|admin|settings|profile|user|users|account|accounts|search|query|webhook|webhooks|callback|redirect|health|status|metrics|monitor|ping|version|docs|swagger|openapi)[a-zA-Z0-9/_-]*)["'`]/g,
      // Mattew: REST API paths with broader patterns
      /["'`](\/(?:api|v[0-9]+|graphql|rest|internal|admin|auth|login|register|logout|upload|download|search|users?|accounts?|settings?|config|health|status|metrics|debug|test)\/[a-zA-Z0-9\/_-]*)["'`]/gi,
      // Config objects: baseUrl, apiUrl, etc.
      /(?:baseUrl|baseURL|apiUrl|apiBase|endpoint|apiEndpoint|API_URL|API_BASE)\s*[=:]\s*["'`]([^"'`]+)["'`]/gi,
      // WordPress REST API
      /["'`](\/wp-json\/[^"'`]+)["'`]/gi,
    ];
    for (const re of apiPatterns) {
      while ((m = re.exec(js)) !== null) {
        const path = m[1];
        if (path && path.length > 2 && !path.match(/\.(js|css|png|jpg|gif|svg|ico|woff|ttf|map)$/)) {
          state.apiPaths.push(path);
        }
      }
    }

    // ── GraphQL: queries, mutations, fragments, subscriptions ──
    const gqlQueryRe = /(?:query|subscription)\s+(\w+)(?:\s*\([^)]*\))?\s*\{/gi;
    while ((m = gqlQueryRe.exec(js)) !== null) {
      if (m[1]) state.graphql.queries.push(m[1]);
    }
    const gqlMutRe = /mutation\s+(\w+)(?:\s*\([^)]*\))?\s*\{/gi;
    while ((m = gqlMutRe.exec(js)) !== null) {
      if (m[1]) state.graphql.mutations.push(m[1]);
    }
    const gqlFragRe = /fragment\s+(\w+)\s+on\s+(\w+)/gi;
    while ((m = gqlFragRe.exec(js)) !== null) {
      if (m[1]) state.graphql.fragments.push(`${m[1]} on ${m[2]}`);
    }
    // GQL endpoint detection
    const gqlEndpointRe = /["'`](\/graphql(?:\/[a-zA-Z0-9/_-]+)?)["'`]/gi;
    while ((m = gqlEndpointRe.exec(js)) !== null) {
      if (m[1]) state.apiPaths.push(m[1]);
    }
    // GraphQL reference detection
    if (/graphql/i.test(js) && !state.apiPaths.some((p) => p.includes('graphql'))) {
      state.apiPaths.push('/graphql');
    }

    // ── Parameters from route handlers and fetch calls ─────────
    const paramPatterns = [
      // req.body.key, req.query.key, req.params.key
      /(?:req|request)\.(?:body|query|params)\.(\w+)/g,
      // params.key, query.key, body.key
      /(?:params|query|body|searchParams)\.(\w+)/g,
      // destructuring: const { id, name } = ...
      /(?:const|let|var)\s*\{([^}]+)\}\s*=/g,
      // TypeScript interface properties (API request/response shapes)
      /(\w+)\s*[?:]\s*(?:string|number|boolean|any)/g,
      // URL search params
      /searchParams\.(?:get|set|append|has)\s*\(\s*["'`](\w+)["'`]/g,
    ];
    for (const re of paramPatterns) {
      while ((m = re.exec(js)) !== null) {
        if (re.source.includes('\\{') && m[1]) {
          // Destructuring: extract individual names
          const names = m[1].split(',').map((n) => n.trim().split(':')[0]?.trim().split('=')[0]?.trim() ?? '');
          for (const name of names) {
            if (
              name &&
              name.length > 1 &&
              name.length < 40 &&
              !name.match(
                /^(const|let|var|function|class|return|import|export|default|if|else|for|while|switch|case|break|continue|new|this|null|undefined|true|false)$/
              )
            ) {
              state.parameters.push(name);
            }
          }
        } else {
          const name = m[1];
          if (name && name.length > 1 && name.length < 40) {
            state.parameters.push(name);
          }
        }
      }
    }

    // ── Secrets detection (enhanced from mattew) ──────────────
    const secretPatterns = [
      // API keys
      { re: /(?:api[_-]?key|apikey)\s*[:=]\s*["'`](sk[_-]?[a-zA-Z0-9]{20,})["'`]/gi, type: 'API Key' },
      { re: /(?:api[_-]?key|apikey)\s*[:=]\s*["'`]([a-zA-Z0-9]{32,})["'`]/gi, type: 'API Key' },
      // Supabase keys
      { re: /(sb_publishable_[a-zA-Z0-9_]{20,})/g, type: 'Supabase Key' },
      {
        re: /(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/g,
        type: 'JWT Token',
      },
      // AWS
      { re: /(?:AKIA[0-9A-Z]{16})/g, type: 'AWS Access Key' },
      // GitHub tokens
      { re: /ghp_[a-zA-Z0-9]{36}/g, type: 'GitHub Token' },
      { re: /gho_[a-zA-Z0-9]{36}/g, type: 'GitHub OAuth Token' },
      { re: /ghu_[a-zA-Z0-9]{36}/g, type: 'GitHub App Token' },
      { re: /ghs_[a-zA-Z0-9]{36}/g, type: 'GitHub App Secret' },
      { re: /ghr_[a-zA-Z0-9]{36}/g, type: 'GitHub Refresh Token' },
      // Slack tokens
      { re: /xox[baprs]-[a-zA-Z0-9-]+/g, type: 'Slack Token' },
      // Stripe keys
      { re: /(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{24,}/g, type: 'Stripe Key' },
      // Google API key
      { re: /AIza[0-9A-Za-z_-]{35}/g, type: 'Google API Key' },
      // GitLab PAT
      { re: /glpat-[a-zA-Z0-9\-]{20,}/g, type: 'GitLab PAT' },
      // Private keys
      { re: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, type: 'Private Key' },
      // Passwords in code
      { re: /(?:password|passwd|pwd)\s*[:=]\s*["'`]([^"'`]{4,})["'`]/gi, type: 'Hardcoded Password' },
      // Secrets
      { re: /(?:secret|client[_-]?secret)\s*[:=]\s*["'`]([^"'`]{8,})["'`]/gi, type: 'Secret' },
      // Connection strings
      { re: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s"'`]+/gi, type: 'Connection String' },
      // Base64 encoded secrets (high entropy)
      { re: /['"`]([A-Za-z0-9+/]{50,}={0,2})['"`]/g, type: 'Base64 Secret' },
    ];
    for (const { re, type } of secretPatterns) {
      while ((m = re.exec(js)) !== null) {
        const value = m[0];
        // Skip low-entropy false positives for base64
        if (type === 'Base64 Secret') {
          const encoded = m[1];
          if (encoded && /^[a-f0-9]+$/.test(encoded)) continue; // hex hash, not a secret
        }
        state.vulnerabilities.push({
          type: 'Exposed Secret',
          detail: `${type} found in ${jsUrl}: ${value.slice(0, 80)}...`,
          severity: 'critical',
        });
      }
    }

    // ── Dangerous JS functions (from mattew) ──────────────────
    const dangerousFns = [
      { re: /eval\s*\(/g, desc: 'eval() call', sev: 'high' },
      { re: /Function\s*\(/g, desc: 'Function constructor', sev: 'high' },
      { re: /document\.write\s*\(/g, desc: 'document.write()', sev: 'medium' },
    ];
    for (const { re, desc, sev } of dangerousFns) {
      if (re.test(js)) {
        state.vulnerabilities.push({
          type: 'Dangerous JS Pattern',
          detail: `${desc} found in ${jsUrl}`,
          severity: sev,
        });
      }
    }

    // ── WebSocket endpoints ────────────────────────────────────
    const wsRe = /["'`](wss?:\/\/[^"']+)["'`]/gi;
    while ((m = wsRe.exec(js)) !== null) {
      if (m[1]) state.apiPaths.push(m[1]);
    }

    // ── External URLs and domains ──────────────────────────────
    const urlRe = /https?:\/\/([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}/gi;
    while ((m = urlRe.exec(js)) !== null) {
      try {
        const u = new URL(m[0]);
        const host = u.hostname.toLowerCase();
        if (
          host &&
          !host.endsWith(state.hostname) &&
          !host.includes('example.') &&
          !host.includes('sentry.io') &&
          !host.includes('cloudflareinsights')
        ) {
          state.domains.push(host);
        }
      } catch (_catchErr) {
        console.error('handler failed:', errMessage(_catchErr));
        /* skip */
      }
    }

    // ── Emails in JS ───────────────────────────────────────────
    const emailRe = /["'`](?:mailto:)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["'`]/gi;
    while ((m = emailRe.exec(js)) !== null) {
      if (m[1] && !m[1].includes('example.') && !m[1].includes('email@') && !m[1].includes('user@')) {
        state.emails.push(m[1].toLowerCase());
      }
    }

    // ── GUIDs in JS ────────────────────────────────────────────
    const guidRe = /["'=\s]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/gi;
    while ((m = guidRe.exec(js)) !== null) {
      if (m[1]) state.guids.push(m[1]);
    }

    // ── File URLs in JS ────────────────────────────────────────
    const fileRe =
      /["'`](https?:\/\/[^"']+?\.(?:pdf|doc|docx|xls|xlsx|csv|zip|tar\.gz|rar|sql|db|log|conf|env|bak|pem|key|crt|json|xml|yaml|yml))["'`]/gi;
    while ((m = fileRe.exec(js)) !== null) {
      if (m[1]) state.fileExtensionUrls.push(m[1]);
    }

    // ── Localhost refs in JS ───────────────────────────────────
    const lhRe = /["'`](https?:\/\/localhost:\d+[^"']*)["'`]/gi;
    while ((m = lhRe.exec(js)) !== null) {
      if (m[1]) state.localhostRefs.push(m[1]);
    }

    // ── Node modules exposure ──────────────────────────────────
    const nmRe = /["'`](\/node_modules\/[^"']+)["'`]/gi;
    while ((m = nmRe.exec(js)) !== null) {
      if (m[1]) state.nodeModules.push(m[1]);
    }

    // ── NPM confusion detection ────────────────────────────────
    if (js.includes('require(') && (js.includes('MODULE_NOT_FOUND') || js.includes('module-not-found'))) {
      state.npmConfusion.push(jsUrl);
    }

    // ── Port URLs ──────────────────────────────────────────────
    const portRe = /["'`](https?:\/\/[^"'`\s]*:\d{2,5}[^"'`\s]*)["'`]/gi;
    while ((m = portRe.exec(js)) !== null) {
      if (m[1]) state.filteredPortUrls.push(m[1]);
    }

    // ── process.env references in JS ───────────────────────────
    const envRe = /(?:process\.env\.|import\.meta\.env\.)(\w+)/g;
    while ((m = envRe.exec(js)) !== null) {
      if (m[1]) state.techHints.push(`process.env.${m[1]} in ${jsUrl}`);
    }
  }
}
