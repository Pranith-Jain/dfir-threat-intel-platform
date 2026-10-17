import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { BackLink } from '../../components/BackLink';
import { Textarea } from '../../components/ui/Input';
import { AlertTriangle, ShieldCheck, Info } from 'lucide-react';
import { errMessage } from '../../lib/log';
interface DecodedJwt {
  raw: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  warnings: string[];
  oks: string[];
  notes: string[];
  error?: string;
}

function b64urlDecode(s: string): string {
  const padded = s
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(s.length + ((4 - (s.length % 4)) % 4), '=');
  try {
    return decodeURIComponent(
      atob(padded)
        .split('')
        .map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('')
    );
  } catch (_catchErr) {
    console.error('b64urlDecode failed:', errMessage(_catchErr));
    return atob(padded);
  }
}

function decode(token: string): DecodedJwt {
  const result: DecodedJwt = { raw: token, header: {}, payload: {}, signature: '', warnings: [], oks: [], notes: [] };
  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    result.error = `Expected 3 dot-separated segments, got ${parts.length}.`;
    return result;
  }
  const [h, p, s] = parts;
  try {
    result.header = JSON.parse(b64urlDecode(h!));
  } catch (e) {
    console.error('decode failed:', errMessage(e));
    result.error = `Header is not valid JSON (${(e as Error).message})`;
    return result;
  }
  try {
    result.payload = JSON.parse(b64urlDecode(p!));
  } catch (e) {
    console.error('decode failed:', errMessage(e));
    result.error = `Payload is not valid JSON (${(e as Error).message})`;
    return result;
  }
  result.signature = s!;

  const alg = String(result.header.alg ?? '').toLowerCase();
  if (alg === 'none' || alg === '') {
    result.warnings.push("Algorithm is 'none'. The token has no signature verification, which is a critical risk.");
  } else if (alg.startsWith('hs')) {
    result.notes.push(`Symmetric algorithm ${alg.toUpperCase()}. Secret strength depends on the issuer.`);
  } else if (alg.startsWith('rs') || alg.startsWith('es') || alg.startsWith('ps')) {
    result.oks.push(`Asymmetric algorithm ${alg.toUpperCase()}.`);
  } else {
    result.warnings.push(`Unknown or non-standard algorithm: ${alg}`);
  }

  if (!result.signature) result.warnings.push('Empty signature segment.');
  else result.notes.push(`Signature length: ${result.signature.length} chars.`);

  const now = Math.floor(Date.now() / 1000);
  const exp = Number(result.payload.exp);
  if (Number.isFinite(exp)) {
    if (exp < now) {
      result.warnings.push(`Expired ${humanDelta(now - exp)} ago (exp = ${new Date(exp * 1000).toISOString()}).`);
    } else {
      result.oks.push(`Valid until ${new Date(exp * 1000).toISOString()} (in ${humanDelta(exp - now)}).`);
    }
  } else {
    result.warnings.push('No "exp" claim, so the token does not expire.');
  }

  const nbf = Number(result.payload.nbf);
  if (Number.isFinite(nbf) && nbf > now) {
    result.warnings.push(`Not yet valid (nbf = ${new Date(nbf * 1000).toISOString()}).`);
  }

  if (!result.payload.iss) result.notes.push('No "iss" claim. Issuer is not stated.');
  if (!result.payload.aud) result.notes.push('No "aud" claim. Audience is not stated.');
  if (!result.payload.sub) result.notes.push('No "sub" claim. Subject is not stated.');
  if (!result.payload.iat) result.notes.push('No "iat" claim. Issued-at is not stated.');

  if (result.header.kid) result.oks.push(`Key ID present: ${result.header.kid}`);
  if (result.header.jku)
    result.warnings.push(`"jku" header present (${result.header.jku}). Verify it is allow-listed by the verifier.`);
  if (result.header.x5u)
    result.warnings.push(`"x5u" header present (${result.header.x5u}). Often a sign of misconfiguration.`);

  return result;
}

function humanDelta(seconds: number): string {
  const abs = Math.abs(seconds);
  if (abs < 60) return `${abs}s`;
  if (abs < 3600) return `${Math.round(abs / 60)}m`;
  if (abs < 86400) return `${Math.round(abs / 3600)}h`;
  return `${Math.round(abs / 86400)}d`;
}

export default function JwtInspect(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialToken = searchParams.get('token') ?? searchParams.get('q') ?? '';
  const [token, setToken] = useState(initialToken);
  const decoded = useMemo<DecodedJwt | null>(() => (token.trim() ? decode(token) : null), [token]);

  // Persist current token into the URL - only when non-empty so the page
  // doesn't drop a stray ?token= behind it.
  useEffect(() => {
    setSearchParams(
      (prev) => {
        const out = new URLSearchParams(prev);
        if (token.trim()) out.set('token', token.trim());
        else {
          out.delete('token');
          out.delete('q');
        }
        return out;
      },
      { replace: true }
    );
  }, [token, setSearchParams]);

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-8 py-12 text-heading">
      <BackLink
        to="/dfir"
        className="inline-flex items-center gap-2 text-sm text-muted hover:text-brand-600 dark:hover:text-brand-400 mb-8 font-mono"
      >
        back
      </BackLink>

      <div className="animate-fade-in-up">
        <h1 className="text-3xl sm:text-4xl font-display font-semibold mb-2">JWT Inspector</h1>
        <p className="text-muted mb-8 max-w-2xl">
          Paste a JSON Web Token. Header and payload are decoded locally; common security weaknesses are flagged.
          Nothing leaves your browser.
        </p>
      </div>

      <label htmlFor="jwt-input" className="sr-only">
        JSON Web Token to decode
      </label>
      <Textarea
        id="jwt-input"
        value={token}
        onChange={(e) => setToken(e.target.value)}
        placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.…"
        rows={5}
        aria-label="JSON Web Token"
        className="break-all"
      />

      {decoded?.error && (
        <p className="mt-6 text-sm font-mono text-rose-600 dark:text-rose-400">parse error: {decoded.error}</p>
      )}

      {decoded && !decoded.error && (
        <div className="mt-8 space-y-6">
          {(decoded.warnings.length > 0 || decoded.oks.length > 0 || decoded.notes.length > 0) && (
            <section className="surface-card p-5 space-y-2">
              {decoded.warnings.map((w) => (
                <div key={w} className="flex items-start gap-2 text-sm text-rose-700 dark:text-rose-400">
                  <AlertTriangle size={14} className="mt-0.5 flex-shrink-0" />
                  <span>{w}</span>
                </div>
              ))}
              {decoded.oks.map((w) => (
                <div key={w} className="flex items-start gap-2 text-sm text-emerald-700 dark:text-emerald-400">
                  <ShieldCheck size={14} className="mt-0.5 flex-shrink-0" />
                  <span>{w}</span>
                </div>
              ))}
              {decoded.notes.map((w) => (
                <div key={w} className="flex items-start gap-2 text-sm text-muted">
                  <Info size={14} className="mt-0.5 flex-shrink-0" />
                  <span>{w}</span>
                </div>
              ))}
            </section>
          )}

          <Section title="Header" json={decoded.header} />
          <Section title="Payload" json={decoded.payload} />
          <section className="surface-card p-5">
            <h3 className="font-display font-semibold mb-3">Signature</h3>
            <pre className="font-mono text-sm break-all text-body">{decoded.signature || '(empty)'}</pre>
          </section>
        </div>
      )}
    </div>
  );
}

function Section({ title, json }: { title: string; json: Record<string, unknown> }): JSX.Element {
  return (
    <section className="surface-card p-5">
      <h3 className="font-display font-semibold mb-3">{title}</h3>
      <pre className="font-mono text-sm text-body overflow-x-auto whitespace-pre-wrap">
        {JSON.stringify(json, null, 2)}
      </pre>
    </section>
  );
}
