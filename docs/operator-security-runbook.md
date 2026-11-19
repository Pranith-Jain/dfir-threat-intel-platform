# Operator security actions (residuals from the 2026-11-16 audit)

All code-level fixes from `docs/security-audit-2026-11-16.md` are shipped. The items
below need Cloudflare zone/DNS/secret credentials and cannot be applied from the
repository alone. Status was re-checked live on **2026-11-19**.

## 1. M-1 — TLS 1.0/1.1 still accepted (P0)

**Live evidence:** `openssl s_client -connect pranithjain.qzz.io:443 -tls1_1
-cipher 'DEFAULT:@SECLEVEL=0'` completes a TLSv1.0 handshake with
`ECDHE-RSA-AES128-SHA`.

**Fix (one of):**

- Dashboard: Cloudflare → SSL/TLS → Edge Certificates → **Minimum TLS Version =
  TLS 1.2**, **TLS 1.3 = On**.
- Script (needs a token with **Zone Settings:Edit** on `pranithjain.qzz.io`):

  ```bash
  CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ZONE_NAME=pranithjain.qzz.io \
    ./scripts/fix-tls-min-version.sh
  ```

  The script sets `min_tls_version=1.2`, best-effort enables TLS 1.3, then
  verifies TLS ≤1.1 is rejected. The token is never written to disk or printed.

**Verify:**

```bash
echo | openssl s_client -connect pranithjain.qzz.io:443 -tls1_1 \
  -cipher 'DEFAULT:@SECLEVEL=0' 2>/dev/null | grep 'Protocol'
# expected: handshake failure / no Protocol line
```

## 2. M-3 — rotate the master admin token after the cookie migration

The legacy `localStorage` path is gone (`ExternalResources.tsx` now uses
`createAdminSession()`), so the token is no longer JS-readable. Rotate anyway:

```bash
npx wrangler secret put ADMIN_TOKEN          # from the repo root
npx wrangler secret put ADMIN_TOKEN_VERSION  # bump to invalidate existing admin_session cookies
```

`ADMIN_TOKEN_VERSION` is checked in `api/src/lib/admin-auth.ts:71`; changing it
invalidates every previously issued HttpOnly admin cookie.

## 3. L-1 — submit the HSTS preload list

The response header already advertises `preload` (`max-age=63072000;
includeSubDomains; preload`). Submit `pranithjain.qzz.io` at
<https://hstspreload.org/>; no code change is needed.

## 4. L-2 / L-3 — DNS hardening

In Cloudflare DNS for `pranithjain.qzz.io`:

- Enable **DNSSEC**, then add the DS record at the `qzz.io` delegation.
- Add a **CAA** record, e.g. `0 issue "letsencrypt.org"` (the live cert is Google
  Trust Services, so include `pki.goog` if issuing there).

**Verify:** `dig +dnssec pranithjain.qzz.io` (expect `ad` flag), `dig CAA
pranithjain.qzz.io`.

## 5. L-4 — email authentication

**Live evidence:** SPF `v=spf1 include:_spf.mx.cloudflare.net ~all`;
DMARC `v=DMARC1; p=quarantine; …`.

- Change SPF softfail `~all` → hardfail `-all` once all legitimate senders are
  enumerated (Cloudflare Email Routing is the known sender).
- Move DMARC `p=quarantine` → `p=reject` after reviewing aggregate reports.
- Optional: publish MTA-STS + TLS-RPT records.

**Verify:** `dig +short TXT pranithjain.qzz.io` and `dig +short TXT
_dmarc.pranithjain.qzz.io`.

## 6. Read-only re-check (no credentials needed)

```bash
# TLS floor
echo | openssl s_client -connect pranithjain.qzz.io:443 -tls1_1 \
  -cipher 'DEFAULT:@SECLEVEL=0' 2>/dev/null | grep Protocol

# Email auth
dig +short TXT pranithjain.qzz.io
dig +short TXT _dmarc.pranithjain.qzz.io
dig +dnssec pranithjain.qzz.io | grep -m1 'flags:'

# Security headers
curl -sI https://pranithjain.qzz.io/ | grep -iE 'strict-transport|content-security-policy|cross-origin'
```

## Notes

- The audit document still describes M-3 as open; that section is stale — the
  component now uses the HttpOnly admin session only.
- No code change in this repo can enable TLS 1.2, DNSSEC, CAA, SPF/DMARC or
  HSTS preload submission; those are zone/delegation settings.
