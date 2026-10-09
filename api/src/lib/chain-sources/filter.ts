// timing-audit: accept-reason `token` here is a crypto asset SYMBOL (USDT/BTC)
// from the explorer APIs, lowercased for a case-insensitive user-facing filter.
// It is public on-chain data, not a credential — constant-time comparison would
// be noise. The scanner's check E matches on the identifier name alone.
import type { Transfer, TransferFilter, FetchResult } from './types';

const DEFAULT_MAX = 50;

/**
 * Apply time-window / token / min-amount filtering, then cap. A transfer with a
 * null OR unparseable timestamp is kept when a window is set (we can't prove it's
 * outside the window). `truncated` is true when more transfers matched than the
 * cap allowed.
 */
export function applyFilter(transfers: Transfer[], filter: TransferFilter = {}): FetchResult {
  const parseBound = (s?: string): number | undefined => {
    if (!s) return undefined;
    const ms = Date.parse(s);
    return Number.isNaN(ms) ? undefined : ms;
  };
  const fromMs = parseBound(filter.from);
  const toMs = parseBound(filter.to);
  const tokenLc = filter.token?.toLowerCase();

  const matched = transfers.filter((t) => {
    if (fromMs !== undefined || toMs !== undefined) {
      if (t.timestamp) {
        const ts = Date.parse(t.timestamp);
        if (!Number.isNaN(ts)) {
          if (fromMs !== undefined && ts < fromMs) return false;
          if (toMs !== undefined && ts > toMs) return false;
        }
      }
    }
    if (tokenLc && t.token.toLowerCase() !== tokenLc) return false;
    if (filter.minAmount !== undefined && t.amount_num < filter.minAmount) return false;
    return true;
  });

  const cap = Math.max(0, filter.maxTransfers ?? DEFAULT_MAX);
  return { transfers: matched.slice(0, cap), truncated: matched.length > cap };
}
