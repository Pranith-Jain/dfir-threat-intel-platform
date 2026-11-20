/**
 * si-analyst MCP tool registrations.
 *
 * Moved verbatim out of `DfirMcpServer.init()` in worker/mcp-server.ts.
 * `h` is the McpAgent instance typed as McpToolHost, so the bodies below
 * are unchanged: `h.tools(...)`, `h.env.*` and `h.apiKey` resolve
 * against that host at call time.
 */

import { siParseText } from '../lib/si-parse';
import type { ArtifactKind } from '../lib/si-parse';
import { siHyposGenerate } from '../lib/si-hypos';
import { siParseEmailHeaders } from '../lib/si-mailscope';
import { untrustedToolResult } from './core';
import { z } from 'zod';

import type { McpToolHost } from './host';

// ── imports restored after the mcp-server split ──────────────
// The tool bodies below were moved out of DfirMcpServer.init()
// without carrying these dependencies, which left 221 dangling
// names. esbuild does not typecheck free variables, so the Worker
// still bundled and deployed while every tool that touched one threw
// ReferenceError at call time. Fixed alongside the tsc (worker) gate.
import { shiftlogClose, shiftlogCreate, shiftlogGet, shiftlogList, shiftlogUpdate } from '../lib/si-shiftlog';
import type { UpdateShiftLogInput } from '../lib/si-shiftlog';
export function registerSiAnalystTools(h: McpToolHost): void {
  // ── si_parse_text (PARSE-X) ─────────────────────────────────────────
  h.tools(
    'si_parse_text',
    'PARSE-X: extract IOCs, file paths, registry keys, processes, DLLs, CVEs, MITRE techniques, hashes, emails, ports, MACs, and ASNs from raw text. Handles defang (hxxp, [.], (dot)) and Cyrillic/Greek homographs.',
    {
      text: z.string().describe('Raw text — incident report, SIEM alert, log lines, email body, etc.'),
      refang: z.boolean().optional().describe('Apply iterative refang to defanged indicators. Default: true.'),
      fold_homographs: z.boolean().optional().describe('Fold Cyrillic/Greek lookalikes to ASCII. Default: true.'),
      max_chars: z
        .number()
        .int()
        .positive()
        .max(5_000_000)
        .optional()
        .describe('Cap input size in chars. Default: 1,000,000.'),
      kinds: z
        .array(z.string())
        .optional()
        .describe('Only return these artifact kinds (ipv4, domain, sha256, cve, mitre, etc.).'),
    },
    async ({ text, refang, fold_homographs, max_chars, kinds }) => {
      const result = siParseText(text, {
        refang: refang ?? true,
        foldHomographs: fold_homographs ?? true,
        maxChars: max_chars ?? 1_000_000,
        kinds: kinds as ArtifactKind[] | undefined,
      });
      return untrustedToolResult(result);
    }
  );

  // ── si_parse_email_headers (MAILSCOPE) ──────────────────────────────
  h.tools(
    'si_parse_email_headers',
    'MAILSCOPE: parse raw email headers, extract the Received hop chain, compute SPF/DKIM/DMARC verdicts, and flag spoofing/impersonation patterns. Returns a 0-100 risk score.',
    {
      headers: z.string().describe('Raw email headers, or a full RFC 822 message (body will be stripped).'),
      max_chars: z
        .number()
        .int()
        .positive()
        .max(5_000_000)
        .optional()
        .describe('Cap input size in chars. Default: 1,000,000.'),
    },
    async ({ headers, max_chars }) => {
      const result = siParseEmailHeaders(headers, { maxChars: max_chars ?? 1_000_000 });
      return untrustedToolResult(result);
    }
  );

  // ── si_shiftlog_* (SHIFTLOG) ────────────────────────────────────────
  h.tools(
    'si_shiftlog_create',
    'SHIFTLOG: start a new SOC shift handover entry. Returns the created entry including its id (sl_...).',
    {
      shift: z.enum(['morning', 'afternoon', 'night', 'weekend', 'oncall']).describe('Shift type.'),
      author: z.string().describe('Analyst handle (≤64 chars).'),
      started_at: z.string().optional().describe('ISO timestamp. Default: now.'),
      open_cases: z.array(z.string()).optional().describe('Case ids open at the start of the shift.'),
      iocs: z.array(z.string()).optional().describe('IOC strings to flag.'),
      escalations: z.array(z.string()).optional().describe('Escalation targets / ticket ids.'),
      notes: z.string().optional().describe('Free-form notes (≤8000 chars).'),
    },
    async (input) => {
      const entry = await shiftlogCreate(h.env, {
        shift: input.shift,
        author: input.author,
        startedAt: input.started_at,
        openCases: input.open_cases,
        iocs: input.iocs,
        escalations: input.escalations,
        notes: input.notes,
      });
      return untrustedToolResult(entry);
    }
  );
  h.tools(
    'si_shiftlog_list',
    'SHIFTLOG: list recent shift handover entries. Filter by author, shift, or openOnly (excludes closed shifts).',
    {
      author: z.string().optional(),
      shift: z.enum(['morning', 'afternoon', 'night', 'weekend', 'oncall']).optional(),
      open_only: z.boolean().optional(),
      limit: z.number().int().min(1).max(100).optional(),
    },
    async (input) => {
      const list = await shiftlogList(h.env, {
        author: input.author,
        shift: input.shift,
        openOnly: input.open_only,
        limit: input.limit,
      });
      return untrustedToolResult(list);
    }
  );
  h.tools(
    'si_shiftlog_get',
    'SHIFTLOG: fetch a single shift handover entry by id (sl_...).',
    { id: z.string().describe('The sl_... id returned by si_shiftlog_create.') },
    async ({ id }) => {
      const e = await shiftlogGet(h.env, id);
      return untrustedToolResult(e);
    }
  );
  h.tools(
    'si_shiftlog_update',
    'SHIFTLOG: patch a shift entry (notes, open cases, IOCs, escalations, endedAt).',
    {
      id: z.string(),
      open_cases: z.array(z.string()).optional(),
      iocs: z.array(z.string()).optional(),
      escalations: z.array(z.string()).optional(),
      notes: z.string().optional(),
      ended_at: z.string().nullable().optional(),
    },
    async ({ id, ...patch }) => {
      const e = await shiftlogUpdate(h.env, id, patch as UpdateShiftLogInput);
      return untrustedToolResult(e);
    }
  );
  h.tools(
    'si_shiftlog_close',
    'SHIFTLOG: close a shift entry (sets ended_at to now, or to a provided ISO timestamp).',
    { id: z.string(), ended_at: z.string().optional() },
    async ({ id, ended_at }) => {
      const e = await shiftlogClose(h.env, id, ended_at);
      return untrustedToolResult(e);
    }
  );

  // ── si_hypos_generate (HYPOS) ───────────────────────────────────────
  h.tools(
    'si_hypos_generate',
    'HYPOS: hypothesis engine for threat hunting. Given a free-text anomaly description and optional IOCs / environment, return ranked hypotheses with kill-chain phase, MITRE techniques, what-to-look-for signals, sample KQL, and matched SI skills.',
    {
      text: z
        .string()
        .describe('Free-text description of the anomaly (alert name, observed behaviour, user report, etc.).'),
      iocs: z.array(z.string()).optional().describe('Optional IOCs to bias scoring.'),
      environment: z.enum(['endpoint', 'identity', 'cloud', 'network', 'email', 'saas', 'unknown']).optional(),
      top_n: z.number().int().min(1).max(10).optional().describe('Number of hypotheses to return. Default: 5.'),
      include_skills: z.boolean().optional().describe('Also return matched SI skill slugs. Default: true.'),
    },
    async (input) => {
      const r = await siHyposGenerate(
        {
          text: input.text,
          iocs: input.iocs,
          environment: input.environment,
          topN: input.top_n,
          includeSkills: input.include_skills,
        },
        { ASSETS: h.env.ASSETS }
      );
      return untrustedToolResult(r);
    }
  );
}
