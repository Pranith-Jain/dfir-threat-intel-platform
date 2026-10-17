/**
 * sample-velociraptor MCP tool registrations.
 *
 * Moved verbatim out of `DfirMcpServer.init()` in worker/mcp-server.ts.
 * `h` is the McpAgent instance typed as McpToolHost, so the bodies below
 * are unchanged: `h.tools(...)`, `h.env.*` and `h.apiKey` resolve
 * against that host at call time.
 */

import { adminApiFetch, apiFetch, untrustedToolResult } from './core';
import { z } from 'zod';

import type { McpToolHost } from './host';

export function registerSampleVelociraptorTools(h: McpToolHost): void {
  // ── Sample submission (detonation bridge) ─────────────────────────
  h.tools(
    'submit_sample_for_analysis',
    'Upload a suspicious file (base64, max ~32MB decoded) to Hybrid Analysis (detonation) and/or VirusTotal (multi-engine scan). Returns submission ids/links; poll with get_sample_analysis_status.',
    {
      data_base64: z.string().describe('Base64-encoded sample bytes'),
      filename: z.string().optional().describe('Original filename'),
      providers: z
        .array(z.enum(['hybridanalysis', 'virustotal']))
        .optional()
        .describe('Provider subset (default both)'),
    },
    async ({ data_base64, filename, providers }) => {
      const b64 = data_base64.replace(/\s+/g, '');
      const approxBytes = Math.floor((b64.length * 3) / 4);
      if (approxBytes > 32 * 1024 * 1024) {
        return {
          content: [
            { type: 'text', text: JSON.stringify({ error: `sample too large (~${approxBytes} bytes > 32MB)` }) },
          ],
        };
      }
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/sample-submission/upload', h.apiKey, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          dataBase64: b64,
          ...(filename ? { filename } : {}),
          ...(providers && providers.length ? { providers } : {}),
        }),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'get_sample_analysis_status',
    'Poll analysis results for a submitted sample: VirusTotal verdict stats and/or Hybrid Analysis detonation state + threat score + AV detection ratio.',
    {
      virustotal_analysis_id: z.string().optional().describe('VT analysis id from submit'),
      sha256: z.string().length(64).optional().describe('Sample SHA-256 (Hybrid Analysis)'),
    },
    async ({ virustotal_analysis_id, sha256 }) => {
      if (!virustotal_analysis_id && !sha256) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: 'virustotal_analysis_id or sha256 required' }) }],
        };
      }
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/sample-submission/status', h.apiKey, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          ...(virustotal_analysis_id ? { virustotalAnalysisId: virustotal_analysis_id } : {}),
          ...(sha256 ? { sha256 } : {}),
        }),
      });
      return untrustedToolResult(data);
    }
  );

  // ── Velociraptor endpoint acquisition bridge ─────────────────────
  h.tools(
    'velo_list_clients',
    'List Velociraptor-managed endpoints (hostname, OS, arch, labels, last-seen). Optional hostname search. Degrades gracefully when VELO_API_URL is not configured.',
    {
      search: z.string().optional().describe('Hostname/client-id filter'),
      limit: z.number().int().min(1).max(500).optional().describe('Max clients (default 50)'),
    },
    async ({ search, limit }) => {
      const p = new URLSearchParams();
      if (search) p.set('search', search);
      if (limit) p.set('limit', String(limit));
      const qs = p.toString() ? `?${p}` : '';
      const data = await adminApiFetch<Record<string, unknown>>(h, `/api/v1/velociraptor/clients${qs}`);
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'velo_get_client',
    'Get one Velociraptor-managed endpoint by client id (C.xxxx) — OS build, labels, last check-in.',
    { client_id: z.string().describe("Client id ('C.1234')") },
    async ({ client_id }) => {
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/velociraptor/client', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_id }),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'velo_list_flows',
    'List recent collections (flows) on a managed endpoint — artifact names, state (RUNNING/FINISHED/ERROR), created time.',
    {
      client_id: z.string().describe('Velociraptor client id'),
      limit: z.number().int().min(1).max(200).optional().describe('Max flows (default 20)'),
    },
    async ({ client_id, limit }) => {
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/velociraptor/flows', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_id, ...(limit ? { limit } : {}) }),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'velo_collect_artifact',
    'Launch a Velociraptor artifact collection on a managed endpoint (evidence acquisition): e.g. Windows.KapeFiles.Collect. Returns flow id; poll with velo_get_flow_status then velo_get_flow_results.',
    {
      client_id: z.string().describe('Velociraptor client id'),
      artifacts: z.array(z.string()).max(10).describe('Artifact names to collect'),
      parameters_json: z.string().optional().describe('JSON object of artifact env parameters'),
      urgent: z.boolean().optional().describe('Queue ahead of scheduled hunts'),
    },
    async ({ client_id, artifacts, parameters_json, urgent }) => {
      let parameters: Record<string, string> | undefined;
      if (parameters_json) {
        try {
          parameters = JSON.parse(parameters_json) as Record<string, string>;
        } catch {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: 'parameters_json is not valid JSON' }) }],
          };
        }
      }
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/velociraptor/collect', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_id,
          artifacts,
          ...(parameters ? { parameters } : {}),
          urgent: urgent === true,
        }),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'velo_get_flow_status',
    'Poll a Velociraptor collection status — state, duration, bytes collected, files loaded.',
    {
      client_id: z.string().describe('Velociraptor client id'),
      flow_id: z.string().describe("Flow id from velo_collect_artifact ('F.xxxx')"),
    },
    async ({ client_id, flow_id }) => {
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/velociraptor/flow', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ client_id, flow_id }),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'velo_get_flow_results',
    'Fetch collected rows from a finished Velociraptor collection (VQL results table with pagination) — the evidence payload for the investigation.',
    {
      client_id: z.string().describe('Velociraptor client id'),
      flow_id: z.string().describe('Flow id'),
      artifact: z.string().optional().describe('Filter to one collected artifact'),
      offset: z.number().int().min(0).optional().describe('Row offset'),
      rows: z.number().int().min(1).max(1000).optional().describe('Max rows (default 100)'),
    },
    async ({ client_id, flow_id, artifact, offset, rows }) => {
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/velociraptor/results', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_id,
          flow_id,
          ...(artifact ? { artifact } : {}),
          ...(offset !== undefined ? { offset } : {}),
          ...(rows !== undefined ? { rows } : {}),
        }),
      });
      return untrustedToolResult(data);
    }
  );

  // ── Velociraptor hunts ────────────────────────────────────────────
  h.tools(
    'velo_create_hunt',
    'Launch a Velociraptor HUNT across all managed endpoints (or a label subset) — fleet-wide artifact sweep. Returns hunt id; poll with velo_get_hunt.',
    {
      artifacts: z.array(z.string()).max(10).describe('Artifact names'),
      parameters_json: z.string().optional().describe('JSON artifact parameters'),
      label: z.string().optional().describe('Restrict to labeled endpoints'),
      expire_hours: z.number().int().min(1).max(720).optional().describe('Hunt expiry hours'),
    },
    async ({ artifacts, parameters_json, label, expire_hours }) => {
      let parameters: Record<string, string> | undefined;
      if (parameters_json) {
        try {
          parameters = JSON.parse(parameters_json) as Record<string, string>;
        } catch {
          return {
            content: [{ type: 'text', text: JSON.stringify({ error: 'parameters_json is not valid JSON' }) }],
          };
        }
      }
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/velociraptor/hunts/create', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          artifacts,
          ...(parameters ? { parameters } : {}),
          ...(label ? { label } : {}),
          ...(expire_hours ? { expire_hours } : {}),
        }),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'velo_get_hunt',
    'Poll a Velociraptor hunt — state, scheduled/completed/erroring client counts.',
    { hunt_id: z.string().describe("Hunt id ('H.xxxx')") },
    async ({ hunt_id }) => {
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/velociraptor/hunt', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ hunt_id }),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'velo_list_hunts',
    'List recent Velociraptor hunts across the fleet — descriptions, states, completion counts.',
    { limit: z.number().int().min(1).max(200).optional().describe('Max hunts') },
    async ({ limit }) => {
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/velociraptor/hunts', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ...(limit ? { limit } : {}) }),
      });
      return untrustedToolResult(data);
    }
  );

  // ── Investigation recipes ─────────────────────────────────────────
  h.tools(
    'get_recipe',
    'Fetch a proven multi-step investigation playbook (file-triage, phishing-email, c2-identification, dns-tunnel-hunt, report-ioc-sweep). Returns ordered steps with tool names, argument templates ({input}/{ioc} placeholders), and why each step matters.',
    { recipe_id: z.string().describe('Playbook id') },
    async ({ recipe_id }) => {
      const data = await apiFetch<Record<string, unknown>>(
        h.env.SELF,
        `/api/v1/tools/recipes/${encodeURIComponent(recipe_id)}`,
        h.apiKey
      );
      return untrustedToolResult(data);
    }
  );

  // ── Detection-rule validation & Sigma conversion ────────────────
  h.tools(
    'validate_detection_rule',
    'Validate a detection rule before use: YARA (structure, string refs, hex tokens, dup names), Sigma (schema + logsource + detection + condition identifiers), Suricata/Snort (header grammar, msg/sid/rev, local sid range), osquery (read-only guard, paren balance, known tables).',
    {
      kind: z.enum(['yara', 'sigma', 'suricata', 'snort', 'osquery']).describe('Rule kind'),
      source: z.string().describe('Full rule text to validate'),
    },
    async ({ kind, source }) => {
      const data = await adminApiFetch<Record<string, unknown>>(h, '/api/v1/rules/validate', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ kind, source }),
      });
      return untrustedToolResult(data);
    }
  );
  h.tools(
    'convert_sigma_rule',
    'Convert a Sigma rule to Splunk SPL or Microsoft Sentinel KQL. Handles field modifiers (contains/startswith/endswith/re/null), multi-value lists, N-of expansions, and optional field-name mapping.',
    {
      yaml: z.string().describe('Sigma rule YAML source'),
      target: z.enum(['splunk', 'kql']).describe('Target query language'),
      field_map_json: z.string().optional().describe('Optional JSON object mapping Sigma fields to target names'),
    },
    async ({ yaml, target, field_map_json }) => {
      let fieldNameMap: Record<string, string> | undefined;
      if (field_map_json) {
        try {
          fieldNameMap = JSON.parse(field_map_json) as Record<string, string>;
        } catch {
          return { content: [{ type: 'text', text: JSON.stringify({ error: 'field_map_json is not valid JSON' }) }] };
        }
      }
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/rules/sigma/convert', h.apiKey, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ yaml, target, fieldNameMap }),
      });
      return untrustedToolResult(data);
    }
  );

  // ── Deterministic observable extraction ──────────────────────────
  h.tools(
    'extract_observables_fast',
    'Deterministic regex-based IOC extraction from raw text — no AI. Handles defanged indicators (hxxp, [.], [at], [dot]); extracts IPs, domains, URLs, emails, hashes, CVEs, mutexes, registry keys, file paths, and crypto addresses with positions.',
    {
      text: z.string().describe('Raw text to extract observables from (max 500k chars)'),
      max_hits: z.number().int().min(1).max(50000).optional().describe('Cap on unique observables (default 2000)'),
    },
    async ({ text, max_hits }) => {
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/observables/extract', h.apiKey, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text, ...(max_hits ? { maxHits: max_hits } : {}) }),
      });
      return untrustedToolResult(data);
    }
  );

  // ── Static file triage ────────────────────────────────────────────
  h.tools(
    'static_triage_file',
    'Static file triage from base64 bytes (max ~6MB decoded): magic-byte family detection, hashes, entropy analysis, PE header parse, packer signals (UPX etc.), embedded artifacts (embedded PE/nested zip/OLE). No execution — pure structural analysis.',
    {
      data_base64: z.string().describe('Base64-encoded file bytes'),
      filename: z.string().optional().describe('Original filename hint'),
    },
    async ({ data_base64, filename }) => {
      const b64 = data_base64.replace(/\s+/g, '');
      const approxBytes = Math.floor((b64.length * 3) / 4);
      if (approxBytes > 8 * 1024 * 1024) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ error: `file too large for static triage (${approxBytes} bytes > 8MB limit)` }),
            },
          ],
        };
      }
      const data = await apiFetch<Record<string, unknown>>(h.env.SELF, '/api/v1/file/triage-static', h.apiKey, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ dataBase64: b64, ...(filename ? { filename } : {}) }),
      });
      return untrustedToolResult(data);
    }
  );
}
