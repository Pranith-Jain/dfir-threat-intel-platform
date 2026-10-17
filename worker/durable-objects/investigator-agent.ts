import { Agent, type Connection } from 'agents';
import type { Env } from '../env';
import type { Env as ApiEnv } from '../../api/src/env';
import type { AgentState, AgentStep, AgentToolResult, AgentToolCall, IocEntry } from '../../api/src/lib/agent/types';
import { buildToolRegistry } from '../../api/src/lib/agent/tools';
import { bridgeMcpTools } from '../../api/src/lib/agent/mcp-bridge';
import { bridgeTiMindmapTools } from '../lib/ti-mindmap-mcp-bridge';
import { planNextStep } from '../../api/src/lib/agent/planner';
import {
  evaluateCtiExit,
  filterCtiToolCalls,
  canSynthesizeNow,
  getDroppedCalls,
  shouldBanTool,
} from '../../api/src/lib/agent/cti-loop';
import { observeStep } from '../../api/src/lib/agent/observer';
import { synthesizeReport, splitSynthOutput } from '../../api/src/lib/agent/synthesizer';
import { verifyReport } from '../../api/src/lib/agent/qa-verifier';
import { selfEvaluateReport } from '../../api/src/lib/agent/self-eval';
import { extractToolFailures } from '../../api/src/lib/agent/introspection';
import { signInternalToken } from '../../api/src/lib/internal-token';
import {
  buildOrchestratorPlan,
  checkSpecialistExit,
  getSpecialistPrompt,
  applySpecialistGuardrails,
  extractFindings,
} from '../../api/src/lib/agent/orchestrator';
import {
  SPECIALIST_REGISTRY,
  SPECIALIST_TOOLS,
  getToolsForSpecialist,
  getSpecialistsForQueryType,
  filterToolsForQueryType,
  resolveRoutingQueryType,
  type SpecialistRole,
  type SpecialistFinding,
} from '../../api/src/lib/agent/specialist-types';
import { runParallelSpecialists, type SpecialistExecutor } from '../../api/src/lib/agent/parallel-specialists';
import {
  rebuildWorkingMemory,
  memoryToPrompt,
  shouldRetry,
  shouldConverge,
  buildSelfCorrectionPrompt,
  type WorkingMemory,
} from '../../api/src/lib/agent/agent-framework';
import { getCachedResult, setCachedResult } from '../../api/src/lib/agent/agent-cache';
import { suggestAlternative, nextActionsFor } from '../../api/src/lib/agent/tool-retry';
import { saveInvestigationMemory } from '../../api/src/lib/agent/investigation-memory';
import {
  createCostTracker,
  isOverBudget,
  recordCompletion,
  type InvestigationCost,
} from '../../api/src/lib/agent/cost-tracker';
import { checkDuplicate, registerInvestigation } from '../../api/src/lib/agent/request-dedup';
import { extractGraphFromSteps } from '../../api/src/lib/agent/ioc-graph';
import { truncateData } from '../lib/truncate-data';
import { createVersionedReport, addVersion, getVersionDiff } from '../../api/src/lib/agent/report-versioning';
import { errMessage } from '../lib/err';

/** Map a specialist finding to an action-card IOC entry type. */
function classifyFindingIocType(f: SpecialistFinding): IocEntry['type'] | null {
  switch (f.type) {
    case 'actor':
      return 'actor';
    case 'cve':
      return 'cve';
    case 'domain':
      return 'domain';
    case 'hash':
      return 'hash';
    case 'ioc': {
      const v = f.value.trim();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ipv4';
      if (/^[a-f0-9]{32,64}$/i.test(v)) return 'hash';
      if (/^https?:\/\//i.test(v)) return 'url';
      if (/^[^@\s]+@[^@\s]+$/.test(v)) return 'email';
      return 'domain';
    }
    default:
      return null;
  }
}

/**
 * Agent<Env, State> state shape. One DO instance per investigation (callers
 * route via `INVESTIGATOR_AGENT.idFromName(investigationId)`), so this holds
 * a single investigation's state.
 *
 * `costTracker` is non-serializable (accumulates token usage), so it lives in
 * a private field, not `this.state`. The SDK's `setState` persists + broadcasts
 * serializable state; the cost tracker is ephemeral per-instance.
 */
interface InvestigatorAgentState {
  /** The investigation state. `null` before POST /investigate creates it. */
  investigation: AgentState | null;
}

/**
 * Autonomous investigator agent built on the Cloudflare Agents SDK
 * (`Agent<Env, State>`).
 *
 * Each DO instance serves ONE investigation (callers route via
 * `INVESTIGATOR_AGENT.idFromName(investigationId)`), matching the pre-port
 * routing. The Agents SDK provides:
 *   - `this.state` / `this.setState()` — SQLite-backed persistence (replaces
 *     `ctx.storage.put/get('state:*')`)
 *   - `this.schedule(when, callbackName)` — replaces `ctx.storage.setAlarm()`
 *   - `onConnect` / `onMessage` / `onClose` — managed WebSocket lifecycle
 *     (replaces the manual `sessions`/`sessionAgentIds`/`ipConnections` Maps)
 *   - `this.getConnections()` + `conn.send()` — replaces manual `broadcast()`
 *
 * The alarm-per-step pattern is preserved: each `runStep()` runs ONE
 * planning+execution cycle, persists state, and reschedules via
 * `this.schedule(0.1, 'runStep')` until the investigation is complete. This
 * keeps each step within the Worker subrequest/CPU budget so the agent can
 * run for minutes.
 *
 * The `LoopEngine` / `cti-loop.ts` decision logic is unchanged — this class
 * only owns the runtime shell (state, scheduling, WebSocket, HTTP routes).
 * The parity test (`api/test/lib/loop-engine.test.ts`) is unaffected.
 */
const MAX_AGENT_WS_CONNECTIONS = 10;
const MAX_WS_PER_IP = 5;

export class InvestigatorAgentDO extends Agent<Env, InvestigatorAgentState> {
  override initialState = { investigation: null } as InvestigatorAgentState;

  private costTrackers = new Map<string, InvestigationCost>();
  private degradedToolsCache: { at: number; note: string; set: Set<string> } | null = null;
  private calibrationHintCache: { at: number; hint: string } | null = null;
  /**
   * Session-scoped tool-failure tracker (fix #7). After MAX_TOOL_FAILURES_PER_SESSION
   * consecutive failures of the same tool within one investigation, the tool is
   * added to sessionBannedTools and preventively dropped by the noDegradedTools
   * guardrail on subsequent steps. Reset when a new investigation starts.
   */
  private sessionToolFailures = new Map<string, number>();
  private sessionBannedTools = new Set<string>();
  /**
   * Transient working-memory cache keyed by investigation id. Invalidated when
   * the step count changes (state.steps.push), so the 4 call sites that need
   * working memory (pre-plan, self-correction, memory-save, + private method)
   * reuse one rebuild per alarm invocation instead of rebuilding 4×. Not
   * serialized — a cache miss falls through to rebuildWorkingMemory, which is
   * the cross-alarm recovery path.
   */
  private workingMemoryCache = new Map<string, { stepCount: number; mem: WorkingMemory }>();
  private connectionAgentIds = new Map<string, string>();
  private ipConnections = new Map<string, number>();
  /** conn.id -> client IP, so onClose can decrement the per-IP cap. */
  private connIps = new Map<string, string>();

  /** Called for every non-WebSocket HTTP request to this DO instance.
   *
   *  The Agents SDK base `fetch()` detects WebSocket upgrades and routes them
   *  to `onConnect`/`onMessage`/`onClose` automatically — `onRequest` only
   *  sees plain HTTP. The 13 call sites (`agent.ts`, `vera.ts`,
   *  `copilot-chat.ts`, `tie-enrich.ts`) all use `idFromName(investigationId)`
   *  + `stub.fetch(...)`, so each investigation gets its own DO instance and
   *  this handler serves that one investigation's HTTP routes. */
  override async onRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/investigate' && request.method === 'POST') {
      const body = (await request.json()) as {
        id: string;
        query: string;
        queryType?: string;
        maxSteps?: number;
        allowedTools?: string[] | null;
        role?: string;
        rolePreamble?: string;
        responseFormat?: string;
        tiMindmapApiKey?: string;
      };
      const existingId = await checkDuplicate(body.query);
      if (existingId) {
        return Response.json({ id: existingId, status: 'running', duplicate: true });
      }

      const state: AgentState = {
        id: body.id,
        query: body.query,
        queryType: body.queryType ?? 'generic',
        status: 'running',
        steps: [],
        currentStep: 0,
        maxSteps: body.maxSteps ?? 6,
        report: null,
        modelUsed: null,
        startedAt: new Date().toISOString(),
        completedAt: null,
        error: null,
        role: body.role,
        allowedTools: body.allowedTools,
        rolePreamble: body.rolePreamble,
        responseFormat: body.responseFormat,
        tiMindmapApiKey: body.tiMindmapApiKey,
      };
      // Reset session-scoped tool-failure state for the new investigation (fix #7).
      this.resetSessionToolState();
      this.setState({ investigation: state });
      await registerInvestigation(body.query, body.id);
      await this.schedule(0.1, 'runStep');
      return Response.json({ id: body.id, status: 'running' });
    }

    if (url.pathname === '/state') {
      const id = url.searchParams.get('id') ?? '';
      const state = this.state.investigation;
      if (!state || state.id !== id) return Response.json({ error: 'not found' }, { status: 404 });
      return Response.json(state);
    }

    if (url.pathname === '/cancel' && request.method === 'DELETE') {
      const id = url.searchParams.get('id') ?? '';
      if (!id) return Response.json({ error: 'id required' }, { status: 400 });
      const state = this.state.investigation;
      if (!state || state.id !== id) return Response.json({ error: 'not found' }, { status: 404 });
      if (state.status === 'running') {
        state.status = 'error';
        state.error = 'Cancelled by user';
        state.completedAt = new Date().toISOString();
        this.setState({ investigation: state });
        await this.persist(state);
        this.broadcastToWatchers({ type: 'error', error: 'Cancelled by user', agentId: id });
      }
      return Response.json({ ok: true, status: state.status });
    }

    if (url.pathname === '/delete' && request.method === 'DELETE') {
      const id = url.searchParams.get('id') ?? '';
      if (id) this.setState({ investigation: null });
      return Response.json({ ok: true });
    }

    return new Response('not found', { status: 404 });
  }

  /** Called when a new WebSocket connection is established. The SDK base
   *  `fetch()` already accepted the upgrade; this fires per connection. */
  override async onConnect(conn: Connection, ctx: { request: Request }): Promise<void> {
    if ([...this.getConnections()].length >= MAX_AGENT_WS_CONNECTIONS) {
      conn.close(1013, 'Too many connections');
      return;
    }
    const clientIp = ctx.request.headers.get('cf-connecting-ip') ?? 'unknown';
    const ipCount = this.ipConnections.get(clientIp) ?? 0;
    if (ipCount >= MAX_WS_PER_IP) {
      conn.close(1013, 'Too many connections from this IP');
      return;
    }
    this.ipConnections.set(clientIp, ipCount + 1);
    // Track which IP this socket belongs to so onClose can decrement —
    // without this, refreshes accumulate against the cap until the DO is
    // evicted and the client is permanently locked out with 1013.
    this.connIps.set(conn.id, clientIp);
    conn.send(JSON.stringify({ type: 'connected' }));
  }

  override async onMessage(conn: Connection, message: string | ArrayBuffer | ArrayBufferView): Promise<void> {
    try {
      const msg = JSON.parse(typeof message === 'string' ? message : new TextDecoder().decode(message));
      if (typeof msg.agentId === 'string') {
        this.connectionAgentIds.set(conn.id, msg.agentId);
      }
    } catch (_catchErr) {
      console.error('handler failed:', errMessage(_catchErr));
    }
  }

  override async onClose(conn: Connection): Promise<void> {
    this.connectionAgentIds.delete(conn.id);
    const ip = this.connIps.get(conn.id);
    if (ip !== undefined) {
      this.connIps.delete(conn.id);
      const remaining = (this.ipConnections.get(ip) ?? 1) - 1;
      if (remaining <= 0) this.ipConnections.delete(ip);
      else this.ipConnections.set(ip, remaining);
    }
  }

  private broadcastToWatchers(msg: unknown): void {
    const conns = [...this.getConnections()];
    if (conns.length === 0) return;
    const payload = JSON.stringify(msg);
    const msgAgentId = (msg as Record<string, unknown>).agentId;
    for (const conn of conns) {
      const watching = this.connectionAgentIds.get(conn.id);
      if (watching && watching !== msgAgentId) continue;
      try {
        conn.send(payload);
      } catch (_catchErr) {
        console.error('handler failed:', errMessage(_catchErr));
      }
    }
  }

  /** Scheduled step callback — runs one investigation cycle. Invoked by
   *  `this.schedule(0.1, 'runStep')`. Each invocation runs ONE
   *  planning+execution cycle, persists state, and reschedules until the
   *  investigation is complete (synthesized) or errored. */
  async runStep(): Promise<void> {
    const state = this.state.investigation;
    if (!state || state.status !== 'running') return;

    try {
      const next = await this.advanceOneStep(state);
      this.setState({ investigation: next });

      if (next.steps.length > state.steps.length) {
        const newStep = next.steps[next.steps.length - 1];
        this.broadcastToWatchers({ type: 'step', step: newStep });
      }

      if (next.status === 'done' || next.status === 'error') {
        await this.persist(next);
        this.broadcastToWatchers({
          type: next.status,
          report: next.report,
          error: next.error,
          modelUsed: next.modelUsed,
          qa: next.qa,
          actionCard: next.actionCard,
          sources: next.sources,
          reportVersioning: next.reportVersioning,
          cost: next.cost,
          priorIntelligence: next.priorIntelligence,
        });
      } else {
        await this.schedule(0.1, 'runStep');
      }
    } catch (err) {
      const errMsg = errMessage(err);
      console.error(`agent ${state.id}: step failed`, errMsg);
      state.status = 'error';
      state.error = errMsg;
      state.completedAt = new Date().toISOString();
      this.setState({ investigation: state });
      await this.persist(state);
      this.broadcastToWatchers({ type: 'error', error: errMsg });
    }
  }

  private async advanceOneStep(state: AgentState): Promise<AgentState> {
    const apiEnv = this.env as unknown as ApiEnv;
    const ai = apiEnv.AI;
    const groqKey = apiEnv.GROQ_API_KEY;
    const googleKey = apiEnv.GOOGLE_AI_STUDIO_API_KEY;
    const nvidiaKey = apiEnv.NVIDIA_API_KEY;
    const infronKey = apiEnv.INFRON_API_KEY;
    const tokenSecret = this.env.INTERNAL_TOKEN_SECRET;
    if (!tokenSecret) throw new Error('INTERNAL_TOKEN_SECRET not configured');
    const internalToken = await signInternalToken('investigator-do', tokenSecret);
    const allTools = buildToolRegistry(this.env.SELF, undefined, { 'x-internal-token': internalToken });

    // Bridge MCP-only tools that the hand-written registry doesn't cover.
    // These call library functions directly (same as the MCP server) — no
    // HTTP hop, no auth. Adds ti_* (CVEs/KEV/IOCs/darknet), si_* (skills/
    // queries), winreg_*, traceix, whoxy, depx, breach_vip, dn_* (43
    // darknet-intel provider tools) tools.
    const existingNames = new Set(allTools.map((t) => t.name));
    const bridged = bridgeMcpTools(
      this.env.ASSETS,
      this.env as unknown as { ASSETS?: Fetcher; TRACEIX_API_KEY?: string; WHOXY_API_KEY?: string },
      existingNames,
      this.env.SELF,
      { 'x-internal-token': internalToken }
    );
    const allToolsWithBridge = [...allTools, ...bridged];

    // Bridge TI-Mindmap MCP tools (user-keyed external knowledge graph).
    // Only bridged when the user provides their TI-Mindmap API key — the
    // tools call the upstream MCP directly (server-side, no CORS proxy).
    const tiMindmapTools = bridgeTiMindmapTools(state.tiMindmapApiKey);
    const allToolsWithTiMindmap = [...allToolsWithBridge, ...tiMindmapTools];

    const allowedTools = state.allowedTools;
    const availableTools =
      allowedTools && allowedTools.length > 0
        ? allToolsWithTiMindmap.filter((t) => allowedTools.includes(t.name))
        : allToolsWithTiMindmap;

    const stepNum = state.currentStep + 1;
    const stepStart = new Date().toISOString();
    const view = { stepNum, maxSteps: state.maxSteps, steps: state.steps };

    const workingMemory = this.buildWorkingMemory(state);
    const degradedNote = await this.degradedToolsNote();

    const costTracker = this.costTrackers.get(state.id) ?? createCostTracker();
    this.costTrackers.set(state.id, costTracker);

    if (isOverBudget(costTracker)) {
      return await this.doSynthesize(
        state,
        ai,
        groqKey,
        googleKey,
        nvidiaKey,
        infronKey,
        stepNum,
        stepStart,
        'Budget exceeded — synthesizing with collected data.'
      );
    }

    const exit = evaluateCtiExit(view);
    if (exit) {
      return await this.doSynthesize(
        state,
        ai,
        groqKey,
        googleKey,
        nvidiaKey,
        infronKey,
        stepNum,
        stepStart,
        exit.reason
      );
    }

    let currentRole: SpecialistRole | undefined = state.currentSpecialist as SpecialistRole | undefined;

    if (stepNum === 1) {
      // ── Deterministic IOC pivot chain (step 0) ────────────────────────────
      // When the query contains a concrete indicator (hash/domain/IP/URL), run
      // a deterministic infrastructure walk BEFORE the LLM planner takes over.
      // This seeds the investigation with the subdomain/C2/contacted-IP graph a
      // deep-dive report needs (NamrataSonii-style), so the planner starts
      // from a rich working memory instead of an empty one. Best-effort: a
      // single tool failure never blocks the rest.
      if (state.steps.length === 0) {
        try {
          const { extractQueryEntities, hasIndicators } = await import('../../api/src/lib/agent/query-entities');
          const { executePivotChain } = await import('../../api/src/lib/agent/pivot-chain');
          const entities = extractQueryEntities(state.query);
          if (hasIndicators(entities)) {
            const pivotStep = await executePivotChain(entities, allToolsWithTiMindmap);
            if (pivotStep) {
              state.steps.push(pivotStep);
              this.broadcastToWatchers({ type: 'step', step: pivotStep });
            }
          }
        } catch (_pivotErr) {
          console.error('pivot chain failed:', errMessage(_pivotErr));
        }
      }

      // ── CTI investigation skill (methodology playbook) ────────────────────
      // Pick the best-matching methodology skill for the query (IOC pivot,
      // ransomware deep-dive, CVE triage, APT profiling, etc.) and load its
      // playbook. The playbook tells the planner which tools to call, which
      // report sections to populate, and which anti-patterns to avoid. Injected
      // as specialist context so the LLM follows the methodology.
      if (!state.ctiSkillPlaybook) {
        try {
          const { loadCtiIndex, pickCtiSkillForQuery, getCtiSkill } =
            await import('../../worker/lib/cti-skills-manifest');
          const idx = await loadCtiIndex(this.env.ASSETS);
          const skill = pickCtiSkillForQuery(idx, state.query, state.queryType);
          if (skill) {
            const body = await getCtiSkill(this.env.ASSETS, skill.slug);
            if (body?.bodyMarkdown) {
              state.ctiSkillPlaybook = {
                slug: skill.slug,
                name: skill.name,
                playbook: body.bodyMarkdown,
              };
            }
          }
        } catch (_skillErr) {
          console.error('cti skill load failed:', errMessage(_skillErr));
        }
      }

      try {
        const plan = await buildOrchestratorPlan(state.query, state.queryType, {
          infronKey,
          groqKey,
          googleKey,
          nvidiaKey,
        });
        if (plan.specialistCalls.length > 0 && plan.specialistCalls[0]) {
          currentRole = plan.specialistCalls[0].role;
          state.currentSpecialist = currentRole;
        }
      } catch (_catchErr) {
        console.error('handler failed:', errMessage(_catchErr));
      }

      if (!state.priorIntelligence) {
        try {
          const db = (this.env as unknown as ApiEnv).BRIEFINGS_DB;
          if (db) {
            const { extractQueryEntities, hasIndicators, entitiesToMemoryIndicators } =
              await import('../../api/src/lib/agent/query-entities');
            const entities = extractQueryEntities(state.query);
            if (hasIndicators(entities)) {
              const { lookupMemory, buildPriorIntelNote } =
                await import('../../api/src/lib/agent/investigation-memory');
              const related = await lookupMemory(db, entitiesToMemoryIndicators(entities));
              state.priorIntelligence = buildPriorIntelNote(related);
            }
          }
        } catch (_catchErr) {
          console.error('memory lookup failed:', errMessage(_catchErr));
        }
      }

      const burst = await this.tryParallelBurst(
        state,
        ai,
        groqKey,
        googleKey,
        nvidiaKey,
        infronKey,
        allToolsWithTiMindmap,
        workingMemory
      );
      if (burst) return burst;
    } else if (currentRole) {
      const specialistCheck = checkSpecialistExit(
        currentRole,
        state.steps,
        stepNum,
        state.maxSteps,
        state.queryType,
        state.query
      );
      if (specialistCheck.shouldSwitch) {
        if (specialistCheck.nextRole) {
          currentRole = specialistCheck.nextRole;
          state.currentSpecialist = currentRole;
        } else {
          return await this.doSynthesize(
            state,
            ai,
            groqKey,
            googleKey,
            nvidiaKey,
            infronKey,
            stepNum,
            stepStart,
            `All specialists complete (${specialistCheck.reason}). Synthesizing.`
          );
        }
      }
    }

    let specialistTools = allToolsWithTiMindmap;
    let specialistPrompt = '';

    if (currentRole) {
      specialistTools = getToolsForSpecialist(currentRole, allToolsWithTiMindmap);
      specialistPrompt = getSpecialistPrompt(
        currentRole,
        specialistTools,
        stepNum,
        state.maxSteps,
        state.query,
        state.steps
      );

      const specialistContext =
        (specialistPrompt
          ? `\n<specialist_role>${SPECIALIST_REGISTRY[currentRole].label}</specialist_role>\n<specialist_instructions>${specialistPrompt}</specialist_instructions>`
          : '') +
          (state.ctiSkillPlaybook
            ? `\n<cti_methodology_skill slug="${state.ctiSkillPlaybook.slug}" name="${state.ctiSkillPlaybook.name}">\n${state.ctiSkillPlaybook.playbook}\n</cti_methodology_skill>`
            : '') +
          degradedNote +
          (state.priorIntelligence ?? '') || undefined;

      const plan = await planNextStep(
        ai,
        state.query,
        state.queryType,
        state.steps,
        stepNum,
        state.maxSteps,
        specialistTools,
        { infronKey, groqKey, googleKey, nvidiaKey, specialistContext, workingMemory }
      );

      if (plan.shouldSynthesize && canSynthesizeNow(view)) {
        return await this.doSynthesize(
          state,
          ai,
          groqKey,
          googleKey,
          nvidiaKey,
          infronKey,
          stepNum,
          stepStart,
          plan.reasoning
        );
      }

      // MINIMUM-DATA FLOOR: the planner asked to synthesize but we don't yet
      // have enough successful tool results (and we're not at the step ceiling).
      // Override the planner and force another tool call so the report isn't thin.
      if (plan.shouldSynthesize && !canSynthesizeNow(view)) {
        plan.shouldSynthesize = false;
        // Fall through to the tool-execution path below.
      }

      const validToolNames = new Set(specialistTools.map((t) => t.name));
      const degradedTools = await this.degradedToolsSet();
      let toolCalls = filterCtiToolCalls(plan.toolCalls, view, validToolNames, degradedTools);
      const droppedCalls = getDroppedCalls(plan.toolCalls, view, validToolNames, degradedTools);
      toolCalls = applySpecialistGuardrails(currentRole, toolCalls, view);

      if (toolCalls.length === 0) {
        const specialistCheck = checkSpecialistExit(
          currentRole,
          state.steps,
          stepNum,
          state.maxSteps,
          state.queryType,
          state.query
        );
        if (specialistCheck.shouldSwitch && specialistCheck.nextRole) {
          currentRole = specialistCheck.nextRole;
          state.currentSpecialist = currentRole;
          return await this.advanceOneStep({ ...state, currentStep: stepNum - 1 });
        }
        return await this.doSynthesize(
          state,
          ai,
          groqKey,
          googleKey,
          nvidiaKey,
          infronKey,
          stepNum,
          stepStart,
          'No valid tools for specialist'
        );
      }

      const step: AgentStep = {
        stepNumber: stepNum,
        plan: `[${SPECIALIST_REGISTRY[currentRole].label}] ${plan.reasoning}${
          plan.parseRetries && plan.parseRetries > 0 ? ` (planner parse retries: ${plan.parseRetries})` : ''
        }`,
        toolCalls,
        results: [],
        status: 'running',
        startedAt: stepStart,
        droppedCalls: droppedCalls.length > 0 ? droppedCalls : undefined,
      };

      const results = await this.executeTools(toolCalls, specialistTools);
      step.results = results;
      step.completedAt = new Date().toISOString();

      const observation = await observeStep(ai, stepNum, plan.reasoning, results, {
        infronKey,
        groqKey,
        googleKey,
        nvidiaKey,
      });
      step.observation = observation.observation;
      step.observerFindings = {
        iocs: observation.iocs,
        actors: observation.actors,
        cves: observation.cves,
        malware: observation.malware,
        mitre: observation.mitre,
        keyFacts: observation.keyFacts,
        confidence: observation.confidence,
        gaps: observation.gaps,
        provenance: observation.provenance,
        hypothesisUpdates: observation.hypothesisUpdates,
      };
      step.nextAction = 'continue';
      step.status = 'done';

      state.steps.push(step);
      state.currentStep = stepNum;

      return state;
    }

    // Context-aware tool filtering: pass only the tools relevant to this
    // query type to the planner, not all ~291. This cuts the planner's
    // tool-description context from ~5,800 tokens to ~1,500-2,500 tokens.
    const plannerTools = filterToolsForQueryType(state.queryType, state.query, availableTools);

    const plan = await planNextStep(
      ai,
      state.query,
      state.queryType,
      state.steps,
      stepNum,
      state.maxSteps,
      plannerTools,
      {
        infronKey,
        groqKey,
        googleKey,
        nvidiaKey,
        workingMemory,
        specialistContext: degradedNote + (state.priorIntelligence ?? '') || undefined,
      }
    );

    if (plan.shouldSynthesize && canSynthesizeNow(view)) {
      return await this.doSynthesize(
        state,
        ai,
        groqKey,
        googleKey,
        nvidiaKey,
        infronKey,
        stepNum,
        stepStart,
        plan.reasoning
      );
    }

    // MINIMUM-DATA FLOOR: override early synthesis when there isn't enough data yet.
    if (plan.shouldSynthesize && !canSynthesizeNow(view)) {
      plan.shouldSynthesize = false;
    }

    const validToolNames = new Set(availableTools.map((t) => t.name));
    const degradedTools = await this.degradedToolsSet();
    const toolCalls = filterCtiToolCalls(plan.toolCalls, view, validToolNames, degradedTools);
    const droppedCalls = getDroppedCalls(plan.toolCalls, view, validToolNames, degradedTools);
    if (toolCalls.length === 0) {
      return await this.doSynthesize(
        state,
        ai,
        groqKey,
        googleKey,
        nvidiaKey,
        infronKey,
        stepNum,
        stepStart,
        plan.reasoning
      );
    }

    const step: AgentStep = {
      stepNumber: stepNum,
      plan: plan.reasoning,
      toolCalls,
      results: [],
      status: 'running',
      startedAt: stepStart,
      droppedCalls: droppedCalls.length > 0 ? droppedCalls : undefined,
    };

    const results = await this.executeTools(toolCalls, availableTools);
    step.results = results;
    step.completedAt = new Date().toISOString();

    const observation = await observeStep(ai, stepNum, plan.reasoning, results, {
      infronKey,
      groqKey,
      googleKey,
      nvidiaKey,
    });
    step.observation = observation.observation;
    step.observerFindings = {
      iocs: observation.iocs,
      actors: observation.actors,
      cves: observation.cves,
      malware: observation.malware,
      mitre: observation.mitre,
      keyFacts: observation.keyFacts,
      confidence: observation.confidence,
      gaps: observation.gaps,
      provenance: observation.provenance,
      hypothesisUpdates: observation.hypothesisUpdates,
    };
    step.nextAction = 'continue';
    step.status = 'done';

    state.steps.push(step);
    state.currentStep = stepNum;

    return state;
  }

  private async tryParallelBurst(
    state: AgentState,
    ai: ApiEnv['AI'],
    groqKey: string | undefined,
    googleKey: string | undefined,
    nvidiaKey: string | undefined,
    infronKey: string | undefined,
    allTools: ReturnType<typeof buildToolRegistry>,
    workingMemory: WorkingMemory
  ): Promise<AgentState | null> {
    try {
      const roles = getSpecialistsForQueryType(state.queryType, state.query);
      const burst: SpecialistRole[] = [];
      const usedTools = new Set<string>();
      for (const role of roles) {
        const tools = SPECIALIST_TOOLS[role];
        if (tools.some((t) => usedTools.has(t))) break;
        burst.push(role);
        for (const t of tools) usedTools.add(t);
      }
      if (burst.length < 2) return null;

      const opts = { infronKey, groqKey, googleKey, nvidiaKey };
      const degradedTools = await this.degradedToolsSet();
      const executor: SpecialistExecutor = {
        plan: (role, tools, steps, sn, ms) => {
          const prompt = getSpecialistPrompt(role, tools, sn, ms, state.query, steps);
          const specialistContext = prompt
            ? `\n<specialist_role>${SPECIALIST_REGISTRY[role].label}</specialist_role>\n<specialist_instructions>${prompt}</specialist_instructions>`
            : undefined;
          return planNextStep(ai, state.query, state.queryType, steps, sn, ms, tools, {
            ...opts,
            specialistContext,
            workingMemory,
          });
        },
        execute: (calls, tools) => this.executeTools(calls, tools),
        observe: (sn, reasoning, results) => observeStep(ai, sn, reasoning, results, opts),
        guard: (role, calls, view) => {
          const valid = new Set(getToolsForSpecialist(role, allTools).map((t) => t.name));
          return applySpecialistGuardrails(role, filterCtiToolCalls(calls, view, valid, degradedTools), view);
        },
      };

      const results = await runParallelSpecialists(burst, allTools, 1, executor);
      const newSteps = results.flatMap((r) => r.steps);
      if (newSteps.length === 0) return null;

      let sn = state.currentStep;
      for (const s of newSteps) {
        sn += 1;
        s.stepNumber = sn;
      }
      state.steps.push(...newSteps);
      state.currentStep = sn;
      state.currentSpecialist = burst[burst.length - 1];
      state.usedParallelBurst = true;
      return state;
    } catch (err) {
      console.error('parallel burst failed, falling back to sequential:', errMessage(err));
      return null;
    }
  }

  private async executeTools(
    calls: AgentToolCall[],
    tools: ReturnType<typeof buildToolRegistry>
  ): Promise<AgentToolResult[]> {
    const toolMap = new Map(tools.map((t) => [t.name, t]));
    const results: AgentToolResult[] = [];
    const allToolNames = new Set(tools.map((t) => t.name));
    const calledKeys = new Set(calls.map((c) => `${c.tool}:${JSON.stringify(c.args)}`));

    const promises = calls.map(async (call): Promise<AgentToolResult> => {
      const tool = toolMap.get(call.tool);
      if (!tool)
        return {
          tool: call.tool,
          args: call.args,
          status: 'error',
          error: `Unknown tool: ${call.tool}`,
          durationMs: 0,
          nextActions: [],
        };

      const cached = await getCachedResult(call.tool, call.args);
      if (cached !== null) {
        return {
          tool: call.tool,
          args: call.args,
          status: 'ok',
          data: cached,
          durationMs: 0,
          nextActions: nextActionsFor(call.tool, 'ok'),
        };
      }

      const start = Date.now();
      try {
        const isHeavyFanout = [
          'enrich_actor',
          'check_ioc',
          'enrich_ioc_deep',
          'actor_timeline',
          'sample_scan',
          'breach_check',
          'check_breach',
          'scan_dependencies',
          'unified_search',
          'cross_correlate',
        ].includes(call.tool);
        const timeoutMs = isHeavyFanout ? 40_000 : 20_000;
        let timer: ReturnType<typeof setTimeout> | undefined;
        const data = await Promise.race([
          tool.execute(call.args).finally(() => clearTimeout(timer)),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error(`Tool timeout (${timeoutMs / 1000}s)`)), timeoutMs);
          }),
        ]);

        await setCachedResult(call.tool, call.args, data);
        this.resetToolFailure(call.tool);
        return {
          tool: call.tool,
          args: call.args,
          status: 'ok',
          data,
          durationMs: Date.now() - start,
          nextActions: nextActionsFor(call.tool, 'ok'),
        };
      } catch (err) {
        const alt = suggestAlternative(call, allToolNames, calledKeys);
        if (alt) {
          const altTool = toolMap.get(alt.tool);
          if (altTool) {
            try {
              const altStart = Date.now();
              let altTimer: ReturnType<typeof setTimeout> | undefined;
              const altData = await Promise.race([
                altTool.execute(alt.args),
                new Promise<never>((_, reject) => {
                  altTimer = setTimeout(() => reject(new Error('Alt tool timeout')), 20_000);
                }),
              ]).finally(() => clearTimeout(altTimer));
              await setCachedResult(alt.tool, alt.args, altData);
              this.resetToolFailure(alt.tool);
              return {
                tool: alt.tool,
                args: alt.args,
                status: 'ok',
                data: altData,
                durationMs: Date.now() - altStart,
                nextActions: nextActionsFor(alt.tool, 'ok'),
              };
            } catch {
              // Alt also failed — fall through to error
            }
          }
        }

        console.error('handler failed:', errMessage(err));
        // Session-banned-tool stop condition (fix #7): track consecutive
        // failures per tool. After MAX_TOOL_FAILURES_PER_SESSION, ban it for
        // the rest of this investigation so the noDegradedTools guardrail
        // drops it preventively on subsequent steps.
        this.recordToolFailure(call.tool);
        return {
          tool: call.tool,
          args: call.args,
          status: 'error',
          error: errMessage(err),
          durationMs: Date.now() - start,
          nextActions: this.sessionBannedTools.has(call.tool)
            ? nextActionsFor(call.tool, 'error').filter((t) => !this.sessionBannedTools.has(t))
            : nextActionsFor(call.tool, 'error'),
        };
      }
    });

    const settled = await Promise.allSettled(promises);
    for (const s of settled) {
      results.push(
        s.status === 'fulfilled'
          ? s.value
          : { tool: 'unknown', args: {}, status: 'error', error: 'Promise rejected', durationMs: 0, nextActions: [] }
      );
    }
    return results;
  }

  private buildWorkingMemory(state: AgentState): WorkingMemory {
    return rebuildWorkingMemory(state.steps);
  }

  private async degradedToolsNote(): Promise<string> {
    const set = await this.degradedToolsSet();
    if (set.size === 0) return '';
    return `\n<degraded_tools>Deprioritize these tools (high recent failure rate): ${[...set].join(', ')}. Prefer alternatives when available.</degraded_tools>`;
  }

  /**
   * Return the cached set of degraded tools (high recent failure rate from D1
   * tool-health stats). Used both for the prompt note (degradedToolsNote)
   * and to gate tools out of the valid set preventively (filterCtiToolCalls).
   * Cached for 5 min to avoid re-querying D1 every step.
   */
  private async degradedToolsSet(): Promise<Set<string>> {
    const now = Date.now();
    if (this.degradedToolsCache && now - this.degradedToolsCache.at < 5 * 60 * 1000) {
      return this.degradedToolsCache.set;
    }
    let set = new Set<string>();
    try {
      const db = (this.env as unknown as ApiEnv).BRIEFINGS_DB;
      if (db) {
        const { getToolHealth, selectDegradedTools } = await import('../../api/src/lib/agent/observability');
        const degraded = selectDegradedTools(await getToolHealth(db));
        set = new Set(degraded);
      }
    } catch (err) {
      console.error('degradedToolsSet failed:', errMessage(err));
    }
    this.degradedToolsCache = { at: now, note: '', set };
    // Union with session-banned tools (fix #7) so the noDegradedTools guardrail
    // drops them preventively on subsequent steps.
    for (const t of this.sessionBannedTools) set.add(t);
    return set;
  }

  /**
   * Record a tool failure for the session-banned-tool stop condition (fix #7).
   * After MAX_TOOL_FAILURES_PER_SESSION consecutive failures of the same tool,
   * ban it for the rest of this investigation. A success resets the counter.
   */
  private recordToolFailure(tool: string): void {
    const count = (this.sessionToolFailures.get(tool) ?? 0) + 1;
    this.sessionToolFailures.set(tool, count);
    if (shouldBanTool(count) && !this.sessionBannedTools.has(tool)) {
      this.sessionBannedTools.add(tool);
      console.warn(`Tool ${tool} banned for session after ${count} failures.`);
    }
  }

  /** Reset a tool's failure counter on success (consecutive-failure semantics). */
  private resetToolFailure(tool: string): void {
    this.sessionToolFailures.delete(tool);
  }

  /** Reset session-scoped tool-failure state (called when a new investigation starts). */
  private resetSessionToolState(): void {
    this.sessionToolFailures.clear();
    this.sessionBannedTools.clear();
  }

  private async calibrationHint(): Promise<string> {
    const now = Date.now();
    if (this.calibrationHintCache && now - this.calibrationHintCache.at < 10 * 60 * 1000) {
      return this.calibrationHintCache.hint;
    }
    let hint = '';
    try {
      const db = (this.env as unknown as ApiEnv).BRIEFINGS_DB;
      if (db) {
        const { getCalibrationHint } = await import('../../api/src/lib/agent/confidence-calibration');
        hint = await getCalibrationHint(db);
      }
    } catch (err) {
      console.error('calibrationHint failed:', errMessage(err));
    }
    this.calibrationHintCache = { at: now, hint };
    return hint;
  }

  private async doSynthesize(
    state: AgentState,
    ai: ApiEnv['AI'],
    groqKey: string | undefined,
    googleKey: string | undefined,
    nvidiaKey: string | undefined,
    infronKey: string | undefined,
    stepNum: number,
    stepStart: string,
    planReasoning: string
  ): Promise<AgentState> {
    const synthesizeStep: AgentStep = {
      stepNumber: stepNum,
      plan: planReasoning,
      toolCalls: [],
      results: [],
      status: 'running',
      startedAt: stepStart,
    };

    this.broadcastToWatchers({
      type: 'step',
      step: {
        ...synthesizeStep,
        observation: `Synthesizing report from ${state.steps.reduce((n, s) => n + s.results.filter((r) => r.status === 'ok').length, 0)} tool results across ${state.steps.length} step(s)…`,
      },
    });

    try {
      const totalOk = state.steps.reduce((n, s) => n + s.results.filter((r) => r.status === 'ok').length, 0);
      const totalErr = state.steps.reduce((n, s) => n + s.results.filter((r) => r.status === 'error').length, 0);
      const emptyResults = state.steps.reduce(
        (n, s) => n + s.results.filter((r) => r.status === 'ok' && r.data && JSON.stringify(r.data).length < 50).length,
        0
      );

      const synthTracker = this.costTrackers.get(state.id) ?? createCostTracker();
      this.costTrackers.set(state.id, synthTracker);
      const recordUsage = (model: string, inputText: string, outputText: string, role: string) =>
        recordCompletion(synthTracker, model, inputText, outputText, role);

      const result = await synthesizeReport(ai, state.query, state.queryType, state.steps, {
        infronKey,
        groqKey,
        googleKey,
        nvidiaKey,
        dataQuality: { totalOk, totalErr, emptyResults },
        calibrationHint: await this.calibrationHint(),
        onToken: (token) => this.broadcastToWatchers({ type: 'token', token }),
        recordUsage,
      });

      const qaStepNum = stepNum + 1;
      const qaStep: AgentStep = {
        stepNumber: qaStepNum,
        plan: 'QA verification — fact-checking report against collected data',
        toolCalls: [],
        results: [],
        status: 'running',
        startedAt: new Date().toISOString(),
      };

      this.broadcastToWatchers({
        type: 'step',
        step: {
          ...qaStep,
          observation: `Fact-checking report against ${state.steps.reduce((n, s) => n + s.results.filter((r) => r.status === 'ok').length, 0)} collected data points…`,
        },
      });

      try {
        // JUDGE-INDEPENDENCE: extract the provider that generated the report and
        // exclude it from the QA provider chain so the judge is never the same
        // model as the generator. modelUsed is shaped "provider:model".
        const generatorProvider = result.modelUsed.split(':')[0] as 'groq' | 'gemini' | 'nvidia' | undefined;

        const qa = await verifyReport(ai, state.query, state.queryType, result.report, state.steps, {
          groqKey,
          googleKey,
          nvidiaKey,
          recordUsage,
          excludeProvider: generatorProvider,
        });

        let finalReport = result.report;
        let finalActionCard = result.actionCard;
        let finalModelUsed = `${result.modelUsed} → QA:${qa.modelUsed}`;
        let finalQa = {
          qualityScore: qa.qualityScore,
          flaggedClaims: qa.flaggedClaims,
          missingFacts: qa.missingFacts,
        };

        let versioned = addVersion(createVersionedReport(state.id), result.report, {
          qualityScore: qa.qualityScore,
          modelUsed: qa.modelUsed,
          reason: 'Initial synthesis + QA',
        });

        // GAN-STYLE CONVERGENCE LOOP: generator (synthesizer) → evaluator (QA)
        // → generator revises → evaluator re-scores. Stops when:
        //   - score reaches target (80) with no flagged claims
        //   - score stops improving (delta <= 0)
        //   - max 3 iterations (bounded — never spins)
        //   - no fixable issues remaining
        // Each iteration uses a different provider for QA (judge independence).
        let convergenceIteration = 0;
        let prevScore: number | null = null;
        let currentReport = result.report;
        let currentActionCard = result.actionCard;
        let currentModelUsed = result.modelUsed;
        let currentQa = qa;
        let convergenceReason = '';

        while (
          qa.qualityScore >= 0 &&
          shouldRetry(
            currentQa.qualityScore,
            currentQa.flaggedClaims.length,
            currentQa.missingFacts.length,
            stepNum,
            state.maxSteps,
            convergenceIteration,
            3 // maxRetries — GAN convergence allows up to 3 iterations
          )
        ) {
          const convCheck = shouldConverge(
            currentQa.qualityScore,
            prevScore,
            currentQa.flaggedClaims.length,
            currentQa.missingFacts.length,
            convergenceIteration,
            3,
            80
          );
          if (!convCheck.continue) {
            convergenceReason = convCheck.reason;
            break;
          }

          this.broadcastToWatchers({
            type: 'step',
            step: {
              ...qaStep,
              observation: `GAN convergence iteration ${convergenceIteration + 1}: ${convCheck.reason}`,
            },
          });

          const workingMem = this.buildWorkingMemory(state);
          const memStr = memoryToPrompt(workingMem);
          const correctionPrompt = buildSelfCorrectionPrompt(
            currentReport,
            { flaggedClaims: currentQa.flaggedClaims, missingFacts: currentQa.missingFacts, qualityNotes: '' },
            memStr
          );

          const { report: correctedText, modelUsed: correctedModel } = await synthesizeReport(
            ai,
            state.query,
            state.queryType,
            state.steps,
            {
              infronKey,
              groqKey,
              googleKey,
              nvidiaKey,
              dataQuality: { totalOk, totalErr, emptyResults },
              correctionPrompt,
              recordUsage,
            }
          );

          const { report: correctedProse, actionCard: correctedCard } = splitSynthOutput(correctedText);

          // QA excludes the generator (judge independence)
          const correctedProvider = correctedModel.split(':')[0] as 'groq' | 'gemini' | 'nvidia' | undefined;
          const qaNext = await verifyReport(ai, state.query, state.queryType, correctedProse, state.steps, {
            groqKey,
            googleKey,
            nvidiaKey,
            recordUsage,
            excludeProvider: correctedProvider,
          });

          versioned = addVersion(versioned, correctedProse, {
            qualityScore: qaNext.qualityScore,
            modelUsed: qaNext.modelUsed,
            reason: `GAN convergence iteration ${convergenceIteration + 1}`,
          });

          prevScore = currentQa.qualityScore;

          // ADOPTION GATE (audit fix 2026-08): adopt the corrected report when it
          // is strictly better on EITHER axis — score OR flagged-claims count.
          // The previous gate was purely numeric (`qaNext.qualityScore >
          // currentQa.qualityScore`), so a corrected report that removed 3
          // flagged hallucinations but held the same score (e.g. 72→72 because
          // it also added missing facts that balanced the rubric) was REJECTED
          // and the loop stopped, keeping the original report with its
          // hallucinations. The convergence-stop condition (shouldConverge)
          // already handles the true no-improvement case (score delta <= 0 AND
          // no claim reduction) — the adoption gate must not be stricter than
          // the stop condition.
          const claimsReduced = qaNext.flaggedClaims.length < currentQa.flaggedClaims.length;
          const scoreImproved = qaNext.qualityScore > currentQa.qualityScore;
          if (scoreImproved || claimsReduced) {
            // Improvement — adopt the corrected version
            currentReport = correctedProse;
            currentActionCard = correctedCard ?? currentActionCard;
            currentModelUsed = `${currentModelUsed} → QA:${qaNext.modelUsed}`;
            currentQa = qaNext;
            const how = scoreImproved && claimsReduced ? 'score + claims' : scoreImproved ? 'score' : 'claims';
            convergenceReason = `Improved (${how}): ${qa.qualityScore}→${qaNext.qualityScore}/100, flagged ${currentQa.flaggedClaims.length}→${qaNext.flaggedClaims.length} (iteration ${convergenceIteration + 1})`;
          } else {
            // No improvement on either axis — stop the loop (convergence)
            convergenceReason = `Convergence: no improvement (score ${currentQa.qualityScore}→${qaNext.qualityScore}, flagged ${currentQa.flaggedClaims.length}→${qaNext.flaggedClaims.length}). Stopping after iteration ${convergenceIteration + 1}.`;
            break;
          }

          convergenceIteration++;
        }

        finalReport = currentReport;
        finalActionCard = currentActionCard;
        finalModelUsed = currentModelUsed;
        finalQa = currentQa;

        if (convergenceIteration > 0) {
          qaStep.observation = `QA complete (GAN convergence, ${convergenceIteration} iteration${convergenceIteration > 1 ? 's' : ''}). ${convergenceReason}`;
        } else if (qa.qualityScore < 0) {
          qaStep.observation = `QA skipped — all LLM providers exhausted. Original report preserved.`;
        } else {
          qaStep.observation = `QA complete. Score: ${qa.qualityScore}/100. Flagged: ${qa.flaggedClaims.length} claims. Missing: ${qa.missingFacts.length} facts.`;
        }

        const { report: proseOnly, actionCard: qaCard } = splitSynthOutput(finalReport);
        state.report = proseOnly;
        state.actionCard = qaCard ?? finalActionCard;
        state.modelUsed = finalModelUsed;
        state.qa = finalQa;

        if (versioned.versions.length > 1) {
          const diff = getVersionDiff(versioned, 1, versioned.currentVersion);
          state.reportVersioning = {
            versions: versioned.versions.map((v) => ({
              version: v.version,
              qualityScore: v.qualityScore,
              modelUsed: v.modelUsed,
              reason: v.reason,
            })),
            diff: diff
              ? {
                  fromVersion: diff.fromVersion,
                  toVersion: diff.toVersion,
                  fromScore: diff.fromScore,
                  toScore: diff.toScore,
                  additions: diff.additions,
                  deletions: diff.deletions,
                }
              : undefined,
          };
        }

        qaStep.status = 'done';
        qaStep.completedAt = new Date().toISOString();
      } catch (qaErr) {
        console.error('handler failed:', errMessage(qaErr));
        qaStep.observation = `QA failed: ${errMessage(qaErr)}. Original report preserved.`;
        qaStep.status = 'error';
        qaStep.completedAt = new Date().toISOString();
        state.report = result.report;
        state.actionCard = result.actionCard;
        state.modelUsed = result.modelUsed;
      }

      // ── Self-evaluation (5-axis scorecard) ──────────────────────────
      // Runs after QA verification. Additive — never blocks delivery.
      try {
        const selfEval = await selfEvaluateReport(
          ai,
          state.query,
          state.queryType,
          state.report ?? result.report,
          state.steps,
          {
            groqKey,
            nvidiaKey,
            googleKey,
            recordUsage,
          }
        );
        if (selfEval) {
          state.selfEval = selfEval;
          qaStep.observation =
            (qaStep.observation ? qaStep.observation + ' ' : '') +
            `Self-eval: ${selfEval.overallScore}/5 (${selfEval.modelUsed}). Top gap: ${selfEval.topGap.slice(0, 100)}`;
        }
      } catch (selfEvalErr) {
        console.error('self-eval failed:', errMessage(selfEvalErr));
      }

      // ── Introspection: extract tool failures for the UI ────────────
      // Populates state.dataGaps so the frontend can surface what was
      // missed. The synthesizer prompt already includes the data-gaps
      // section in the report prose; this is the structured version.
      try {
        const failures = extractToolFailures(state.steps);
        if (failures.length > 0) {
          state.dataGaps = failures;
        }
      } catch (introErr) {
        console.error('introspection failed:', errMessage(introErr));
      }

      const toolCounts = new Map<string, number>();
      for (const s of state.steps) {
        for (const r of s.results) {
          if (r.status === 'ok' && r.data) {
            const count = (toolCounts.get(r.tool) ?? 0) + 1;
            toolCounts.set(r.tool, count);
          }
        }
      }
      state.sources = [...toolCounts.entries()]
        .map(([name, items]) => ({
          name: name.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
          items,
        }))
        .sort((a, b) => b.items - a.items);

      if (state.actionCard) {
        const graph = extractGraphFromSteps(state.steps);
        if (graph.nodes.length > 0) state.actionCard.graph = graph;
      }

      const findings: SpecialistFinding[] = [];
      const seenFinding = new Set<string>();
      for (const s of state.steps) {
        for (const r of s.results) {
          if (r.status !== 'ok' || !r.data) continue;
          for (const f of extractFindings(r, undefined, s.stepNumber)) {
            const key = `${f.type}:${f.value.toLowerCase()}`;
            if (seenFinding.has(key)) continue;
            seenFinding.add(key);
            findings.push(f);
          }
        }
      }
      state.findings = findings;

      if (state.actionCard) {
        const existing = new Set(state.actionCard.iocs.map((i) => i.value.toLowerCase()));
        const confMap = { high: 'Confirmed', medium: 'Probable', low: 'Possible' } as const;
        for (const f of findings) {
          if (existing.has(f.value.toLowerCase())) continue;
          const type = classifyFindingIocType(f);
          if (!type) continue;
          state.actionCard.iocs.push({ type, value: f.value, confidence: confMap[f.confidence], source: f.source });
          existing.add(f.value.toLowerCase());
        }
      }

      state.steps.push(synthesizeStep);
      state.steps.push(qaStep);
      state.currentStep = qaStepNum;
      state.status = 'done';
      state.completedAt = new Date().toISOString();
      state.cost = {
        usd: Math.round(synthTracker.totalCostUsd * 10000) / 10000,
        tokens: synthTracker.totalInputTokens + synthTracker.totalOutputTokens,
        llmCalls: synthTracker.entries.length,
      };

      const db = (this.env as unknown as ApiEnv).BRIEFINGS_DB;
      if (db) {
        const mem = this.buildWorkingMemory(state);
        // MEMORY-ADMISSION GATE: only persist findings from investigations that
        // passed QA (qualityScore >= 70) AND only LLM-confirmed keyFacts (not
        // heuristic fallback stubs). Agent-inferred or fallback-sourced facts
        // must not become ground-truth memory for the next investigation.
        const qualityScore = state.qa?.qualityScore ?? 0;
        const llmKeyFacts = state.steps
          .filter((s) => s.observerFindings?.provenance === 'llm')
          .flatMap((s) => s.observerFindings?.keyFacts ?? [])
          .slice(0, 10);
        await saveInvestigationMemory(db, {
          query: state.query,
          queryType: state.queryType,
          iocs: mem.iocs.map((i) => ({ type: i.type, value: i.value, confidence: i.confidence })),
          actors: mem.actors,
          mitre: mem.mitre.map((m) => m.id),
          cves: mem.cves,
          // Persist LLM-confirmed keyFacts only when QA passed; otherwise persist
          // an empty array so the investigation is recorded (for history) but its
          // unverified facts don't contaminate future investigations.
          keyFindings: qualityScore >= 70 ? llmKeyFacts : [],
          qualityScore,
          modelUsed: state.modelUsed ?? '',
          completedAt: state.completedAt,
        });

        const { extractKnowledgeGraph, recordKnowledgeGraph } = await import('../../api/src/lib/agent/knowledge-graph');
        await recordKnowledgeGraph(db, extractKnowledgeGraph(state.steps));

        const { recordMetrics } = await import('../../api/src/lib/agent/observability');
        const durationMs = new Date(state.completedAt).getTime() - new Date(state.startedAt).getTime();
        const toolsUsed = [...new Set(state.steps.flatMap((s) => s.results.map((r) => r.tool)))];
        const toolTimings = state.steps.flatMap((s) =>
          s.results.map((r) => ({ name: r.tool, ms: r.durationMs, ok: r.status === 'ok' }))
        );
        const diff = state.reportVersioning?.diff;
        await recordMetrics(db, {
          query: state.query,
          status: state.status,
          totalSteps: state.steps.length,
          durationMs,
          qualityScore: state.qa?.qualityScore ?? 0,
          modelUsed: state.modelUsed ?? '',
          toolsUsed,
          toolTimings,
          meta: {
            parallelBurst: state.usedParallelBurst === true,
            selfCorrection: (state.reportVersioning?.versions.length ?? 0) > 1,
            scoreDelta: diff ? diff.toScore - diff.fromScore : undefined,
            routingRefined: resolveRoutingQueryType(state.query, state.queryType) !== state.queryType,
            findings: state.findings?.length ?? 0,
            graphNodes: state.actionCard?.graph?.nodes.length ?? 0,
            costUsd: Math.round(synthTracker.totalCostUsd * 10000) / 10000,
            tokens: synthTracker.totalInputTokens + synthTracker.totalOutputTokens,
            llmCalls: synthTracker.entries.length,
            convergenceIterations: (state.reportVersioning?.versions.length ?? 1) - 1,
            selfEvalScore: state.selfEval?.overallScore,
            dataGapsCount: state.dataGaps?.length ?? 0,
          },
          error: state.error ?? undefined,
          completedAt: state.completedAt,
        });

        const { recordCalibration } = await import('../../api/src/lib/agent/confidence-calibration');
        const predictedConfidence = state.actionCard?.verdict.confidence ?? 'medium';
        const calScore = state.qa?.qualityScore ?? 0;
        await recordCalibration(db, {
          query: state.query,
          predictedConfidence,
          actualOutcome: calScore >= 75 ? 'correct' : calScore >= 50 ? 'partial' : 'incorrect',
          qualityScore: calScore,
          modelUsed: state.modelUsed ?? '',
          recordedAt: state.completedAt,
        });
      }

      // ── Agent → SOC automation feedback loop ────────────────────────
      // When the investigation produced IOCs and passed QA (qualityScore >= 70),
      // automatically create a SOC playbook with detection/containment actions
      // and add IOCs to the watchlist. This closes the loop: investigation →
      // automated response. Only fires for SOC-relevant query types.
      try {
        // Guard: only fire on successful investigations with IOCs
        if (state.status === 'done') {
          const isSocRelevant = [
            'soc',
            'incident',
            'alert',
            'playbook',
            'detection',
            'ip',
            'domain',
            'hash',
            'url',
            'ransomware',
            'malware',
          ].includes(state.queryType);
          const qualityScore = state.qa?.qualityScore ?? 0;
          const iocs = state.actionCard?.iocs ?? [];
          const mitreTechniques = state.actionCard?.mitre ?? [];

          if (isSocRelevant && qualityScore >= 70 && iocs.length > 0) {
            const tokenSecret = this.env.INTERNAL_TOKEN_SECRET;
            if (tokenSecret) {
              const internalToken = await signInternalToken('investigator-do', tokenSecret);
              const headers = { 'content-type': 'application/json', 'x-internal-token': internalToken };

              // Create a SOC playbook from the investigation findings
              const playbookName = `Auto: ${state.query.slice(0, 60)}`;
              const playbookActions = [
                {
                  id: 'detect',
                  type: 'mcp_tool',
                  label: `Detect: ${iocs
                    .slice(0, 5)
                    .map((i) => i.value)
                    .join(', ')}`,
                  config: { tool: 'generate_hunting_queries', args: { threat: state.query } },
                  timeout_seconds: 30,
                },
                {
                  id: 'contain',
                  type: 'add_note',
                  label: `Contain: ${
                    mitreTechniques
                      .slice(0, 3)
                      .map((m) => m.id)
                      .join(', ') || 'Review IOCs for blocking'
                  }`,
                  config: { note: `Investigation ${state.id} found ${iocs.length} IOCs. Review and block.` },
                  timeout_seconds: 10,
                },
                {
                  id: 'watchlist',
                  type: 'mcp_tool',
                  label: `Add ${iocs.length} IOCs to watchlist`,
                  config: {
                    tool: 'ioc_watchlist_add',
                    args: { iocs: iocs.map((i) => ({ type: i.type, value: i.value })) },
                  },
                  timeout_seconds: 15,
                },
              ];

              const pbRes = await this.env.SELF.fetch(
                new Request('https://api.local/api/v1/soc/playbooks', {
                  method: 'POST',
                  headers,
                  body: JSON.stringify({
                    name: playbookName,
                    description: `Auto-generated from investigation ${state.id}. Query: ${state.query}. QA: ${qualityScore}/100.`,
                    trigger: 'manual',
                    actions: playbookActions,
                    enabled: false,
                    tags: ['auto-generated', state.queryType, `qa-${qualityScore}`],
                  }),
                })
              );

              if (pbRes.ok) {
                console.log(`Agent → SOC: created playbook from investigation ${state.id}`);
              }
            }
          }
        }
      } catch (socErr) {
        // Non-fatal — the investigation is still complete even if SOC
        // playbook creation fails.
        console.error('Agent → SOC feedback loop failed:', errMessage(socErr));
      }

      this.costTrackers.delete(state.id);
    } catch (err) {
      console.error('handler failed:', errMessage(err));
      synthesizeStep.status = 'error';
      synthesizeStep.completedAt = new Date().toISOString();
      state.steps.push(synthesizeStep);
      state.status = 'error';
      state.error = `Synthesis failed: ${errMessage(err)}`;
      state.completedAt = new Date().toISOString();
    }

    return state;
  }

  private async persist(state: AgentState): Promise<void> {
    const db = (this.env as unknown as ApiEnv).BRIEFINGS_DB;
    if (!db) return;

    const trimmedSteps = state.steps.map((s) => ({
      ...s,
      results: s.results.map((r) => ({
        ...r,
        data: r.data ? truncateData(r.data, 2000) : r.data,
      })),
    }));

    await db
      .prepare(
        `INSERT INTO agent_sessions (id, query, query_type, status, steps_json, report_json, model_used, total_steps, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
           status=excluded.status,
           steps_json=excluded.steps_json,
           report_json=COALESCE(excluded.report_json, agent_sessions.report_json),
           model_used=COALESCE(excluded.model_used, agent_sessions.model_used),
           total_steps=excluded.total_steps,
           updated_at=excluded.updated_at`
      )
      .bind(
        state.id,
        state.query,
        state.queryType,
        state.status,
        JSON.stringify(trimmedSteps),
        state.report ?? null,
        state.modelUsed ?? null,
        state.currentStep,
        state.startedAt,
        new Date().toISOString()
      )
      .run();
  }
}
