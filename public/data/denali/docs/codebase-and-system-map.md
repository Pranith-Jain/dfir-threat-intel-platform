# Denali codebase and system map

This is the living, descriptive map of the Denali repository. It answers “where does this
behavior live?” and “how does data move through the product?” The numbered architecture
decision records remain authoritative for why individual boundaries were chosen.

Read these documents first when joining the project:

1. [`AGENTS.md`](../../AGENTS.md) for repository-wide safety and contribution constraints.
2. This system map for code ownership and end-to-end flow.
3. [ADR 0028](0028-hosted-multi-tenant-runtime.md) before changing authentication, tenancy,
   persistence, hosted routing, secrets, durable work, or provider onboarding.
4. The feature-specific ADR linked from the routing table near the end of this document.

## Product contract

Denali is an evidence-backed AI security product. Its central rule is that different evidence
classes stay different:

```text
provider/repository observation
        |
        v
inventory assertions + coverage ------------------------------------+
        |                                                            |
        +-> exact relationships and code-to-cloud lineage            |
        |                                                            v
scanner/configuration observation -> findings or vulnerabilities -> deterministic issues
                                                                     ^
runtime metadata -----------------> activity -> detections -----------+
```

Inventory is not a finding. Activity is not a detection. A source/deployment relationship is
not a security verdict. Missing or unsupported coverage is not a safe result. Issue and
detection engines may compose retained evidence, but they never create facts that a connector
did not observe.

The current product surfaces are inventory, findings, vulnerabilities, issues, code-to-cloud,
runtime activity, runtime detections, source coverage, provider connections, governance, and a
manifest-bounded Golden Path demonstration.

## Runtime topologies

### Local development and demonstration

```text
Browser :3080
  -> nginx container
       -> React/Vite static application
       -> /api/* proxy
            -> FastAPI container :8088
                 -> PostgreSQL 16 container :55450
```

Local mode uses `DENALI_AUTH_MODE=local` and the fixed development tenant
`00000000-0000-4000-8000-000000000001`. It has no end-user authorization layer and must not be
treated as a production deployment. `compose.yaml`, `Dockerfile.api`, `Dockerfile.web`, and
`web/nginx.conf` define this path.

### Hosted invitation-only pilot

```text
Browser
  -> denali.transilience.cloud
  -> Vercel static app and same-origin /api/* rewrite
  -> Modal FastAPI authorization boundary
       -> Modal validation_worker for durable connection validation
  -> Neon PostgreSQL source of truth

Clerk Organization session
  -> signed JWT
  -> FastAPI verification
  -> stable internal Denali tenant UUID
```

Hosted code is in `modal_app.py`, `web/vercel.mjs`, `src/denali/api/auth.py`, and the hosted
migrations. The authoritative topology, authorization model, secret ownership, and durable-work
rules are in [ADR 0028](0028-hosted-multi-tenant-runtime.md). The executable deployment state is
in [`docs/deployment/pilot-launch-checklist.md`](../deployment/pilot-launch-checklist.md).

The browser never calls Modal or Neon directly. It always calls same-origin `/api/*`. Vercel
contains only public client/server routing configuration. Backend, database, Clerk backend, and
provider integration secrets belong in Modal Secrets.

## Repository map

| Path                           | Responsibility                                                                                                                                                                 |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `src/denali/domain/`           | Provider-neutral immutable contracts for inventory, findings, vulnerabilities, activity, detections, issues, and deployment identity.                                          |
| `src/denali/connectors/`       | Bounded collectors and import adapters. Connectors normalize external observations into domain batches and explicit coverage.                                                  |
| `src/denali/connections/`      | Self-service AWS, Azure, Microsoft Entra, GCP, Google Workspace, GitHub, and Azure Repos connection plans, validators, setup artifacts, and credential acquisition boundaries. |
| `src/denali/store/`            | PostgreSQL migrations, ingestion, tenant-scoped queries, governance, issue/detection evaluation persistence, connections, setup state, and durable validation jobs.            |
| `src/denali/api/`              | FastAPI routes, authentication/authorization, setup callbacks, validation orchestration, response contracts, and hosted/local mode selection.                                  |
| `src/denali/issues/`           | Deterministic cross-evidence issue correlation.                                                                                                                                |
| `src/denali/detections/`       | Deterministic runtime detection evaluation.                                                                                                                                    |
| `src/denali/golden_path.py`    | Manifest loading, tenant reset preview/apply, and acceptance verification.                                                                                                     |
| `web/src/`                     | React product, API client, URL-state navigation, presentation rules, types, and CSS.                                                                                           |
| `src/denali/store/migrations/` | Append-only numbered PostgreSQL schema migrations.                                                                                                                             |
| `tests/` and `web/tests/`      | Domain, connector, API, persistence, tenancy, durable-job, navigation, and presentation contracts.                                                                             |
| `golden-paths/`                | Versioned local demonstration acceptance manifests.                                                                                                                            |
| `docs/architecture/`           | Decisions and this living system map.                                                                                                                                          |
| `docs/deployment/`             | Hosted deployment and provider operator runbooks.                                                                                                                              |
| `docs/product/`                | Presenter guides, acceptance evidence, roadmap, and product semantics.                                                                                                         |
| `docs/handoffs/`               | Time-bounded operational checkpoints for continuing work safely.                                                                                                               |

## Backend request path

`src/denali/api/app.py` is the composition root for the HTTP API. `create_app()` selects local or
Clerk authentication, attaches the PostgreSQL repository, registers public setup callbacks and
protected `/v1/*` routes, and wires connection validators and collection dispatchers.

In hosted mode, `src/denali/api/auth.py` verifies the Clerk token signature, issuer, expiry,
authorized party, session state, active Organization, role, and optional Organization allowlist.
The server maps the Clerk Organization to an internally generated Denali UUID. Client-provided
tenant selectors never choose the tenant. Read routes allow `org:member` and `org:admin`; mutation
routes require `org:admin`.

Provider callbacks are public only at the middleware layer. They resolve tenant and connection
from expiring, one-time setup state stored before redirect, not from browser Organization state.

## Provider onboarding and validation

The connection lifecycle is intentionally separate from collection:

```text
create connection plan
  -> publish or launch provider setup
  -> callback/completion using one-time state
  -> validate declared read planes
  -> healthy or degraded connection evidence

explicit collection action
  -> provider API reads inside selected boundary
  -> inventory/findings/activity batch
  -> PostgreSQL ingestion and coverage
```

A healthy connection proves that declared entrypoints were callable for the recorded identity and
scope. It does not prove collection ran, inventory exists, or risk is absent.

`src/denali/connections/` owns setup and validation:

- AWS: tenant-owned assume role, external ID, selected account and Regions.
- Azure: Denali multi-tenant application consent and selected subscriptions.
- Microsoft Entra: tenant-bound admin consent for the disclosed Graph application-read bundle.
- GCP: unique per-connection keyless principal and selected projects/resources.
- GitHub: GitHub App installation and exact repository selection.
- Azure Repos: one-time delegated organization proof and exact repository selection followed by
  app-only, read-only steady-state collection.
- Google Workspace: domain-wide delegation for one disclosed Admin Reports read scope.

Connection validation is durable in hosted mode. `src/denali/api/validation.py` and migration
`011_hosted_pilot.sql` implement PostgreSQL jobs, deduplication, leases, bounded terminal state,
and Modal dispatch. All provider collection uses the same durable design through
`src/denali/api/collection.py`, migration `013_connection_collection_jobs.sql`, and the provider
kind expansion in migration `014_provider_collection_jobs.sql`.

## Connector and importer inventory

All connectors return one or more immutable domain batches with connector ID, connection ID,
collection run ID, scope key, timestamp, observations, and coverage.

| Area                  | Main modules                                                                                                      | Current observations                                                                                                                                                          |
| --------------------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Repository source     | `repository.py`, `github_repository.py`, `repository_posture.py`                                                  | Immutable repository revision, bounded source tree, AI declarations, posture, deployment identifiers, model/tool/action declarations.                                         |
| Code to cloud         | `code_to_cloud.py`, provider deployment modules                                                                   | Exact source declaration to independently observed workload joins; unmatched and ambiguous candidates remain visible.                                                         |
| AWS AI                | `aws_bedrock.py`, `aws_agentcore.py`, `aws_agent_runtime_activity.py`, `aws_stack.py`, `aws_deployments.py`       | Bedrock, AgentCore, metadata-only ordered runtime spans, Lambda, ECS, EKS, SageMaker, CloudFormation topology and posture.                                                    |
| Azure                 | `azure_deployments.py`, `azure_agent_runtime_activity.py`                                                         | Container Apps, Function Apps, AKS, deployment identity and control-plane metadata, plus opt-in metadata-only Azure Foundry agent/model/tool spans from Application Insights. |
| GCP                   | `gcp_deployments.py`, `gcp_vertex_activity.py`                                                                    | Cloud Run, Cloud Run functions Gen2, GKE, Vertex model references, Cloud Audit Log runtime metadata.                                                                          |
| Microsoft Entra       | `entra_ai.py`                                                                                                     | Catalog-matched AI enterprise apps, service principals, grants, app roles, sign-ins, and application-management audits.                                                       |
| Runtime imports       | `activity_json.py`, `aws_bedrock_activity.py`, `aws_agent_runtime_activity.py`, `azure_agent_runtime_activity.py` | Provider-neutral Bedrock, Vertex, Workspace Gemini, and Entra activity plus provider-native AgentCore and Azure Foundry OpenTelemetry/OpenInference session spans.            |
| Software supply chain | `syft_json.py`, `grype_json.py`                                                                                   | Component occurrences, scan subject identity, vulnerabilities, fixes, and exact component correlation.                                                                        |
| External findings     | `ocsf_findings.py`                                                                                                | Scanner-neutral finding import without invented graph identity.                                                                                                               |
| Kubernetes            | `kubernetes.py`                                                                                                   | Bounded workload identity import shared across EKS, GKE, and AKS.                                                                                                             |
| MCP                   | `mcp_http.py`                                                                                                     | Initialization and paginated `tools/list`; no tool invocation.                                                                                                                |
| Fixture               | `demo.py`                                                                                                         | Explicitly labelled demonstration data only; forbidden by the Golden Path manifest.                                                                                           |

Collectors must bound pagination, record counts, file/tree bytes, time windows, and selected
provider scope. Error details are sanitized. Raw prompts, responses, tokens, credentials, secret
values, arbitrary source snapshots, and caller IPs are excluded from retained evidence.

## Domain and evidence model

`src/denali/domain/` contains the contracts connectors and evaluators share:

- `inventory.py`: `AssetRef`, `AssetAssertion`, `RelationshipAssertion`, `Evidence`, lifecycle,
  governance, coverage, and connector capabilities.
- `findings.py`: atomic evaluated conditions and affected-resource references.
- `vulnerabilities.py`: scanner-neutral vulnerability IDs, component occurrences, scan subjects,
  fix state, exploit state, and match method.
- `activity.py`: immutable provider-neutral runtime records, outcome, actor/model/tool entities,
  and exact/unresolved correlation.
- `detections.py`: evidence links and deterministic runtime detection candidates/evaluations.
- `issues.py`: findings, relationships, detections, activities, path nodes, and issue candidates.
- `deployments.py`: normalized deployment identifiers and comparison results.

Natural keys are provider-qualified exact identifiers. Relationships require explicit connector
assertions; activity or findings cannot manufacture them. Assertions retain source type, safe
locator, observed timestamp, and bounded payload fields.

Coverage states are `complete`, `partial`, `failed`, `not_supported`, or `unknown`. A new
collection run may update current assertions only inside its exact connector/connection/scope
boundary. Failed or partial absence does not withdraw earlier assets or close evidence.

## Persistence

PostgreSQL is the only durable application store. `PostgresInventoryRepository` in
`src/denali/store/repository.py` owns ingestion and query transactions. Every tenant-owned call
accepts the server-resolved Denali tenant UUID and every SQL path must retain that predicate.

The migration sequence is append-only:

| Migrations  | Capability                                                                                               |
| ----------- | -------------------------------------------------------------------------------------------------------- |
| `001`–`003` | Inventory, findings, issues.                                                                             |
| `004`–`006` | Vulnerabilities, scan subjects, component correlation.                                                   |
| `007`–`009` | Runtime activity, detections, runtime issue evidence.                                                    |
| `010`       | Provider connections and setup lifecycle.                                                                |
| `011`–`012` | Hosted tenant mapping, durable validation jobs, and tenant/connection constraints.                       |
| `013`–`018` | Durable provider collection, vulnerability evidence, Google Workspace, and Azure Repos jobs.             |
| `019`       | AWS AgentCore span/session fields, runtime collection jobs, and approval-gated manual response requests. |
| `020`       | Azure Foundry runtime scope and durable collection-job kind.                                             |

Never edit an applied migration. Add a new numbered migration. `src/denali/store/db.py` runs each
migration once under a transaction-scoped PostgreSQL advisory lock. Hosted API startup never
runs migrations; `modal_app.py::migrate_database` is explicit and uses the direct migration DSN.

## Deterministic evaluation

The two evaluation engines are pure over repository snapshots and persist only evidence-linked
results:

- `src/denali/detections/engine.py` evaluates runtime observations. Current rules include repeated
  failed Entra AI sign-ins, high-impact Entra consent, and invocation of an exact unreviewed AI
  model, plus AWS AgentCore undeclared-model drift, unapproved tool execution, and
  retrieval-to-mutation session sequences.
- `src/denali/issues/engine.py` composes findings, exact graph relationships, detections, and
  temporally ordered activity when a rule's evidence threshold is satisfied.

Evaluations retain coverage, incomplete candidates, ambiguous references, correlation keys,
evidence links, first/last seen times, and resolution state. An expiring observation window alone
does not prove remediation.

## Code-to-cloud path

Repository collection extracts literal deployment declarations, model references, dependency
identity, and declared tool/action call sites at an immutable commit. Cloud collectors observe
runtime resources and execution identities independently. Correlation compares exact normalized
identifiers and stores the evidence class; it does not rely on display-name similarity.

The displayed lineage is conceptually:

```text
repository agent declaration
  -> deployed workload
  -> execution identity
  -> model
  -> declared tools/actions
  -> evidence-linked findings, vulnerabilities, runtime activity, and issues
```

Tool/action declarations say what source is coded to invoke. They are labelled **not observed**
until a successful runtime event links the exact tool—and for an action, its exact target—in the
same observation. Name similarity and trace proximity are insufficient.

## Frontend

The web application is deliberately small and centralized:

- `main.tsx` initializes Clerk when configured and mounts the application.
- The shared `app-sidebar` app switcher is temporarily paused. Its script in `index.html` and
  mount in `App.tsx` are commented out, and `styles.css` sets its product-rail offset to zero.
  To restore it, re-enable both comments and the 56px rail together. Its product list,
  destinations, icons, and active-product behavior remain owned by
  `transilienceai/shared-components`; do not duplicate that configuration in Denali.
- `App.tsx` owns page composition, shared data loading, drawers, filters, governance controls,
  connection workflows, the provider-neutral Agent Execution Graph, and product presentation.
- `api.ts` is the typed same-origin `/api/v1/*` client and attaches Clerk session authorization.
- `navigation.ts` defines canonical routes and URL-serialized page/filter/drawer/tab state.
- `presentation.ts` contains evidence-applicability rules that should not live in JSX.
- `types.ts` mirrors API response contracts.
- `design-tokens.css` is the vendored, plain-CSS adapter for the canonical Figma-backed
  Transilience token snapshot. It contains Brand -> Alias -> Mapped role tokens and the shared
  light/dark and responsive-type contract. Do not hand-edit token values; refresh the snapshot
  from the upstream design-system export.
- `styles.css` owns Denali-specific composition and component layouts. Product UI consumes mapped
  `--color-role-*`, spacing, radius, type, gradient, and shadow tokens from `design-tokens.css`;
  it must not introduce a competing application palette or font scale.
- `vercel.mjs` defines the production build, `/api/*` rewrite, and SPA fallback.

Browser Back/Forward, pasted deep links, refresh, drawer close, and connection callbacks must
preserve the canonical URL contract. New backend routes normally require a typed client method,
role classification, tenant-scoped repository behavior, and tests.

The **AI application discovery** surface presents catalog matches that require review. A catalog
match alone does not prove an application is unauthorized or used. “Shadow AI” is reserved for
observed use that violates an explicit policy.

## Golden Path demonstration

`golden-paths/code-to-cloud.yaml` is a versioned acceptance contract, not a seed. The current local
story contains:

- Anna: GitHub source to AWS Lambda/ECS, execution identity, Bedrock models, seven declared
  actions, six findings, three fixable image vulnerabilities, and two correlated issues.
- Summit: GitHub source to GCP Cloud Run, dedicated service account, Gemini 2.5 Flash, one real
  Vertex `GenerateContent` activity record, and one unreviewed-model detection.
- Entra discovery: two real catalog-matched enterprise applications with explicit permission and
  audit coverage limits.

The manifest caps row counts, requires expected repositories/workloads/edges, and rejects fixture
connectors. `src/denali/golden_path.py` previews or applies a tenant-scoped reset and verifies the
retained boundary. Never run `denali-demo-seed` against the Golden Path tenant.

See [`docs/product/golden-path-demo.md`](../product/golden-path-demo.md) for the presenter sequence,
exact resource identifiers, coverage limits, and teardown notes.

## Security and secret boundaries

- Never place a backend secret in `VITE_*`, Vercel, source, fixtures, screenshots, logs, or docs.
- Never persist customer cloud access keys, service-account JSON, provider access tokens, GitHub
  user tokens, setup codes, private keys, or raw source archives.
- Vercel receives only the Clerk publishable key, Modal API origin, and optional public
  PostHog project token/host for [anonymous product analytics](../development/product-analytics.md).
- Modal Secrets own backend/database/provider integration material.
- Tenant cloud access is assume-role, consent, principal-grant, or App-installation based.
- Provider callbacks use verified one-time state and cannot take a tenant from the browser.
- Operational logs may contain structured tenant, connection, and job UUIDs, never credentials or
  raw provider payloads.

## Testing and acceptance

The default gates are:

```bash
pytest
ruff check .
npm --prefix web ci
npm --prefix web test -- --run
npm --prefix web run build
```

PostgreSQL integration tests require `DENALI_TEST_DSN`. Authentication changes require invalid and
expired tokens, authorized-party enforcement, missing Organization, member/admin roles,
Organization switching, and cross-tenant tests. Durable worker changes require duplicate dispatch,
retry, timeout, worker failure, stale lease, and API-container replacement cases.

Mocks prove contracts, not live onboarding. A provider becomes hosted-ready only after create,
setup/callback, validate, disable, and delete succeed in the hosted product; collection is accepted
separately.

## Safe change recipes

### Add a connector

1. Define or reuse provider-neutral domain types.
2. Bound scope, pagination, records, time, and payload fields.
3. Return explicit coverage for every declared plane.
4. Add repository ingestion/query behavior with tenant predicates.
5. Add API/UI exposure only if the observation is a new product surface.
6. Test success, empty-complete, partial, failure, duplicates, and withdrawal boundaries.
7. Add or update the relevant ADR and operator documentation.

### Add an issue or detection rule

1. State the exact evidence threshold and applicability coverage.
2. Keep the engine deterministic over a snapshot.
3. Retain evidence links and incomplete/ambiguous candidates.
4. Do not interpret lack of data as lack of risk.
5. Test positive, negative, stale, duplicate, and missing-link cases.

### Add a hosted workflow

1. Add a PostgreSQL job table in a new migration.
2. Add an idempotent claim, lease, timeout, safe terminal state, and retry contract.
3. Spawn a Modal worker with durable identifiers only.
4. Poll PostgreSQL, not process memory.
5. Add tenant isolation and API-container replacement tests.

## Documentation routing

| Question                                                  | Authoritative document                                                                                                                                                                                                                                                   |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Hosted tenancy, Clerk, Modal, Neon, secrets, durable work | [ADR 0028](0028-hosted-multi-tenant-runtime.md)                                                                                                                                                                                                                          |
| Inventory and standalone product boundary                 | [ADR 0001](0001-standalone-product.md)                                                                                                                                                                                                                                   |
| OCSF interchange boundary                                 | [ADR 0002](0002-ocsf-boundary.md)                                                                                                                                                                                                                                        |
| Evidence-bearing issues                                   | [ADR 0005](0005-evidence-bearing-issues.md)                                                                                                                                                                                                                              |
| Vulnerabilities and component identity                    | [ADR 0006](0006-sbom-first-vulnerability-model.md), [0013](0013-artifact-vulnerability-correlation.md), [0014](0014-package-occurrence-identity.md)                                                                                                                      |
| Code-to-cloud semantics                                   | [ADR 0010](0010-evidence-led-code-to-cloud.md), [0023](0023-provider-neutral-deployment-identity.md)                                                                                                                                                                     |
| Provider-specific code to cloud                           | [GCP 0024](0024-gcp-code-to-cloud.md), [Azure 0025](0025-azure-code-to-cloud.md), [AWS 0026](0026-aws-deployment-code-to-cloud.md), [Kubernetes 0027](0027-shared-kubernetes-code-to-cloud.md)                                                                           |
| Runtime activity and detections                           | [ADR 0015](0015-provider-neutral-runtime-activity.md), [0017](0017-evidence-led-runtime-detections.md), [AWS AgentCore AIDR 0035](0035-aws-agentcore-runtime-detection-and-response.md), [Azure Foundry AIDR 0036](0036-azure-foundry-runtime-detection-and-response.md) |
| Entra application discovery                               | [ADR 0016](0016-entra-shadow-ai-and-runtime.md)                                                                                                                                                                                                                          |
| Provider onboarding                                       | [AWS 0018](0018-self-service-aws-connections.md), [Azure 0019](0019-self-service-azure-connections.md), [GCP 0020](0020-self-service-gcp-connections.md), [GitHub 0021](0021-self-service-github-connections.md), [Entra 0029](0029-self-service-entra-connections.md)   |
| Hosted deployment status and next actions                 | [Pilot checklist](../deployment/pilot-launch-checklist.md)                                                                                                                                                                                                               |
| Golden Path operator/presenter sequence                   | [Golden Path guide](../product/golden-path-demo.md)                                                                                                                                                                                                                      |

## Known architectural gaps

- Full create, setup/callback, validate, collect, disable, and delete evidence remains incomplete
  for some hosted providers; individual dated acceptance records are authoritative.
- Azure Foundry runtime collection is production accepted, but the reference session still has
  unresolved agent, model, tool, and execution-identity references against inventory.
- The Neon runtime role is not yet split to least privilege and restore operations are untested.
- Entra sign-in logs depend on tenant licensing and retention; coverage must remain explicit.
- The local Golden Path is reproducible by manifest and documented collection order, but not yet a
  one-command, secret-free hosted demo snapshot.
- The production web build currently emits a chunk-size warning at approximately 527 KB minified;
  route-level code splitting is deferred.
- `npm audit` currently reports a high-severity backtracking-regex advisory in the build-time
  `@vercel/config` -> `@vercel/routing-utils` -> `path-to-regexp` chain. The offered automatic fix
  is a breaking downgrade, so remediation needs an explicit Vercel configuration dependency
  review rather than `npm audit fix --force`.

Update this map when a new package, runtime boundary, persistence model, or primary data flow is
introduced. Update the corresponding ADR when the decision itself changes.
