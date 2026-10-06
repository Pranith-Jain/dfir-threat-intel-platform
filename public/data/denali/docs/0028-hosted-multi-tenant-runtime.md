# ADR 0028: Hosted multi-tenant runtime uses Vercel, Clerk, Modal, and Neon

## Status

Accepted and deployed for the invitation-only pilot on 2026-09-01, with the current production
schema and runtime updated through migration 020 on 2026-09-14. The web application,
same-origin API proxy, Clerk Organization authorization, Modal API, durable connection-validation
worker, durable provider-collection workers, and Neon schema are live. Provider integrations still
require individual production configuration and hosted acceptance.

## Decision

Denali's hosted runtime has four service boundaries:

```text
Browser
  -> Vercel: React/Vite application and same-origin /api/* rewrite
  -> Modal: FastAPI authorization/API boundary
       -> Modal validation_worker: durable connection validation
       -> Modal collection_worker: durable provider collection
  -> Neon: PostgreSQL system of record

Clerk Organizations
  -> browser session token
  -> FastAPI JWT verification and active-organization resolution
```

Vercel serves static frontend assets and proxies `/api/*` to the Modal origin. The browser attaches
the current Clerk session token to every API request and does not know the Neon DSN, Clerk backend
key, or provider integration secrets. Keeping the API same-origin gives the application one public
domain for authenticated requests and provider callbacks.

Modal packages the existing FastAPI application as an ASGI application. API containers are
ephemeral and must be replaceable; durable correctness cannot depend on their memory. Neon
PostgreSQL is the sole durable application store. Migrations execute as an explicit deployment
operation using the direct Neon connection and a PostgreSQL advisory lock; API startup never
mutates the schema.

## Identity and authorization

Clerk owns sign-in, invitations, membership, Organization switching, and the `org:admin` and
`org:member` roles. Denali owns authorization and data isolation.

Denali's custom profile page uses the Clerk frontend components for the signed-in user's account,
Organization switching, and existing membership resources. Privileged member onboarding crosses
the same-origin API boundary instead of exposing the Clerk secret in Vercel:

- `POST /v1/profile/organization/invitations/bulk` sends at most 50 normalized, unique invitations
  and returns a per-address result so partial failure can be retried.
- `POST /v1/profile/organization/users` creates a Clerk user and adds it to the active Organization.
  The initial password is accepted only as transient request material, forwarded to Clerk, and is
  never persisted, logged, or returned by the Denali API. If membership creation fails after user
  creation, the backend attempts to delete the just-created Clerk user.

Both routes require `org:admin`. They derive the Organization and inviter from the verified Clerk
session; neither request accepts a tenant or Organization identifier. Direct creation also
requires password sign-in to be enabled and the supplied password to satisfy the selected Clerk
instance's policy. The UI can retain the submitted password in browser memory long enough for the
admin to copy it once, then clears it when the result or workflow is dismissed.

On the first approved authenticated request, the API maps the active Clerk Organization ID to one
random Denali tenant UUID in the `tenant` table. This mapping is permanent. All existing tenant
foreign keys and predicates continue to use the Denali UUID; Clerk identifiers do not become
domain primary keys.

The API verifies the Clerk token signature, issuer, expiry, authorized party, session state, active
Organization, and Organization role. Both roles may read. Only `org:admin` may create, configure,
validate, disable, or delete connections and mutate governance. UI role checks may hide controls,
but they never replace API enforcement.

Every tenant-owned repository method accepts the server-resolved Denali tenant UUID. Tenant IDs
from request bodies, query parameters, routes, arbitrary headers, or the browser's selected state
are untrusted and cannot select a tenant.

The optional Platform results/MCP receiver is a separate internal API boundary, not
a second database reader or browser API. It accepts only named, versioned Denali
capabilities and short-lived Clerk M2M tokens from an exact gateway machine,
bound to a verified user and Organization. Denali checks live Organization
membership, resolves an existing tenant mapping without creating one, and
requires an Organization admin plus an idempotency key for Denali-record writes.
See [the capability gateway contract](../development/capability-gateway.md).
Its metadata-only runtime-session export has explicit activity and byte limits.
Evidence import submission also requires an expected-organization guard and
explicit confirmation; the native durable job and gateway audit commit atomically,
while the existing leased worker owns ingestion and evaluation.

`/healthz`, API documentation, and the Entra and GitHub provider callbacks are public at
the HTTP middleware layer. Callback authorization instead uses verified, expiring, one-time setup
state. The stored state resolves both tenant and connection, so changing the browser's active
Organization cannot redirect a callback into another tenant.

## Durable work

Connection validation is the reference durable-work implementation:

1. The authenticated API creates a `connection_validation_job` row scoped to tenant and
   connection. A partial unique index prevents two active jobs for the same connection.
2. The API calls Modal `Function.spawn()` with only the job UUID and stores the Modal call ID.
3. `validation_worker` claims a bounded PostgreSQL lease, reloads the tenant-scoped connection,
   performs validation idempotently, and records success or a sanitized failure.
4. Status polling reads PostgreSQL. It does not rely on the API process that accepted the request.
5. Stale leases become failed before a later manual retry creates a replacement job.

All new hosted work that can outlive a request must follow this pattern: durable job row, idempotent
claim, explicit lease/timeout, Modal worker receiving durable identifiers, database-backed status,
sanitized terminal result, and safe retry/deduplication behavior.

The hard Modal timeouts and default database leases share named constants in
`denali.worker_limits`. Validation and collection use a 2400-second hard timeout with a
2700-second lease; evidence imports use a 1200-second hard timeout with a 1500-second lease.
The 300-second grace prevents stale-job replacement while the original container can still
execute. A validation loop's shorter soft deadline cannot bound blocking provider calls and
must not shorten its lease. Longer native/local validation deadlines retain a correspondingly
longer lease.

Microsoft Entra evidence, GitHub source, and AWS/Azure/GCP deployment collection all use
`connection_collection_job` records and the dedicated Modal `collection_worker`. The API returns
after the durable job is recorded and dispatched; polling reads PostgreSQL, so completion does not
depend on the accepting API container remaining alive.

Every durable collection job kind is bound to an explicit provider allowlist. The worker reloads
the tenant-scoped connection and rejects a job if its collection kind does not belong to that
connection's provider, even when the job row and a collector both exist. This is an independent
execution-time check in addition to tenant/connection foreign keys and hard-coded API routes.

Opt-in AWS AgentCore and Azure Foundry runtime collection use the same durable job and worker
boundary. Five-minute Modal schedulers select only due, healthy connections, create durable jobs,
and pass identifiers to the worker. PostgreSQL cursors, bounded overlap, leases, retries, and
explicit partial coverage preserve continuity without relying on scheduler or API memory. The
provider-neutral Runtime page reads the retained sessions and ordered execution graph through the
authenticated, tenant-scoped API. Azure's metadata-only contract and production acceptance are in
[ADR 0036](0036-azure-foundry-runtime-detection-and-response.md).

## Database connections and migrations

- `DENALI_DSN` is the pooled Neon endpoint used by the API and workers.
- `DENALI_MIGRATION_DSN` is the direct Neon endpoint used only by explicit migration and database
  administration operations.
- Production runtime roles should be least privilege; the migration role owns the schema while the
  runtime role receives required DML and sequence privileges.
- A schema change always adds a new numbered SQL migration. Applied migrations are immutable.
- Tenant-owned tables, jobs, connections, inventory, findings, and governance records must retain
  database-enforced tenant relationships where practical and tenant predicates in every query.

## Configuration and secret ownership

Hosted preview and production are isolated security environments:

| Vercel target | Clerk instance | Modal environment | Modal app/Secret    | Neon environment             |
| ------------- | -------------- | ----------------- | ------------------- | ---------------------------- |
| Production    | Production     | `denali-prod`     | `denali-production` | Production                   |
| Preview       | Development    | `denali-dev`      | `denali-dev`        | `denali-dev` branch/database |

A default `*.vercel.app` preview uses the Clerk development publishable key and proxies `/api/*`
to the `denali-dev` Modal origin. That Modal deployment verifies with the matching development
Secret and reads only the isolated Neon development environment. Production Modal never accepts
development Clerk tokens, and preview builds never connect to production Neon.

Preview deployment URLs may change per Vercel deployment. Use the stable branch alias for Clerk
redirect/origin configuration when one is available, and keep the Preview `MODAL_API_ORIGIN`
pointed at the stable `denali-dev` Modal API origin. If the branch alias changes, update the Clerk
development instance allowlist plus `CLERK_AUTHORIZED_PARTIES`, `DENALI_WEB_URL`, and
`DENALI_CORS_ORIGINS` in the `denali-dev` Modal Secret together, then redeploy `denali-dev`.
The live development values, safe redeploy sequence, and authentication recovery steps are in the
[hosted development runbook](../development/hosted-dev-environment.md).

The shared Clerk development instance uses the same custom session claims as production and does
not emit a custom `aud` claim. `CLERK_AUDIENCE` is therefore intentionally absent from
`denali-dev`; adding an application-specific audience would break other applications sharing that
development instance.

Vercel receives only:

| Variable                     | Purpose                         | Secret |
| ---------------------------- | ------------------------------- | ------ |
| `VITE_CLERK_PUBLISHABLE_KEY` | Initialize Clerk in the browser | No     |
| `MODAL_API_ORIGIN`           | Server-side rewrite target      | No     |

Modal receives core backend configuration:

| Variable                                | Purpose                                          | Secret                            |
| --------------------------------------- | ------------------------------------------------ | --------------------------------- |
| `DENALI_DSN`                            | Pooled Neon runtime connection                   | Yes                               |
| `DENALI_MIGRATION_DSN`                  | Direct Neon migration connection                 | Yes, privileged                   |
| `CLERK_SECRET_KEY`                      | Clerk backend operations                         | Yes                               |
| `CLERK_JWT_KEY`                         | Offline Clerk JWT verification key               | Public key material, backend-only |
| `CLERK_AUTHORIZED_PARTIES`              | Allowed production browser origins               | No                                |
| `DENALI_WEB_URL`, `DENALI_CORS_ORIGINS` | Canonical web and controlled direct-call origins | No                                |

Provider values in Modal describe Denali-operated integrations: the GitHub App, Azure multi-tenant
application, GCP operator project, private setup-artifact locations, and Modal's AWS OIDC role.
They are not one shared customer credential and they do not replace tenant-specific grants.

Tenant onboarding remains bring-your-own-cloud without uploaded long-lived credentials:

- AWS stores a tenant role ARN, external ID, selected account/Regions, and validation evidence.
  Modal uses its short-lived OIDC identity to assume the role.
- Azure stores the customer tenant and selected subscription identifiers. A customer tenant
  administrator creates the Denali-operated multi-tenant application's local service principal;
  subscription administrators grant Reader only on the subscriptions they select. Denali obtains
  bounded tokens when required; access tokens are not persisted.
- GCP stores selected project identifiers and a unique per-connection principal grant. No service
  account JSON key is accepted or stored. Modal's OIDC token is exchanged through a Google
  Workload Identity Federation provider restricted to the production Modal workspace,
  environment, and app, then impersonates Denali's operator runtime service account.
- GitHub stores App installation and exact repository identifiers. Installer OAuth tokens and App
  private keys never enter tenant records.

## Deployment and request contracts

The frontend continues to call relative `/api/v1/*` paths. Production provider redirect URLs use
the same canonical web domain under `/api/v1/connections/...`; they never expose the Modal origin
as the product callback URL.

The Modal application contains separate functions for the ASGI API, database migration, database
status, configuration status, validation worker, collection worker, and bounded runtime-collection
schedulers. The pilot keeps a warm API container, but correctness must not depend on its lifetime
or on requests reaching the same container.

The protected production deployment invokes configuration status with `core`, `aws`, `azure`,
`entra`, `gcp`, `google_workspace`, `github`, and `azure_repos` as required groups. The check
reports only presence and missing variable names, never values, and fails before migrations or
deployment when any required group is incomplete. Development invokes the same check with only
`core` required so an isolated environment may intentionally exercise a provider subset.

`DENALI_MODAL_REGION`, `DENALI_MODAL_APP_NAME`, `DENALI_MODAL_SECRET_NAME`, and
`DENALI_MODAL_PROVIDER_SECRET_NAME` are deploy-shell
configuration because Modal resolves image/function declarations before runtime Secrets are
attached. Every function mounts one core Secret and one environment-local provider Secret; keeping
those resources stable is required for consistent local and remote Modal module evaluation. The
provider Secret is mounted after the core Secret and must not repeat core Clerk or Neon keys.
The shared-connections pilot also mounts one deployment-scoped configuration object for its
public platform origin on every function, including workers that import the API module. That
object remains present when unset, so the dependency count stays identical on remote import;
the machine key remains in the core Secret. The production bridge is dark until its separate
rollout configures both values. A server-side `DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS` allowlist
in the core Secret defaults to no organizations even if the origin and key are present; the
allowlist applies to browser routes, operator snapshots, and worker leases. Existing Denali
provider connections and their execution paths remain unchanged.
Production normally uses `custom-secret` plus `denali-github-provider`; the Shasta Workspace pilot
function additionally mounts a fixed-name `shasta-denali-bridge` for its per-source signing key and
bindings, while retaining the provider Secret's Google Workspace operator identity. The fixed name
keeps the dependency count identical when the deploy process and remote worker each import this
module. Preview uses `denali-dev` plus environment-local `denali-github-provider` and
`shasta-denali-bridge` Secrets; the bridge Secret there contains only a disabled marker. The Shasta
function is not configured for collection in development.

Local Compose mode remains supported for development with one configured tenant and no Clerk
authorization. Local mode is not a production topology and must not weaken hosted defaults.

## Observability and acceptance

Structured logs may carry Denali tenant UUID, connection UUID, job UUID, route, status, and bounded
error classification. They must not carry Clerk tokens, authorization headers, DSNs, callback
codes, provider tokens, private keys, source contents, or customer credential payloads.

A hosted change is accepted only after the relevant automated tests and production builds pass.
Authentication or persistence changes additionally require PostgreSQL-backed cross-tenant tests.
Durable work requires restart, duplicate, retry, timeout, failure, and stale-lease coverage.

A provider is enabled only after its production configuration exists and the hosted UI completes
create, setup/callback, validation, disable, and delete. Connection health and provider collection
are separate acceptance planes; one cannot stand in for the other.

## Consequences

- Vercel is replaceable static delivery and routing, not a trusted backend or secret store.
- Modal API containers may scale or restart without losing authoritative state.
- Clerk Organization switching changes the server-resolved tenant without changing domain keys.
- Neon stays compatible with the existing PostgreSQL repository and transaction semantics.
- Customer cloud access is revocable at the provider and does not require Denali to retain
  long-lived customer secrets.
- Durable validation and provider collection survive API-container replacement and scale-out.
- Healthy validation now starts the first durable provider collection, and successful collection
  refreshes dependent source correlation and tenant rule evaluation as specified by
  [ADR 0030](0030-hosted-evidence-orchestration.md).
