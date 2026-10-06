# ADR 0038: finding-linked customer-resource remediation

Status: proposed; implementation is **default-off** until reviewed rollout and explicit customer-resource consent.

## Decision

Denali owns the remediation capability. Browser/API callers and Platform's MCP/CLI adapters invoke the same service; the gateway does not invent provider actions or receive provider credentials. Shared connectors remain read-only. A separate, exact-resource write grant and dedicated purpose are required, separate from ordinary Denali record-write access.

```text
Browser session ───────────────────┐
                                  ▼
MCP / CLI → Platform OAuth gateway → Denali product capability
                                      │ live org-admin checks
                                      │ immutable 15-minute preview
                                      │ request + independent admin approval
                                      ▼
                                Denali PostgreSQL
                                      │ durable request ID only
                                      ▼
                                 Modal worker
                                      │ fresh, purpose-bound M2M
                                      ▼
                            Platform write-grant broker
                                      │ exact org/app/resource consent
                                      │ temporary credentials, audit
                                      ▼
                         Separate GitHub App / AWS role
```

## Supported version-one actions

| Action                              | Eligibility                                                                                                                                                       | Customer effect                                                                                                                                                                                                        |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `github.guardrail_draft_pr`         | Open failing `DENALI-REPO-AI-GRD-001`; current default-branch evidence; one supported JS/TS literal Bedrock SDK call; approved guardrail ID and published version | One deterministic commit on `transilience/remediation/<request-id>` and one **draft** PR. No merge, auto-merge, default-branch push, workflow edit, or arbitrary patch. Existing configured CI can run.                |
| `aws.tighten_bedrock_inline_policy` | Open failing `DENALI-AWS-AI-IAM-001`; exact role and existing inline-policy evidence; approved model ARNs present as IDs/ARNs in finding evidence                 | Replaces only supported wildcard Bedrock invocation resources with narrower exact ARNs. Preserves unrelated statements/conditions. No managed/trust policies, identity creation, deletions, or arbitrary IAM document. |

GitHub supports only unquoted ASCII `identifier: value` outer properties in eligible `src/`, `app/`, or `lib/` `.js`/`.ts` files. Computed, quoted, escaped, shorthand, spread, accessor/method, ambiguous, partially configured, regex/template-literal, generated/vendor/workflow paths, and recognized credential/private-key material fail closed. Preview diffs are still private code excerpts for authorized admins; pattern checks are not a general secret-classification guarantee. This is a conservative deterministic draft, not a general JavaScript semantic proof or automated deployment.

AWS inference-profile-to-foundation-model resolution is not inferred: if selected exact ARN/ID is not in current finding evidence, version one rejects it. Resource subset proof treats only `*` and `?` as IAM wildcards; brackets are literal, and policy variables fail closed. Narrowing a policy may break unobserved consumers or global routing; both admins must review destination regions and test consumers. IAM permissions are bounded by **role ARN**, while the product capability bounds the inline policy name; IAM does not provide a separate inline-policy resource ARN.

## Authorization and durable correctness

1. OAuth needs read/membership plus a separate provider purpose: `denali:github-remediation:write` or `denali:aws-remediation:write`. Existing `denali:write` cannot authorize these actions.
2. Denali verifies the signed delegation, selected Clerk org, existing tenant mapping, and current admin membership. Every write includes `expected_organization_id`; a changed org is rejected.
3. Preview contains the exact finding/resource/base-revision/policy hashes and diff. Only metadata and approved parameters are persisted; repository contents, raw IAM document, M2M/provider tokens and secrets are not stored.
4. Request requires the exact preview hash, explicit `confirm: true`, justification, and stable idempotency key. Reusing a key with a different body is a conflict.
5. A **different** current org admin confirms approval. Actor/reviewer permissions and immutable plan are checked again before execution; stale/revoked/drifted inputs never start a provider mutation.
6. A PostgreSQL claim and attempt marker precede the single provider execution. Duplicate Modal dispatches cannot re-execute a claimed request. Active or unresolved work fences the same grant against another approval. Platform permits one grant per org/app/action/resource identity.
7. A provider timeout, partial GitHub creation or expired worker lease becomes `needs_manual_resolution`. It is never blindly retried. `reconcile` performs provider reads only and records success only for the exact approved output; otherwise the fence remains and operator investigation is required.

Database triggers enforce immutable preview/request identity and append-only audit for normal runtime DML. They are **not tamper-proof against a privileged database owner, DDL caller or disabled triggers**. Denali's existing runtime database identity is unchanged by this rollout; reducing that privileged threat requires a separate Denali database-role review. The Platform broker's reviewed limited role separately enforces SELECT-only consent and SELECT/INSERT-only lease audit through database ACLs. HTTP responses use `Cache-Control: no-store`; invalid arguments and provider exceptions are sanitized.

IAM [`PutRolePolicy`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutRolePolicy.html) exposes no revision/compare-and-swap parameter. Immediately-before and after checks reduce but **cannot eliminate a concurrent external writer race**. Version one attempts once and never rolls back or overwrites a later external change automatically. Use an isolated pilot role and coordinated change window; do not describe this as atomic remediation.

## Product API and worker

| Endpoint                                                 | Operation                                                           |
| -------------------------------------------------------- | ------------------------------------------------------------------- |
| `POST /v1/resource-writes/previews`                      | Preview a named finding/grant with approved parameters              |
| `POST /v1/resource-writes/requests`                      | Submit preview/hash for review; `Idempotency-Key` required          |
| `POST /v1/resource-writes/requests/{id}/review`          | Independent admin approval/rejection; approval queues durable work  |
| `GET /v1/resource-writes/requests/{id}`                  | Admin-only bounded job status                                       |
| `POST /v1/resource-writes/requests/{id}/reconcile`       | Read-only verification of ambiguous/expired attempted work          |
| `POST /internal/v1/capabilities/resource-writes/actions` | Exact purpose-bound Platform receiver; never an arbitrary URL proxy |

`resource_write_worker` receives only a durable request UUID, reconstructs current service/membership/lease clients and claims PostgreSQL work. It has a 900-second hard timeout and a 1200-second persisted claim; stale claims cannot complete as current success.

## Rollout and rollback

- Apply migration `026_resource_write_remediations.sql` through the reviewed release workflow. Existing native/read connector tables and credentials are untouched.
- Configure existing Denali→Platform M2M identity with the separately reviewed Platform receiver scope and `DENALI_PLATFORM_RESOURCE_WRITE_RECEIVER_MACHINE_ID`; no secret is copied to users or MCP clients.
- `DENALI_ENABLE_GITHUB_RESOURCE_WRITES` and `DENALI_ENABLE_AWS_RESOURCE_WRITES` default to false. Enable only the reviewed provider after its independent Platform grant, dedicated OAuth purpose and named pilot resource pass acceptance.
- Deploy reviewed Denali first, then pin Platform's read contract to the merged Denali SHA. See Platform `docs/customer-resource-writes.md` for broker/database/client configuration.
- Roll back by disabling both product/provider flags, disabling the specific Platform grant and revoking the separate installation/role when required. Flags stop new work/leases; already issued GitHub tokens can survive up to one hour and AWS sessions up to 15 minutes. **An in-flight mutation is not instantly canceled.** Coordinate provider revocation and inspect durable status.
- Never delete an unresolved request to remove its fence. Manually inspect approved versus observed output, preserve audit evidence, and use a reviewed operator recovery after determining the outcome.

## Acceptance before activation

Pass complete unit/API/PostgreSQL/frontend gates. With isolated opt-in resources and two real admins, verify preview → request → independent review → durable status; then read-only reconciliation. Verify missing scope, member/removed admin, wrong org, self-review, changed base/policy/finding, expired preview/claim, disabled grant, duplicate request/dispatch, and ambiguous timeout failures. Mock tests do not certify a live provider integration. New customer resource permissions are not enabled by merging default-off code alone.
