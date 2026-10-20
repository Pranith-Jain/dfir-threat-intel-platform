# ADR 0033: Self-service Google Workspace connections

- Status: Accepted
- Date: 2026-09-08

## Context

Denali needs the Google Workspace equivalent of Microsoft Entra application discovery and
activity evidence. Treating an unconfigured or forbidden audit source as an empty source would
create a false zero. Storing a customer service-account key, OAuth refresh token, or exported
audit file would also conflict with the hosted provider identity model.

The first useful boundary is the Google Workspace Admin Reports API. It exposes Gemini in
Workspace activity and OAuth token audit activity, supports a read-only audit scope, and has a
bounded retention window. It does not provide a complete current inventory of every OAuth grant;
therefore Denali must describe OAuth applications as observed within the collected audit window.

## Decision

Denali adds `google_workspace` as a first-class provider with a fixed evidence bundle:

- `google_workspace.gemini_activity` reads `gemini_in_workspace_apps` reports;
- `google_workspace.oauth_activity` reads `token` reports; and
- both planes require only
  `https://www.googleapis.com/auth/admin.reports.audit.readonly`.

A Denali-operated Google service account is the domain-wide delegation target. Modal's runtime
identity impersonates that service account through IAM Credentials, and the service account then
delegates to the customer-supplied Workspace administrator email for the fixed scope. Credentials
are short-lived. Denali stores only the operator service-account identifier, numeric OAuth client
ID, customer domain, delegated administrator email, declared scopes, validation evidence, and
coverage state. It never stores a service-account key, Workspace user token, refresh token, audit
export, prompt, response, or IP address.

Setup is explicit and reviewable:

1. an organization admin records the delegated Workspace administrator;
2. the UI displays the exact OAuth client ID and read-only scope;
3. a Workspace super administrator authorizes that pair in Admin Console;
4. the Denali organization admin confirms the external step; and
5. a durable validation job calls the Gemini and OAuth report planes independently.

Confirmation is not proof of access. Only successful API validation can make the connection
healthy. A healthy validation automatically queues durable collection. Empty successful reports
authorize a zero for the bounded window; permission, licensing, pagination, parsing, or provider
failures remain failed or partial coverage.

The collector creates externally verified `ai_application` assertions only for native Gemini
activity or catalog-matched OAuth applications observed in the window. Activity references do not
create identities or graph authority. OAuth events expose observations, not a complete current
grant inventory and not a security finding.

## Consequences

The opt-in Platform shared connection path uses the same fixed report bundle and
Denali-owned normalizers through a sanitized Reports client. Exact organization,
customer identity and operator bindings are admitted by Platform and pinned in
Denali; credentials stay in Platform. Native configuration remains unchanged.
See [the shared Workspace runbook](../development/shared-google-workspace-connections-pilot.md).

- A Workspace super-admin action remains necessary because Google does not provide Denali with a
  customer-side consent callback equivalent to Entra admin consent for this service-account flow.
- Domain-wide delegation propagation may delay the first successful validation.
- The first slice deliberately omits Directory API token inventory because its user-security scope
  also permits revocation and is not read-only.
- Future Marketplace installation may streamline authorization, but it must preserve the same
  fixed scope, tenant binding, validation, and no-token persistence guarantees.
