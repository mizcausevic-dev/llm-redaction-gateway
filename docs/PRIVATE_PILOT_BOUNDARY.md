# Authenticated private pilot boundary

## Goal and release class

Prepare a reviewable R3 decision API candidate that rejects unknown callers and cross-tenant requests. This is a local process boundary, not a production authorization or detection-accuracy claim.

## Current state and scope

The existing API is an explicitly opted-in loopback demo. Its bundled policies and audit entries are synthetic, and no route forwards to a model provider. The private pilot keeps loopback binding, adds a separately opted-in signed access-token path, and mounts only `/health` plus `/api/gateway/process`. The decision endpoint continues to return advice only.

## Acceptance criteria

- Startup always refuses `NODE_ENV=production`. The separate nonproduction pilot requires `NODE_ENV=development`, `GATEWAY_PRIVATE_PILOT=1`, issuer, audience, same-origin HTTPS JWKS URL, and explicit client-to-tenant grants. Local-demo opt-in cannot be combined with pilot mode.
- A process request requires a verified access token with exact issuer and audience, `at+jwt` type, RS256 signature, expiry, recent issue time, subject, tenant, client, and `gateway:decide` scope.
- The verified client-to-tenant pair must appear in the configured grants. The body must name exactly the verified tenant. Pilot decisions use catalog defaults, not bundled sample tenant policies.
- Missing, malformed, expired, wrong-audience, wrong-issuer, wrong-scope, cross-tenant, and nongranted tokens fail before decision processing. Pilot fixture routes remain unavailable.
- The pilot limits API requests to one shared 60-per-minute loopback quota before token verification. Excess attempts return HTTP 429; `/health` remains available.
- No input, token, or match value appears in access logs. No caller token or prompt is forwarded upstream.

## Design and decisions

`jose` verifies tokens against a configured, trusted JWKS. The server never takes a key URL or tenant grant from a request. The JWKS URL must share the issuer origin and use HTTPS. The private pilot binds to loopback and checks the peer address, Host, and proxy forwarding headers. A 15-minute maximum token age bounds stale grants but does not replace issuer-side revocation. Every accepted 127/8 source shares one fixed request quota, so source aliases cannot reset it; one local caller can also exhaust the quota for others. The limiter uses a process-local memory store, so it does not coordinate multiple processes or survive restarts. Identity-provider configuration, actual client consent, live policy storage, rate limiting at a trusted ingress, provider egress enforcement, human-labeled detection accuracy, hosted monitoring, and hosted rollback remain external release gates.

The only pilot API route is `POST /api/gateway/process`. It requires an `Authorization: Bearer` access token with RS256 signature, `at+jwt` type, exact single audience, issuer, expiry, issue time, subject, `client_id`, `tenant_id`, and `gateway:decide` scope. Configure `GATEWAY_CLIENT_TENANT_GRANTS` as comma-separated `client:tenant` pairs. The JWT issuer must be trusted to assign those claims. No real issuer or grants have been configured or verified here.

## Execution and verification

1. Add strict runtime configuration and token verification middleware.
2. Bind the verified principal to the process route; hide synthetic fixture routes in pilot mode.
3. Add signed-token endpoint tests and startup denial tests.
4. Run build, tests, synthetic detector evaluation, dependency audit, and diff review.

## Deployment and rollback

No hosted target, issuer, or known-good hosted artifact is configured. Do not deploy or process real data. A later private deployment requires a real issuer/tenant grant review, denial tests at the deployed boundary, health and alert verification, and rollback to a content-equivalent artifact. Local process-switch drills do not satisfy that gate.

## Progress and outcome

The loopback-only pilot route now limits attempts before verifying signed caller tokens and exact client-to-tenant grants, then parses decision bodies. The production startup refusal remains unconditional. No real issuer, provider, customer data, hosted boundary, or rollback artifact was configured. A CodeQL check on the preceding candidate commit reported a new high-severity missing-rate-limiting alert; this fixed-limit change still requires an exact-head CodeQL recheck before review completion.

Checks executed on 2026-10-01:

- `npm.cmd run build`: exit 0.
- `npm.cmd test` on local Node 24.11.0: exit 0, 56/56, including the 429, loopback-alias, and forwarding-header limiter assertions. Visible `ECONNRESET` transport retries occurred in synthetic HTTP tests; an independent full run passed 56/56 with seven visible retries, including one request that needed both allowed retries.
- Full five-file `node --require ./tests/setup-env.cjs --require ts-node/register --test --test-concurrency=1` suite through `npm.cmd exec --package=node@20.19.5`: exit 0, 56/56, with visible `ECONNRESET` transport retries.
- Focused private-pilot suite through `npm.cmd exec --package=node@22.12.0`: exit 0, 11/11, with visible transport retries. Node 22.12 emitted an experimental CommonJS-to-ESM warning for `jose`.
- A Node 20 full run with the shared test-client retry disabled failed 54/55 after a logged HTTP 200 and `read ECONNRESET`; this is why the test-only helper retries transport resets at most twice. It never retries an HTTP status. A green result does not prove the Windows loopback transport is reliable.
- `npm.cmd run eval:detection`: exit 0; supported synthetic probes 14/14 and challenge probes 1/4. The three misses remain release blockers.
- `npm.cmd audit --audit-level=moderate` and `npm.cmd audit --omit=dev --audit-level=moderate`: both exit 0 with zero reported vulnerabilities.
- `gitleaks dir . --no-banner --redact --exit-code 1`: exit 0 with no findings in the scoped ~193 KB directory scan. This is not a verified-clean audit.

Production remains **BLOCKED** by real issuer and grant review, provider enforcement, representative detection evidence, abuse controls, hosted monitoring, and hosted rollback proof.
