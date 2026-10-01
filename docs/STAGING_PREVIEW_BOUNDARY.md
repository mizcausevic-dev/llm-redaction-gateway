# Synthetic Vercel preview boundary

This branch prepares a private, synthetic-only preview drill. It has not been deployed. Commit `40ddbf5ddf9a71162b31102890f6c6a37142c534` is the safe-deny source: it returns minimal `/health` metadata and has no decision-capable route, body parser, provider adapter, or audit writer. The later candidate adds only a fixture-ID route. A source commit alone is not hosted rollback proof.

For a reproducible **local handler/source-switch simulation**, run `node scripts/drill-staging-source-restore.cjs 40ddbf5ddf9a71162b31102890f6c6a37142c534` from the repository root after committing the candidate. The script archives and compiles that exact safe-deny commit, uses an ephemeral in-memory RSA signer, then checks baseline → candidate → baseline with the candidate opt-in and public JWKS still set. It validates archive paths and deletes only its verified repository-local temporary directory. Its `simulationOnly: true` and `hostedDeploymentOrRollback: false` result does not verify a process restart, Vercel routing, Deployment Protection, branch alias restoration, or revocation of an immutable candidate URL.

## Application guard

Staging requires `NODE_ENV=production`, `VERCEL=1`, `VERCEL_ENV=preview`, `VERCEL_TARGET_ENV=preview`, and explicit `GATEWAY_STAGING_PREVIEW=1`. Both `VERCEL_URL` and `VERCEL_BRANCH_URL` must be generated `.vercel.app` hostnames and differ from `VERCEL_PROJECT_PRODUCTION_URL`. Only requests whose Host exactly matches one of those two generated hosts pass. Other aliases, a port suffix, and a production environment fail closed. Local demo and loopback private-pilot opt-ins cannot be combined with staging.

The `VERCEL*` markers and Host check are configuration guards, not proof that a request came from Vercel or that a caller is authenticated. Vercel's **Deployment Protection must be configured and verified before the first upload** for every URL that can serve the preview, including generated deployment and branch URLs. Do not create a public exception, shareable bypass, or automation bypass token. A local `npm test` run cannot verify the edge protection, platform routing, body buffering, or restoration.

All app responses set `Cache-Control: no-store` and `X-Robots-Tag: noindex, nofollow, noarchive`. The preview has no access log middleware. Vercel platform logging and retention must still be inspected before a hosted drill; no real prompts, tenant data, or credentials belong in this preview.

## Fixture-only candidate

The second opt-in is `GATEWAY_STAGING_DECISIONS=1` with `GATEWAY_STAGING_PUBLIC_JWKS` containing exactly one public 2048-bit RSA signing key. No private signing key is bundled, committed, or deployed. The fixture signer would need to be created and held outside this repository only after an approved hosted plan exists. The candidate requires a short-lived RS256 `at+jwt` access token with exact issuer `urn:llm-redaction-gateway:synthetic-preview`, exact audience `urn:llm-redaction-gateway:synthetic-preview:api`, scope `gateway:staging:decide`, client `fixture_client`, and tenant `fixture_tenant`. It does not reuse the loopback pilot's issuer, audience, scope, or grants.

The only decision route is `POST /api/staging/decide` with a strict JSON body containing one `fixtureId`: `clean-text`, `obfuscated-email`, `invalid-card`, or `valid-card`. The server resolves the known prompt in source. Caller-provided prompts, tenant IDs, policy overrides, extra fields, and unknown IDs receive a generic rejection without echo. The route calls the same detection and policy engine as the local demo, returns advice only, and has no LLM/provider forwarding or persistent audit writes. Authentication and a 60-attempt-per-minute process-local quota run before the 256 KB JSON parser. The quota is **not distributed across Vercel instances**; the Vercel Function may buffer a larger body before Express sees it. Neither is an ingress abuse control. The hosted edge and function behavior remain unverified.

Even a successful hosted synthetic drill would prove only access control, fixture decisions, and restoration behavior at that preview boundary. It would not prove detection accuracy on representative data, real tenant consent, provider egress enforcement, durable audit evidence, or production rollback.

## Before a hosted drill

**The hosted drill is currently blocked.** Vercel states that the first deployment of a new project is always a production deployment, even when invoked from a nonproduction branch or without `--prod`. This code intentionally refuses production startup. Do not create a new Vercel project expecting a preview-first upload. A pre-existing protected project, or a separately reviewed and approved production bootstrap path, is required before any deployment.

Once a suitable existing private target is identified:

1. Verify the project's Deployment Protection and existing artifact state before connecting this repository. No project or credential is created by this branch.
2. Enable system environment variables and restrict preview access using Vercel Authentication for **All Deployments**. Scope the staging opt-ins and public JWKS to only the intended preview branch. Verify unauthenticated denial at the generated and branch URLs, and verify the production URL cannot reach the staging app. Confirm no shareable link, exception, or bypass header grants unintended access.
3. Deploy the safe-deny commit as a preview, record its immutable deployment URL and ID, and check `/health` plus a denied decision route at the protected boundary.
4. Only then test the later synthetic candidate with a separate fixture-only token. Restore by building and deploying the exact safe-deny source as a **new preview artifact** on the same staging branch. Confirm that the branch URL now resolves to that new artifact, then recheck access denial, health, and the absent decision route. If the branch alias does not advance to the restored artifact, the drill is blocked. Do not use production Instant Rollback as a proxy for preview restoration.
5. Branch restoration is limited: the candidate's immutable deployment URL may remain decision-capable for authenticated users holding the synthetic token. Revoke the signer/token and deactivate or delete that deployment only if the platform provides a reviewed, supported path; verify the URL no longer serves decisions before calling the candidate fully disabled. Until then, report branch restoration only, not a complete rollback.

## Review order

Draft PR #33 targets `main` so this repository's `main`-filtered CI and CodeQL run. Its source branch includes Gateway PR #32. Review #32 first and do not merge #33 out of order. If #32 is later merged, recheck #33's remaining diff and exact-head checks before any merge decision. Neither PR authorizes a hosted deployment.

Official references: [Express on Vercel](https://vercel.com/docs/frameworks/backend/express), [system environment variables](https://vercel.com/docs/environment-variables/system-environment-variables), [Deployment Protection](https://vercel.com/docs/deployment-protection), [September 2026 All Deployments update](https://vercel.com/changelog/protect-production-deployments-for-free-on-every-plan), [generated URLs](https://vercel.com/docs/deployments/generated-urls), [first-deployment behavior](https://vercel.com/docs/deployments/environments), [function payload limit](https://vercel.com/docs/functions/limitations).
