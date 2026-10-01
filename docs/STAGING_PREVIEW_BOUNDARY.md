# Synthetic Vercel preview boundary

This branch prepares a private, synthetic-only preview drill. It has not been deployed. The first commit is a safe-deny artifact: it returns minimal `/health` metadata and has no decision-capable route, body parser, provider adapter, or audit writer. Retain its commit SHA and deployment ID as the intended restoration artifact before testing a later candidate. A source commit alone is not hosted rollback proof.

## Application guard

Staging requires `NODE_ENV=production`, `VERCEL=1`, `VERCEL_ENV=preview`, `VERCEL_TARGET_ENV=preview`, and explicit `GATEWAY_STAGING_PREVIEW=1`. Both `VERCEL_URL` and `VERCEL_BRANCH_URL` must be generated `.vercel.app` hostnames and differ from `VERCEL_PROJECT_PRODUCTION_URL`. Only requests whose Host exactly matches one of those two generated hosts pass. Other aliases, a port suffix, and a production environment fail closed. Local demo and loopback private-pilot opt-ins cannot be combined with staging.

The `VERCEL*` markers and Host check are configuration guards, not proof that a request came from Vercel or that a caller is authenticated. Vercel's **Deployment Protection must be configured and verified before the first upload** for every URL that can serve the preview, including generated deployment and branch URLs. Do not create a public exception, shareable bypass, or automation bypass token. A local `npm test` run cannot verify the edge protection, platform routing, body buffering, or restoration.

All app responses set `Cache-Control: no-store` and `X-Robots-Tag: noindex, nofollow, noarchive`. The preview has no access log middleware. Vercel platform logging and retention must still be inspected before a hosted drill; no real prompts, tenant data, or credentials belong in this preview.

## Before a hosted drill

**The hosted drill is currently blocked.** Vercel states that the first deployment of a new project is always a production deployment, even when invoked from a nonproduction branch or without `--prod`. This code intentionally refuses production startup. Do not create a new Vercel project expecting a preview-first upload. A pre-existing protected project, or a separately reviewed and approved production bootstrap path, is required before any deployment.

Once a suitable existing private target is identified:

1. Verify the project's Deployment Protection and existing artifact state before connecting this repository. No project or credential is created by this branch.
2. Enable system environment variables and restrict preview access using Vercel Authentication for **All Deployments**. Verify unauthenticated denial at the generated and branch URLs, and verify the production URL cannot reach the staging app.
3. Deploy the safe-deny commit as a preview, record its immutable deployment URL and ID, and check `/health` plus a denied decision route at the protected boundary.
4. Only then test the later synthetic candidate with a separate fixture-only token. Restore by building and deploying the exact safe-deny source as a **new preview artifact** on the same staging branch. Confirm that the branch URL now resolves to that new artifact, then recheck access denial, health, and the absent decision route. If the branch alias does not advance to the restored artifact, the drill is blocked. Do not use production Instant Rollback as a proxy for preview restoration. The candidate's immutable URL can remain available; verify it stays protected.

Official references: [Express on Vercel](https://vercel.com/docs/frameworks/backend/express), [system environment variables](https://vercel.com/docs/environment-variables/system-environment-variables), [Deployment Protection](https://vercel.com/docs/deployment-protection), [generated URLs](https://vercel.com/docs/deployments/generated-urls), [first-deployment behavior](https://vercel.com/docs/deployments/environments).
