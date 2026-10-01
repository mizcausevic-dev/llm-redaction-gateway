// Local handler/source-switch simulation only. No Vercel deployment or rollback.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync } = require('node:fs');
const path = require('node:path');
const express = require('express');
const { exportJWK, generateKeyPair, SignJWT } = require('jose');
const request = require('supertest');

const root = path.resolve(__dirname, '..');
const baselineInput = process.argv[2];
const gitArgs = ['-c', `safe.directory=${root.replace(/\\/g, '/')}`];
const generatedHost = 'gateway-synthetic-123.vercel.app';
const branchHost = 'gateway-git-synthetic.vercel.app';
const productionHost = 'gateway.vercel.app';
const tempPrefix = '.local-staging-drill-';
let drillDir;

if (!baselineInput || !/^[0-9a-f]{40}$/i.test(baselineInput) || process.argv.length !== 3) {
  console.error('Usage: node scripts/drill-staging-source-restore.cjs <full-safe-deny-baseline-sha>');
  process.exit(2);
}

function run(file, args, cwd = root) {
  const result = spawnSync(file, args, {
    cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${path.basename(file)} ${args[0]} failed: ${result.error?.message ?? result.stderr?.trim() ?? result.status}`);
  }
  return result.stdout;
}

function safeEntry(name) {
  const entry = name.replace(/\/$/, ''); // tar may list directory entries.
  if (!entry || /[\x00-\x1f\x7f\\:]/.test(entry)
    || path.posix.isAbsolute(entry) || path.win32.isAbsolute(entry)
    || entry.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new Error('Unsafe baseline archive path');
  }
  return entry;
}

function validateTree(oid) {
  const output = run('git', [...gitArgs, 'ls-tree', '-r', '-z', '--full-tree', oid]);
  const entries = output.split('\0');
  if (entries.pop() !== '') throw new Error('Malformed Git tree listing');
  for (const entry of entries) {
    const match = /^(100644|100755) blob [0-9a-f]+\t(.+)$/.exec(entry);
    if (!match) throw new Error('Baseline contains a link, submodule, or unsupported tree entry');
    safeEntry(match[2]);
  }
}

function validateArchive(archive) {
  const output = run('tar', ['-tf', archive]);
  for (const entry of output.split(/\r?\n/).filter(Boolean)) safeEntry(entry);
}

function cleanup() {
  if (!drillDir) return;
  // Never recursively remove a computed path without proving that it is the
  // immediate, real, non-link child created for this drill under this repo.
  const rootReal = realpathSync.native(root);
  const targetInfo = lstatSync(drillDir);
  const targetReal = realpathSync.native(drillDir);
  const relative = path.relative(rootReal, targetReal);
  if (!targetInfo.isDirectory() || targetInfo.isSymbolicLink()
    || path.dirname(relative) !== '.'
    || !relative.startsWith(tempPrefix)
    || !/^[A-Za-z0-9_-]+$/.test(relative.slice(tempPrefix.length))
    || path.isAbsolute(relative) || path.dirname(targetReal) !== rootReal) {
    throw new Error('Refusing unsafe staging drill cleanup path');
  }
  rmSync(targetReal, { recursive: true });
}

function loadApp(entrypoint) {
  delete require.cache[require.resolve(entrypoint)];
  const app = require(entrypoint);
  assert.equal(typeof app, 'function', 'Expected CommonJS Vercel Express handler');
  const wrapper = express();
  // Supertest uses a local transport. Model only the Host header the platform
  // would deliver; this does not prove edge routing or deployment protection.
  wrapper.use((req, _res, next) => {
    req.headers.host = req.headers['x-drill-host'];
    next();
  });
  wrapper.use(app);
  return wrapper;
}

async function withTransportRetry(send) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try { return await send(); } catch (error) {
      if (error.code !== 'ECONNRESET' || attempt === 2) throw error;
    }
  }
  throw new Error('Unreachable transport retry state');
}

async function assertSafeDeny(entrypoint, label) {
  const app = loadApp(entrypoint);
  for (const host of [generatedHost, branchHost]) {
    const health = await withTransportRetry(() => request(app).get('/health').set('X-Drill-Host', host));
    assert.equal(health.status, 200, `${label} health`);
    assert.deepEqual(health.body, {
      status: 'ok', mode: 'staging-preview', decisionRoute: 'disabled',
    }, `${label} safe-deny state`);
    const decision = await withTransportRetry(() => request(app).post('/api/staging/decide')
      .set('X-Drill-Host', host).send({ fixtureId: 'obfuscated-email' }));
    assert.equal(decision.status, 404, `${label} fixture route absent`);
    assert.deepEqual(decision.body, { error: 'Not found' }, `${label} fixture route response`);
    const legacy = await withTransportRetry(() => request(app).post('/api/gateway/process')
      .set('X-Drill-Host', host));
    assert.equal(legacy.status, 404, `${label} legacy route absent`);
  }
}

async function assertCandidate(entrypoint, signer) {
  const app = loadApp(entrypoint);
  const token = await new SignJWT({
    tenant_id: 'fixture_tenant', client_id: 'fixture_client', scope: 'gateway:staging:decide',
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: 'local-drill-key' })
    .setIssuer('urn:llm-redaction-gateway:synthetic-preview')
    .setAudience('urn:llm-redaction-gateway:synthetic-preview:api')
    .setSubject('synthetic-drill')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(signer);
  const health = await withTransportRetry(() => request(app).get('/health')
    .set('X-Drill-Host', generatedHost));
  assert.equal(health.status, 200, 'candidate health');
  assert.equal(health.body.decisionRoute, 'fixture-only', 'candidate route enabled');
  const unauthenticated = await withTransportRetry(() => request(app).post('/api/staging/decide')
    .set('X-Drill-Host', generatedHost).send({ fixtureId: 'obfuscated-email' }));
  assert.equal(unauthenticated.status, 401, 'candidate rejects missing token');
  const decision = await withTransportRetry(() => request(app).post('/api/staging/decide')
    .set('X-Drill-Host', branchHost).set('Authorization', `Bearer ${token}`)
    .send({ fixtureId: 'obfuscated-email' }));
  assert.equal(decision.status, 200, 'candidate synthetic decision');
  assert.equal(decision.body.decision, 'redact', 'candidate synthetic detection');
  assert.equal(JSON.stringify(decision.body).includes('alice [at] example [dot] com'), false,
    'candidate must not echo raw synthetic fixture');
}

async function main() {
  if (run('git', [...gitArgs, 'status', '--porcelain']).trim()) {
    throw new Error('Commit the candidate before the drill so the tested code matches candidateOid');
  }
  const baselineOid = run('git', [...gitArgs, 'rev-parse', '--verify', `${baselineInput}^{commit}`]).trim();
  assert.equal(baselineOid.toLowerCase(), baselineInput.toLowerCase(), 'Baseline must be an exact full commit SHA');
  const candidateOid = run('git', [...gitArgs, 'rev-parse', 'HEAD']).trim();
  assert.notEqual(baselineOid, candidateOid, 'Baseline and candidate must differ');
  run('git', [...gitArgs, 'merge-base', '--is-ancestor', baselineOid, candidateOid]);
  validateTree(baselineOid);

  drillDir = mkdtempSync(path.join(root, tempPrefix));
  const baselineDir = path.join(drillDir, 'baseline');
  const archive = path.join(drillDir, 'baseline.tar');
  mkdirSync(baselineDir);
  run('git', [...gitArgs, 'archive', '--format=tar', '--output', archive, baselineOid]);
  validateArchive(archive);
  run('tar', ['-xf', archive, '-C', baselineDir]);
  const tsc = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc');
  run(process.execPath, [tsc, '-p', path.join(baselineDir, 'tsconfig.json')]);
  run(process.execPath, [tsc, '-p', path.join(root, 'tsconfig.json')]);

  const pair = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const publicJwk = await exportJWK(pair.publicKey);
  const publicJwks = JSON.stringify({ keys: [{
    kty: publicJwk.kty, n: publicJwk.n, e: publicJwk.e,
    kid: 'local-drill-key', alg: 'RS256', use: 'sig',
  }] });
  const preview = {
    NODE_ENV: 'production', PORT: '3000', VERCEL: '1', VERCEL_ENV: 'preview', VERCEL_TARGET_ENV: 'preview',
    VERCEL_URL: generatedHost, VERCEL_BRANCH_URL: branchHost,
    VERCEL_PROJECT_PRODUCTION_URL: productionHost,
    GATEWAY_STAGING_PREVIEW: '1', GATEWAY_STAGING_DECISIONS: '1',
    GATEWAY_STAGING_PUBLIC_JWKS: publicJwks,
  };
  const touchedKeys = new Set([
    ...Object.keys(preview), 'GATEWAY_LOCAL_DEMO', 'GATEWAY_PRIVATE_PILOT',
    'GATEWAY_CLIENT_TENANT_GRANTS', ...Object.keys(process.env).filter((key) => key.startsWith('GATEWAY_AUTH_')),
  ]);
  const originalValues = new Map([...touchedKeys].map((key) => [key, process.env[key]]));
  const originalCwd = process.cwd();
  try {
    for (const key of touchedKeys) delete process.env[key];
    Object.assign(process.env, preview);
    // Prevent dotenv from reading any local .env while loading either handler.
    process.chdir(baselineDir);
    const baselineEntry = path.join(baselineDir, 'dist', 'index.js');
    const candidateEntry = path.join(root, 'dist', 'index.js');
    await assertSafeDeny(baselineEntry, 'baseline before candidate');
    await assertCandidate(candidateEntry, pair.privateKey);
    await assertSafeDeny(baselineEntry, 'baseline after candidate');
  } finally {
    process.chdir(originalCwd);
    for (const [key, value] of originalValues) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
  console.log(JSON.stringify({
    simulationOnly: true, hostedDeploymentOrRollback: false,
    baselineOid, candidateOid,
    checks: [
      'baseline safe-deny on generated and branch hosts; decision routes absent',
      'candidate requires signed synthetic token and redacts built-in fixture',
      'baseline safe-deny restored with candidate opt-in and public JWKS still configured',
    ],
  }, null, 2));
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
}).finally(() => {
  try { cleanup(); } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
});
