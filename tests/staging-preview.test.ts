import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import express from 'express';
import request from 'supertest';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { createApp } from '../src/index';
import { parseRuntimeEnv } from '../src/config/env';

const preview = {
  NODE_ENV: 'production',
  VERCEL: '1',
  VERCEL_ENV: 'preview',
  VERCEL_TARGET_ENV: 'preview',
  VERCEL_URL: 'gateway-abc123.vercel.app',
  VERCEL_BRANCH_URL: 'gateway-git-staging.vercel.app',
  VERCEL_PROJECT_PRODUCTION_URL: 'gateway.vercel.app',
  GATEWAY_STAGING_PREVIEW: '1',
};

let candidateVariables: typeof preview & { GATEWAY_STAGING_DECISIONS: string; GATEWAY_STAGING_PUBLIC_JWKS: string };
let signingKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let otherSigningKey: typeof signingKey;
let candidateApp: ReturnType<typeof createApp>;
let candidateWrapper: ReturnType<typeof express>;

before(async () => {
  const pair = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  signingKey = pair.privateKey;
  otherSigningKey = (await generateKeyPair('RS256', { modulusLength: 2048 })).privateKey;
  const jwk = await exportJWK(pair.publicKey);
  candidateVariables = {
    ...preview,
    GATEWAY_STAGING_DECISIONS: '1',
    GATEWAY_STAGING_PUBLIC_JWKS: JSON.stringify({ keys: [{
      kty: jwk.kty, n: jwk.n, e: jwk.e, kid: 'synthetic-test-key', alg: 'RS256', use: 'sig',
    }] }),
  };
  candidateApp = createApp(parseRuntimeEnv(candidateVariables));
  candidateWrapper = express();
  candidateWrapper.use((req, _res, next) => { req.headers.host = req.headers['x-test-host'] as string; next(); });
  candidateWrapper.use(candidateApp);
});

type TokenOptions = {
  issuer?: string;
  audience?: string | string[];
  scope?: string;
  tenantId?: string;
  clientId?: string;
  expiresIn?: number;
  typ?: string;
  signingKey?: typeof signingKey;
};

async function bearer(options: TokenOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    tenant_id: options.tenantId ?? 'fixture_tenant',
    client_id: options.clientId ?? 'fixture_client',
    scope: options.scope ?? 'gateway:staging:decide',
  })
    .setProtectedHeader({ alg: 'RS256', typ: options.typ ?? 'at+jwt', kid: 'synthetic-test-key' })
    .setIssuer(options.issuer ?? 'urn:llm-redaction-gateway:synthetic-preview')
    .setAudience(options.audience ?? 'urn:llm-redaction-gateway:synthetic-preview:api')
    .setSubject('synthetic-caller')
    .setIssuedAt(now)
    .setExpirationTime(now + (options.expiresIn ?? 300))
    .sign(options.signingKey ?? signingKey);
}

async function requestWithTransportRetry<T>(send: () => PromiseLike<T>): Promise<T> {
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      return await send();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ECONNRESET' || attempt === 7) throw error;
      process.stderr.write(`[staging-preview] ECONNRESET transport retry ${attempt + 1}/7\n`);
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  throw new Error('Unreachable request retry state');
}

test('staging startup requires exact preview markers, opt-in, and distinct generated hosts', () => {
  assert.equal(parseRuntimeEnv(preview).mode, 'staging-preview');
  const invalid = [
    { ...preview, VERCEL: undefined },
    { ...preview, VERCEL_ENV: 'production' },
    { ...preview, VERCEL_TARGET_ENV: 'production' },
    { ...preview, VERCEL_TARGET_ENV: 'staging' },
    { ...preview, GATEWAY_STAGING_PREVIEW: undefined },
    { ...preview, GATEWAY_LOCAL_DEMO: '1' },
    { ...preview, GATEWAY_PRIVATE_PILOT: '1' },
    { ...preview, GATEWAY_AUTH_JWKS_URL: 'https://issuer.example/keys' },
    { ...preview, NODE_ENV: 'development' },
    { ...preview, VERCEL_URL: 'gateway.example.com' },
    { ...preview, VERCEL_BRANCH_URL: 'gateway.vercel.app' },
    { ...preview, VERCEL_URL: 'gateway.vercel.app' },
  ];
  for (const variables of invalid) {
    assert.throws(() => parseRuntimeEnv(variables), /Staging preview|generated \.vercel\.app|differ from the production/);
  }
});

test('safe-deny preview answers health but has no decision route or request-body parser', async () => {
  const app = createApp(parseRuntimeEnv(preview));
  // Keep the transport Host local on this Windows runner. The wrapper models
  // the Host delivered by Vercel to the Express app; it exists only in tests.
  const wrapper = express();
  wrapper.use((req, _res, next) => { req.headers.host = req.headers['x-test-host'] as string; next(); });
  wrapper.use(app);
  for (const host of [preview.VERCEL_URL, preview.VERCEL_BRANCH_URL]) {
    const health = await requestWithTransportRetry(() => request(wrapper).get('/health').set('X-Test-Host', host));
    assert.equal(health.status, 200);
    assert.deepEqual(health.body, { status: 'ok', mode: 'staging-preview', decisionRoute: 'disabled' });
    assert.equal(health.headers['cache-control'], 'no-store');
    assert.equal(health.headers['x-robots-tag'], 'noindex, nofollow, noarchive');
    const decision = await requestWithTransportRetry(() => request(wrapper).post('/api/gateway/process').set('X-Test-Host', host));
    assert.equal(decision.status, 404);
    assert.deepEqual(decision.body, { error: 'Not found' });
  }
  for (const host of [preview.VERCEL_PROJECT_PRODUCTION_URL, 'gateway.example.com', 'gateway-abc123.vercel.app:443']) {
    const response = await requestWithTransportRetry(() => request(wrapper).get('/health').set('X-Test-Host', host));
    assert.equal(response.status, 403);
    assert.deepEqual(response.body, { error: 'Forbidden' });
  }
});

test('fixture mode requires separate opt-in and one public-only RSA key', () => {
  const valid = parseRuntimeEnv(candidateVariables);
  assert.equal(valid.mode, 'staging-preview');
  if (valid.mode === 'staging-preview') assert.ok(valid.decision);
  const jwks = JSON.parse(candidateVariables.GATEWAY_STAGING_PUBLIC_JWKS);
  const invalid = [
    { ...candidateVariables, GATEWAY_STAGING_DECISIONS: '0' },
    { ...candidateVariables, GATEWAY_STAGING_PUBLIC_JWKS: undefined },
    { ...candidateVariables, GATEWAY_STAGING_PUBLIC_JWKS: JSON.stringify({ keys: [{ ...jwks.keys[0], d: 'private-key' }] }) },
    { ...candidateVariables, GATEWAY_STAGING_PUBLIC_JWKS: JSON.stringify({ keys: [jwks.keys[0], jwks.keys[0]] }) },
    { ...candidateVariables, GATEWAY_STAGING_PUBLIC_JWKS: JSON.stringify({ keys: [{ ...jwks.keys[0], kty: 'oct' }] }) },
    { ...candidateVariables, GATEWAY_AUTH_ISSUER: 'https://issuer.example/' },
    { ...candidateVariables, VERCEL_ENV: 'production' },
  ];
  for (const variables of invalid) assert.throws(() => parseRuntimeEnv(variables));
});

test('candidate has no public decision and accepts only authenticated fixture IDs', async () => {
  const host = preview.VERCEL_URL;
  const health = await requestWithTransportRetry(() => request(candidateWrapper).get('/health').set('X-Test-Host', host));
  assert.equal(health.status, 200);
  assert.equal(health.body.decisionRoute, 'fixture-only');
  assert.equal(health.headers['cache-control'], 'no-store');
  assert.equal(health.headers['x-robots-tag'], 'noindex, nofollow, noarchive');
  assert.equal(health.headers['access-control-allow-origin'], undefined);

  const missing = await requestWithTransportRetry(() => request(candidateWrapper).post('/api/staging/decide')
    .set('X-Test-Host', host));
  assert.equal(missing.status, 401);
  assert.deepEqual(missing.body, { error: 'Unauthorized' });
  const malformed = await requestWithTransportRetry(() => request(candidateWrapper).post('/api/staging/decide')
    .set('X-Test-Host', host).set('Authorization', 'Bearer invalid'));
  assert.equal(malformed.status, 401);

  const token = await bearer();
  const expectations = [
    ['clean-text', 'allow'],
    ['obfuscated-email', 'redact'],
    ['invalid-card', 'allow'],
    ['valid-card', 'block'],
  ];
  for (const [fixtureId, decision] of expectations) {
    const response = await requestWithTransportRetry(() => request(candidateWrapper).post('/api/staging/decide')
      .set('X-Test-Host', host).set('Authorization', `Bearer ${token}`).send({ fixtureId }));
    assert.equal(response.status, 200, fixtureId);
    assert.equal(response.body.decision, decision, fixtureId);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['access-control-allow-origin'], undefined);
    assert.equal(JSON.stringify(response.body).includes(token), false);
  }
  const email = await requestWithTransportRetry(() => request(candidateWrapper).post('/api/staging/decide')
    .set('X-Test-Host', host).set('Authorization', `Bearer ${token}`)
    .send({ fixtureId: 'obfuscated-email' }));
  assert.equal(JSON.stringify(email.body).includes('alice [at] example [dot] com'), false);
  const card = await requestWithTransportRetry(() => request(candidateWrapper).post('/api/staging/decide')
    .set('X-Test-Host', host).set('Authorization', `Bearer ${token}`).send({ fixtureId: 'valid-card' }));
  assert.equal(card.body.redactedPrompt, '');
});

test('candidate rejects caller text, tenant fields, unknown fixtures, and other routes without echo', async () => {
  const token = await bearer();
  const secret = 'do-not-echo@example.com';
  for (const body of [
    { fixtureId: 'missing' },
    { fixtureId: 'clean-text', prompt: secret },
    { fixtureId: 'clean-text', tenantId: 'fixture_tenant' },
    { prompt: secret },
  ]) {
    const response = await requestWithTransportRetry(() => request(candidateWrapper).post('/api/staging/decide')
      .set('X-Test-Host', preview.VERCEL_BRANCH_URL).set('Authorization', `Bearer ${token}`).send(body));
    assert.equal(response.status, 400);
    assert.deepEqual(response.body, { error: 'Invalid payload' });
    assert.equal(JSON.stringify(response.body).includes(secret), false);
  }
  const invalidJson = await requestWithTransportRetry(() => request(candidateWrapper).post('/api/staging/decide')
    .set('X-Test-Host', preview.VERCEL_URL).set('Authorization', `Bearer ${token}`)
    .set('Content-Type', 'application/json').send('{"fixtureId":"clean-text",'));
  assert.equal(invalidJson.status, 400);
  assert.deepEqual(invalidJson.body, { error: 'Invalid payload' });
  const legacy = await requestWithTransportRetry(() => request(candidateWrapper).post('/api/gateway/process')
    .set('X-Test-Host', preview.VERCEL_URL).set('Authorization', `Bearer ${token}`));
  assert.equal(legacy.status, 404);
  const productionAlias = await requestWithTransportRetry(() => request(candidateWrapper).get('/health')
    .set('X-Test-Host', preview.VERCEL_PROJECT_PRODUCTION_URL));
  assert.equal(productionAlias.status, 403);
});

test('candidate verifies isolated issuer, audience, scope, tenant, and expiry', async () => {
  const invalid: Array<[TokenOptions, number]> = [
    [{ issuer: 'urn:another:issuer' }, 401],
    [{ audience: 'urn:production:api' }, 401],
    [{ audience: ['urn:llm-redaction-gateway:synthetic-preview:api', 'urn:production:api'] }, 403],
    [{ scope: 'gateway:decide' }, 403],
    [{ typ: 'JWT' }, 401],
    [{ signingKey: otherSigningKey }, 401],
    [{ tenantId: 'customer_tenant' }, 403],
    [{ clientId: 'customer_client' }, 403],
    [{ expiresIn: -60 }, 401],
  ];
  for (const [options, expectedStatus] of invalid) {
    const token = await bearer(options);
    const response = await requestWithTransportRetry(() => request(candidateWrapper).post('/api/staging/decide')
      .set('X-Test-Host', preview.VERCEL_URL).set('Authorization', `Bearer ${token}`));
    assert.equal(response.status, expectedStatus, JSON.stringify(options));
    assert.equal(JSON.stringify(response.body).includes(token), false);
  }
});

test('candidate denies oversized unauthenticated request headers before body upload', async () => {
  // A checkContinue listener prevents Node from auto-sending HTTP 100. The
  // client advertises an oversized body but never uploads it unless asked.
  const server = createServer();
  server.on('checkContinue', (req, res) => candidateWrapper(req, res));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Expected TCP address');
    const response = await requestWithTransportRetry(() => new Promise<{ status: number; body: string; continued: boolean }>((resolve, reject) => {
      let continued = false;
      const req = httpRequest({
        hostname: '127.0.0.1', port: address.port, method: 'POST', path: '/api/staging/decide',
        headers: {
          Host: `localhost:${address.port}`,
          'X-Test-Host': preview.VERCEL_URL,
          Expect: '100-continue',
          'Content-Type': 'application/json',
          'Content-Length': String(260 * 1024),
        },
      }, (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => { body += chunk; });
        res.on('end', () => { resolve({ status: res.statusCode ?? 0, body, continued }); req.destroy(); });
      });
      req.on('continue', () => { continued = true; reject(new Error('Body upload was requested before authentication.')); req.destroy(); });
      req.on('error', reject);
      req.setTimeout(5000, () => req.destroy(new Error('Header-only request timed out')));
      req.flushHeaders();
    }));
    assert.equal(response.status, 401);
    assert.equal(response.continued, false);
    assert.deepEqual(JSON.parse(response.body), { error: 'Unauthorized' });
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test('candidate bounds authenticated body size and emits no request log', async () => {
  const lines: string[] = [];
  const logged = createApp(parseRuntimeEnv(candidateVariables), undefined, { write: (line) => { lines.push(line); } });
  const wrapper = express();
  wrapper.use((req, _res, next) => { req.headers.host = req.headers['x-test-host'] as string; next(); });
  wrapper.use(logged);
  const token = await bearer();
  const tooLarge = { fixtureId: 'clean-text', prompt: 'x'.repeat(260 * 1024) };
  const response = await requestWithTransportRetry(() => request(wrapper).post('/api/staging/decide')
    .set('X-Test-Host', preview.VERCEL_URL).set('Authorization', `Bearer ${token}`).send(tooLarge));
  assert.equal(response.status, 413);
  assert.deepEqual(response.body, { error: 'Payload too large' });
  assert.equal(lines.length, 0);
});
