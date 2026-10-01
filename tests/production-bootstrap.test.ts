import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import request from 'supertest';
import { createApp } from '../src/index';
import { parseRuntimeEnv } from '../src/config/env';

const production = {
  NODE_ENV: 'production',
  VERCEL: '1',
  VERCEL_ENV: 'production',
  VERCEL_TARGET_ENV: 'production',
  VERCEL_URL: 'gateway-safe-123.vercel.app',
  VERCEL_PROJECT_PRODUCTION_URL: 'gateway.vercel.app',
  GATEWAY_PRODUCTION_BOOTSTRAP: '1',
};

async function transportRetry<T>(send: () => PromiseLike<T>): Promise<T> {
  for (let attempt = 0; attempt < 8; attempt++) {
    try { return await send(); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ECONNRESET' || attempt === 7) throw error;
      process.stderr.write(`[production-bootstrap] ECONNRESET transport retry ${attempt + 1}/7\n`);
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  throw new Error('Unreachable transport retry state');
}

test('production bootstrap requires exact markers, opt-in, and only Vercel domains', () => {
  const valid = parseRuntimeEnv(production);
  assert.equal(valid.mode, 'production-bootstrap');
  if (valid.mode === 'production-bootstrap') {
    assert.deepEqual(valid.allowedHosts, [production.VERCEL_URL]);
  }
  assert.equal(parseRuntimeEnv({
    ...production, VERCEL_PROJECT_PRODUCTION_URL: production.VERCEL_URL,
  }).mode, 'production-bootstrap');
  assert.throws(() => parseRuntimeEnv({ NODE_ENV: 'production' }), /Production API startup is disabled/);
  const invalid = [
    { ...production, NODE_ENV: 'development' },
    { ...production, VERCEL: undefined },
    { ...production, VERCEL_ENV: 'preview' },
    { ...production, VERCEL_TARGET_ENV: 'preview' },
    { ...production, GATEWAY_PRODUCTION_BOOTSTRAP: undefined },
    { ...production, GATEWAY_PRODUCTION_BOOTSTRAP: '0' },
    { ...production, VERCEL_URL: 'gateway.example.com' },
    { ...production, VERCEL_URL: 'gateway-safe-123.vercel.app:443' },
    { ...production, VERCEL_PROJECT_PRODUCTION_URL: 'gateway.example.com' },
    { ...production, GATEWAY_STAGING_PREVIEW: '1' },
    { ...production, GATEWAY_STAGING_DECISIONS: '1' },
    { ...production, GATEWAY_STAGING_PUBLIC_JWKS: '{"keys":[]}' },
    { ...production, GATEWAY_LOCAL_DEMO: '1' },
    { ...production, GATEWAY_PRIVATE_PILOT: '1' },
    { ...production, GATEWAY_AUTH_ISSUER: 'https://issuer.example/' },
    { ...production, GATEWAY_CLIENT_TENANT_GRANTS: 'client:tenant' },
  ];
  for (const variables of invalid) assert.throws(() => parseRuntimeEnv(variables));
});

test('production bootstrap serves only minimal health on its exact deployment Host', async () => {
  const lines: string[] = [];
  const app = createApp(parseRuntimeEnv(production), undefined, { write: (line) => { lines.push(line); } });
  const wrapper = express();
  // The local transport uses 127.0.0.1; model the Host delivered by Vercel.
  wrapper.use((req, _res, next) => { req.headers.host = req.headers['x-test-host'] as string; next(); });
  wrapper.use(app);

  const health = await transportRetry(() => request(wrapper).get('/health')
    .set('X-Test-Host', production.VERCEL_URL));
  assert.equal(health.status, 200);
  assert.deepEqual(health.body, {
    status: 'ok', mode: 'production-bootstrap', decisionRoute: 'disabled',
  });
  assert.equal(health.headers['cache-control'], 'no-store');
  assert.equal(health.headers['x-robots-tag'], 'noindex, nofollow, noarchive');
  assert.equal(health.headers['access-control-allow-origin'], undefined);

  for (const route of ['/api/staging/decide', '/api/gateway/process', '/api/redact', '/api/audit']) {
    const response = await transportRetry(() => request(wrapper).post(route)
      .set('X-Test-Host', production.VERCEL_URL));
    assert.equal(response.status, 404, route);
    assert.deepEqual(response.body, { error: 'Not found' }, route);
  }
  // Verify the mounted stack has no JSON parser. Sending a malformed body to
  // an early-deny route causes a Windows socket reset before a response lands.
  const stack = (app as unknown as { router: { stack: Array<{ name: string }> } }).router.stack;
  assert.equal(stack.some((layer) => layer.name === 'jsonParser'), false);
  assert.equal(lines.length, 0, 'bootstrap must not mount request logging');

  for (const host of [
    production.VERCEL_PROJECT_PRODUCTION_URL, 'gateway.example.com',
    'gateway-git-synthetic.vercel.app', `${production.VERCEL_URL}:443`,
  ]) {
    const denied = await transportRetry(() => request(wrapper).get('/health').set('X-Test-Host', host));
    assert.equal(denied.status, 403, host);
    assert.deepEqual(denied.body, { error: 'Forbidden' }, host);
  }
  const forwarded = await transportRetry(() => request(wrapper).get('/health')
    .set('X-Test-Host', 'gateway.example.com')
    .set('Forwarded', `host=${production.VERCEL_URL}`)
    .set('X-Forwarded-Host', production.VERCEL_URL));
  assert.equal(forwarded.status, 403);

  const sameUrlApp = createApp(parseRuntimeEnv({
    ...production, VERCEL_PROJECT_PRODUCTION_URL: production.VERCEL_URL,
  }));
  const sameUrlWrapper = express();
  sameUrlWrapper.use((req, _res, next) => { req.headers.host = req.headers['x-test-host'] as string; next(); });
  sameUrlWrapper.use(sameUrlApp);
  const sameUrlHealth = await transportRetry(() => request(sameUrlWrapper).get('/health')
    .set('X-Test-Host', production.VERCEL_URL));
  assert.equal(sameUrlHealth.status, 200);
});
