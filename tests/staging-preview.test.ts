import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import request from 'supertest';
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

async function requestWithTransportRetry<T>(send: () => PromiseLike<T>): Promise<T> {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await send();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ECONNRESET' || attempt === 2) throw error;
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
