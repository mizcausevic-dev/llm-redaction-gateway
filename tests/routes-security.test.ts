import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import request from 'supertest';
import { app } from '../src/index';
import { hasProxyForwardingHeaders, isLocalHostHeader } from '../src/config/runtime-boundary';

test('gateway hard blocks a secret even when caller requests pattern exclusion', async () => {
  const secret = 'AKIAIOSFODNN7EXAMPLE';
  const response = await request(app).post('/api/gateway/process').send({
    prompt: `Use ${secret} for a cloud call`,
    excludePatternNames: ['aws-access-key'],
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.decision, 'block');
  assert.equal(response.body.redactedPrompt, '');
  assert.equal('tokenMap' in response.body, false);
  assert.equal(JSON.stringify(response.body).includes(secret), false);
});

test('gateway hard blocks a valid card shape but allows a checksum-invalid ticket', async () => {
  const card = await request(app).post('/api/gateway/process').send({
    prompt: 'Card 4532-1234-5678-9014',
  });
  assert.equal(card.status, 200);
  assert.equal(card.body.decision, 'block');
  assert.equal(card.body.redactedPrompt, '');

  const ticket = await request(app).post('/api/gateway/process').send({
    prompt: 'Ticket 1234-5678-9012-3456',
  });
  assert.equal(ticket.status, 200);
  assert.equal(ticket.body.decision, 'allow');
  assert.equal(ticket.body.hits.length, 0);
});

test('decision metadata never returns full matched values', async () => {
  const response = await request(app).post('/api/gateway/process').send({
    prompt: 'Please email alice@example.com',
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.decision, 'redact');
  assert.equal(response.body.hits.length, 1);
  assert.equal('matchedValue' in response.body.hits[0], false);
  assert.equal('matchedSnippet' in response.body.hits[0], false);
});

test('local API does not grant cross-origin browser access by default', async () => {
  const response = await request(app).get('/api/patterns').set('Origin', 'https://example.test');
  assert.equal(response.status, 200);
  assert.equal(response.headers['access-control-allow-origin'], undefined);
});

test('local API rejects a non-local Host before routing', async () => {
  const response = await request(app)
    .get('/health')
    .set('Host', 'attacker.example');
  assert.equal(response.status, 403);
  assert.deepEqual(response.body, { error: 'Local API only' });
  assert.equal(response.headers['cache-control'], 'no-store');
});

test('local API rejects proxy forwarding headers even with a rewritten local Host', async () => {
  const response = await request(app)
    .get('/health')
    .set('Host', 'localhost:3000')
    .set('X-Forwarded-Host', 'public.example');
  assert.equal(response.status, 403);
  assert.deepEqual(response.body, { error: 'Local API only' });
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(isLocalHostHeader('localhost:65536'), false);
  assert.equal(hasProxyForwardingHeaders({ forwarded: 'for=public.example' }), true);
});

test('local API marks sensitive responses non-cacheable', async () => {
  const response = await request(app).post('/api/redact').send({ text: 'Email alice@example.com' });
  assert.equal(response.status, 200);
  assert.equal(response.headers['cache-control'], 'no-store');
});

test('production API startup fails closed', () => {
  const child = spawnSync(process.execPath, ['dist/index.js'], {
    cwd: process.cwd(),
    env: { ...process.env, NODE_ENV: 'production', GATEWAY_LOCAL_DEMO: '1', PORT: '3000' },
    encoding: 'utf8',
  });
  assert.notEqual(child.status, 0);
  assert.match(child.stderr, /Production API startup is disabled/);
});

test('compiled API refuses missing mode, missing opt-in, and non-demo mode', () => {
  for (const overrides of [
    { NODE_ENV: '', GATEWAY_LOCAL_DEMO: '1' },
    { NODE_ENV: 'development', GATEWAY_LOCAL_DEMO: '' },
    { NODE_ENV: 'staging', GATEWAY_LOCAL_DEMO: '1' },
  ]) {
    const child = spawnSync(process.execPath, ['dist/index.js'], {
      cwd: process.cwd(),
      env: { ...process.env, PORT: '3000', ...overrides },
      encoding: 'utf8',
    });
    assert.notEqual(child.status, 0);
    assert.match(child.stderr, /Local demo startup requires NODE_ENV=development/);
  }
});

test('compiled API refuses malformed port', () => {
  const child = spawnSync(process.execPath, ['dist/index.js'], {
    cwd: process.cwd(),
    env: { ...process.env, NODE_ENV: 'development', GATEWAY_LOCAL_DEMO: '1', PORT: '3000junk' },
    encoding: 'utf8',
  });
  assert.notEqual(child.status, 0);
  assert.match(child.stderr, /PORT must be an integer/);
});
