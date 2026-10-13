import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { app } from '../src/index';
import { hasProxyForwardingHeaders, isLocalHostHeader, isLoopbackPeer } from '../src/config/runtime-boundary';
import { localJsonRequest } from './local-http';

const server = app.listen(0, '127.0.0.1');
after(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test('gateway hard blocks a secret even when caller requests pattern exclusion', async () => {
  const secret = 'AKIAIOSFODNN7EXAMPLE';
  const response = await localJsonRequest(server, 'POST', '/api/gateway/process', {
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
  const card = await localJsonRequest(server, 'POST', '/api/gateway/process', {
    prompt: 'Card 4532-1234-5678-9014',
  });
  assert.equal(card.status, 200);
  assert.equal(card.body.decision, 'block');
  assert.equal(card.body.redactedPrompt, '');

  const ticket = await localJsonRequest(server, 'POST', '/api/gateway/process', {
    prompt: 'Ticket 1234-5678-9012-3456',
  });
  assert.equal(ticket.status, 200);
  assert.equal(ticket.body.decision, 'allow');
  assert.equal(ticket.body.hits.length, 0);
});

test('decision metadata never returns full matched values', async () => {
  const response = await localJsonRequest(server, 'POST', '/api/gateway/process', {
    prompt: 'Please email alice@example.com',
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.decision, 'redact');
  assert.equal(response.body.hits.length, 1);
  assert.equal('matchedValue' in response.body.hits[0], false);
  assert.equal('matchedSnippet' in response.body.hits[0], false);
});

test('local API does not grant cross-origin browser access by default', async () => {
  const response = await localJsonRequest(server, 'GET', '/api/patterns', undefined, { Origin: 'https://example.test' });
  assert.equal(response.status, 200);
  assert.equal(response.headers['access-control-allow-origin'], undefined);
});

test('local API rejects a non-local Host before routing', async () => {
  const response = await localJsonRequest(server, 'GET', '/health', undefined, { Host: 'attacker.example' });
  assert.equal(response.status, 403);
  assert.deepEqual(response.body, { error: 'Local API only' });
  assert.equal(response.headers['cache-control'], 'no-store');
});

test('local API rejects proxy forwarding headers even with a rewritten local Host', async () => {
  const response = await localJsonRequest(server, 'GET', '/health', undefined,
    { Host: 'localhost:3000', 'X-Forwarded-Host': 'public.example' });
  assert.equal(response.status, 403);
  assert.deepEqual(response.body, { error: 'Local API only' });
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(isLocalHostHeader('localhost:65536'), false);
  assert.equal(hasProxyForwardingHeaders({ forwarded: 'for=public.example' }), true);
  assert.equal(isLoopbackPeer('203.0.113.9'), false);
  assert.equal(isLoopbackPeer('::ffff:127.0.0.1'), true);
});

test('local API marks sensitive responses non-cacheable', async () => {
  const response = await localJsonRequest(server, 'POST', '/api/redact', { text: 'Email alice@example.com' });
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
