import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import request from 'supertest';
import { app } from '../src/index';

test('gateway hard blocks a secret even when caller requests pattern exclusion', async () => {
  const secret = 'AKIAIOSFODNN7EXAMPLE';
  const response = await request(app).post('/api/gateway/process').send({
    prompt: `Use ${secret} for a cloud call`,
    excludePatternNames: ['aws-access-key'],
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.decision, 'block');
  assert.equal(response.body.redactedPrompt, '');
  assert.deepEqual(response.body.tokenMap, {});
  assert.equal(JSON.stringify(response.body).includes(secret), false);
});

test('decision metadata never returns full matched values', async () => {
  const response = await request(app).post('/api/gateway/process').send({
    prompt: 'Please email alice@example.com',
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.decision, 'redact');
  assert.equal(response.body.hits.length, 1);
  assert.equal('matchedValue' in response.body.hits[0], false);
});

test('local API does not grant cross-origin browser access by default', async () => {
  const response = await request(app).get('/api/patterns').set('Origin', 'https://example.test');
  assert.equal(response.status, 200);
  assert.equal(response.headers['access-control-allow-origin'], undefined);
});

test('production API startup fails closed', () => {
  const child = spawnSync(process.execPath, ['--require', 'ts-node/register', 'src/index.ts'], {
    cwd: process.cwd(),
    env: { ...process.env, NODE_ENV: 'production' },
    encoding: 'utf8',
  });
  assert.notEqual(child.status, 0);
  assert.match(child.stderr, /Production API startup is disabled/);
});
