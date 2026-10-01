import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Agent, request as httpRequest } from 'node:http';
import type { Server } from 'node:http';
import express from 'express';
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose';
import { createApp } from '../src/index';
import { parseRuntimeEnv, type RuntimeEnv } from '../src/config/env';
import { localJsonRequest } from './local-http';

const ISSUER = 'https://issuer.example/';
const AUDIENCE = 'urn:redaction:private-pilot';
const pilotVariables = {
  NODE_ENV: 'development',
  GATEWAY_PRIVATE_PILOT: '1',
  GATEWAY_AUTH_ISSUER: ISSUER,
  GATEWAY_AUTH_AUDIENCE: AUDIENCE,
  GATEWAY_AUTH_JWKS_URL: 'https://issuer.example/keys',
  GATEWAY_CLIENT_TENANT_GRANTS: 'client_a:tenant_legal,client_b:tenant_default',
};

let app: ReturnType<typeof createApp>;
let localKeyResolver: ReturnType<typeof createLocalJWKSet>;
let server: Server;
let privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
let otherPrivateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

type TokenOptions = {
  issuer?: string;
  audience?: string | string[];
  typ?: string;
  tenantId?: string;
  clientId?: string;
  scope?: string;
  subject?: string;
  expiresIn?: number;
  signingKey?: typeof privateKey;
};

async function token(options: TokenOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    tenant_id: options.tenantId ?? 'tenant_legal',
    client_id: options.clientId ?? 'client_a',
    scope: options.scope ?? 'gateway:decide',
  })
    .setProtectedHeader({ alg: 'RS256', typ: options.typ ?? 'at+jwt', kid: 'pilot-test-key' })
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.audience ?? AUDIENCE)
    .setSubject(options.subject ?? 'caller-subject')
    .setIssuedAt(now)
    .setExpirationTime(now + (options.expiresIn ?? 300))
    .sign(options.signingKey ?? privateKey);
}

before(async () => {
  const pair = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  privateKey = pair.privateKey;
  otherPrivateKey = (await generateKeyPair('RS256', { modulusLength: 2048 })).privateKey;
  const publicJwk = await exportJWK(pair.publicKey);
  const runtime = parseRuntimeEnv(pilotVariables);
  assert.equal(runtime.mode, 'private-pilot');
  localKeyResolver = createLocalJWKSet({ keys: [{ ...publicJwk, kid: 'pilot-test-key', alg: 'RS256', use: 'sig' }] });
  app = createApp(runtime, localKeyResolver);
  server = await new Promise<Server>((resolve) => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
  });
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test('production startup remains disabled even with complete pilot configuration', () => {
  assert.throws(
    () => parseRuntimeEnv({ ...pilotVariables, NODE_ENV: 'production' }),
    /Production API startup is disabled/,
  );
});

test('pilot startup requires explicit mode, HTTPS same-origin JWKS, and exact grants', () => {
  const invalid = [
    [{ ...pilotVariables, GATEWAY_PRIVATE_PILOT: '' }, /Private pilot requires/],
    [{ ...pilotVariables, GATEWAY_AUTH_ISSUER: 'http://issuer.example/' }, /HTTPS URL/],
    [{ ...pilotVariables, GATEWAY_AUTH_JWKS_URL: 'https://attacker.example/keys' }, /share the issuer origin/],
    [{ ...pilotVariables, GATEWAY_AUTH_AUDIENCE: '' }, /exact resource identifier/],
    [{ ...pilotVariables, GATEWAY_CLIENT_TENANT_GRANTS: 'client_a:tenant_legal,' }, /explicit client:tenant pairs/],
    [{ ...pilotVariables, GATEWAY_CLIENT_TENANT_GRANTS: 'client_a:tenant_legal,client_a:tenant_legal' }, /duplicate grant/],
    [{ ...pilotVariables, GATEWAY_LOCAL_DEMO: '1' }, /without local-demo opt-in/],
  ] as const;
  for (const [variables, error] of invalid) {
    assert.throws(() => parseRuntimeEnv(variables), error);
  }
  assert.throws(() => parseRuntimeEnv({ NODE_ENV: 'development' }), /Local demo startup requires/);
});

test('verified caller can request only its explicit tenant decision with catalog defaults', async () => {
  const bearer = await token();
  const response = await rawPilotRequest(server, 'POST', '/api/gateway/process', `Bearer ${bearer}`,
    { tenantId: 'tenant_legal', prompt: 'Please email alice@example.com' });
  assert.equal(response.status, 200);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.body.decision, 'redact');
  assert.equal(JSON.stringify(response.body).includes('alice@example.com'), false);
  assert.equal(JSON.stringify(response.body).includes(bearer), false);
});

test('pilot API rejects missing, malformed, oversized, and duplicate credentials', async () => {
  for (const authorization of [undefined, 'Basic not-bearer', 'Bearer x.y.z', `Bearer ${'a'.repeat(8193)}`]) {
    const response = await rawPilotRequest(server, 'POST', '/api/gateway/process', authorization);
    assert.equal(response.status, 401);
    assert.deepEqual(response.body, { error: 'Unauthorized' });
    assert.equal(response.headers['cache-control'], 'no-store');
  }

  const bearer = await token();
  const duplicateStatus = await rawDuplicateAuthorization(server, bearer);
  // Node may reject duplicate fields in its HTTP parser before middleware.
  assert.ok(duplicateStatus === 400 || duplicateStatus === 401);
});

test('pilot limits repeated API attempts before authentication', async () => {
  const quietApp = createApp(parseRuntimeEnv(pilotVariables), localKeyResolver, { write: () => {} });
  const wrapper = express();
  wrapper.use((req, _res, next) => {
    if (req.headers['x-test-loopback-peer'] === 'alternate') {
      Object.defineProperty(req.socket, 'remoteAddress', { configurable: true, value: '127.0.0.2' });
    }
    next();
  });
  wrapper.use(quietApp);
  const agent = new Agent({ keepAlive: true, maxSockets: 1 });
  const limitedServer = await new Promise<Server>((resolve) => {
    const listening = wrapper.listen(0, '127.0.0.1', () => resolve(listening));
  });
  try {
    let deniedCount = 0;
    let limited: Awaited<ReturnType<typeof rawPilotRequest>> | undefined;
    for (let attempt = 0; attempt <= 60; attempt++) {
      const response = await rawPilotRequest(limitedServer, 'POST', '/api/gateway/process', undefined, undefined, agent);
      if (response.status === 429) {
        limited = response;
        break;
      }
      assert.equal(response.status, 401, `attempt ${attempt + 1}`);
      deniedCount++;
    }
    // A visible ECONNRESET test-client retry can consume an extra server slot.
    assert.ok(deniedCount > 0 && deniedCount <= 60);
    assert.ok(limited);
    assert.equal(limited.status, 429);
    assert.deepEqual(limited.body, { error: 'Too many requests' });
    assert.equal(limited.headers['cache-control'], 'no-store');
    assert.ok(limited.headers['retry-after']);
    const alias = await localJsonRequest(limitedServer, 'POST', '/api/gateway/process', undefined,
      { 'X-Test-Loopback-Peer': 'alternate' });
    assert.equal(alias.status, 429);
    const forwarded = await localJsonRequest(limitedServer, 'POST', '/api/gateway/process', undefined,
      { Forwarded: 'for=127.0.0.3' });
    assert.equal(forwarded.status, 403);
    const health = await rawPilotRequest(limitedServer, 'GET', '/health', undefined, undefined, agent);
    assert.equal(health.status, 200);
  } finally {
    agent.destroy();
    await new Promise<void>((resolve, reject) => limitedServer.close((error) => error ? reject(error) : resolve()));
  }
});

async function rawDuplicateAuthorization(server: Server, bearer: string): Promise<number | undefined> {
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected TCP address');
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: '127.0.0.1',
      port: address.port,
      method: 'POST',
      path: '/api/gateway/process',
      headers: {
        Host: `localhost:${address.port}`,
        Authorization: [`Bearer ${bearer}`, `Bearer ${bearer}`],
        'Content-Length': '0',
      },
    }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject);
    req.end();
  });
}

async function rawPilotRequest(
  target: Server,
  method: string,
  path: string,
  authorization?: string,
  body?: unknown,
  agent?: Agent,
): Promise<{ status: number | undefined; body: Record<string, unknown>; headers: Record<string, string | string[] | undefined> }> {
  // This Windows test host intermittently resets loopback sockets after a
  // complete response. All probes are read-only decisions, so retry transport
  // failures only; an HTTP denial or success is never retried.
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      return await rawPilotRequestOnce(target, method, path, authorization, body, agent);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ECONNRESET' || attempt === 7) throw error;
      process.stderr.write(`[private-pilot-auth] ECONNRESET transport retry ${attempt + 1}/7\n`);
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  throw new Error('Unreachable request retry state');
}

async function rawPilotRequestOnce(
  target: Server,
  method: string,
  path: string,
  authorization?: string,
  body?: unknown,
  agent?: Agent,
): Promise<{ status: number | undefined; body: Record<string, unknown>; headers: Record<string, string | string[] | undefined> }> {
  const address = target.address();
  if (!address || typeof address === 'string') throw new Error('Expected TCP address');
  const serialized = body === undefined ? '' : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: '127.0.0.1',
      port: address.port,
      method,
      path,
      agent,
      headers: {
        Host: `localhost:${address.port}`,
        Connection: agent ? 'keep-alive' : 'close',
        'Content-Length': Buffer.byteLength(serialized),
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(authorization === undefined ? {} : { Authorization: authorization }),
      },
    }, (res) => {
      let responseText = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => { responseText += chunk; });
      res.on('end', () => resolve({
        status: res.statusCode,
        body: JSON.parse(responseText) as Record<string, unknown>,
        headers: res.headers,
      }));
    });
    req.on('error', reject);
    req.end(serialized);
  });
}

test('verified token must have exact issuer, single audience, type, signature, and expiry', async () => {
  const invalid = [
    { issuer: 'https://other.example/' },
    { audience: 'urn:other:resource' },
    { audience: [AUDIENCE, 'urn:other:resource'] },
    { typ: 'JWT' },
    { signingKey: otherPrivateKey },
    { expiresIn: -60 },
  ];
  for (const options of invalid) {
    const response = await rawPilotRequest(server, 'POST', '/api/gateway/process', `Bearer ${await token(options)}`);
    assert.equal(response.status, options.audience instanceof Array ? 403 : 401, JSON.stringify(options));
  }
});

test('tenant and client grants, scope, and body tenant are required', async () => {
  const secondGrant = await rawPilotRequest(server, 'POST', '/api/gateway/process',
    `Bearer ${await token({ clientId: 'client_b', tenantId: 'tenant_default' })}`,
    { tenantId: 'tenant_default', prompt: 'Synthetic prompt' });
  assert.equal(secondGrant.status, 200);

  const deniedTokens = [
    { tenantId: 'tenant_unknown' },
    { clientId: 'client_unknown' },
    { clientId: 'client_b' },
    { scope: 'gateway:read' },
    { subject: '' },
  ];
  for (const options of deniedTokens) {
    const response = await rawPilotRequest(server, 'POST', '/api/gateway/process', `Bearer ${await token(options)}`);
    assert.equal(response.status, 403, JSON.stringify(options));
  }
  const bearer = await token();
  for (const body of [
    { tenantId: 'tenant_default', prompt: 'Synthetic prompt' },
    { prompt: 'Synthetic prompt' },
  ]) {
    const response = await rawPilotRequest(server, 'POST', '/api/gateway/process', `Bearer ${bearer}`, body);
    assert.equal(response.status, 403);
  }
});

test('pilot has no fixture, custom policy, or redaction-preview routes', async () => {
  const bearer = await token();
  const paths = ['/api/audit', '/api/policies', '/api/dashboard/summary', '/api/redact', '/api/gateway/evaluate-policy'];
  for (const path of paths) {
    const response = await rawPilotRequest(server, 'GET', path, `Bearer ${bearer}`);
    assert.equal(response.status, 404, path);
  }
  const health = await rawPilotRequest(server, 'GET', '/health');
  assert.equal(health.status, 200);
  assert.equal(health.body.mode, 'private-pilot');
});

test('pilot rejects proxy forwarding before authentication or body parsing', async () => {
  const response = await localJsonRequest(server, 'POST', '/api/gateway/process', undefined,
    { Host: 'localhost:3000', Forwarded: '' });
  assert.equal(response.status, 403);
  assert.deepEqual(response.body, { error: 'Local API only' });
});

test('app factory rejects non-loopback peers even with a local Host header', async () => {
  const wrapper = express();
  wrapper.use((req, _res, next) => {
    Object.defineProperty(req.socket, 'remoteAddress', { configurable: true, value: '203.0.113.9' });
    next();
  });
  wrapper.use(app);
  const wrapperServer = await new Promise<Server>((resolve) => {
    const listening = wrapper.listen(0, '127.0.0.1', () => resolve(listening));
  });
  try {
    const response = await localJsonRequest(wrapperServer, 'GET', '/health', undefined, { Host: 'localhost:3000' });
    assert.equal(response.status, 403);
    assert.deepEqual(response.body, { error: 'Local API only' });
  } finally {
    await new Promise<void>((resolve, reject) => wrapperServer.close((error) => error ? reject(error) : resolve()));
  }
});

test('pilot access logs omit bearer tokens and prompt values', async () => {
  const lines: string[] = [];
  const runtime = parseRuntimeEnv(pilotVariables);
  const loggedApp = createApp(runtime, localKeyResolver, { write: (line) => { lines.push(line); } });
  const loggedServer = await new Promise<Server>((resolve) => {
    const listening = loggedApp.listen(0, '127.0.0.1', () => resolve(listening));
  });
  try {
    const bearer = await token();
    const secret = 'log-probe@example.com';
    const response = await rawPilotRequest(loggedServer, 'POST', '/api/gateway/process', `Bearer ${bearer}`,
      { tenantId: 'tenant_legal', prompt: `Please email ${secret}` });
    assert.equal(response.status, 200);
    assert.ok(lines.length >= 1);
    assert.equal(lines.join('').includes(bearer), false);
    assert.equal(lines.join('').includes(secret), false);
  } finally {
    await new Promise<void>((resolve, reject) => loggedServer.close((error) => error ? reject(error) : resolve()));
  }
});
