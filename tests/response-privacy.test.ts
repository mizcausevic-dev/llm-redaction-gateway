import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import morgan from 'morgan';
import { ACCESS_LOG_FORMAT } from '../src/config/access-log';
import { app } from '../src/index';
import { localJsonRequest } from './local-http';

const email = 'privacy-probe@example.com';
const server = app.listen(0, '127.0.0.1');
after(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
});

function assertNoMatchedValueInResponse(body: unknown): void {
  const json = JSON.stringify(body);
  assert.equal(json.includes(email), false, 'recognized input leaked into response');
  assert.equal(json.includes('"original"'), false, 'original prompt leaked into response');
  assert.equal(json.includes('"matchedValue"'), false, 'raw hit leaked into response');
  assert.equal(json.includes('"matchedSnippet"'), false, 'partial match leaked into response');
  assert.equal(json.includes('"tokenMap"'), false, 'reversal map leaked into response');
}

test('all redaction and policy response paths keep matched values server-side', async () => {
  const requests = [
    () => localJsonRequest(server, 'POST', '/api/redact', { text: `Email ${email}` }),
    () => localJsonRequest(server, 'POST', '/api/gateway/process', { prompt: `Email ${email}` }),
    () => localJsonRequest(server, 'POST', '/api/gateway/process', { prompt: `Email ${email}`, tenantId: 'tenant_legal' }),
    () => localJsonRequest(server, 'POST', '/api/gateway/evaluate-policy', { text: `Email ${email}` }),
    () => localJsonRequest(server, 'POST', '/api/gateway/evaluate-policy', {
      text: `Email ${email}`,
      tenantPolicy: {
        tenantId: email,
        overrides: [{ patternName: 'email', decision: 'allow' }],
        allowedRedactedCategories: ['pii'],
      },
    }),
  ];

  for (const pending of requests) {
    const response = await pending();
    assert.equal(response.status, 200);
    assertNoMatchedValueInResponse(response.body);
  }
});

test('invalid policy input does not reflect caller values in validation errors', async () => {
  const response = await localJsonRequest(server, 'POST', '/api/gateway/evaluate-policy', {
    text: `Email ${email}`,
    tenantPolicy: {
      tenantId: 'test-policy',
      overrides: [{ patternName: 'email', decision: email }],
      allowedRedactedCategories: ['pii'],
    },
  });
  assert.equal(response.status, 400);
  assertNoMatchedValueInResponse(response.body);
});

test('raw redaction endpoint ignores caller-requested detector exclusion', async () => {
  const response = await localJsonRequest(server, 'POST', '/api/redact', {
    text: `Email ${email}`,
    excludePatternNames: ['email'],
  });
  assert.equal(response.status, 200);
  assert.match(response.body.redacted, /\[EMAIL_1\]/);
  assertNoMatchedValueInResponse(response.body);
});

test('decision endpoint does not return newly recognized synthetic values', async () => {
  const cases = [
    { text: 'user [at] example [dot] com', pattern: 'email' },
    { text: 'SSN 123456789', pattern: 'ssn-us' },
    { text: 'Call 212 555 0123', pattern: 'us-phone' },
  ];
  for (const item of cases) {
    const response = await localJsonRequest(server, 'POST', '/api/gateway/process', { prompt: item.text });
    assert.equal(response.status, 200);
    assert.equal(response.body.decision, 'redact');
    assert.ok(response.body.hits.some((hit: { patternName: string }) => hit.patternName === item.pattern));
    assert.equal(JSON.stringify(response.body).includes(item.text), false);
  }
});

test('public unredact endpoint cannot return original values', async () => {
  const response = await localJsonRequest(server, 'POST', '/api/redact/unredact', {
    text: 'Email [EMAIL_1]',
    tokenMap: { '[EMAIL_1]': email },
  });
  assert.equal(response.status, 404);
  assertNoMatchedValueInResponse(response.body);
});

test('access logs omit query strings carrying caller values', () => {
  const encodedUrl = `/health?probe=${encodeURIComponent(email)}`;
  const output = morgan.compile(ACCESS_LOG_FORMAT)({
    method: () => 'GET',
    status: () => '200',
    'response-time': () => '1.2',
    url: () => encodedUrl,
  }, {} as never, {} as never);
  assert.ok(output);
  assert.match(output, /GET.*200/);
  assert.equal(output.includes(email), false);
  assert.equal(output.includes(encodeURIComponent(email)), false);
});
