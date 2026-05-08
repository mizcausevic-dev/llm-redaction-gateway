import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactText } from '../src/governance/redaction-engine';
import { evaluatePolicy, processGatewayRequest, type TenantPolicy } from '../src/governance/policy-engine';
import { summarizeAudit, type AuditEntry } from '../src/governance/audit-log';

test('evaluatePolicy: clean text → allow', () => {
  const r = redactText('Just summarize this article about gardening.');
  const p = evaluatePolicy(r);
  assert.equal(p.decision, 'allow');
  assert.equal(p.hitCount, 0);
});

test('evaluatePolicy: SSN → redact (default)', () => {
  const r = redactText('SSN: 123-45-6789');
  const p = evaluatePolicy(r);
  assert.equal(p.decision, 'redact');
  assert.equal(p.redactedCount, 1);
});

test('evaluatePolicy: credit card hard-blocks regardless of policy', () => {
  const r = redactText('Card 4532-1234-5678-9010');
  // Try to override credit-card to allow — gateway should still block
  const tenantPolicy: TenantPolicy = {
    tenantId: 'rogue',
    overrides: [{ patternName: 'credit-card', decision: 'allow' }],
    allowedRedactedCategories: [],
  };
  const p = evaluatePolicy(r, tenantPolicy);
  assert.equal(p.decision, 'block');
  assert.equal(p.hardBlockTriggered, true);
});

test('evaluatePolicy: CONFIDENTIAL marker blocks by default', () => {
  const r = redactText('CONFIDENTIAL: M&A deal terms attached');
  const p = evaluatePolicy(r);
  assert.equal(p.decision, 'block');
  assert.ok(p.blockingReasons.length >= 1);
});

test('evaluatePolicy: tenant override allows email passthrough', () => {
  const r = redactText('Reach out to user@corp.com');
  const policy: TenantPolicy = {
    tenantId: 'tenant_legal',
    overrides: [{ patternName: 'email', decision: 'allow' }],
    allowedRedactedCategories: ['pii'],
  };
  const p = evaluatePolicy(r, policy);
  assert.equal(p.decision, 'allow');
  assert.equal(p.allowedCount, 1);
  assert.ok(p.appliedOverrides.length >= 1);
});

test('evaluatePolicy: tenant override can escalate redact → block', () => {
  const r = redactText('JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature123');
  const policy: TenantPolicy = {
    tenantId: 'strict',
    overrides: [{ patternName: 'jwt-token', decision: 'block' }],
    allowedRedactedCategories: [],
  };
  const p = evaluatePolicy(r, policy);
  assert.equal(p.decision, 'block');
});

test('processGatewayRequest: blocked decision returns empty prompt + map', () => {
  const r = redactText('Secret: AKIAIOSFODNN7EXAMPLE');
  const decision = processGatewayRequest(r);
  assert.equal(decision.decision, 'block');
  assert.equal(decision.redactedPrompt, '');
  assert.deepEqual(decision.tokenMap, {});
});

test('processGatewayRequest: redact decision passes through tokenized prompt', () => {
  const r = redactText('Customer email: alice@corp.com');
  const decision = processGatewayRequest(r);
  assert.equal(decision.decision, 'redact');
  assert.match(decision.redactedPrompt, /\[EMAIL_1\]/);
  assert.ok(Object.keys(decision.tokenMap).length > 0);
});

test('processGatewayRequest: allow decision returns original prompt unchanged', () => {
  const r = redactText('What is the weather today?');
  const decision = processGatewayRequest(r);
  assert.equal(decision.decision, 'allow');
  assert.equal(decision.redactedPrompt, 'What is the weather today?');
});

test('summarizeAudit: empty entries → zeros', () => {
  const s = summarizeAudit([]);
  assert.equal(s.totalDecisions, 0);
  assert.equal(s.byDecision.allow, 0);
  assert.equal(s.byDecision.redact, 0);
  assert.equal(s.byDecision.block, 0);
});

test('summarizeAudit: aggregates decision counts', () => {
  const entries: AuditEntry[] = [
    { entryId: '1', timestamp: '2026-05-07T10:00:00Z', tenantId: 't1', user: 'u1', targetProvider: 'Anthropic', targetModel: 'claude', decision: 'allow', hitCount: 0, highestSeverity: null, byCategory: { credential: 0, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 100 },
    { entryId: '2', timestamp: '2026-05-07T10:01:00Z', tenantId: 't1', user: 'u2', targetProvider: 'Anthropic', targetModel: 'claude', decision: 'redact', hitCount: 1, highestSeverity: 'medium', byCategory: { credential: 0, pii: 1, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 200 },
    { entryId: '3', timestamp: '2026-05-07T10:02:00Z', tenantId: 't2', user: 'u3', targetProvider: 'OpenAI', targetModel: 'gpt-5', decision: 'block', hitCount: 1, highestSeverity: 'critical', byCategory: { credential: 1, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: true, promptBytes: 300 },
  ];
  const s = summarizeAudit(entries);
  assert.equal(s.totalDecisions, 3);
  assert.equal(s.byDecision.allow, 1);
  assert.equal(s.byDecision.redact, 1);
  assert.equal(s.byDecision.block, 1);
  assert.equal(s.uniqueTenants, 2);
  assert.equal(s.uniqueUsers, 3);
  assert.equal(s.hardBlockRate, 33.3);
  assert.equal(s.blockRate, 33.3);
});

test('summarizeAudit: top users sorted by block count', () => {
  const entries: AuditEntry[] = [
    { entryId: '1', timestamp: '2026-05-07T10:00:00Z', tenantId: 't1', user: 'safe@corp', targetProvider: 'A', targetModel: 'm', decision: 'allow', hitCount: 0, highestSeverity: null, byCategory: { credential: 0, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 100 },
    { entryId: '2', timestamp: '2026-05-07T10:01:00Z', tenantId: 't1', user: 'risky@corp', targetProvider: 'A', targetModel: 'm', decision: 'block', hitCount: 1, highestSeverity: 'critical', byCategory: { credential: 1, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: true, promptBytes: 200 },
    { entryId: '3', timestamp: '2026-05-07T10:02:00Z', tenantId: 't1', user: 'risky@corp', targetProvider: 'A', targetModel: 'm', decision: 'block', hitCount: 1, highestSeverity: 'critical', byCategory: { credential: 0, pii: 0, pci: 1, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: true, promptBytes: 200 },
  ];
  const s = summarizeAudit(entries);
  assert.equal(s.topUsers[0].user, 'risky@corp');
  assert.equal(s.topUsers[0].blockCount, 2);
});

test('summarizeAudit: by-category totals correct', () => {
  const entries: AuditEntry[] = [
    { entryId: '1', timestamp: '2026-05-07T10:00:00Z', tenantId: 't1', user: 'u', targetProvider: 'A', targetModel: 'm', decision: 'redact', hitCount: 3, highestSeverity: 'high', byCategory: { credential: 0, pii: 2, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 1 }, hardBlockTriggered: false, promptBytes: 100 },
    { entryId: '2', timestamp: '2026-05-07T10:01:00Z', tenantId: 't1', user: 'u', targetProvider: 'A', targetModel: 'm', decision: 'block', hitCount: 1, highestSeverity: 'critical', byCategory: { credential: 1, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: true, promptBytes: 100 },
  ];
  const s = summarizeAudit(entries);
  assert.equal(s.byCategoryTotal.pii, 2);
  assert.equal(s.byCategoryTotal['source-code'], 1);
  assert.equal(s.byCategoryTotal.credential, 1);
});
