import type { AuditEntry } from '../governance/audit-log';

// Realistic 24h window. Most calls allow, some redact, a few block.
// Hard-block scenarios in the mix (credit card, AWS creds, GitHub PAT).
export const AUDIT_ENTRIES: AuditEntry[] = [
  // Allow / clean traffic
  { entryId: 'a_001', timestamp: '2026-05-07T08:14:22Z', tenantId: 'tenant_engineering', user: 'alice@corp.com', targetProvider: 'Anthropic', targetModel: 'claude-sonnet-4.6', decision: 'allow', hitCount: 0, highestSeverity: null, byCategory: { credential: 0, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 1024 },
  { entryId: 'a_002', timestamp: '2026-05-07T08:22:11Z', tenantId: 'tenant_default', user: 'bob@corp.com', targetProvider: 'OpenAI', targetModel: 'gpt-5-mini', decision: 'allow', hitCount: 0, highestSeverity: null, byCategory: { credential: 0, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 768 },

  // Redactions — PII passthrough as redacted tokens
  { entryId: 'a_003', timestamp: '2026-05-07T09:11:05Z', tenantId: 'tenant_support', user: 'carol@corp.com', targetProvider: 'Anthropic', targetModel: 'claude-haiku-4.5', decision: 'redact', hitCount: 2, highestSeverity: 'low', byCategory: { credential: 0, pii: 2, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 2048 },
  { entryId: 'a_004', timestamp: '2026-05-07T09:33:48Z', tenantId: 'tenant_support', user: 'carol@corp.com', targetProvider: 'Anthropic', targetModel: 'claude-haiku-4.5', decision: 'redact', hitCount: 3, highestSeverity: 'medium', byCategory: { credential: 0, pii: 3, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 2400 },
  { entryId: 'a_005', timestamp: '2026-05-07T10:02:33Z', tenantId: 'tenant_default', user: 'dave@corp.com', targetProvider: 'Anthropic', targetModel: 'claude-sonnet-4.6', decision: 'redact', hitCount: 1, highestSeverity: 'high', byCategory: { credential: 0, pii: 1, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 1536 },

  // Block — credit card (hard-block)
  { entryId: 'a_006', timestamp: '2026-05-07T10:18:42Z', tenantId: 'tenant_default', user: 'eve@corp.com', targetProvider: 'OpenAI', targetModel: 'gpt-5', decision: 'block', hitCount: 1, highestSeverity: 'critical', byCategory: { credential: 0, pii: 0, pci: 1, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: true, promptBytes: 1024 },

  // Block — AWS access key (hard-block)
  { entryId: 'a_007', timestamp: '2026-05-07T10:45:19Z', tenantId: 'tenant_engineering', user: 'frank@corp.com', targetProvider: 'OpenAI', targetModel: 'gpt-5', decision: 'block', hitCount: 1, highestSeverity: 'critical', byCategory: { credential: 1, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: true, promptBytes: 4096 },

  // Block — CONFIDENTIAL marker
  { entryId: 'a_008', timestamp: '2026-05-07T11:02:08Z', tenantId: 'tenant_default', user: 'grace@corp.com', targetProvider: 'Anthropic', targetModel: 'claude-opus-4.7', decision: 'block', hitCount: 1, highestSeverity: 'critical', byCategory: { credential: 0, pii: 0, pci: 0, health: 0, 'internal-marker': 1, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 8192 },

  // Redact — connection string  
  { entryId: 'a_009', timestamp: '2026-05-07T11:30:55Z', tenantId: 'tenant_engineering', user: 'henry@corp.com', targetProvider: 'OpenAI', targetModel: 'gpt-5-mini', decision: 'block', hitCount: 1, highestSeverity: 'high', byCategory: { credential: 0, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 1 }, hardBlockTriggered: false, promptBytes: 2560 },

  // Block — GitHub PAT (hard-block)
  { entryId: 'a_010', timestamp: '2026-05-07T11:48:22Z', tenantId: 'tenant_engineering', user: 'iris@corp.com', targetProvider: 'Anthropic', targetModel: 'claude-sonnet-4.6', decision: 'block', hitCount: 1, highestSeverity: 'critical', byCategory: { credential: 1, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: true, promptBytes: 1280 },

  // More allow / redact
  { entryId: 'a_011', timestamp: '2026-05-07T12:05:14Z', tenantId: 'tenant_engineering', user: 'jack@corp.com', targetProvider: 'AWS Bedrock', targetModel: 'claude-sonnet-4.6', decision: 'allow', hitCount: 0, highestSeverity: null, byCategory: { credential: 0, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 1792 },
  { entryId: 'a_012', timestamp: '2026-05-07T12:14:30Z', tenantId: 'tenant_legal', user: 'kate@corp.com', targetProvider: 'Anthropic', targetModel: 'claude-opus-4.7', decision: 'redact', hitCount: 4, highestSeverity: 'high', byCategory: { credential: 0, pii: 4, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 12288 },
  { entryId: 'a_013', timestamp: '2026-05-07T13:22:18Z', tenantId: 'tenant_default', user: 'leo@corp.com', targetProvider: 'OpenAI', targetModel: 'gpt-5-mini', decision: 'allow', hitCount: 0, highestSeverity: null, byCategory: { credential: 0, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 896 },

  // Block — multiple severe hits
  { entryId: 'a_014', timestamp: '2026-05-07T14:08:42Z', tenantId: 'tenant_default', user: 'eve@corp.com', targetProvider: 'OpenAI', targetModel: 'gpt-5', decision: 'block', hitCount: 2, highestSeverity: 'critical', byCategory: { credential: 1, pii: 0, pci: 1, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: true, promptBytes: 3072 },

  // Redactions
  { entryId: 'a_015', timestamp: '2026-05-07T15:11:20Z', tenantId: 'tenant_support', user: 'mia@corp.com', targetProvider: 'Anthropic', targetModel: 'claude-haiku-4.5', decision: 'redact', hitCount: 2, highestSeverity: 'low', byCategory: { credential: 0, pii: 2, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 1408 },
  { entryId: 'a_016', timestamp: '2026-05-07T15:33:11Z', tenantId: 'tenant_engineering', user: 'noah@corp.com', targetProvider: 'AWS Bedrock', targetModel: 'claude-sonnet-4.6', decision: 'allow', hitCount: 0, highestSeverity: null, byCategory: { credential: 0, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 2304 },
  { entryId: 'a_017', timestamp: '2026-05-07T16:02:18Z', tenantId: 'tenant_default', user: 'olivia@corp.com', targetProvider: 'Anthropic', targetModel: 'claude-sonnet-4.6', decision: 'redact', hitCount: 1, highestSeverity: 'low', byCategory: { credential: 0, pii: 1, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 1664 },

  // Block — Anthropic-format key sent through gateway
  { entryId: 'a_018', timestamp: '2026-05-07T16:30:55Z', tenantId: 'tenant_engineering', user: 'paul@corp.com', targetProvider: 'OpenAI', targetModel: 'gpt-5', decision: 'block', hitCount: 1, highestSeverity: 'critical', byCategory: { credential: 1, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: true, promptBytes: 1920 },

  // More clean
  { entryId: 'a_019', timestamp: '2026-05-07T17:14:14Z', tenantId: 'tenant_default', user: 'quinn@corp.com', targetProvider: 'Anthropic', targetModel: 'claude-sonnet-4.6', decision: 'allow', hitCount: 0, highestSeverity: null, byCategory: { credential: 0, pii: 0, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 768 },
  { entryId: 'a_020', timestamp: '2026-05-07T17:48:33Z', tenantId: 'tenant_support', user: 'rita@corp.com', targetProvider: 'Anthropic', targetModel: 'claude-haiku-4.5', decision: 'redact', hitCount: 1, highestSeverity: 'low', byCategory: { credential: 0, pii: 1, pci: 0, health: 0, 'internal-marker': 0, 'source-code': 0 }, hardBlockTriggered: false, promptBytes: 1152 },
];
