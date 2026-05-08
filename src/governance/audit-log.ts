// Gateway decision audit log + telemetry rollup. Every decision (allow,
// redact, block) gets recorded with caller, target, hit categories, and
// final policy decision. The rollup summary is the CISO-facing dashboard.

import type { GatewayDecision } from './policy-engine';
import type { Category, Severity } from './pattern-catalog';

export interface AuditEntry {
  entryId: string;
  timestamp: string;
  tenantId: string;
  user: string;
  targetProvider: string;
  targetModel: string;
  decision: GatewayDecision['decision'];
  hitCount: number;
  highestSeverity: Severity | null;
  byCategory: Record<Category, number>;
  hardBlockTriggered: boolean;
  promptBytes: number;
}

export interface AuditSummary {
  windowStart: string | null;
  windowEnd: string | null;
  totalDecisions: number;
  byDecision: Record<GatewayDecision['decision'], number>;
  bySeverity: Record<Severity, number>;
  byCategoryTotal: Record<Category, number>;
  uniqueTenants: number;
  uniqueUsers: number;
  hardBlockRate: number; // %
  blockRate: number; // %
  redactRate: number; // %
  topProviders: Array<{ provider: string; count: number }>;
  topUsers: Array<{ user: string; count: number; blockCount: number }>;
}

export function summarizeAudit(entries: AuditEntry[]): AuditSummary {
  if (entries.length === 0) {
    return {
      windowStart: null,
      windowEnd: null,
      totalDecisions: 0,
      byDecision: { allow: 0, redact: 0, block: 0 },
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      byCategoryTotal: { credential: 0, pii: 0, pci: 0, 'internal-marker': 0, 'source-code': 0, health: 0 },
      uniqueTenants: 0,
      uniqueUsers: 0,
      hardBlockRate: 0,
      blockRate: 0,
      redactRate: 0,
      topProviders: [],
      topUsers: [],
    };
  }

  const sorted = [...entries].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  const windowStart = sorted[0].timestamp;
  const windowEnd = sorted[sorted.length - 1].timestamp;

  const byDecision: Record<GatewayDecision['decision'], number> = { allow: 0, redact: 0, block: 0 };
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const byCategoryTotal: Record<Category, number> = {
    credential: 0, pii: 0, pci: 0, 'internal-marker': 0, 'source-code': 0, health: 0,
  };
  const tenants = new Set<string>();
  const users = new Set<string>();
  const providerCount = new Map<string, number>();
  const userStats = new Map<string, { count: number; blockCount: number }>();

  let hardBlocks = 0;
  for (const e of entries) {
    byDecision[e.decision]++;
    if (e.highestSeverity) bySeverity[e.highestSeverity]++;
    for (const [cat, count] of Object.entries(e.byCategory) as [Category, number][]) {
      byCategoryTotal[cat] += count;
    }
    tenants.add(e.tenantId);
    users.add(e.user);
    providerCount.set(e.targetProvider, (providerCount.get(e.targetProvider) ?? 0) + 1);
    if (e.hardBlockTriggered) hardBlocks++;

    const cur = userStats.get(e.user) ?? { count: 0, blockCount: 0 };
    cur.count++;
    if (e.decision === 'block') cur.blockCount++;
    userStats.set(e.user, cur);
  }

  const total = entries.length;
  const topProviders = Array.from(providerCount.entries())
    .map(([provider, count]) => ({ provider, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const topUsers = Array.from(userStats.entries())
    .map(([user, s]) => ({ user, count: s.count, blockCount: s.blockCount }))
    .sort((a, b) => b.blockCount - a.blockCount || b.count - a.count)
    .slice(0, 10);

  return {
    windowStart,
    windowEnd,
    totalDecisions: total,
    byDecision,
    bySeverity,
    byCategoryTotal,
    uniqueTenants: tenants.size,
    uniqueUsers: users.size,
    hardBlockRate: Math.round((hardBlocks / total) * 1000) / 10,
    blockRate: Math.round((byDecision.block / total) * 1000) / 10,
    redactRate: Math.round((byDecision.redact / total) * 1000) / 10,
    topProviders,
    topUsers,
  };
}
