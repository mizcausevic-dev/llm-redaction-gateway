// Policy engine. Given a redaction result, evaluate against the active
// policy bundle and decide: allow / redact / block. Policy is layered:
// 1. Per-pattern default policy (from the catalog)
// 2. Per-tenant overrides (e.g., legal team allowed PII passthrough)
// 3. Global hardpins (credit cards always blocked, no override)

import type { RedactionResult } from './redaction-engine';
import type { Category, DefaultPolicy } from './pattern-catalog';
import { patternByName } from './pattern-catalog';

export type PolicyDecision = 'allow' | 'redact' | 'block';

export interface PolicyOverride {
  patternName: string;
  decision: 'allow' | 'redact' | 'block';
}

export interface TenantPolicy {
  tenantId: string;
  overrides: PolicyOverride[];
  // Categories where the tenant accepts redacted-but-passed traffic
  allowedRedactedCategories: Category[];
}

// Patterns that NEVER allow passthrough regardless of tenant policy.
// Hardcoded for safety: PCI cards, private keys, source-code creds.
const HARD_BLOCK_PATTERNS = new Set([
  'private-key-block',
  'aws-sdk-creds',
  'credit-card',
  'aws-access-key',
  'github-pat',
  'github-fine-pat',
  'openai-key',
  'anthropic-key',
  'slack-token',
]);

export interface PolicyEvaluation {
  decision: PolicyDecision;
  tenantId: string | null;
  hitCount: number;
  blockingReasons: string[];
  redactedCount: number;
  allowedCount: number;
  appliedOverrides: string[];
  hardBlockTriggered: boolean;
  recommendedAction: string;
}

export function evaluatePolicy(
  result: RedactionResult,
  tenantPolicy: TenantPolicy | null = null
): PolicyEvaluation {
  const overrideByName = new Map(
    (tenantPolicy?.overrides ?? []).map((o) => [o.patternName, o.decision])
  );

  let blockTriggered = false;
  let hardBlockTriggered = false;
  const blockingReasons: string[] = [];
  let redactedCount = 0;
  let allowedCount = 0;
  const appliedOverrides: string[] = [];

  type EffectivePolicy = 'block' | 'redact' | 'warn' | 'allow';

  for (const hit of result.hits) {
    const pattern = patternByName(hit.patternName);
    if (!pattern) continue;

    // Resolve effective policy for this hit
    let effective: EffectivePolicy = pattern.defaultPolicy;
    const override = overrideByName.get(hit.patternName);
    if (override && !HARD_BLOCK_PATTERNS.has(hit.patternName)) {
      effective = override;
      appliedOverrides.push(`${hit.patternName} → ${override}`);
    }

    if (HARD_BLOCK_PATTERNS.has(hit.patternName)) {
      hardBlockTriggered = true;
      blockTriggered = true;
      blockingReasons.push(`${hit.patternName} (${hit.severity}) — hard-block pattern.`);
      continue;
    }

    if (effective === 'block') {
      blockTriggered = true;
      blockingReasons.push(`${hit.patternName} (${hit.severity}) — policy blocks ${pattern.category}.`);
    } else if (effective === 'redact') {
      redactedCount++;
    } else {
      // 'allow' or 'warn' — both pass through
      allowedCount++;
    }
  }

  // Final decision
  let decision: PolicyDecision;
  let recommendedAction: string;
  if (blockTriggered) {
    decision = 'block';
    recommendedAction = hardBlockTriggered
      ? 'Reject upstream call; quarantine prompt; alert security team. Hard-block triggered.'
      : 'Reject upstream call; notify caller of policy violation.';
  } else if (redactedCount === 0) {
    // No hits, OR all hits were override-allowed/warned → pass through
    decision = 'allow';
    recommendedAction = result.hits.length === 0
      ? 'Pass-through; no sensitive content detected.'
      : 'Pass-through; all detected items overridden to allow/warn.';
  } else {
    decision = 'redact';
    recommendedAction = `Forward redacted prompt to LLM (${redactedCount} redaction(s) applied).`;
  }

  return {
    decision,
    tenantId: tenantPolicy?.tenantId ?? null,
    hitCount: result.hits.length,
    blockingReasons,
    redactedCount,
    allowedCount,
    appliedOverrides,
    hardBlockTriggered,
    recommendedAction,
  };
}

// Composite gateway response: redaction + policy decision in one shape
export interface GatewayDecision {
  decision: PolicyDecision;
  redactedPrompt: string;
  hits: RedactionResult['hits'];
  tokenMap: Record<string, string>;
  policy: PolicyEvaluation;
  highestSeverity: RedactionResult['highestSeverity'];
  byCategory: RedactionResult['byCategory'];
}

export function processGatewayRequest(
  result: RedactionResult,
  tenantPolicy: TenantPolicy | null = null
): GatewayDecision {
  const policy = evaluatePolicy(result, tenantPolicy);
  return {
    decision: policy.decision,
    // If blocked, don't forward anything — caller should handle
    redactedPrompt: policy.decision === 'block' ? '' : result.redacted,
    hits: result.hits,
    // If blocked, don't expose the token map either (it could contain
    // the very secrets we're trying to suppress)
    tokenMap: policy.decision === 'block' ? {} : result.tokenMap,
    policy,
    highestSeverity: result.highestSeverity,
    byCategory: result.byCategory,
  };
}
