// Policy engine. Given a redaction result, evaluate against the active
// policy bundle and decide: allow / redact / block. Policy is layered:
// 1. Per-pattern default policy (from the catalog)
// 2. Per-tenant overrides (sample policy classifications only)
// 3. Global hardpins (credit cards always blocked, no override)

import { toPublicRedactionResult, type PublicDetectionHit, type RedactionResult } from './redaction-engine';
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

export type PublicPolicyEvaluation = Omit<PolicyEvaluation, 'tenantId'>;

// Tenant IDs on the custom policy endpoint are caller-controlled and must not
// become a second path for reflecting detected prompt values.
export function toPublicPolicyEvaluation(policy: PolicyEvaluation): PublicPolicyEvaluation {
  return {
    decision: policy.decision,
    hitCount: policy.hitCount,
    blockingReasons: policy.blockingReasons,
    redactedCount: policy.redactedCount,
    allowedCount: policy.allowedCount,
    appliedOverrides: policy.appliedOverrides,
    hardBlockTriggered: policy.hardBlockTriggered,
    recommendedAction: policy.recommendedAction,
  };
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
      // 'allow' or 'warn' in the sample policy; public output still tokenizes.
      allowedCount++;
    }
  }

  // Final decision
  let decision: PolicyDecision;
  let recommendedAction: string;
  if (blockTriggered) {
    decision = 'block';
    recommendedAction = hardBlockTriggered
      ? 'Block decision: caller must not forward this prompt. No quarantine or alert is performed by this prototype.'
      : 'Block decision: caller must not forward this prompt.';
  } else if (redactedCount === 0) {
    // No hits, OR all hits were override-allowed/warned in sample policy.
    decision = 'allow';
    recommendedAction = result.hits.length === 0
      ? 'Allow decision: no catalog match detected. Detection is not exhaustive.'
      : 'Allow decision: detected items are allowed or warned by sample policy. The returned prompt still tokenizes catalog matches.';
  } else {
    decision = 'redact';
    recommendedAction = `Redact decision: a caller could use the returned prompt after review (${redactedCount} redaction(s) applied).`;
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
  hits: PublicDetectionHit[];
  policy: PublicPolicyEvaluation;
  highestSeverity: RedactionResult['highestSeverity'];
  byCategory: RedactionResult['byCategory'];
}

export function processGatewayRequest(
  result: RedactionResult,
  tenantPolicy: TenantPolicy | null = null
): GatewayDecision {
  const policy = evaluatePolicy(result, tenantPolicy);
  const publicDetection = toPublicRedactionResult(result);
  return {
    decision: policy.decision,
    // An allow policy is advisory. Never put a detected value into the
    // returned prompt, even when a sample tenant policy allows that pattern.
    redactedPrompt: policy.decision === 'block'
      ? ''
      : publicDetection.redacted,
    hits: publicDetection.hits,
    policy: toPublicPolicyEvaluation(policy),
    highestSeverity: result.highestSeverity,
    byCategory: result.byCategory,
  };
}
