import { z } from 'zod';

export const RedactSchema = z.object({
  text: z.string(),
  excludePatternNames: z.array(z.string()).optional(),
});

export const UnredactSchema = z.object({
  text: z.string(),
  tokenMap: z.record(z.string()),
});

export const GatewayProcessSchema = z.object({
  prompt: z.string(),
  tenantId: z.string().optional(),
  excludePatternNames: z.array(z.string()).optional(),
});

const PolicyOverrideSchema = z.object({
  patternName: z.string().min(1),
  decision: z.enum(['allow', 'redact', 'block']),
});

export const TenantPolicyEvalSchema = z.object({
  text: z.string(),
  tenantPolicy: z.object({
    tenantId: z.string().min(1),
    overrides: z.array(PolicyOverrideSchema),
    allowedRedactedCategories: z.array(z.enum(['credential', 'pii', 'pci', 'health', 'internal-marker', 'source-code'])),
  }).optional(),
});
