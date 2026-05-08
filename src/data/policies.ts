import type { TenantPolicy } from '../governance/policy-engine';

// Sample tenant policies. Most tenants take defaults; legal-team has
// PII passthrough for case work; engineering has tighter creds policy.
export const TENANT_POLICIES: TenantPolicy[] = [
  {
    tenantId: 'tenant_default',
    overrides: [],
    allowedRedactedCategories: ['pii', 'pci'],
  },
  {
    tenantId: 'tenant_legal',
    // Legal team needs to pass case identifiers through (PII passthrough),
    // but credentials and PCI are still hardpinned by the gateway.
    overrides: [
      { patternName: 'ssn-us', decision: 'redact' },
      { patternName: 'email', decision: 'allow' },
      { patternName: 'us-phone', decision: 'allow' },
      { patternName: 'date-of-birth', decision: 'redact' },
    ],
    allowedRedactedCategories: ['pii'],
  },
  {
    tenantId: 'tenant_engineering',
    // Engineering: aggressive policy on credentials. Block JWT and
    // generic API keys outright (default is redact for JWT).
    overrides: [
      { patternName: 'jwt-token', decision: 'block' },
      { patternName: 'connection-string', decision: 'block' },
    ],
    allowedRedactedCategories: ['source-code'],
  },
  {
    tenantId: 'tenant_support',
    overrides: [
      { patternName: 'email', decision: 'redact' },
      { patternName: 'us-phone', decision: 'redact' },
    ],
    allowedRedactedCategories: ['pii'],
  },
];

export function findTenantPolicy(tenantId: string): TenantPolicy | undefined {
  return TENANT_POLICIES.find((p) => p.tenantId === tenantId);
}
