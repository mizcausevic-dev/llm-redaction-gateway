import { Router } from 'express';
import {
  RedactSchema,
  GatewayProcessSchema,
  TenantPolicyEvalSchema,
} from '../schemas/validation-schemas';
import { redactText, toPublicRedactionResult } from '../governance/redaction-engine';
import { evaluatePolicy, processGatewayRequest, toPublicPolicyEvaluation } from '../governance/policy-engine';
import { summarizeAudit } from '../governance/audit-log';
import { PATTERN_CATALOG, patternsByCategory } from '../governance/pattern-catalog';
import { TENANT_POLICIES, findTenantPolicy } from '../data/policies';
import { AUDIT_ENTRIES } from '../data/audit';

export const patternsRouter = Router();

patternsRouter.get('/', (_req, res) => {
  res.json({
    catalogSize: PATTERN_CATALOG.length,
    patterns: PATTERN_CATALOG.map((p) => ({
      name: p.name,
      category: p.category,
      severity: p.severity,
      description: p.description,
      defaultPolicy: p.defaultPolicy,
      tokenLabel: p.tokenLabel,
    })),
  });
});

patternsRouter.get('/category/:category', (req, res) => {
  const list = patternsByCategory(req.params.category as never);
  res.json({ category: req.params.category, patterns: list });
});

export const redactRouter = Router();

redactRouter.post('/', (req, res) => {
  const parsed = RedactSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Invalid payload' }); return; }
  const result = redactText(parsed.data.text);
  res.json(toPublicRedactionResult(result));
});

export const gatewayRouter = Router();

gatewayRouter.post('/process', (req, res) => {
  const parsed = GatewayProcessSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Invalid payload' }); return; }
  const tenant = parsed.data.tenantId ? findTenantPolicy(parsed.data.tenantId) ?? null : null;
  // Caller-controlled exclusions must never bypass the decision endpoint's hard blocks.
  const detection = redactText(parsed.data.prompt);
  const decision = processGatewayRequest(detection, tenant);
  res.json(decision);
});

gatewayRouter.post('/evaluate-policy', (req, res) => {
  const parsed = TenantPolicyEvalSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Invalid payload' }); return; }
  const detection = redactText(parsed.data.text);
  const policy = evaluatePolicy(detection, parsed.data.tenantPolicy ?? null);
  res.json({ detection: toPublicRedactionResult(detection), policy: toPublicPolicyEvaluation(policy) });
});

export const policiesRouter = Router();

policiesRouter.get('/', (_req, res) => {
  res.json({ policies: TENANT_POLICIES });
});

policiesRouter.get('/:tenantId', (req, res) => {
  const t = findTenantPolicy(req.params.tenantId);
  if (!t) { res.status(404).json({ error: 'Tenant policy not found.' }); return; }
  res.json(t);
});

export const auditRouter = Router();

auditRouter.get('/', (_req, res) => {
  res.json({ count: AUDIT_ENTRIES.length, entries: AUDIT_ENTRIES });
});

auditRouter.get('/summary', (_req, res) => {
  res.json(summarizeAudit(AUDIT_ENTRIES));
});

export const dashboardRouter = Router();

dashboardRouter.get('/summary', (_req, res) => {
  res.json({
    capturedAt: new Date().toISOString(),
    catalog: { size: PATTERN_CATALOG.length },
    tenants: TENANT_POLICIES.length,
    audit: summarizeAudit(AUDIT_ENTRIES),
  });
});
