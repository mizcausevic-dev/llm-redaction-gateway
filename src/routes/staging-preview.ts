import { Router } from 'express';
import { z } from 'zod';
import type { PilotPrincipal } from '../config/caller-auth';
import { redactText } from '../governance/redaction-engine';
import { processGatewayRequest } from '../governance/policy-engine';

// Callers submit only an ID. There is no route that accepts or reflects a
// prompt, policy override, tenant ID, or reversal map in hosted staging.
const FixtureId = z.enum(['clean-text', 'obfuscated-email', 'invalid-card', 'valid-card']);
const RequestSchema = z.object({ fixtureId: FixtureId }).strict();
const FIXTURES: Readonly<Record<z.infer<typeof FixtureId>, string>> = Object.freeze({
  'clean-text': 'Summarize this synthetic launch note.',
  'obfuscated-email': 'Please email alice [at] example [dot] com.',
  'invalid-card': 'Ticket 1234-5678-9012-3456',
  'valid-card': 'Card 4532-1234-5678-9014',
});

export const stagingPreviewRouter = Router();
stagingPreviewRouter.post('/decide', (req, res) => {
  const principal = res.locals.pilotPrincipal as PilotPrincipal | undefined;
  if (!principal || principal.clientId !== 'fixture_client' || principal.tenantId !== 'fixture_tenant') {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }
  const parsed = RequestSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid payload' });
    return;
  }
  res.json(processGatewayRequest(redactText(FIXTURES[parsed.data.fixtureId]), null));
});
