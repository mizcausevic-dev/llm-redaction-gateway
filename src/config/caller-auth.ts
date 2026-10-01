import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { RequestHandler } from 'express';
import type { CallerAuthConfig, PilotAuthConfig } from './env';

export interface PilotPrincipal {
  subject: string;
  tenantId: string;
  clientId: string;
}

const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

export function createPilotCallerAuth(config: PilotAuthConfig, getKey?: JWTVerifyGetKey): RequestHandler {
  return createCallerAuth(config, getKey ?? createRemoteJWKSet(new URL(config.jwksUrl), {
    timeoutDuration: 2000,
    cooldownDuration: 30000,
    cacheMaxAge: 300000,
  }));
}

export function createCallerAuth(
  config: CallerAuthConfig,
  getKey: JWTVerifyGetKey,
): RequestHandler {
  return async (req, res, next) => {
    const authorization = req.headers.authorization;
    const authorizationFieldCount = req.rawHeaders.filter((header, index) =>
      index % 2 === 0 && header.toLowerCase() === 'authorization').length;
    const match = authorizationFieldCount === 1 && authorization && authorization.length <= 8192
      ? BEARER.exec(authorization) : null;
    if (!match) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    try {
      const { payload } = await jwtVerify(match[1], getKey, {
        issuer: config.issuer,
        audience: config.audience,
        algorithms: ['RS256'],
        typ: 'at+jwt',
        maxTokenAge: '15 minutes',
        clockTolerance: '5 seconds',
        requiredClaims: ['exp', 'iat', 'sub', 'tenant_id', 'client_id', 'scope'],
      });
      const tenantId = payload.tenant_id;
      const clientId = payload.client_id;
      const scope = payload.scope;
      if (payload.aud !== config.audience
        || typeof payload.sub !== 'string' || !payload.sub.trim() || payload.sub.length > 256
        || typeof tenantId !== 'string' || !IDENTIFIER.test(tenantId)
        || typeof clientId !== 'string' || !IDENTIFIER.test(clientId)
        || typeof scope !== 'string' || !scope.split(/\s+/).includes(config.requiredScope)
        || !config.clientTenantGrants.get(clientId)?.has(tenantId)) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }
      res.locals.pilotPrincipal = {
        subject: payload.sub as string,
        tenantId,
        clientId,
      } satisfies PilotPrincipal;
      next();
    } catch {
      // Never expose token content, verification internals, or key-fetch errors.
      res.setHeader('WWW-Authenticate', 'Bearer');
      res.status(401).json({ error: 'Unauthorized' });
    }
  };
}
