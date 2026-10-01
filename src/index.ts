import express, { type NextFunction, type Request, type Response } from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import { rateLimit } from 'express-rate-limit';
import { createLocalJWKSet, type JWTVerifyGetKey } from 'jose';
import { env, type RuntimeEnv } from './config/env';
import { ACCESS_LOG_FORMAT } from './config/access-log';
import { createCallerAuth, createPilotCallerAuth } from './config/caller-auth';
import { stagingPreviewRouter } from './routes/staging-preview';
import { hasProxyForwardingHeaders, isLocalHostHeader, isLoopbackPeer } from './config/runtime-boundary';
import {
  patternsRouter,
  redactRouter,
  gatewayRouter,
  privatePilotGatewayRouter,
  policiesRouter,
  auditRouter,
  dashboardRouter,
} from './routes/index';

export function createApp(
  runtime: RuntimeEnv = env,
  getKey?: JWTVerifyGetKey,
  accessLogStream?: { write(message: string): void },
): express.Express {
  const app = express();
  const startedAt = Date.now();
  app.disable('x-powered-by');
  // NODE_ENV remains development for the local pilot, but error responses
  // must not reveal implementation details if a handler throws.
  if (runtime.mode === 'private-pilot' || runtime.mode === 'staging-preview') app.set('env', 'production');
  app.use(helmet());
  app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    if (runtime.mode === 'staging-preview') {
      res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
      // Accept only Vercel-generated preview and branch hosts, never a custom
      // or production alias. The platform must separately protect both URLs.
      if (!runtime.allowedHosts.includes(req.headers.host ?? '')) {
        res.status(403).json({ error: 'Forbidden' });
        return;
      }
      next();
      return;
    }
    // Reject before logging or parsing a potentially sensitive request body.
    if (!isLoopbackPeer(req.socket.remoteAddress)
      || !isLocalHostHeader(req.headers.host) || hasProxyForwardingHeaders(req.headers)) {
      res.status(403).json({ error: 'Local API only' });
      return;
    }
    next();
  });
  if (runtime.mode === 'staging-preview') {
    app.get('/health', (_req, res) => res.json({
      status: 'ok', mode: 'staging-preview', decisionRoute: runtime.decision ? 'fixture-only' : 'disabled',
    }));
    if (runtime.decision) {
      // This is an instance-local throttle, not a distributed edge quota.
      app.use('/api', rateLimit({
        windowMs: 60_000,
        limit: 60,
        standardHeaders: 'draft-8',
        legacyHeaders: false,
        keyGenerator: () => 'synthetic-preview',
        message: { error: 'Too many requests' },
      }));
      // Authentication and quota run before Express reads any body bytes.
      app.use('/api', createCallerAuth(runtime.decision.auth, createLocalJWKSet(runtime.decision.publicJwks)));
      app.use(express.json({ limit: '256kb' }));
      app.use('/api/staging', stagingPreviewRouter);
      app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
        const status = typeof error === 'object' && error !== null && 'status' in error
          && (error.status === 400 || error.status === 413) ? error.status : 500;
        res.status(status).json({ error: status === 413 ? 'Payload too large'
          : status === 400 ? 'Invalid payload' : 'Internal error' });
      });
    }
    app.use((_req, res) => { res.status(404).json({ error: 'Not found' }); });
    return app;
  }
  app.use(morgan(ACCESS_LOG_FORMAT, accessLogStream ? { stream: accessLogStream } : undefined));
  // Bound failed authentication and JWKS work before parsing the request body.
  // This process-local store is for the loopback pilot only.
  if (runtime.mode === 'private-pilot') {
    app.use('/api', rateLimit({
      windowMs: 60_000,
      limit: 60,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      // Every accepted 127/8 peer shares one quota; local source aliases must
      // not create fresh buckets. This can let one local caller exhaust it.
      keyGenerator: () => 'loopback-pilot',
      message: { error: 'Too many requests' },
    }));
    app.use('/api', createPilotCallerAuth(runtime.auth, getKey));
  }
  app.use(express.json({ limit: '256kb' }));

  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'llm-redaction-gateway',
      uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
      nodeEnv: runtime.nodeEnv,
      mode: runtime.mode,
    });
  });

  if (runtime.mode === 'local-demo') {
    app.use('/api/patterns', patternsRouter);
    app.use('/api/redact', redactRouter);
    app.use('/api/gateway', gatewayRouter);
    app.use('/api/policies', policiesRouter);
    app.use('/api/audit', auditRouter);
    app.use('/api/dashboard', dashboardRouter);
  } else {
    app.use('/api/gateway', privatePilotGatewayRouter);
  }

  app.use((_req, res) => { res.status(404).json({ error: 'Not found' }); });
  return app;
}

export const app = createApp();

// Vercel's Express adapter recognizes src/index.ts. The CommonJS export is
// applied only for its runtime; local imports retain the named factory export.
if (process.env.VERCEL === '1') module.exports = app;

if (require.main === module && process.env.VERCEL !== '1') {
  const server = app.listen(env.port, '127.0.0.1', () => {
    // eslint-disable-next-line no-console
    console.log(`llm-redaction-gateway listening on :${env.port}`);
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
}
