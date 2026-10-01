import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import { env } from './config/env';
import { ACCESS_LOG_FORMAT } from './config/access-log';
import {
  patternsRouter,
  redactRouter,
  gatewayRouter,
  policiesRouter,
  auditRouter,
  dashboardRouter,
} from './routes/index';

export const app = express();
const startedAt = Date.now();
const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?$/i;

app.use(helmet());
app.use((_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use(morgan(ACCESS_LOG_FORMAT));
app.use(express.json({ limit: '256kb' }));
app.use((req, res, next) => {
  // Loopback binding alone does not stop browser DNS rebinding to a local API.
  if (typeof req.headers.host !== 'string' || !LOCAL_HOST.test(req.headers.host)) {
    res.status(403).json({ error: 'Local API only' });
    return;
  }
  next();
});

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'llm-redaction-gateway',
    uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
    nodeEnv: env.nodeEnv,
  });
});

app.use('/api/patterns', patternsRouter);
app.use('/api/redact', redactRouter);
app.use('/api/gateway', gatewayRouter);
app.use('/api/policies', policiesRouter);
app.use('/api/audit', auditRouter);
app.use('/api/dashboard', dashboardRouter);

app.use((_req, res) => { res.status(404).json({ error: 'Not found' }); });

if (require.main === module) {
  app.listen(env.port, '127.0.0.1', () => {
    // eslint-disable-next-line no-console
    console.log(`llm-redaction-gateway listening on :${env.port}`);
  });
}
