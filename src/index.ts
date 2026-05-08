import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import { env } from './config/env';
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

app.use(helmet());
app.use(cors());
app.use(morgan('tiny'));
app.use(express.json({ limit: '8mb' }));

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
  app.listen(env.port, () => {
    // eslint-disable-next-line no-console
    console.log(`llm-redaction-gateway listening on :${env.port}`);
  });
}
