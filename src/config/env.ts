import dotenv from 'dotenv';
dotenv.config();

export const env = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
};

// This repository ships a local policy-decision prototype, not an authenticated
// multi-tenant egress proxy. Refuse accidental production service startup.
if (env.nodeEnv === 'production') {
  throw new Error('Production API startup is disabled: authentication, tenant binding, and provider egress are not implemented.');
}
