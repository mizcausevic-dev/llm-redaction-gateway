import dotenv from 'dotenv';
import { assertLocalDemoRuntime } from './runtime-boundary';

dotenv.config();

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

export interface PilotAuthConfig {
  issuer: string;
  audience: string;
  jwksUrl: string;
  clientTenantGrants: ReadonlyMap<string, ReadonlySet<string>>;
}

export type RuntimeEnv =
  | { mode: 'local-demo'; port: number; nodeEnv: 'development' | 'test' }
  | { mode: 'private-pilot'; port: number; nodeEnv: 'development'; auth: PilotAuthConfig }
  | { mode: 'staging-preview'; port: number; nodeEnv: 'production'; allowedHosts: readonly string[] };

const VERCEL_HOST = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.vercel\.app$/;

function readVercelHost(value: string | undefined, name: string): string {
  if (!value || value.length > 253 || !VERCEL_HOST.test(value)) {
    throw new Error(`${name} must be one generated .vercel.app hostname.`);
  }
  return value;
}

function readStagingPreview(source: NodeJS.ProcessEnv, port: number): RuntimeEnv {
  if (source.NODE_ENV !== 'production'
    || source.VERCEL !== '1'
    || source.VERCEL_ENV !== 'preview'
    || source.VERCEL_TARGET_ENV !== 'preview'
    || source.GATEWAY_STAGING_PREVIEW !== '1'
    || source.GATEWAY_LOCAL_DEMO !== undefined
    || source.GATEWAY_PRIVATE_PILOT !== undefined
    || source.GATEWAY_AUTH_ISSUER !== undefined
    || source.GATEWAY_AUTH_JWKS_URL !== undefined
    || source.GATEWAY_AUTH_AUDIENCE !== undefined
    || source.GATEWAY_CLIENT_TENANT_GRANTS !== undefined) {
    throw new Error('Staging preview requires exact Vercel preview markers and its own opt-in.');
  }
  const deploymentHost = readVercelHost(source.VERCEL_URL, 'VERCEL_URL');
  const branchHost = readVercelHost(source.VERCEL_BRANCH_URL, 'VERCEL_BRANCH_URL');
  const productionHost = source.VERCEL_PROJECT_PRODUCTION_URL;
  if (!productionHost || productionHost === deploymentHost || productionHost === branchHost) {
    throw new Error('Staging preview hosts must differ from the production host.');
  }
  return { mode: 'staging-preview', port, nodeEnv: 'production', allowedHosts: [deploymentHost, branchHost] };
}

function readGrants(value: string | undefined): ReadonlyMap<string, ReadonlySet<string>> {
  const entries = value?.split(',').map((item) => item.trim()) ?? [];
  if (entries.length === 0 || entries.some((item) => !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}:[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(item))) {
    throw new Error('GATEWAY_CLIENT_TENANT_GRANTS must list explicit client:tenant pairs.');
  }
  const grants = new Map<string, Set<string>>();
  for (const entry of entries) {
    const [clientId, tenantId] = entry.split(':');
    if (!IDENTIFIER.test(clientId) || !IDENTIFIER.test(tenantId)) {
      throw new Error('GATEWAY_CLIENT_TENANT_GRANTS contains an invalid identifier.');
    }
    const tenants = grants.get(clientId) ?? new Set<string>();
    if (tenants.has(tenantId)) {
      throw new Error('GATEWAY_CLIENT_TENANT_GRANTS contains a duplicate grant.');
    }
    tenants.add(tenantId);
    grants.set(clientId, tenants);
  }
  return grants;
}

function readHttpsUrl(value: string | undefined, name: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value ?? '');
  } catch {
    throw new Error(`${name} must be an HTTPS URL.`);
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash || parsed.search) {
    throw new Error(`${name} must be an HTTPS URL without credentials, query, or fragment.`);
  }
  return parsed;
}

export function parseRuntimeEnv(source: NodeJS.ProcessEnv): RuntimeEnv {
  const rawPort = source.PORT ?? '3000';
  if (!/^[1-9]\d{0,4}$/.test(rawPort) || Number(rawPort) > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535.');
  }
  const port = Number(rawPort);

  if (source.VERCEL !== undefined || source.VERCEL_ENV !== undefined
    || source.VERCEL_TARGET_ENV !== undefined || source.GATEWAY_STAGING_PREVIEW !== undefined) {
    return readStagingPreview(source, port);
  }

  if (source.NODE_ENV === 'production') {
    throw new Error('Production API startup is disabled: deployed identity, egress, and rollback are unverified.');
  }
  if (source.GATEWAY_PRIVATE_PILOT !== undefined) {
    if (source.NODE_ENV !== 'development' || source.GATEWAY_PRIVATE_PILOT !== '1'
      || source.GATEWAY_LOCAL_DEMO === '1') {
      throw new Error('Private pilot requires NODE_ENV=development and GATEWAY_PRIVATE_PILOT=1 without local-demo opt-in.');
    }
    const issuer = readHttpsUrl(source.GATEWAY_AUTH_ISSUER, 'GATEWAY_AUTH_ISSUER');
    const jwks = readHttpsUrl(source.GATEWAY_AUTH_JWKS_URL, 'GATEWAY_AUTH_JWKS_URL');
    if (issuer.origin !== jwks.origin) {
      throw new Error('GATEWAY_AUTH_JWKS_URL must share the issuer origin.');
    }
    const audience = source.GATEWAY_AUTH_AUDIENCE?.trim();
    if (!audience || audience.length > 256 || /\s/.test(audience)) {
      throw new Error('GATEWAY_AUTH_AUDIENCE must be a nonempty, exact resource identifier.');
    }
    return {
      mode: 'private-pilot',
      port,
      nodeEnv: 'development',
      auth: {
        issuer: issuer.href,
        audience,
        jwksUrl: jwks.href,
        clientTenantGrants: readGrants(source.GATEWAY_CLIENT_TENANT_GRANTS),
      },
    };
  }

  const nodeEnv = source.NODE_ENV ?? '';
  assertLocalDemoRuntime(nodeEnv, source.GATEWAY_LOCAL_DEMO);
  return { mode: 'local-demo', port, nodeEnv: nodeEnv as 'development' | 'test' };
}

export const env = parseRuntimeEnv(process.env);
