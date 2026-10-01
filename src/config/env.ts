import dotenv from 'dotenv';
import type { JSONWebKeySet } from 'jose';
import { assertLocalDemoRuntime } from './runtime-boundary';

dotenv.config();

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

export interface CallerAuthConfig {
  issuer: string;
  audience: string;
  requiredScope: string;
  clientTenantGrants: ReadonlyMap<string, ReadonlySet<string>>;
}

export interface PilotAuthConfig extends CallerAuthConfig {
  jwksUrl: string;
}

export interface StagingDecisionConfig {
  auth: CallerAuthConfig;
  publicJwks: JSONWebKeySet;
}

export type RuntimeEnv =
  | { mode: 'local-demo'; port: number; nodeEnv: 'development' | 'test' }
  | { mode: 'private-pilot'; port: number; nodeEnv: 'development'; auth: PilotAuthConfig }
  | { mode: 'staging-preview'; port: number; nodeEnv: 'production'; allowedHosts: readonly string[]; decision: StagingDecisionConfig | null };

const VERCEL_HOST = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.vercel\.app$/;
const STAGING_ISSUER = 'urn:llm-redaction-gateway:synthetic-preview';
const STAGING_AUDIENCE = 'urn:llm-redaction-gateway:synthetic-preview:api';
const STAGING_CLIENT = 'fixture_client';
const STAGING_TENANT = 'fixture_tenant';

function readPublicStagingJwks(value: string | undefined): JSONWebKeySet {
  if (!value || value.length > 2048) throw new Error('A bounded public-only staging JWKS is required.');
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error('A bounded public-only staging JWKS is required.'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
    || Object.keys(parsed).length !== 1 || !Object.hasOwn(parsed, 'keys')) {
    throw new Error('Staging JWKS must contain exactly one public RSA key.');
  }
  const keys = (parsed as { keys: unknown }).keys;
  if (!Array.isArray(keys) || keys.length !== 1) {
    throw new Error('Staging JWKS must contain exactly one public RSA key.');
  }
  const key = keys[0];
  const permitted = ['alg', 'e', 'kid', 'kty', 'n', 'use'];
  if (!key || typeof key !== 'object' || Array.isArray(key)
    || Object.keys(key).length !== permitted.length
    || Object.keys(key).some((name) => !permitted.includes(name))
    || key.kty !== 'RSA' || key.alg !== 'RS256' || key.use !== 'sig'
    || typeof key.kid !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(key.kid)
    || key.e !== 'AQAB' || typeof key.n !== 'string'
    || !/^[A-Za-z0-9_-]+$/.test(key.n)
    || Buffer.from(key.n, 'base64url').length !== 256) {
    throw new Error('Staging JWKS must contain exactly one public 2048-bit RSA signing key.');
  }
  return parsed as JSONWebKeySet;
}

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
  let decision: StagingDecisionConfig | null = null;
  if (source.GATEWAY_STAGING_DECISIONS !== undefined || source.GATEWAY_STAGING_PUBLIC_JWKS !== undefined) {
    if (source.GATEWAY_STAGING_DECISIONS !== '1') {
      throw new Error('Staging decisions require their own exact opt-in.');
    }
    decision = {
      auth: {
        issuer: STAGING_ISSUER,
        audience: STAGING_AUDIENCE,
        requiredScope: 'gateway:staging:decide',
        clientTenantGrants: new Map([[STAGING_CLIENT, new Set([STAGING_TENANT])]]),
      },
      publicJwks: readPublicStagingJwks(source.GATEWAY_STAGING_PUBLIC_JWKS),
    };
  }
  return { mode: 'staging-preview', port, nodeEnv: 'production', allowedHosts: [deploymentHost, branchHost], decision };
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
        requiredScope: 'gateway:decide',
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
