import type { IncomingHttpHeaders } from 'node:http';

const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1)(?::([1-9]\d{0,4}))?$/i;
const PROXY_HEADERS = ['forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'via'] as const;

export function isLocalHostHeader(host: string | undefined): boolean {
  const match = LOCAL_HOST.exec(host ?? '');
  return match !== null && (match[1] === undefined || Number(match[1]) <= 65535);
}

export function hasProxyForwardingHeaders(headers: IncomingHttpHeaders): boolean {
  return PROXY_HEADERS.some((name) => headers[name] !== undefined);
}

export function assertLocalDemoRuntime(nodeEnv: string, optIn: string | undefined): void {
  if (nodeEnv === 'production') {
    throw new Error('Production API startup is disabled: authentication, tenant binding, and provider egress are not implemented.');
  }
  if ((nodeEnv !== 'development' && nodeEnv !== 'test') || optIn !== '1') {
    throw new Error('Local demo startup requires NODE_ENV=development and GATEWAY_LOCAL_DEMO=1.');
  }
}
