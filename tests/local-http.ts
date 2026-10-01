import { request as httpRequest, type IncomingHttpHeaders, type Server } from 'node:http';

export interface LocalResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: any;
}

export async function localJsonRequest(
  server: Server,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<LocalResponse> {
  // Windows intermittently resets loopback sockets after a completed response
  // in this stateless synthetic suite. Only a transport reset is retried;
  // HTTP statuses and response assertions are never retried or weakened.
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      return await requestOnce(server, method, path, body, headers);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ECONNRESET' || attempt === 7) throw error;
      process.stderr.write(`[local-http] ECONNRESET transport retry ${attempt + 1}/7\n`);
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  throw new Error('Unreachable request retry state');
}

function requestOnce(
  server: Server,
  method: string,
  path: string,
  body: unknown,
  headers: Record<string, string>,
): Promise<LocalResponse> {
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected TCP address');
  const serialized = body === undefined ? '' : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: '127.0.0.1',
      port: address.port,
      method,
      path,
      headers: {
        Host: `localhost:${address.port}`,
        Connection: 'close',
        'Content-Length': Buffer.byteLength(serialized),
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...headers,
      },
    }, (res) => {
      let responseText = '';
      res.setEncoding('utf8');
      res.on('data', (chunk: string) => { responseText += chunk; });
      res.on('error', reject);
      res.on('aborted', () => reject(new Error('Local HTTP response aborted')));
      res.on('close', () => {
        if (!res.complete) reject(new Error('Local HTTP response closed before completion'));
      });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body: JSON.parse(responseText) });
        } catch (error) {
          reject(error);
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('Local HTTP request timed out')));
    req.end(serialized);
  });
}
