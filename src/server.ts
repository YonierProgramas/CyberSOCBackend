import { createServer, type IncomingMessage } from 'node:http';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { validateConfig, type ApiConfig } from './config.js';
import { ApiError, invalid, requireValid } from './errors.js';
import { JwtVerifier } from './auth.js';
import { Postgrest, type Fetcher } from './upstream.js';
import { RateLimits } from './limits.js';
import { CursorStore } from './cursor.js';
import { ApiService } from './service.js';
import { profileInput, preferencePatch, consentInput, purpose, uuid, downloadInput, PUBLIC_PLATFORMS } from './schemas.js';

export interface SafeLog { requestId: string; route: string; code: string; status: number; durationMs: number }
export interface ServerOptions { config?: ApiConfig; fetcher?: Fetcher; now?: () => number; logger?: (value: SafeLog) => void }
export const API_ROUTES = [
  { path: '/healthz', methods: ['GET', 'HEAD'], private: false },
  { path: '/v1/releases/latest', methods: ['GET'], private: false },
  { path: '/v1/me', methods: ['GET', 'PUT'], private: true },
  { path: '/v1/me/preferences', methods: ['PATCH'], private: true },
  { path: '/v1/me/consents', methods: ['GET'], private: true },
  { path: '/v1/me/consents/{purposeCode}', methods: ['PUT'], private: true },
  { path: '/v1/downloads', methods: ['POST'], private: true },
  { path: '/v1/devices', methods: ['GET'], private: true },
  { path: '/v1/devices/{deviceId}', methods: ['DELETE'], private: true },
] as const;
const emptyQuery = z.strictObject({});
const pageQuery = z.strictObject({ limit: z.string().regex(/^(?:[1-9]\d?|100)$/).transform(Number).optional(),
  cursor: z.string().max(46).optional() });

function queryObject(params: URLSearchParams): Record<string, string> {
  const result: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [key, value] of params) {
    if (Object.hasOwn(result, key)) throw invalid();
    result[key] = value;
  }
  return result;
}
async function readJson(request: IncomingMessage, signal: AbortSignal): Promise<unknown> {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type'] ?? '')
    || (request.headers['content-encoding'] && request.headers['content-encoding'] !== 'identity')) {
    throw new ApiError(415, 'UNSUPPORTED_MEDIA_TYPE');
  }
  if (Number(request.headers['content-length'] ?? 0) > 16384) throw new ApiError(413, 'PAYLOAD_TOO_LARGE');
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const dispose = () => {
      request.removeListener('data', onData); request.removeListener('end', onEnd);
      request.removeListener('error', onError); signal.removeEventListener('abort', onAbort);
    };
    const fail = (error: ApiError) => { dispose(); request.resume(); reject(error); };
    const onError = () => fail(invalid());
    const onAbort = () => fail(new ApiError(504, 'UPSTREAM_TIMEOUT'));
    const onData = (chunk: Buffer) => {
      size += chunk.length;
      if (size > 16384) { fail(new ApiError(413, 'PAYLOAD_TOO_LARGE')); return; }
      chunks.push(chunk);
    };
    const onEnd = () => {
      dispose();
      try { resolve(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); }
      catch { reject(invalid()); }
    };
    if (signal.aborted) { onAbort(); return; }
    request.on('data', onData); request.once('end', onEnd); request.once('error', onError);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

export function createApiServer(options: ServerOptions = {}) {
  const config = options.config ? validateConfig(options.config) : undefined;
  const fetcher = options.fetcher ?? fetch;
  const now = options.now ?? Date.now;
  const verifier = config ? new JwtVerifier(config, fetcher, now) : undefined;
  const limits = new RateLimits(now);
  const healthLimits = new RateLimits(now, 1000);
  const service = config ? new ApiService(config, new Postgrest(config, fetcher), new CursorStore(now)) : undefined;
  const logger = options.logger ?? (value => console.log(JSON.stringify(value)));
  const server = createServer({ maxHeaderSize: 16384, connectionsCheckingInterval: 1000 }, async (request, response) => {
    const requestId = randomUUID();
    const started = performance.now();
    let routeName = 'unmatched';
    let resultCode = 'OK';
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    timer.unref();
    let rejectDeadline: ((reason: ApiError) => void) | undefined;
    const deadline = new Promise<never>((_, reject) => { rejectDeadline = reject; });
    const onAbort = () => rejectDeadline?.(new ApiError(504, 'UPSTREAM_TIMEOUT'));
    controller.signal.addEventListener('abort', onAbort, { once: true });
    const onClientAbort = () => controller.abort();
    request.once('aborted', onClientAbort);
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Request-Id', requestId);
    response.setHeader('Vary', 'Origin');
    const origin = request.headers.origin;
    if (config && origin === config.portalOrigin) {
      response.setHeader('Access-Control-Allow-Origin', origin);
      response.setHeader('Access-Control-Expose-Headers', 'Retry-After');
    }
    try {
      const operation = async (): Promise<{ status: number; body?: unknown }> => {
        const raw = request.url ?? '/';
        if (!raw.startsWith('/') || raw.startsWith('//') || raw.length > 4096 || raw.includes('#')) throw invalid();
        const url = new URL(raw, 'http://api.local');
        const path = url.pathname;
        const consentMatch = path.match(/^\/v1\/me\/consents\/([^/]+)$/);
        const deviceMatch = path.match(/^\/v1\/devices\/([^/]+)$/);
        const route = API_ROUTES.find(item => item.path === path)
          ?? (consentMatch ? API_ROUTES[5] : deviceMatch ? API_ROUTES[8] : undefined);
        if (!route) throw new ApiError(404, 'NOT_FOUND');
        if (!config && path !== '/healthz') {
          if (path === '/v1/releases/latest') throw new ApiError(503, 'RELEASE_UNAVAILABLE');
          throw new ApiError(404, 'NOT_FOUND');
        }
        routeName = route.path;
        // Health conserva su propia cuota: no consume ni depende del tráfico de cuenta.
        (path === '/healthz' ? healthLimits : limits).consume(`ip:${request.socket.remoteAddress ?? 'unknown'}`, 60);
        if (request.method === 'OPTIONS' && config) {
          const requestedMethod = request.headers['access-control-request-method'] ?? '';
          const requestedHeaders = (request.headers['access-control-request-headers'] ?? '').split(',').map(value => value.trim().toLowerCase()).filter(Boolean);
          if (origin !== config.portalOrigin || !(route.methods as readonly string[]).includes(requestedMethod)
            || requestedHeaders.some(value => !['authorization', 'content-type'].includes(value))) throw new ApiError(403, 'FORBIDDEN');
          response.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
          response.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
          response.setHeader('Access-Control-Max-Age', '600');
          return { status: 204 };
        }
        if (!(route.methods as readonly string[]).includes(request.method ?? '')) {
          throw new ApiError(405, 'METHOD_NOT_ALLOWED', { Allow: route.methods.join(', ') });
        }
        if (path === '/healthz') return { status: 200, ...(request.method === 'HEAD' ? {} : { body: {
          service: 'cybersoc-api', status: 'ok', stage: config ? 'p0' : 'foundation',
          capabilities: { authentication: Boolean(config), database: Boolean(config) },
        } }) };
        if (!service || !verifier) throw new ApiError(500, 'INTERNAL');
        let user;
        if (route.private) {
          const copies = request.rawHeaders.filter((_, index, all) => index % 2 === 0 && all[index]?.toLowerCase() === 'authorization').length;
          if (copies > 1) throw new ApiError(401, 'TOKEN_INVALID');
          user = await verifier.verify(request.headers.authorization);
          controller.signal.throwIfAborted();
          limits.consume(`user:${user.userId}`, 120);
          if (!['GET', 'HEAD'].includes(request.method ?? '')) limits.consume(`mutation:${user.userId}`, 20);
        }
        const query = queryObject(url.searchParams);
        if (['GET', 'HEAD'].includes(request.method ?? '')
          && (request.headers['transfer-encoding'] || Number(request.headers['content-length'] ?? 0) > 0)) throw invalid();
        if (path === '/v1/releases/latest') {
          const input = requireValid(z.strictObject({ platform: z.enum(PUBLIC_PLATFORMS) }).safeParse(query));
          return { status: 200, body: await service.latest(input.platform, controller.signal) };
        }
        if (!user) throw new ApiError(401, 'AUTH_REQUIRED');
        if (path === '/v1/devices') {
          if (query.cursor !== undefined && !/^c1\.[A-Za-z0-9_-]{43}$/.test(query.cursor)) throw new ApiError(400, 'INVALID_CURSOR');
          const input = requireValid(pageQuery.safeParse(query));
          return { status: 200, body: await service.devices(user, controller.signal, input.limit, input.cursor) };
        }
        requireValid(emptyQuery.safeParse(query));
        if (path === '/v1/me') {
          if (request.method === 'GET') return { status: 200, body: await service.me(user, controller.signal) };
          const input = requireValid(profileInput.safeParse(await readJson(request, controller.signal)));
          return { status: 200, body: await service.putMe(input.displayName, user, controller.signal) };
        }
        if (path === '/v1/me/preferences') {
          const input = requireValid(preferencePatch.safeParse(await readJson(request, controller.signal)));
          return { status: 200, body: await service.patchPreferences(input, user, controller.signal) };
        }
        if (path === '/v1/me/consents') return { status: 200, body: await service.consents(user, controller.signal) };
        if (consentMatch) {
          const code = requireValid(purpose.safeParse(consentMatch[1]));
          const input = requireValid(consentInput.safeParse(await readJson(request, controller.signal)));
          return { status: 200, body: await service.putConsent(code, input, user, controller.signal) };
        }
        if (path === '/v1/downloads') {
          const input = requireValid(downloadInput.safeParse(await readJson(request, controller.signal)));
          return { status: 200, body: await service.download(input.platform, user, controller.signal) };
        }
        if (deviceMatch) {
          const id = requireValid(uuid.safeParse(deviceMatch[1]));
          if (request.headers['transfer-encoding'] || Number(request.headers['content-length'] ?? 0) > 0) throw invalid();
          await service.revoke(id, user, controller.signal);
          return { status: 204 };
        }
        throw new ApiError(404, 'NOT_FOUND');
      };
      const result = await Promise.race([operation(), deadline]);
      response.writeHead(result.status);
      response.end(result.body === undefined ? undefined : JSON.stringify(result.body));
    } catch (error) {
      const failure = error instanceof ApiError ? error : new ApiError(500, 'INTERNAL');
      resultCode = failure.code;
      if (!response.destroyed && !response.writableEnded) {
        response.writeHead(failure.status, failure.headers);
        response.end(JSON.stringify({ error: { code: failure.code, message: failure.message, requestId } }));
      }
      request.resume();
    } finally {
      clearTimeout(timer); controller.signal.removeEventListener('abort', onAbort);
      request.removeListener('aborted', onClientAbort);
      try { logger({ requestId, route: routeName, code: resultCode, status: response.statusCode,
        durationMs: Math.max(0, Math.round(performance.now() - started)) }); } catch { /* Un logger fallido no expone detalles ni altera permisos. */ }
    }
  });
  server.headersTimeout = 8000;
  server.requestTimeout = 10000;
  server.maxRequestsPerSocket = 100;
  server.maxHeadersCount = 50;
  server.on('clientError', (_error, socket) => {
    if (socket.writable && !socket.writableEnded) {
      const requestId = randomUUID();
      const body = JSON.stringify({ error: { code: 'VALIDATION_FAILED', message: 'Petición no válida.', requestId } });
      socket.end(`HTTP/1.1 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Request-Id: ${requestId}\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
    }
  });
  return server;
}
