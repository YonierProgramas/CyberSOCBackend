import { ApiError, unavailable } from './errors.js';
import type { ApiConfig } from './config.js';

export type Fetcher = typeof fetch;
export interface JsonReply { data: unknown; count: number | undefined }
export class DatabaseError extends ApiError {
  constructor(status: number, public readonly sqlCode: string | undefined) {
    super(status === 401 ? 401 : status === 403 ? 403 : status === 409 ? 409 : 503,
      status === 401 ? 'TOKEN_INVALID' : status === 403 ? 'FORBIDDEN' : status === 409 ? 'CONFLICT' : 'UPSTREAM_UNAVAILABLE');
  }
}

export async function fetchJson(fetcher: Fetcher, url: string, init: RequestInit,
  maxBytes: number, signal?: AbortSignal): Promise<JsonReply> {
  const timeout = AbortSignal.timeout(5000);
  const combined = signal ? AbortSignal.any([timeout, signal]) : timeout;
  try {
    combined.throwIfAborted();
    const response = await fetcher(url, { ...init, redirect: 'error', signal: combined });
    const length = response.headers.get('content-length');
    if (length && (!/^\d+$/.test(length) || Number(length) > maxBytes)) {
      await response.body?.cancel();
      throw unavailable();
    }
    const chunks: Uint8Array[] = [];
    let size = 0;
    const reader = response.body?.getReader();
    if (reader) {
      try {
        for (;;) {
          combined.throwIfAborted();
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > maxBytes) throw unavailable();
          chunks.push(value);
        }
      } finally { await reader.cancel().catch(() => undefined); }
    }
    combined.throwIfAborted();
    let data: unknown = null;
    if (size) {
      if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')) throw unavailable();
      const body = new Uint8Array(size);
      let position = 0;
      for (const chunk of chunks) { body.set(chunk, position); position += chunk.byteLength; }
      data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
    }
    if (!response.ok) {
      const code = data && typeof data === 'object' && 'code' in data && typeof data.code === 'string'
        && /^[A-Z0-9]{5,10}$/.test(data.code) ? data.code : undefined;
      throw new DatabaseError(response.status, code);
    }
    const range = response.headers.get('content-range');
    const total = range?.match(/^(?:\d+-\d+|\*)\/(\d+)$/)?.[1];
    const count = total === undefined ? undefined : Number(total);
    if (count !== undefined && !Number.isSafeInteger(count)) throw unavailable();
    return { data, count };
  } catch (error) {
    if (combined.aborted || (error instanceof Error && ['AbortError', 'TimeoutError'].includes(error.name))) {
      throw new ApiError(504, 'UPSTREAM_TIMEOUT');
    }
    if (error instanceof ApiError) throw error;
    throw unavailable();
  }
}

export class Postgrest {
  constructor(private readonly config: ApiConfig, private readonly fetcher: Fetcher) {}
  async request(table: string, query: Record<string, string>, token: string | undefined,
    signal: AbortSignal, method = 'GET', body?: unknown, exactCount = false): Promise<JsonReply> {
    // Nombre cerrado por el servicio; jamás construir una URL desde un dato del cliente.
    if (!/^(?:profiles|user_preferences|user_consents|consent_purposes|app_releases|download_requests|devices|rpc\/revoke_device)$/.test(table)) {
      throw new ApiError(500, 'INTERNAL');
    }
    const url = new URL(`${this.config.supabaseUrl}/rest/v1/${table}`);
    url.search = new URLSearchParams(query).toString();
    const headers: Record<string, string> = { apikey: this.config.publishableKey, Accept: 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const preferences: string[] = [];
    if (body !== undefined) { headers['Content-Type'] = 'application/json'; preferences.push('return=representation'); }
    if (exactCount) preferences.push('count=exact');
    if (preferences.length) headers.Prefer = preferences.join(',');
    try {
      return await fetchJson(this.fetcher, url.toString(), { method, headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }) }, 1024 * 1024, signal);
    } catch (error) {
      if (!token && error instanceof DatabaseError && [401, 403].includes(error.status)) throw unavailable();
      throw error;
    }
  }
}
