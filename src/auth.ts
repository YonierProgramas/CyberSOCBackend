import { webcrypto } from 'node:crypto';
import { z } from 'zod';
import { ApiError, unavailable } from './errors.js';
import type { ApiConfig } from './config.js';
import { fetchJson, type Fetcher } from './upstream.js';
import { uuid } from './schemas.js';

const headerSchema = z.strictObject({ alg: z.enum(['ES256', 'RS256']), kid: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/),
  typ: z.literal('JWT').optional() });
const claimsSchema = z.object({ sub: uuid, iss: z.string().max(2048), aud: z.union([z.string().max(100), z.array(z.string().max(100)).max(10)]),
  role: z.string().max(100), exp: z.number().int().nonnegative(), iat: z.number().int().nonnegative(),
  nbf: z.number().int().nonnegative().optional(), session_id: uuid.optional(),
  email: z.email().max(320).optional(), is_anonymous: z.boolean().optional() });
const publicCommon = { kid: z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/), use: z.literal('sig').optional(),
  key_ops: z.array(z.literal('verify')).max(1).optional() };
const jwksSchema = z.object({ keys: z.array(z.discriminatedUnion('kty', [
  z.object({ ...publicCommon, kty: z.literal('RSA'), alg: z.literal('RS256').optional(),
    n: z.string().max(1400), e: z.string().max(8) }),
  z.object({ ...publicCommon, kty: z.literal('EC'), alg: z.literal('ES256').optional(), crv: z.literal('P-256'),
    x: z.string().max(44), y: z.string().max(44) }),
])).min(1).max(20) });

export interface Identity { userId: string; token: string; email: string | null; sessionId: string | undefined }
function invalidToken(): ApiError { return new ApiError(401, 'TOKEN_INVALID'); }
function bytes(part: string): Uint8Array<ArrayBuffer> {
  if (!part || !/^[A-Za-z0-9_-]+$/.test(part)) throw invalidToken();
  const decoded = Buffer.from(part, 'base64url');
  if (decoded.toString('base64url') !== part) throw invalidToken();
  return Uint8Array.from(decoded);
}
function json(part: string): unknown { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes(part))); }
type CachedKey = { alg: 'ES256' | 'RS256'; key: webcrypto.CryptoKey };

export class JwtVerifier {
  // Invariante del Map: un kid identifica una sola clave pública/algoritmo del
  // JWKS configurado, como máximo 20. Lookup O(1) esperado, recarga O(K).
  private keys = new Map<string, CachedKey>();
  private expiresAt = 0;
  private lastForced = -Infinity;
  private loading: Promise<void> | undefined;
  constructor(private readonly config: ApiConfig, private readonly fetcher: Fetcher,
    private readonly now: () => number = Date.now) {}

  private async reload(): Promise<void> {
    if (this.loading) return this.loading;
    this.loading = (async () => {
      let reply;
      try { reply = await fetchJson(this.fetcher, this.config.jwksUrl, { headers: { Accept: 'application/json' } }, 65536); }
      catch (error) {
        if (error instanceof ApiError && [401, 403].includes(error.status)) throw unavailable();
        throw error;
      }
      const parsed = jwksSchema.safeParse(reply.data);
      if (!parsed.success) throw unavailable();
      const next = new Map<string, CachedKey>();
      try {
        for (const source of parsed.data.keys) {
          if (next.has(source.kid)) throw unavailable();
          let key: webcrypto.CryptoKey;
          if (source.kty === 'EC') {
            if (bytes(source.x).length !== 32 || bytes(source.y).length !== 32) throw unavailable();
            key = await webcrypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: source.x, y: source.y },
              { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
          } else {
            const modulus = bytes(source.n);
            if (modulus.length < 256 || modulus.length > 1024) throw unavailable();
            bytes(source.e);
            key = await webcrypto.subtle.importKey('jwk', { kty: 'RSA', n: source.n, e: source.e },
              { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
            const size = (key.algorithm as webcrypto.RsaHashedKeyAlgorithm).modulusLength;
            if (size < 2048 || size > 8192) throw unavailable();
          }
          next.set(source.kid, { key, alg: source.kty === 'EC' ? 'ES256' : 'RS256' });
        }
      } catch { throw unavailable(); }
      this.keys = next;
      this.expiresAt = this.now() + 600000;
    })();
    try { await this.loading; } finally { this.loading = undefined; }
  }

  async verify(authorization: string | undefined): Promise<Identity> {
    if (authorization === undefined) throw new ApiError(401, 'AUTH_REQUIRED');
    if (Buffer.byteLength(authorization) > 8200 || !/^Bearer [^\s]+$/i.test(authorization)) throw invalidToken();
    const token = authorization.slice(7);
    if (Buffer.byteLength(token) > 8192) throw invalidToken();
    let header: z.infer<typeof headerSchema>;
    let claims: z.infer<typeof claimsSchema>;
    let signature: Uint8Array<ArrayBuffer>;
    const parts = token.split('.');
    try {
      if (parts.length !== 3) throw invalidToken();
      header = headerSchema.parse(json(parts[0]!));
      claims = claimsSchema.parse(json(parts[1]!));
      signature = bytes(parts[2]!);
      if (header.alg === 'ES256' && signature.length !== 64) throw invalidToken();
    } catch { throw invalidToken(); }
    let downloaded = false;
    if (this.now() >= this.expiresAt) { await this.reload(); downloaded = true; }
    let selected = this.keys.get(header.kid);
    if (!selected && !downloaded && this.now() - this.lastForced >= 60000) {
      this.lastForced = this.now();
      await this.reload();
      selected = this.keys.get(header.kid);
    }
    if (!selected || selected.alg !== header.alg) throw invalidToken();
    let verified = false;
    try {
      verified = await webcrypto.subtle.verify(header.alg === 'ES256' ? { name: 'ECDSA', hash: 'SHA-256' }
        : { name: 'RSASSA-PKCS1-v1_5' }, selected.key, signature,
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    } catch { throw invalidToken(); }
    if (!verified || claims.iss !== this.config.issuer
      || !(typeof claims.aud === 'string' ? claims.aud === 'authenticated' : claims.aud.includes('authenticated'))) throw invalidToken();
    const now = this.now() / 1000;
    if (claims.exp <= now - 30) throw new ApiError(401, 'TOKEN_EXPIRED');
    if (claims.iat > now + 30 || (claims.nbf !== undefined && claims.nbf > now + 30) || claims.exp <= claims.iat) throw invalidToken();
    if (claims.role !== 'authenticated' || claims.is_anonymous === true) throw new ApiError(403, 'FORBIDDEN');
    return { userId: claims.sub, token, email: claims.email ?? null, sessionId: claims.session_id };
  }
}
