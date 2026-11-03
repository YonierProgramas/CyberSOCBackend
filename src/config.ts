import { z } from 'zod';

export const RELEASE_PREFIX = 'https://github.com/YonierProgramas/CyberSOC/releases/download/';
export interface ApiConfig {
  supabaseUrl: string; publishableKey: string; issuer: string; jwksUrl: string;
  portalOrigin: string; releasePrefix: string;
}

export function validateConfig(value: ApiConfig): ApiConfig {
  const parsed = z.strictObject({
    supabaseUrl: z.string(), publishableKey: z.string().regex(/^sb_publishable_[A-Za-z0-9_-]{8,256}$/),
    issuer: z.string(), jwksUrl: z.string(), portalOrigin: z.string(), releasePrefix: z.literal(RELEASE_PREFIX),
  }).safeParse(value);
  if (!parsed.success) throw new Error('Configuración P0 no válida; revisa los parámetros públicos.');
  try {
    const url = new URL(value.supabaseUrl);
    const origin = new URL(value.portalOrigin);
    if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/.test(value.supabaseUrl)
      || url.origin !== value.supabaseUrl
      || value.issuer !== `${value.supabaseUrl}/auth/v1`
      || value.jwksUrl !== `${value.issuer}/.well-known/jwks.json`
      || origin.origin !== value.portalOrigin || origin.username || origin.password
      || !(origin.protocol === 'https:' || (origin.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(origin.hostname)))) {
      throw new Error();
    }
  } catch { throw new Error('URLs de configuración P0 no válidas.'); }
  return Object.freeze({ ...value });
}

export function configFromEnvironment(): ApiConfig | undefined {
  // Solo variables propias; nunca enumerar ni registrar el entorno.
  if (process.env.SUPABASE_SECRET_KEY) throw new Error('P0 no admite una clave privilegiada.');
  const supabaseUrl = process.env.SUPABASE_URL;
  const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  const portalOrigin = process.env.PORTAL_ORIGIN;
  if (!supabaseUrl && !publishableKey && !portalOrigin) return undefined;
  return validateConfig({ supabaseUrl: supabaseUrl ?? '', publishableKey: publishableKey ?? '',
    portalOrigin: portalOrigin ?? '', issuer: process.env.SUPABASE_JWT_ISSUER ?? `${supabaseUrl}/auth/v1`,
    jwksUrl: process.env.SUPABASE_JWKS_URL ?? `${supabaseUrl}/auth/v1/.well-known/jwks.json`,
    releasePrefix: process.env.RELEASE_ASSET_URL_PREFIX ?? RELEASE_PREFIX });
}
