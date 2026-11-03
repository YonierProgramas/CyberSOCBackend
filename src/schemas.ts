import { z } from 'zod';
import { unavailable } from './errors.js';

export const PUBLIC_PLATFORMS = ['windows-x64'] as const;
export const purpose = z.enum(['scan_summaries', 'report_storage']);
export const uuid = z.string().regex(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i).transform(v => v.toLowerCase());
export const displayName = z.string().trim().min(1).max(100).refine(v => !/\p{Cc}/u.test(v));
export const policyVersion = z.string().min(1).max(40);
// Invariante del Set: solo zonas IANA enumeradas por este runtime. Construcción
// O(Z), consulta de pertenencia O(1) esperada; no aceptar una zona arbitraria.
const timeZones = new Set(Intl.supportedValuesOf('timeZone'));
export const preferences = z.strictObject({ locale: z.enum(['es-CO', 'es']),
  timezone: z.string().max(100).refine(v => timeZones.has(v)), theme: z.enum(['system', 'light', 'dark']) });
export const preferencePatch = preferences.partial().refine(v => Object.keys(v).length > 0);
export const consentInput = z.discriminatedUnion('granted', [
  z.strictObject({ granted: z.literal(true), policyVersion }),
  z.strictObject({ granted: z.literal(false), policyVersion: z.string().max(40).optional() }),
]);
export const profileInput = z.strictObject({ displayName });
export const downloadInput = z.strictObject({ platform: z.enum(PUBLIC_PLATFORMS) });
export const timestamp = z.string().regex(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)$/)
  .refine(v => Number.isFinite(Date.parse(v)) && new Date(v).toISOString().slice(0, 19) === v.slice(0, 19)).transform(v => {
    const [whole, rest = ''] = v.replace(/(?:Z|\+00:00)$/, '').split('.');
    return `${whole}.${rest.padEnd(6, '0')}Z`;
  });
export const profileRow = z.object({ user_id: uuid, display_name: displayName, created_at: timestamp });
export const preferenceRow = preferences.extend({ user_id: uuid });
export const consentRow = z.object({ user_id: uuid, purpose_code: purpose, granted: z.boolean(),
  policy_version: policyVersion, changed_at: timestamp });
export const purposeRow = z.object({ code: purpose, current_policy_version: policyVersion });
export const deviceRow = z.object({ id: uuid, user_id: uuid, display_name: displayName,
  platform_code: z.enum(PUBLIC_PLATFORMS), app_version: z.string().min(1).max(60),
  created_at: timestamp, last_seen_at: timestamp.nullable(), revoked_at: timestamp.nullable() });
export const revokedRow = z.object({ id: uuid, revoked_at: timestamp });
export const downloadRow = z.object({ id: uuid, user_id: uuid, asset_id: uuid, requested_at: timestamp });
export const releaseRow = z.object({ id: uuid, version: z.string().regex(/^\d+\.\d+\.\d+(?:[+-][0-9A-Za-z.-]+)?$/),
  source_commit: z.string().regex(/^[a-f0-9]{40}$/), status: z.literal('PUBLISHED'), published_at: timestamp,
  release_assets: z.array(z.object({ id: uuid, platform_code: z.enum(PUBLIC_PLATFORMS),
    download_url: z.string().url().max(2048), sha256: z.string().regex(/^[a-f0-9]{64}$/),
    size_bytes: z.number().int().positive().max(2147483647) })).length(1),
  release_notes: z.array(z.object({ locale: z.enum(['es-CO', 'es']), body: z.string().max(10000) })).max(2) });

export function output<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw unavailable();
  return result.data;
}
export const defaults = { locale: 'es-CO', timezone: 'America/Bogota', theme: 'system' } as const;
