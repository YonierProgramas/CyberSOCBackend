import { z } from 'zod';
import type { ApiConfig } from './config.js';
import type { Identity } from './auth.js';
import { ApiError, unavailable } from './errors.js';
import { CursorStore, comparePositions, type Position } from './cursor.js';
import { DatabaseError, Postgrest } from './upstream.js';
import { acceptedDownloadUrl } from './release-url.js';
import { output, defaults, profileRow, preferenceRow, consentRow, purposeRow, deviceRow, revokedRow, downloadRow, releaseRow,
  type consentInput, type preferencePatch } from './schemas.js';

const profileSelect = 'user_id,display_name,created_at';
const preferencesSelect = 'user_id,locale,timezone,theme';
const consentSelect = 'user_id,purpose_code,granted,policy_version,changed_at';
const deviceSelect = 'id,user_id,display_name,platform_code,app_version,created_at,last_seen_at,revoked_at';

export class ApiService {
  constructor(private readonly config: ApiConfig, private readonly database: Postgrest,
    private readonly cursors: CursorStore) {}
  private ownRows<T extends { user_id: string }>(schema: z.ZodType<T>, value: unknown, user: Identity, maximum: number): T[] {
    const rows = output(z.array(schema).max(maximum), value);
    if (rows.some(row => row.user_id !== user.userId)) throw unavailable();
    return rows;
  }
  private async purposes(user: Identity, signal: AbortSignal) {
    const reply = await this.database.request('consent_purposes', {
      select: 'code,current_policy_version', order: 'code.asc', limit: '3',
    }, user.token, signal, 'GET', undefined, true);
    const rows = output(z.array(purposeRow).length(2), reply.data);
    if (reply.count !== 2 || rows[0]?.code === rows[1]?.code) throw unavailable();
    return rows;
  }
  async consents(user: Identity, signal: AbortSignal) {
    const [catalog, reply] = await Promise.all([this.purposes(user, signal),
      this.database.request('user_consents', { select: consentSelect, user_id: `eq.${user.userId}`, limit: '3' }, user.token, signal)]);
    const rows = this.ownRows(consentRow, reply.data, user, 2);
    // Invariante: como máximo una decisión por finalidad, impuesta por PK y
    // verificada al leer. Construir Map O(P), consultar O(1) esperado; P<=2.
    const decisions = new Map(rows.map(row => [row.purpose_code, row]));
    if (decisions.size !== rows.length) throw unavailable();
    return catalog.map(item => {
      const row = decisions.get(item.code);
      const granted = row?.granted ?? false;
      return { purpose: item.code, granted, policyVersion: row?.policy_version ?? null,
        currentPolicyVersion: item.current_policy_version,
        needsRenewal: granted && row?.policy_version !== item.current_policy_version,
        effective: granted && row?.policy_version === item.current_policy_version, changedAt: row?.changed_at ?? null };
    });
  }
  async me(user: Identity, signal: AbortSignal) {
    const [profiles, preferences, consents] = await Promise.all([
      this.database.request('profiles', { select: profileSelect, user_id: `eq.${user.userId}`, limit: '2' }, user.token, signal),
      this.database.request('user_preferences', { select: preferencesSelect, user_id: `eq.${user.userId}`, limit: '2' }, user.token, signal),
      this.consents(user, signal),
    ]);
    const profile = this.ownRows(profileRow, profiles.data, user, 1)[0];
    if (!profile) throw new ApiError(404, 'PROFILE_NOT_FOUND');
    const pref = this.ownRows(preferenceRow, preferences.data, user, 1)[0];
    return { userId: user.userId, email: user.email,
      profile: { displayName: profile.display_name, createdAt: profile.created_at },
      preferences: pref ? { locale: pref.locale, timezone: pref.timezone, theme: pref.theme } : { ...defaults }, consents };
  }
  private async writeOwn(table: 'profiles' | 'user_preferences' | 'user_consents',
    query: Record<string, string>, patch: Record<string, unknown>, keys: Record<string, string>,
    user: Identity, signal: AbortSignal): Promise<void> {
    const filtered = { ...query, user_id: `eq.${user.userId}` };
    const changed = await this.database.request(table, filtered, user.token, signal, 'PATCH', patch);
    if (!Array.isArray(changed.data) || changed.data.length > 1) throw unavailable();
    if (changed.data.length) { this.checkWriteOwner(changed.data[0], user); return; }
    try {
      const created = await this.database.request(table, query.select ? { select: query.select } : {}, user.token,
        signal, 'POST', { ...patch, ...keys, user_id: user.userId });
      if (!Array.isArray(created.data) || created.data.length !== 1) throw unavailable();
      this.checkWriteOwner(created.data[0], user);
    } catch (error) {
      if (!(error instanceof DatabaseError && error.sqlCode === '23505')) throw error;
      // Solo carrera de unicidad: nunca reintentar una mutación por timeout/5xx.
      const retried = await this.database.request(table, filtered, user.token, signal, 'PATCH', patch);
      if (!Array.isArray(retried.data) || retried.data.length !== 1) throw new ApiError(409, 'CONFLICT');
      this.checkWriteOwner(retried.data[0], user);
    }
  }
  private checkWriteOwner(row: unknown, user: Identity): void {
    if (!row || typeof row !== 'object' || !('user_id' in row) || row.user_id !== user.userId) throw unavailable();
  }
  async putMe(name: string, user: Identity, signal: AbortSignal) {
    await this.writeOwn('profiles', { select: profileSelect }, { display_name: name }, {}, user, signal);
    try {
      await this.database.request('user_preferences', {}, user.token, signal, 'POST', { user_id: user.userId });
    } catch (error) { if (!(error instanceof DatabaseError && error.sqlCode === '23505')) throw error; }
    return this.me(user, signal);
  }
  async patchPreferences(patch: z.infer<typeof preferencePatch>, user: Identity, signal: AbortSignal) {
    const profiles = await this.database.request('profiles', { select: profileSelect, user_id: `eq.${user.userId}`, limit: '2' }, user.token, signal);
    if (!this.ownRows(profileRow, profiles.data, user, 1).length) throw new ApiError(404, 'PROFILE_NOT_FOUND');
    await this.writeOwn('user_preferences', { select: preferencesSelect }, patch, {}, user, signal);
    const reply = await this.database.request('user_preferences', { select: preferencesSelect, user_id: `eq.${user.userId}`, limit: '2' }, user.token, signal);
    const pref = this.ownRows(preferenceRow, reply.data, user, 1)[0];
    if (!pref) throw unavailable();
    return { locale: pref.locale, timezone: pref.timezone, theme: pref.theme };
  }
  async putConsent(code: 'scan_summaries' | 'report_storage', input: z.infer<typeof consentInput>, user: Identity, signal: AbortSignal) {
    const catalog = await this.purposes(user, signal);
    const current = catalog.find(item => item.code === code);
    if (!current) throw unavailable();
    if (input.granted && input.policyVersion !== current.current_policy_version) throw new ApiError(409, 'POLICY_VERSION_OUTDATED');
    const patch = input.granted ? { granted: true, policy_version: input.policyVersion } : { granted: false };
    try {
      await this.writeOwn('user_consents', { select: consentSelect, purpose_code: `eq.${code}` }, patch,
        { purpose_code: code }, user, signal);
    } catch (error) {
      if (input.granted && error instanceof DatabaseError && error.sqlCode === '23514') throw new ApiError(409, 'POLICY_VERSION_OUTDATED');
      if (error instanceof DatabaseError && error.sqlCode === '23503') throw new ApiError(404, 'PROFILE_NOT_FOUND');
      throw error;
    }
    const result = (await this.consents(user, signal)).find(item => item.purpose === code);
    if (!result) throw unavailable();
    return result;
  }
  private async release(platform: 'windows-x64', user: Identity | undefined, signal: AbortSignal) {
    const reply = await this.database.request('app_releases', {
      select: 'id,version,source_commit,status,published_at,release_assets!inner(id,platform_code,download_url,sha256,size_bytes),release_notes(locale,body)',
      status: 'eq.PUBLISHED', 'release_assets.platform_code': `eq.${platform}`, order: 'published_at.desc,id.desc', limit: '1',
    }, user?.token, signal);
    const release = output(z.array(releaseRow).max(1), reply.data)[0];
    if (!release) throw new ApiError(503, 'RELEASE_UNAVAILABLE');
    const asset = release.release_assets[0]!;
    if (asset.platform_code !== platform || !asset.download_url.startsWith(this.config.releasePrefix)
      || !acceptedDownloadUrl(asset.download_url)) throw new ApiError(503, 'RELEASE_UNAVAILABLE');
    return { release, asset };
  }
  async latest(platform: 'windows-x64', signal: AbortSignal) {
    const { release, asset } = await this.release(platform, undefined, signal);
    return { version: release.version, platform, publishedAt: release.published_at, sizeBytes: asset.size_bytes,
      sha256: asset.sha256, sourceCommit: release.source_commit,
      notes: release.release_notes.find(note => note.locale === 'es-CO')?.body ?? release.release_notes.find(note => note.locale === 'es')?.body ?? '',
      requirements: { os: 'Windows 10/11 x64', admin: false } };
  }
  async download(platform: 'windows-x64', user: Identity, signal: AbortSignal) {
    const { release, asset } = await this.release(platform, user, signal);
    let reply;
    try {
      reply = await this.database.request('download_requests', {}, user.token, signal, 'POST', { user_id: user.userId, asset_id: asset.id });
    } catch (error) {
      if (error instanceof DatabaseError && error.sqlCode === '42501') throw new ApiError(503, 'RELEASE_UNAVAILABLE');
      if (error instanceof DatabaseError && error.sqlCode === '23503') throw new ApiError(409, 'CONFLICT');
      throw error;
    }
    const row = this.ownRows(downloadRow, reply.data, user, 1)[0];
    if (!row || row.asset_id !== asset.id) throw unavailable();
    return { requestId: row.id, version: release.version, downloadUrl: asset.download_url, sizeBytes: asset.size_bytes,
      sha256: asset.sha256, notice: 'Es un enlace público de GitHub. Comprueba el SHA-256 después de descargar.' };
  }
  async devices(user: Identity, signal: AbortSignal, suppliedLimit?: number, token?: string) {
    const context = token !== undefined ? this.cursors.resolve(token, user.userId, 'devices', suppliedLimit) : undefined;
    const limit = context?.limit ?? suppliedLimit ?? 20;
    const query: Record<string, string> = { select: deviceSelect, user_id: `eq.${user.userId}`,
      order: 'created_at.desc,id.desc', limit: String(limit + 1) };
    if (context) {
      const below = (p: Position, inclusive: boolean) => `or(created_at.lt.${p.time},and(created_at.eq.${p.time},id.${inclusive ? 'lte' : 'lt'}.${p.id}))`;
      query.and = `(${below(context.after, false)},${below(context.upper, true)})`;
    }
    const reply = await this.database.request('devices', query, user.token, signal, 'GET', undefined, true);
    const rows = this.ownRows(deviceRow, reply.data, user, limit + 1);
    if (reply.count === undefined || reply.count < rows.length || (reply.count > rows.length && rows.length < limit + 1)) throw unavailable();
    const position = (row: z.infer<typeof deviceRow>): Position => ({ time: row.created_at, id: row.id });
    for (let i = 0; i < rows.length; i += 1) {
      const point = position(rows[i]!);
      if ((i && comparePositions(point, position(rows[i - 1]!)) >= 0)
        || (context && (comparePositions(point, context.after) >= 0 || comparePositions(point, context.upper) > 0))) throw unavailable();
    }
    const page = rows.slice(0, limit);
    const nextCursor = rows.length > limit ? this.cursors.issue(user.userId, 'devices', limit,
      context?.upper ?? position(rows[0]!), position(page.at(-1)!)) : null;
    return { items: page.map(row => ({ deviceId: row.id, displayName: row.display_name, platform: row.platform_code,
      appVersion: row.app_version, createdAt: row.created_at, lastSeenAt: row.last_seen_at, revokedAt: row.revoked_at })), nextCursor };
  }
  async revoke(id: string, user: Identity, signal: AbortSignal): Promise<void> {
    const reply = await this.database.request('rpc/revoke_device', {}, user.token, signal, 'POST', { device_id: id });
    const rows = output(z.array(revokedRow).max(1), reply.data);
    if (rows.length) { if (rows[0]!.id !== id) throw unavailable(); return; }
    const current = await this.database.request('devices', { select: deviceSelect, user_id: `eq.${user.userId}`, id: `eq.${id}`, limit: '2' }, user.token, signal);
    const own = this.ownRows(deviceRow, current.data, user, 1)[0];
    if (own && own.id !== id) throw unavailable();
    if (own?.revoked_at) throw new ApiError(409, 'CONFLICT');
    throw new ApiError(404, 'NOT_FOUND');
  }
}
