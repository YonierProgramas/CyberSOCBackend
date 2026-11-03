import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { once } from 'node:events';
import { createApiServer } from '../dist/server.js';
import { RELEASE_PREFIX } from '../dist/config.js';

export const A = '10000000-0000-0000-0000-000000000001';
export const B = '20000000-0000-0000-0000-000000000002';
export const config = Object.freeze({ supabaseUrl: 'https://aaaaaaaaaaaaaaaaaaaa.supabase.co',
  issuer: 'https://aaaaaaaaaaaaaaaaaaaa.supabase.co/auth/v1',
  jwksUrl: 'https://aaaaaaaaaaaaaaaaaaaa.supabase.co/auth/v1/.well-known/jwks.json',
  publishableKey: 'sb_publishable_ficticio_solo_pruebas', portalOrigin: 'http://localhost:5173', releasePrefix: RELEASE_PREFIX });
export const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
export const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
export const rsaJwk = { ...rsa.publicKey.export({ format: 'jwk' }), alg: 'RS256', kid: 'rsa-demo', use: 'sig' };
export const ecJwk = { ...ec.publicKey.export({ format: 'jwk' }), alg: 'ES256', kid: 'ec-demo', use: 'sig' };
export function token(changes = {}, headerChanges = {}, key = rsa.privateKey, now = Date.now()) {
  const header = { alg: 'RS256', typ: 'JWT', kid: 'rsa-demo', ...headerChanges };
  const claims = { sub: A, iss: config.issuer, aud: 'authenticated', role: 'authenticated',
    iat: Math.floor(now / 1000) - 60, exp: Math.floor(now / 1000) + 3600, email: 'ficticio@example.invalid', ...changes };
  const unsigned = [header, claims].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
  const signature = sign('sha256', Buffer.from(unsigned), header.alg === 'ES256'
    ? { key, dsaEncoding: 'ieee-p1363' } : key).toString('base64url');
  return `${unsigned}.${signature}`;
}
export function jsonReply(data, status = 200, count) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json',
    ...(count === undefined ? {} : { 'Content-Range': `${Array.isArray(data) && data.length ? `0-${data.length - 1}` : '*'}/${count}` }) } });
}
const errorReply = (status, code) => jsonReply({ code, message: 'DETALLE_PRIVADO_NO_MOSTRAR' }, status);
export function device(index, owner = A, time = '2026-10-27T12:00:00.000001Z') {
  return { id: `30000000-0000-0000-0000-${String(index).padStart(12, '0')}`, user_id: owner,
    display_name: `Ficticio ${index}`, platform_code: 'windows-x64', app_version: '0.0.0-demo',
    created_at: time, last_seen_at: null, revoked_at: null };
}
export function release() {
  return { id: '50000000-0000-0000-0000-000000000001', version: '0.0.0-demo', source_commit: '0'.repeat(40),
    status: 'PUBLISHED', published_at: '2026-10-27T12:00:00.000000Z',
    release_assets: [{ id: '60000000-0000-0000-0000-000000000001', platform_code: 'windows-x64',
      download_url: `${RELEASE_PREFIX}ficticio/fixture-no-publicado.exe`, sha256: '0'.repeat(64), size_bytes: 100 }],
    release_notes: [{ locale: 'es', body: 'DATOS FICTICIOS, sin binario publicado.' }] };
}
export function makeUpstream() {
  // Doble explícito, no acredita SQL/RLS reales. Maps con una fila por PK;
  // lookup O(1) esperado, filtrado/orden O(N log N) para fixtures pequeñas.
  const state = {
    keys: [rsaJwk, ecJwk], calls: [], jwksCalls: 0, failure: undefined, truncate: undefined,
    profiles: new Map([A, B].map(user_id => [user_id, { user_id, display_name: 'Perfil ficticio', created_at: '2026-10-27T12:00:00.000000Z' }])),
    preferences: new Map([A, B].map(user_id => [user_id, { user_id, locale: 'es-CO', timezone: 'America/Bogota', theme: 'system' }])),
    purposes: [{ code: 'report_storage', current_policy_version: '2026-10-26' }, { code: 'scan_summaries', current_policy_version: '2026-10-26' }],
    consents: new Map(), devices: [], releases: [], downloads: [], profileCreates: 0, revokeEvents: 0,
  };
  const fetcher = async (value, init = {}) => {
    const url = new URL(String(value));
    if (url.origin !== config.supabaseUrl) throw new Error('Origen externo no autorizado en pruebas');
    if (url.href === config.jwksUrl) {
      state.jwksCalls += 1;
      return jsonReply({ keys: state.keys });
    }
    if (init.signal?.aborted) throw new DOMException('Cancelado', 'AbortError');
    const headers = new Headers(init.headers);
    const authorization = headers.get('authorization');
    const claims = authorization ? JSON.parse(Buffer.from(authorization.slice(7).split('.')[1], 'base64url')) : undefined;
    const owner = claims?.sub;
    const body = init.body ? JSON.parse(init.body) : undefined;
    const method = init.method ?? 'GET';
    const table = url.pathname.replace('/rest/v1/', '');
    const query = url.searchParams;
    const call = { url, method, table, body, authorization, apikey: headers.get('apikey'), redirect: init.redirect };
    state.calls.push(call);
    if (state.failure) {
      const response = await state.failure(call, init);
      if (response) return response;
    }
    if (table === 'app_releases') return jsonReply(state.releases);
    if (!owner) return errorReply(401, '42501');
    if (table === 'consent_purposes') return jsonReply(state.purposes, 200, state.purposes.length);
    const filtersOwner = query.get('user_id');
    if (filtersOwner && filtersOwner !== `eq.${owner}`) return jsonReply([]);
    if (['profiles', 'user_preferences', 'user_consents'].includes(table)) {
      const code = query.get('purpose_code')?.slice(3) ?? body?.purpose_code;
      const collection = table === 'profiles' ? state.profiles : table === 'user_preferences' ? state.preferences : state.consents;
      const key = table === 'user_consents' ? `${owner}:${code}` : owner;
      if (method === 'GET') {
        return jsonReply(table === 'user_consents' ? [...collection.values()].filter(row => row.user_id === owner)
          : collection.has(key) ? [collection.get(key)] : []);
      }
      if (body.user_id && body.user_id !== owner) return errorReply(403, '42501');
      if (method === 'PATCH' && !collection.has(key)) return jsonReply([]);
      if (method === 'POST' && collection.has(key)) return errorReply(409, '23505');
      if (['user_consents', 'user_preferences'].includes(table) && ('changed_at' in body || 'updated_at' in body)) return errorReply(403, '42501');
      const previous = collection.get(key);
      let row = { ...previous, ...body, user_id: owner };
      if (table === 'profiles') {
        if (!previous) { state.profileCreates += 1; row.created_at = new Date().toISOString(); }
      } else if (table === 'user_preferences') {
        row = { locale: 'es-CO', timezone: 'America/Bogota', theme: 'system', ...row };
      } else {
        const purposeCode = code ?? previous?.purpose_code;
        const current = state.purposes.find(item => item.code === purposeCode)?.current_policy_version;
        if (body.granted && body.policy_version !== current) return errorReply(400, '23514');
        row.purpose_code = purposeCode;
        row.policy_version = body.granted ? body.policy_version : previous?.policy_version ?? current;
        row.changed_at = new Date().toISOString();
      }
      collection.set(key, row);
      return jsonReply([row], method === 'POST' ? 201 : 200);
    }
    if (table === 'download_requests') {
      if (body.user_id !== owner) return errorReply(403, '42501');
      if (!state.profiles.has(owner)) return errorReply(409, '23503');
      const row = { ...body, id: randomUUID(), requested_at: new Date().toISOString() };
      state.downloads.push(row);
      return jsonReply([row], 201);
    }
    if (table === 'rpc/revoke_device') {
      const row = state.devices.find(item => item.id === body.device_id && item.user_id === owner && item.revoked_at === null);
      if (!row) return jsonReply([]);
      row.revoked_at = new Date().toISOString(); state.revokeEvents += 1;
      return jsonReply([{ id: row.id, revoked_at: row.revoked_at }]);
    }
    if (table === 'devices') {
      let rows = state.devices.filter(row => row.user_id === owner);
      if (query.has('id')) rows = rows.filter(row => `eq.${row.id}` === query.get('id'));
      if (query.has('and')) {
        const bounds = [...query.get('and').matchAll(/created_at\.lt\.([0-9T:.\-]+Z),and\(created_at\.eq\.[0-9T:.\-]+Z,id\.(lt|lte)\.([a-f0-9-]+)\)/g)];
        if (bounds.length !== 2) return errorReply(400, 'PGRST100');
        for (const [, time, operator, id] of bounds) rows = rows.filter(row => row.created_at < time || (row.created_at === time && (operator === 'lt' ? row.id < id : row.id <= id)));
      }
      rows.sort((a, b) => a.created_at === b.created_at ? b.id.localeCompare(a.id) : b.created_at.localeCompare(a.created_at));
      const total = rows.length;
      const limit = Math.min(Number(query.get('limit') ?? total), state.truncate ?? Infinity);
      return jsonReply(rows.slice(0, limit), 200, total);
    }
    throw new Error('Llamada de prueba inesperada');
  };
  return { state, fetcher };
}

export async function application(t, upstream = makeUpstream(), options = {}) {
  const logs = [];
  const server = createApiServer({ config, fetcher: upstream.fetcher, logger: value => logs.push(value), ...options });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const jwt = token({}, {}, rsa.privateKey, options.now?.() ?? Date.now());
  async function request(path, { auth = jwt, body, headers = {}, method = 'GET', raw } = {}) {
    const response = await fetch(base + path, { method,
      headers: { ...(auth ? { Authorization: `Bearer ${auth}` } : {}),
        ...(body === undefined && raw === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
      ...(body === undefined && raw === undefined ? {} : { body: raw ?? JSON.stringify(body) }) });
    const text = await response.text();
    return { status: response.status, headers: response.headers, data: text ? JSON.parse(text) : null };
  }
  return { ...upstream, request, server, base, logs, jwt };
}
