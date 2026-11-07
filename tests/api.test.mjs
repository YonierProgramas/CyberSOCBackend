import assert from 'node:assert/strict';
import test from 'node:test';
import { API_ROUTES } from '../dist/server.js';
import { application, makeUpstream, A, B, token, device, release, jsonReply, config } from './helpers.mjs';

test('H-01: todas las rutas privadas exigen JWT antes de consultar datos', async t => {
  const app = await application(t);
  for (const route of API_ROUTES.filter(item => item.private)) {
    for (const method of route.methods) {
      const path = route.path.replace('{purposeCode}', 'scan_summaries').replace('{deviceId}', device(1).id);
      const reply = await app.request(path, { auth: null, method });
      assert.equal(reply.status, 401);
      assert.equal(reply.data.error.code, 'AUTH_REQUIRED');
    }
  }
  assert.equal(app.state.calls.length, 0);
  assert.equal(app.state.jwksCalls, 0);
});
test('H-07: perfil/consentimientos solo propios, JWT/apikey conservados y preferencias por defecto', async t => {
  const app = await application(t);
  app.state.consents.set(`${B}:scan_summaries`, { user_id: B, purpose_code: 'scan_summaries', granted: true,
    policy_version: '2026-10-26', changed_at: '2026-10-27T12:00:00.000000Z' });
  const reply = await app.request('/v1/me');
  assert.equal(reply.status, 200);
  assert.equal(reply.data.userId, A);
  assert.ok(reply.data.consents.every(row => row.granted === false));
  for (const call of app.state.calls) {
    assert.equal(call.authorization === `Bearer ${app.jwt}`, true);
    assert.equal(call.apikey === config.publishableKey, true);
    assert.equal(call.redirect, 'error');
    if (call.table !== 'consent_purposes') assert.equal(call.url.searchParams.get('user_id'), `eq.${A}`);
  }
  const ownB = await app.request('/v1/me', { auth: token({ sub: B }) });
  assert.equal(ownB.data.userId, B);
  assert.equal(ownB.data.consents.find(row => row.purpose === 'scan_summaries').effective, true);
});
test('PUT perfil idempotente y carrera INSERT única, sin sobrescribir preferencias', async t => {
  const app = await application(t);
  app.state.profiles.delete(A); app.state.preferences.delete(A);
  assert.equal((await app.request('/v1/me')).status, 404);
  const first = await app.request('/v1/me', { method: 'PUT', body: { displayName: '  Prueba  ' } });
  assert.equal(first.status, 200); assert.equal(first.data.profile.displayName, 'Prueba');
  assert.equal(app.state.profileCreates, 1);
  assert.equal((await app.request('/v1/me/preferences', { method: 'PATCH', body: { theme: 'dark' } })).status, 200);
  const repeated = await app.request('/v1/me', { method: 'PUT', body: { displayName: 'Nuevo' } });
  assert.equal(repeated.data.preferences.theme, 'dark');
  assert.equal(app.state.profileCreates, 1);
});
test('H-17: retirada con política vieja/arbitraria/omitida; conceder solo vigente', async t => {
  const app = await application(t);
  const path = '/v1/me/consents/scan_summaries';
  assert.equal((await app.request(path, { method: 'PUT', body: { granted: true, policyVersion: '2026-10-26' } })).status, 200);
  app.state.purposes.find(row => row.code === 'scan_summaries').current_policy_version = 'v2';
  const old = await app.request('/v1/me/consents');
  assert.equal(old.data.find(row => row.purpose === 'scan_summaries').effective, false);
  assert.equal(old.data.find(row => row.purpose === 'scan_summaries').needsRenewal, true);
  for (const body of [{ granted: false, policyVersion: '2026-10-26' }, { granted: false, policyVersion: 'arbitraria' }, { granted: false }]) {
    const reply = await app.request(path, { method: 'PUT', body });
    assert.equal(reply.status, 200); assert.equal(reply.data.granted, false);
    assert.equal(reply.data.policyVersion, '2026-10-26');
  }
  const rejected = await app.request(path, { method: 'PUT', body: { granted: true, policyVersion: '2026-10-26' } });
  assert.equal(rejected.status, 409); assert.equal(rejected.data.error.code, 'POLICY_VERSION_OUTDATED');
  assert.equal((await app.request(path, { method: 'PUT', body: { granted: true, policyVersion: 'v2' } })).data.effective, true);
  for (const call of app.state.calls.filter(row => row.method === 'PATCH' || row.method === 'POST')) {
    assert.equal('changed_at' in call.body, false);
    if (call.body.granted === false) assert.equal('policy_version' in call.body, false);
  }
});
test('H-17: cambio concurrente de política detectado también por error SQL 23514', async t => {
  const app = await application(t);
  app.state.failure = call => call.table === 'user_consents' && call.method === 'PATCH'
    ? jsonReply({ code: '23514', message: 'SQL PRIVADO' }, 400) : undefined;
  const reply = await app.request('/v1/me/consents/scan_summaries', { method: 'PUT', body: { granted: true, policyVersion: '2026-10-26' } });
  assert.equal(reply.status, 409); assert.equal(reply.data.error.code, 'POLICY_VERSION_OUTDATED');
});
test('H-06/O1: propietario, fechas, contraseña y otros campos desconocidos son 400', async t => {
  const app = await application(t);
  for (const body of [{ displayName: 'X', userId: B }, { displayName: 'X', user_id: B },
    { displayName: 'X', role: 'admin' }, { displayName: 'X', password: 'ficticio' },
    { displayName: 'X', created_at: '2099' }, { displayName: '\u0000' }, {}]) {
    assert.equal((await app.request('/v1/me', { method: 'PUT', body })).status, 400);
  }
  for (const body of [{ granted: false, changedAt: '2099' }, { granted: false, changed_at: '2099' }, { granted: true }]) {
    assert.equal((await app.request('/v1/me/consents/scan_summaries', { method: 'PUT', body })).status, 400);
  }
  assert.equal((await app.request('/v1/me/preferences', { method: 'PATCH', body: { updated_at: '2099' } })).status, 400);
  assert.equal((await app.request('/v1/me/preferences', { method: 'PATCH', body: { timezone: 'No/Existe' } })).status, 400);
  assert.equal((await app.request('/v1/me?user_id=' + B)).status, 400);
  assert.equal(app.state.calls.length, 0);
});
test('H-06: cuerpos 16 KiB, JSON/tipo y parámetros duplicados', async t => {
  const app = await application(t);
  assert.equal((await app.request('/v1/me', { method: 'PUT', raw: '{' })).status, 400);
  assert.equal((await app.request('/v1/me', { method: 'PUT', body: { displayName: 'X' }, headers: { 'Content-Type': 'text/plain' } })).status, 415);
  assert.equal((await app.request('/v1/me', { method: 'PUT', raw: ' '.repeat(16385) })).status, 413);
  assert.equal((await app.request('/v1/releases/latest?platform=windows-x64&platform=windows-x64', { auth: null })).status, 400);
  assert.equal((await app.request('/v1/devices?limit=0')).status, 400);
  assert.equal((await app.request('/v1/devices?offset=20')).status, 400);
});
test('H-08/H-16: sin release real 503, consulta pública anon y plataforma cerrada', async t => {
  const app = await application(t);
  const unavailable = await app.request('/v1/releases/latest?platform=windows-x64', { auth: null });
  assert.equal(unavailable.status, 503); assert.equal(unavailable.data.error.code, 'RELEASE_UNAVAILABLE');
  assert.equal(app.state.calls[0].authorization, null);
  assert.equal(app.state.calls[0].table, 'app_releases');
  const count = app.state.calls.length;
  assert.equal((await app.request('/v1/releases/latest?platform=linux-x64', { auth: null })).status, 400);
  assert.equal(app.state.calls.length, count);
  assert.equal((await app.request('/v1/downloads', { method: 'POST', body: { platform: 'windows-x64' } })).data.error.code, 'RELEASE_UNAVAILABLE');
  assert.equal(app.state.downloads.length, 0);
});
test('Release ficticia identificada: metadatos sin URL; registro de solicitud propio', async t => {
  const app = await application(t);
  app.state.releases = [release()];
  const latest = await app.request('/v1/releases/latest?platform=windows-x64', { auth: null });
  assert.equal(latest.status, 200); assert.equal('downloadUrl' in latest.data, false);
  assert.ok(latest.data.notes.includes('FICTICIOS'));
  const download = await app.request('/v1/downloads', { method: 'POST', body: { platform: 'windows-x64' } });
  assert.equal(download.status, 200);
  assert.equal(app.state.downloads[0].user_id, A);
  assert.equal(app.state.downloads[0].asset_id, app.state.releases[0].release_assets[0].id);
  assert.equal(app.state.calls.at(-1).authorization === `Bearer ${app.jwt}`, true);
  for (const url of ['https://github.com.evil.invalid/x.exe', 'https://github.com/Otro/repo/releases/download/x/a.exe',
    config.releasePrefix + '../otro.exe', config.releasePrefix + 'ficticio/a.exe?redirect=evil']) {
    app.state.releases[0].release_assets[0].download_url = url;
    assert.equal((await app.request('/v1/downloads', { method: 'POST', body: { platform: 'windows-x64' } })).status, 503);
  }
  assert.equal(app.state.downloads.length, 1);
});
test('O2/H-07: revocar solo RPC, ajeno/inexistente 404 y repetido 409', async t => {
  const app = await application(t);
  app.state.devices = [device(1), device(2, B)];
  assert.equal((await app.request(`/v1/devices/${device(2, B).id}`, { method: 'DELETE' })).status, 404);
  assert.equal((await app.request(`/v1/devices/${device(3).id}`, { method: 'DELETE' })).status, 404);
  assert.equal((await app.request(`/v1/devices/${device(1).id}`, { method: 'DELETE' })).status, 204);
  assert.equal((await app.request(`/v1/devices/${device(1).id}`, { method: 'DELETE' })).status, 409);
  assert.equal((await app.request(`/v1/devices/${device(2).id}`, { method: 'PATCH', body: { revoked_at: null } })).status, 405);
  assert.equal(app.state.revokeEvents, 1);
  assert.equal(app.state.calls.some(call => call.table === 'devices' && call.method === 'PATCH'), false);
});
test('H-10/H-12: fallos upstream y filas ajenas/malformadas no exponen datos o detalles', async t => {
  const app = await application(t);
  app.state.failure = () => jsonReply({ message: 'CORREO-SECRETO-SQL' }, 500);
  let reply = await app.request('/v1/me');
  assert.equal(reply.status, 503); assert.equal(JSON.stringify(reply.data).includes('CORREO'), false);
  app.state.failure = call => call.table === 'profiles' ? jsonReply([app.state.profiles.get(B)]) : undefined;
  reply = await app.request('/v1/me');
  assert.equal(reply.status, 503); assert.equal(JSON.stringify(reply.data).includes(B), false);
  app.state.failure = () => new Response('no-json', { status: 200 });
  assert.equal((await app.request('/v1/me')).status, 503);
  app.state.failure = () => { throw new DOMException('timeout-ficticio', 'TimeoutError'); };
  reply = await app.request('/v1/me');
  assert.equal(reply.status, 504); assert.equal(reply.data.error.code, 'UPSTREAM_TIMEOUT');
  app.state.failure = () => new Response('x', { headers: { 'Content-Type': 'application/json', 'Content-Length': String(1048577) } });
  assert.equal((await app.request('/v1/me')).status, 503);
  const logs = JSON.stringify(app.logs);
  assert.equal(logs.includes(app.jwt) || logs.includes('ficticio@example.invalid') || logs.includes('CORREO-SECRETO'), false);
  assert.ok(app.logs.every(row => row.requestId && row.route && Number.isFinite(row.durationMs)));
});
test('H-14: CORS exacto, preflight, sin credenciales ni confianza por origen', async t => {
  const app = await application(t);
  let reply = await app.request('/v1/me', { auth: null, headers: { Origin: config.portalOrigin } });
  assert.equal(reply.status, 401); assert.equal(reply.headers.get('access-control-allow-origin'), config.portalOrigin);
  reply = await app.request('/v1/me', { headers: { Origin: 'https://ajeno.invalid' } });
  assert.equal(reply.status, 200); assert.equal(reply.headers.get('access-control-allow-origin'), null);
  assert.equal(reply.headers.get('access-control-allow-credentials'), null);
  reply = await app.request('/v1/me', { method: 'OPTIONS', auth: null, headers: { Origin: config.portalOrigin,
    'Access-Control-Request-Method': 'PUT', 'Access-Control-Request-Headers': 'authorization,content-type' } });
  assert.equal(reply.status, 204); assert.equal(reply.headers.get('access-control-max-age'), '600');
  assert.equal((await app.request('/v1/me', { method: 'OPTIONS', auth: null, headers: { Origin: 'https://ajeno.invalid', 'Access-Control-Request-Method': 'GET' } })).status, 403);
});
test('H-11: límite mutaciones/IP acotado y Retry-After, sin confiar en X-Forwarded-For', async t => {
  const app = await application(t);
  for (let i = 0; i < 20; i += 1) await app.request('/v1/me/preferences', { method: 'PATCH', body: {} });
  const limited = await app.request('/v1/me/preferences', { method: 'PATCH', body: { theme: 'dark' } });
  assert.equal(limited.status, 429); assert.ok(Number(limited.headers.get('retry-after')) > 0);
  for (let i = 0; i < 39; i += 1) await app.request('/v1/me');
  const ipLimited = await app.request('/v1/me', { headers: { 'X-Forwarded-For': '203.0.113.1' } });
  assert.equal(ipLimited.status, 429);
});
test('P1/P2, actividad opcional y rutas con datos privados no se publican ni se loguean', async t => {
  const app = await application(t);
  for (const path of ['/v1/device-links', '/v1/me/activity', '/v1/password', '/correo-ficticio@example.invalid']) {
    assert.equal((await app.request(path)).status, 404);
  }
  assert.ok(app.logs.every(row => row.route === 'unmatched'));
});
