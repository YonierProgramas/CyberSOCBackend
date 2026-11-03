import assert from 'node:assert/strict';
import test from 'node:test';
import { JwtVerifier } from '../dist/auth.js';
import { validateConfig } from '../dist/config.js';
import { config, token, rsa, ec, rsaJwk, ecJwk, jsonReply, A } from './helpers.mjs';

function verifier(clock = Date.now) {
  const state = { keys: [rsaJwk, ecJwk], requests: 0 };
  const service = new JwtVerifier(config, async (url, init) => {
    assert.equal(String(url) === config.jwksUrl, true);
    assert.equal(new Headers(init.headers).has('authorization'), false);
    assert.equal(init.redirect, 'error');
    state.requests += 1;
    return jsonReply({ keys: state.keys });
  }, clock);
  return { service, state };
}
const rejection = code => error => error.code === code;

test('H-03: RS256 y ES256 válidos con firma nativa r||s de 64 bytes', async () => {
  const { service, state } = verifier();
  assert.equal((await service.verify(`Bearer ${token()}`)).userId, A);
  const signed = token({ aud: ['authenticated', 'otra'] }, { alg: 'ES256', kid: 'ec-demo' }, ec.privateKey);
  assert.equal(Buffer.from(signed.split('.')[2], 'base64url').length, 64);
  assert.equal((await service.verify(`Bearer ${signed}`)).userId, A);
  assert.equal(state.requests, 1);
});
test('H-01/H-02: ausencia, formato, alg none/HS256, URLs y firma alterada', async () => {
  const { service, state } = verifier();
  await assert.rejects(service.verify(undefined), rejection('AUTH_REQUIRED'));
  for (const candidate of ['', 'Basic x', 'Bearer a.b', `Bearer ${'a'.repeat(8193)}`, 'Bearer a.b.c.d']) {
    await assert.rejects(service.verify(candidate), rejection('TOKEN_INVALID'));
  }
  for (const change of [{ alg: 'none' }, { alg: 'HS256' }, { jku: 'https://example.invalid/key' },
    { x5u: 'https://example.invalid/key' }, { crit: ['x'] }, { kid: 'https://example.invalid/key' }]) {
    await assert.rejects(service.verify(`Bearer ${token({}, change)}`), rejection('TOKEN_INVALID'));
  }
  assert.equal(state.requests, 0);
  const signed = token();
  const parts = signed.split('.');
  parts[2] = Buffer.from('firma falsa').toString('base64url');
  await assert.rejects(service.verify(`Bearer ${parts.join('.')}`), rejection('TOKEN_INVALID'));
});
test('H-02/H-04: issuer/audiencia/sub/iat/nbf/rol y usuario anónimo', async () => {
  const { service } = verifier();
  for (const claims of [{ iss: 'https://ajeno.invalid' }, { aud: 'otro' }, { sub: 'ajeno' },
    { iat: Math.floor(Date.now() / 1000) + 31 }, { nbf: Math.floor(Date.now() / 1000) + 31 }]) {
    await assert.rejects(service.verify(`Bearer ${token(claims)}`), rejection('TOKEN_INVALID'));
  }
  for (const claims of [{ role: 'anon' }, { role: 'service_role' }, { is_anonymous: true }]) {
    await assert.rejects(service.verify(`Bearer ${token(claims)}`), rejection('FORBIDDEN'));
  }
});
test('H-04: tolerancia exacta 30 s y firma inválida prevalece sobre exp', async () => {
  const now = 1800000000000;
  const { service } = verifier(() => now);
  await service.verify(`Bearer ${token({ exp: now / 1000 - 29, iat: now / 1000 - 100 }, {}, rsa.privateKey, now)}`);
  await assert.rejects(service.verify(`Bearer ${token({ exp: now / 1000 - 30, iat: now / 1000 - 100 }, {}, rsa.privateKey, now)}`), rejection('TOKEN_EXPIRED'));
  await service.verify(`Bearer ${token({ iat: now / 1000 + 30 }, {}, rsa.privateKey, now)}`);
  const expired = token({ exp: now / 1000 - 100, iat: now / 1000 - 200 }, {}, rsa.privateKey, now).split('.');
  expired[2] = Buffer.from('falso').toString('base64url');
  await assert.rejects(service.verify(`Bearer ${expired.join('.')}`), rejection('TOKEN_INVALID'));
});
test('H-05: rotación, recarga única por minuto y TTL 10 min', async () => {
  let now = Date.now();
  const { service, state } = verifier(() => now);
  await service.verify(`Bearer ${token()}`);
  state.keys = [...state.keys, { ...rsaJwk, kid: 'nuevo' }];
  await service.verify(`Bearer ${token({}, { kid: 'nuevo' })}`);
  assert.equal(state.requests, 2);
  for (const kid of ['falso1', 'falso2']) await assert.rejects(service.verify(`Bearer ${token({}, { kid })}`), rejection('TOKEN_INVALID'));
  assert.equal(state.requests, 2);
  now += 60001;
  await assert.rejects(service.verify(`Bearer ${token({}, { kid: 'falso3' })}`), rejection('TOKEN_INVALID'));
  assert.equal(state.requests, 3);
  now += 600001;
  await service.verify(`Bearer ${token()}`);
  assert.equal(state.requests, 4);
});
test('JWKS concurrente solo descarga una vez; kid duplicado y clave/alg confusos rechazados', async () => {
  const { service, state } = verifier();
  await Promise.all([1, 2, 3].map(() => service.verify(`Bearer ${token()}`)));
  assert.equal(state.requests, 1);
  await assert.rejects(service.verify(`Bearer ${token({}, { alg: 'ES256', kid: 'rsa-demo' }, ec.privateKey)}`), rejection('TOKEN_INVALID'));
  const duplicate = new JwtVerifier(config, async () => jsonReply({ keys: [rsaJwk, rsaJwk] }));
  await assert.rejects(duplicate.verify(`Bearer ${token()}`), rejection('UPSTREAM_UNAVAILABLE'));
});
test('Configuración rechaza credencial privilegiada y URLs/issuer/orígenes ajenos', () => {
  for (const change of [{ publishableKey: 'sb_secret_ficticio_no_usar' }, { supabaseUrl: 'http://127.0.0.1' },
    { jwksUrl: 'https://ajeno.invalid/jwks' }, { issuer: 'https://ajeno.invalid' },
    { portalOrigin: 'https://portal.invalid/ruta' }, { releasePrefix: 'https://ajeno.invalid/' }]) {
    assert.throws(() => validateConfig({ ...config, ...change }));
  }
});
