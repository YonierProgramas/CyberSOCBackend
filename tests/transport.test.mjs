import assert from 'node:assert/strict';
import test from 'node:test';
import { request as httpRequest } from 'node:http';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { fetchJson } from '../dist/upstream.js';
import { application, A, jsonReply } from './helpers.mjs';

function raw(base, headers, chunks = [], method = 'PUT') {
  return new Promise((resolve, reject) => {
    const request = httpRequest(base + '/v1/me', { method, headers }, response => {
      const parts = [];
      response.on('data', chunk => parts.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers,
        body: JSON.parse(Buffer.concat(parts).toString('utf8')) }));
    });
    request.on('error', reject);
    for (const chunk of chunks) request.write(chunk);
    request.end();
  });
}
test('Cuerpo chunked: límite 16 KiB y JSON exacto, sin depender de Content-Length', async t => {
  const app = await application(t);
  const headers = { Authorization: `Bearer ${app.jwt}`, 'Content-Type': 'application/json' };
  const oversized = await raw(app.base, headers, [' '.repeat(8000), ' '.repeat(8385)]);
  assert.equal(oversized.status, 413);
  assert.equal(oversized.body.error.requestId, oversized.headers['x-request-id']);
  const exact = await raw(app.base, headers, ['{"displayName":"OK"}', ' '.repeat(16384 - 20)]);
  // Un cuerpo completo en el límite pasa el control de tamaño y esquema.
  assert.equal(exact.status, 200);
});
test('Authorization duplicada se rechaza antes de descargar JWKS', async t => {
  const app = await application(t);
  const reply = await raw(app.base, { Authorization: [`Bearer ${app.jwt}`, `Bearer ${app.jwt}`] }, [], 'GET');
  assert.equal(reply.status, 401); assert.equal(reply.body.error.code, 'TOKEN_INVALID');
  assert.equal(app.state.jwksCalls, 0);
});
test('GET no acepta un cuerpo de propietario aunque el token sea válido', async t => {
  const app = await application(t);
  const reply = await raw(app.base, { Authorization: `Bearer ${app.jwt}`, 'Content-Type': 'application/json' }, ['{"userId":"otro"}'], 'GET');
  assert.equal(reply.status, 400); assert.equal(app.state.calls.length, 0);
});
test('Carrera de creación: solo 23505 reintenta PATCH una vez; 5xx no reintenta', async t => {
  const app = await application(t);
  app.state.profiles.delete(A);
  let raced = false;
  app.state.failure = call => {
    if (!raced && call.table === 'profiles' && call.method === 'POST') {
      raced = true;
      app.state.profiles.set(A, { user_id: A, display_name: 'Ficticio concurrente', created_at: '2026-10-27T12:00:00.000000Z' });
      return jsonReply({ code: '23505' }, 409);
    }
    return undefined;
  };
  assert.equal((await app.request('/v1/me', { method: 'PUT', body: { displayName: 'Final' } })).data.profile.displayName, 'Final');
  assert.equal(app.state.calls.filter(call => call.table === 'profiles' && call.method === 'PATCH').length, 2);
  app.state.failure = call => call.method === 'PATCH' ? jsonReply({ code: 'XX000' }, 500) : undefined;
  const before = app.state.calls.length;
  assert.equal((await app.request('/v1/me', { method: 'PUT', body: { displayName: 'Otra' } })).status, 503);
  assert.equal(app.state.calls.length - before, 1);
});
test('JWKS inaccesible no simula sesión inválida; cuerpo de respuesta interrumpido es timeout', async t => {
  const app = await application(t, { ...((await import('./helpers.mjs')).makeUpstream()),
    fetcher: async () => jsonReply({}, 401) });
  assert.equal((await app.request('/v1/me')).status, 503);
  const second = await application(t);
  second.state.failure = () => new Response(new ReadableStream({ start(controller) {
    controller.error(new DOMException('ficticio', 'TimeoutError'));
  } }), { headers: { 'Content-Type': 'application/json' } });
  assert.equal((await second.request('/v1/me')).status, 504);
});
test('Timeout real de 5 s incluye lectura del cuerpo en fetch nativo', { timeout: 15000 }, async t => {
  const hanging = createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' }); response.write('[');
  });
  hanging.listen(0, '127.0.0.1'); await once(hanging, 'listening');
  t.after(async () => { hanging.closeAllConnections(); await new Promise(resolve => hanging.close(resolve)); });
  const started = performance.now();
  await assert.rejects(fetchJson(fetch, `http://127.0.0.1:${hanging.address().port}`, {}, 1024), error => error.code === 'UPSTREAM_TIMEOUT');
  assert.ok(performance.now() - started >= 4500);
});
