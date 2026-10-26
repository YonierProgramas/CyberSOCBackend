import assert from 'node:assert/strict';
import { once } from 'node:events';
import { after, before, test } from 'node:test';
import { createApiServer } from '../src/server.mjs';

let server;
let base;
before(async () => {
  server = createApiServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  server.closeAllConnections();
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
});

test('healthz indica transporte disponible y capacidades aún no implementadas', async () => {
  const response = await fetch(`${base}/healthz`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const body = await response.json();
  assert.equal(body.status, 'ok');
  assert.deepEqual(body.capabilities, { authentication: false, database: false });
});
test('HEAD funciona y los métodos no admitidos devuelven 405', async () => {
  const head = await fetch(`${base}/healthz`, { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  const post = await fetch(`${base}/healthz`, { method: 'POST' });
  assert.equal(post.status, 405);
  assert.equal(post.headers.get('allow'), 'GET, HEAD');
});
test('una ruta de cuenta no simula autenticación ni devuelve datos', async () => {
  const response = await fetch(`${base}/v1/me`);
  assert.equal(response.status, 404);
  assert.equal((await response.json()).error.code, 'NOT_FOUND');
});
