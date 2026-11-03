import assert from 'node:assert/strict';
import test from 'node:test';
import { randomBytes } from 'node:crypto';
import { CursorStore } from '../dist/cursor.js';
import { RateLimits } from '../dist/limits.js';
import { application, A, B, token, device, jsonReply } from './helpers.mjs';

const point = (i = 1) => ({ time: '2026-10-27T12:00:00.000001Z', id: device(i).id });
test('K10-03/04/05/06: versión/canonicalización, dueño/recurso/límite y TTL inmutables', () => {
  let now = 1000;
  const store = new CursorStore(() => now);
  const cursor = store.issue(A, 'devices', 20, point(10), point(5));
  assert.match(cursor, /^c1\.[A-Za-z0-9_-]{43}$/);
  for (const altered of ['c2.' + cursor.slice(3), cursor.slice(0, -1), cursor + '=', 'c1.' + 'A'.repeat(43), cursor + 'ñ']) {
    assert.throws(() => store.resolve(altered, A, 'devices'), error => error.code === 'INVALID_CURSOR');
  }
  for (const [owner, resource, limit] of [[B, 'devices', 20], [A, 'activity', 20], [A, 'devices', 21]]) {
    assert.throws(() => store.resolve(cursor, owner, resource, limit), error => error.code === 'INVALID_CURSOR');
  }
  now += 599999; assert.equal(store.resolve(cursor, A, 'devices').limit, 20);
  assert.throws(() => { store.resolve(cursor, A, 'devices').limit = 100; });
  now += 1; assert.throws(() => store.resolve(cursor, A, 'devices'), error => error.code === 'INVALID_CURSOR');
  assert.equal(store.size, 0);
  assert.throws(() => new CursorStore().resolve(cursor, A, 'devices'));
});
test('K10-10/11/12: reutilización, cupo por dueño/global y colisión sin sobrescritura', () => {
  let now = 0;
  const bytes = randomBytes(32);
  const collision = new CursorStore(() => now, () => bytes);
  const first = collision.issue(A, 'devices', 20, point(9), point(5));
  assert.equal(collision.issue(A, 'devices', 20, point(9), point(5)), first);
  assert.throws(() => collision.issue(A, 'devices', 20, point(9), point(4)), error => error.code === 'INTERNAL');
  assert.equal(collision.resolve(first, A, 'devices').after.id, point(5).id);
  const store = new CursorStore(() => now, () => randomBytes(32), 3, 2);
  store.issue(A, 'devices', 20, point(9), point(5));
  store.issue(A, 'devices', 20, point(9), point(4));
  assert.throws(() => store.issue(A, 'devices', 20, point(9), point(3)), error => error.code === 'RATE_LIMITED' && error.headers['Retry-After'] === '600');
  const other = store.issue(B, 'devices', 20, point(9), point(5));
  assert.throws(() => store.issue(B, 'devices', 20, point(9), point(4)), error => error.code === 'RATE_LIMITED');
  assert.ok(store.resolve(other, B, 'devices'));
  now = 600000; assert.equal(store.size, 0);
  store.issue(A, 'devices', 20, point(9), point(5));
  assert.throws(() => new CursorStore(Date.now, () => { throw new Error(); }).issue(A, 'devices', 20, point(9), point(5)));
});
test('H-11: bucket rellena, memoria y caducidad acotadas', () => {
  let now = 0;
  const limits = new RateLimits(() => now, 2);
  limits.consume('A', 1); assert.throws(() => limits.consume('A', 1), error => error.status === 429);
  limits.consume('B', 1); assert.throws(() => limits.consume('C', 1));
  now = 60000; limits.consume('A', 1);
  now = 180001; limits.consume('C', 1); assert.equal(limits.size, 1);
});
test('K10-01/02: recorrido completo con empates/microsegundos y tamaños 1/20/100', async t => {
  for (const limit of [1, 20, 100]) {
    const app = await application(t);
    const total = limit === 1 ? 5 : limit * 2 + 3;
    app.state.devices = Array.from({ length: total }, (_, i) => device(i + 1, A,
      i % 2 ? '2026-10-27T12:00:00.000002Z' : '2026-10-27T12:00:00.000001Z'));
    app.state.devices.push(device(9000, B));
    const expected = app.state.devices.filter(row => row.user_id === A).toSorted((a, b) => b.created_at.localeCompare(a.created_at) || b.id.localeCompare(a.id)).map(row => row.id);
    const collected = [];
    let cursor;
    do {
      const reply = await app.request('/v1/devices?' + new URLSearchParams(cursor ? { cursor } : { limit: String(limit) }));
      assert.equal(reply.status, 200);
      collected.push(...reply.data.items.map(row => row.deviceId));
      assert.ok(reply.data.items.every(row => !('installation_id' in row) && !('user_id' in row)));
      cursor = reply.data.nextCursor;
    } while (cursor);
    assert.deepEqual(collected, expected);
    assert.equal(new Set(collected).size, total);
  }
});
test('K10-03/04/05/10/13: cursor alterado/ajeno/cambio de límite, autenticación primero y reintento concurrente', async t => {
  const app = await application(t);
  app.state.devices = [device(1), device(2), device(3), device(4)];
  const first = await app.request('/v1/devices?limit=1');
  const cursor = first.data.nextCursor;
  const url = '/v1/devices?cursor=' + cursor;
  assert.equal((await app.request(url, { auth: null })).status, 401);
  assert.equal((await app.request(url, { auth: token({ sub: B }) })).data.error.code, 'INVALID_CURSOR');
  assert.equal((await app.request(url + '&limit=2')).data.error.code, 'INVALID_CURSOR');
  assert.equal((await app.request(url + '&sort=asc')).status, 400);
  const altered = 'c1.' + Buffer.from('f'.repeat(32)).toString('base64url');
  assert.equal((await app.request('/v1/devices?cursor=' + altered)).data.error.code, 'INVALID_CURSOR');
  for (const value of ['', 'c2.invalido', 'c1.' + 'A'.repeat(44)]) {
    assert.equal((await app.request('/v1/devices?cursor=' + value)).data.error.code, 'INVALID_CURSOR');
  }
  const [one, two] = await Promise.all([app.request(url), app.request(url)]);
  assert.deepEqual(one.data, two.data);
  assert.equal(JSON.stringify(app.logs).includes(cursor), false);
});
test('K10-07/08/09: nueva fila superior, borrado del ancla e inserción retrodatada', async t => {
  const app = await application(t);
  app.state.devices = [device(1), device(2), device(3), device(4)];
  const first = await app.request('/v1/devices?limit=2');
  const anchor = first.data.items.at(-1).deviceId;
  app.state.devices = app.state.devices.filter(row => row.id !== anchor);
  app.state.devices.push(device(9000, A, '2026-10-28T12:00:00.000001Z'));
  app.state.devices.push(device(9001, A, '2026-10-26T12:00:00.000001Z'));
  const second = await app.request('/v1/devices?cursor=' + first.data.nextCursor);
  assert.equal(second.status, 200);
  assert.deepEqual(second.data.items.map(row => row.deviceId), [device(2).id, device(1).id]);
  const third = await app.request('/v1/devices?cursor=' + second.data.nextCursor);
  assert.deepEqual(third.data.items.map(row => row.deviceId), [device(9001).id]);
  assert.equal(third.data.nextCursor, null);
});
test('K10-11/14: tope oculto/upstream fallido/filas ajenas no producen fin falso o avance', async t => {
  const app = await application(t);
  app.state.devices = Array.from({ length: 5 }, (_, i) => device(i + 1));
  app.state.truncate = 1;
  assert.equal((await app.request('/v1/devices?limit=2')).status, 503);
  app.state.truncate = undefined;
  const first = await app.request('/v1/devices?limit=2');
  app.state.failure = () => jsonReply({ code: 'XX000' }, 500);
  assert.equal((await app.request('/v1/devices?cursor=' + first.data.nextCursor)).status, 503);
  app.state.failure = undefined;
  const repeated = await app.request('/v1/devices?cursor=' + first.data.nextCursor);
  assert.deepEqual(repeated.data.items.map(row => row.deviceId), [device(3).id, device(2).id]);
  app.state.failure = () => jsonReply({ code: '42501' }, 403);
  assert.equal((await app.request('/v1/devices?cursor=' + first.data.nextCursor)).status, 403);
  app.state.failure = call => call.table === 'devices' ? jsonReply([device(8, B)], 200, 1) : undefined;
  assert.equal((await app.request('/v1/devices')).status, 503);
});
