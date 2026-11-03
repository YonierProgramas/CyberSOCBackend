import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync, readdirSync } from 'node:fs';
import { API_ROUTES } from '../dist/server.js';
import { PUBLIC_PLATFORMS } from '../dist/schemas.js';
import { application, config } from './helpers.mjs';

const spec = JSON.parse(readFileSync(new URL('../openapi/v1.yaml', import.meta.url), 'utf8'));
test('OpenAPI 3.1: rutas/métodos reales, Bearer privado y preflight público', () => {
  assert.equal(spec.openapi, '3.1.0');
  assert.deepEqual(Object.keys(spec.paths).sort(), API_ROUTES.map(route => route.path).sort());
  // Set de IDs: invariante de unicidad; buscar/insertar O(1) esperado, total O(R).
  const ids = new Set();
  for (const route of API_ROUTES) {
    const item = spec.paths[route.path];
    assert.deepEqual(Object.keys(item).sort(), [...route.methods.map(method => method.toLowerCase()), 'options'].sort());
    for (const [method, operation] of Object.entries(item)) {
      assert.ok(!ids.has(operation.operationId)); ids.add(operation.operationId);
      assert.deepEqual(operation.security, route.private && method !== 'options' ? [{ bearerAuth: [] }] : []);
      for (const variable of [...route.path.matchAll(/\{([^}]+)\}/g)].map(match => match[1])) {
        assert.ok(operation.parameters.some(parameter => parameter.name === variable && parameter.in === 'path' && parameter.required));
      }
    }
  }
});
test('OpenAPI: referencias locales resolubles y límites/forma estrictos', () => {
  function check(value) {
    if (!value || typeof value !== 'object') return;
    if ('$ref' in value) {
      assert.ok(value.$ref.startsWith('#/'));
      const target = value.$ref.slice(2).split('/').reduce((current, key) => current?.[key], spec);
      assert.ok(target);
    }
    for (const child of Object.values(value)) check(child);
  }
  check(spec);
  assert.equal(spec.components.schemas.ProfileInput.additionalProperties, false);
  assert.equal(spec.components.schemas.PreferencePatch.minProperties, 1);
  assert.equal(spec.components.schemas.ConsentInput.oneOf[1].required.includes('policyVersion'), false);
  assert.deepEqual(spec.components.schemas.DownloadInput.properties.platform.enum, PUBLIC_PLATFORMS);
  assert.equal(spec['x-limits'].upstreamTimeoutMs, 5000);
  assert.equal(spec['x-limits'].cursorsGlobal, 10000);
});
test('Respuestas HTTP corresponden a claves requeridas del OpenAPI sin campos extra', async t => {
  const app = await application(t);
  function check(value, schema) {
    if (schema.$ref) schema = schema.$ref.slice(2).split('/').reduce((current, key) => current[key], spec);
    if (schema.type === 'object') {
      for (const key of schema.required ?? []) assert.ok(Object.hasOwn(value, key), key);
      if (schema.additionalProperties === false) assert.ok(Object.keys(value).every(key => Object.hasOwn(schema.properties, key)));
      for (const [key, child] of Object.entries(schema.properties)) if (Object.hasOwn(value, key)) check(value[key], child);
    }
    if (schema.type === 'array') for (const item of value) check(item, schema.items);
  }
  for (const [path, url] of [['/healthz', '/healthz'], ['/v1/me', '/v1/me'], ['/v1/me/consents', '/v1/me/consents'], ['/v1/devices', '/v1/devices']]) {
    const reply = await app.request(url);
    assert.equal(reply.status, 200);
    check(reply.data, spec.paths[path].get.responses[200].content['application/json'].schema);
  }
});
test('Build sin material de clave privilegiada/JWT fijo ni dependencias directas fuera de autorización', () => {
  for (const name of readdirSync(new URL('../dist/', import.meta.url))) {
    if (!name.endsWith('.js')) continue;
    const content = readFileSync(new URL('../dist/' + name, import.meta.url), 'utf8');
    assert.equal(/sb_secret_[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/.test(content), false, name);
  }
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.deepEqual(pkg.dependencies, { zod: '4.6.7' });
  assert.deepEqual(pkg.devDependencies, { '@types/node': '24.19.0', typescript: '5.9.3' });
  assert.ok(!JSON.stringify(config).includes('sb_secret_'));
});
