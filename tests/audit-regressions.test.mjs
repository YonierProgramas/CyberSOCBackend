import assert from 'node:assert/strict';
import test from 'node:test';
import { acceptedDownloadUrl } from '../dist/release-url.js';
import { application, config, release } from './helpers.mjs';

const prefix = 'https://github.com/YonierProgramas/CyberSOC/releases/download/';
export const urlCases = [
  [prefix + 'v0.11.1/CyberSOC-Defender-0.11.1-windows-x64-setup.exe', true],
  [prefix + 'v1.0.0-rc.1+test/instalador-%C3%B1.exe', true],
  ...['tag/subfolder/setup.exe', 'tag/', '/setup.exe', '../tag/setup.exe',
    'tag/../setup.exe', 'tag/%2e%2e', 'tag/%2Fbad.exe', 'tag/%5cbad.exe',
    'tag/%252Fbad.exe', 'tag/%00bad.exe', 'tag/%C2%85bad.exe', 'tag/bad%20name.exe',
    'tag/bad%.exe', 'tag/setup.exe?next=evil', 'tag/setup.exe#x',
    'tag/a\\b.exe', 'tag/setup.exe?', 'tag/setup.exe#'].map(path => [prefix + path, false]),
  [prefix.replace('https:', 'http:') + 'tag/a.exe', false],
  [prefix.replace('github.com', 'github.com:443') + 'tag/a.exe', false],
  [prefix.replace('github.com', 'other.invalid') + 'tag/a.exe', false],
  [prefix.replace('CyberSOC/', 'Other/') + 'tag/a.exe', false],
];
test('AUD-08: URLs canónicas de releases, sin segmentos ambiguos', () => {
  for (const [url, valid] of urlCases) assert.equal(acceptedDownloadUrl(url), valid, url);
});
test('AUD-08: catálogo con URL inválida no ofrece latest ni registra descarga', async t => {
  const app = await application(t);
  const candidate = release();
  candidate.release_assets[0].download_url = prefix + 'tag/subfolder/setup.exe';
  app.state.releases = [candidate];
  assert.equal((await app.request('/v1/releases/latest?platform=windows-x64', { auth: null })).status, 503);
  assert.equal((await app.request('/v1/downloads', { method: 'POST', body: { platform: 'windows-x64' } })).status, 503);
  assert.equal(app.state.downloads.length, 0);
});
test('AUD-06: solo origen autorizado expone Retry-After, sin credenciales', async t => {
  const app = await application(t);
  const own = await app.request('/v1/me', { headers: { Origin: config.portalOrigin } });
  assert.equal(own.headers.get('access-control-expose-headers'), 'Retry-After');
  assert.equal(own.headers.get('access-control-allow-credentials'), null);
  const other = await app.request('/v1/me', { headers: { Origin: 'https://other.invalid' } });
  assert.equal(other.headers.get('access-control-expose-headers'), null);
  assert.equal(other.headers.get('access-control-allow-origin'), null);
});
test('AUD-07: cuota de negocio y salud independientes, ambas acotadas', async t => {
  const at = Date.now();
  const app = await application(t, undefined, { now: () => at });
  for (let i = 0; i < 60; i++) await app.request('/v1/releases/latest?platform=windows-x64', { auth: null });
  assert.equal((await app.request('/v1/releases/latest?platform=windows-x64', { auth: null })).status, 429);
  assert.equal((await app.request('/healthz')).status, 200);
  assert.equal((await app.request('/healthz', { method: 'HEAD' })).status, 200);
  for (let i = 0; i < 58; i++) assert.equal((await app.request('/healthz')).status, 200);
  assert.equal((await app.request('/healthz')).status, 429);
  assert.equal((await app.request('/v1/me', { headers: { 'X-Forwarded-For': '192.0.2.10' } })).status, 429);
});
