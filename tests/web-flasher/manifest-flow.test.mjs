import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

test('switching Main to Development discards the Main release and selects Development images', async () => {
  const html = await readFile(new URL('../../docs/janos_flash.html', import.meta.url), 'utf8');
  const moduleScript = /<script type="module">([\s\S]*?)<\/script>/.exec(html)?.[1];
  assert.ok(moduleScript, 'The docs flasher page must run its module script.');

  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: id === 'branchSelect' ? 'main' : '',
      textContent: '',
      innerHTML: '',
      style: {},
      classList: { add() {}, remove() {} },
      handlers: {},
      addEventListener(name, handler) { this.handlers[name] = handler; },
    });
    return elements.get(id);
  };
  const rawMain = 'https://raw.githubusercontent.com/C5Lab/projectZero/main/';
  const rawDevelopment = 'https://raw.githubusercontent.com/C5Lab/projectZero/development/';
  const mainManifest = {
    name: 'projectZero ESP32-C5', version: 'latest', build: 'main-build', chipFamily: 'ESP32-C5',
    parts: [
      { path: `${rawMain}ESP32C5/binaries-esp32c5/bootloader.bin`, offset: 8192 },
      { path: `${rawMain}ESP32C5/binaries-esp32c5/partition-table.bin`, offset: 32768 },
      { path: `${rawMain}ESP32C5/binaries-esp32c5/projectZero.bin`, offset: 131072 },
      { path: `${rawMain}ESP32C5/binaries-esp32c5/projectZero.bin`, offset: 4259840 },
    ],
  };
  const developmentManifest = {
    name: 'projectZero ESP32-C5', version: '1.7.5-dev', build: 'dev-build', chipFamily: 'ESP32-C5',
    parts: [
      { path: `${rawMain}ESP32C5/binaries-esp32c5/bootloader.bin`, offset: 8192 },
      { path: 'firmware/partition-table.bin', offset: 32768 },
      { path: 'firmware/projectZero.bin', offset: 131072 },
      { path: 'firmware/projectZero.bin', offset: 4259840 },
    ],
  };
  const calls = [];
  const fetch = async (input) => {
    const url = String(input);
    calls.push(url);
    if (url.startsWith('http://localhost:8765/docs/manifest.json?')) {
      return { ok: true, json: async () => mainManifest };
    }
    if (url === 'https://api.github.com/repos/C5Lab/projectZero/releases/latest') {
      return { ok: true, json: async () => ({
        tag_name: 'v1.7.5', name: 'JanOS v1.7.5', assets: [],
        html_url: 'https://github.com/C5Lab/projectZero/releases/tag/v1.7.5',
        published_at: '2026-10-24T00:00:00Z',
      }) };
    }
    if (url.startsWith(`${rawDevelopment}docs/manifest.json?`)) {
      return { ok: true, json: async () => developmentManifest };
    }
    throw new Error(`Unexpected manifest request: ${url}`);
  };
  const context = vm.createContext({
    document: { getElementById: element },
    window: { location: { href: 'http://localhost:8765/docs/janos_flash.html', search: '' }, addEventListener() {} },
    navigator: {}, fetch, URL, URLSearchParams, TextEncoder, Date,
    console, setTimeout, clearTimeout,
  });
  // Only external module imports are removed; the page's own manifest code runs unchanged.
  vm.runInContext(moduleScript.replace(/^\s*import\s+.*;\s*$/gm, '')
    + '\n globalThis.__flasher = { getState: () => state, resolveManifestPath };', context);

  const waitForManifest = async (branch) => {
    for (let turn = 0; turn < 20; turn++) {
      if (element('statusText').textContent === 'Manifest loaded.'
          && element('manifestText').textContent.endsWith(` - ${branch}`)) return;
      await new Promise((resolve) => setImmediate(resolve));
    }
    assert.fail(`Manifest did not load for ${branch}: ${element('statusText').textContent}`);
  };

  await waitForManifest('main');
  assert.equal(calls[0].split('?')[0], 'http://localhost:8765/docs/manifest.json');
  assert.equal(calls[1], 'https://api.github.com/repos/C5Lab/projectZero/releases/latest');
  assert.ok(element('releaseInfo').innerHTML.includes('latest v1.7.5'));

  element('branchSelect').value = 'development';
  element('branchSelect').handlers.change();
  await waitForManifest('development');
  assert.equal(calls[2].split('?')[0], `${rawDevelopment}docs/manifest.json`);
  assert.equal(calls.length, 3, 'Development must not fetch the latest Main release.');
  assert.equal(context.__flasher.getState().manifest.parts[0].path,
    `${rawDevelopment}ESP32C5/binaries-esp32c5/bootloader.bin`);
  assert.equal(context.__flasher.resolveManifestPath('firmware/projectZero.bin'),
    `${rawDevelopment}ESP32C5/binaries-esp32c5/projectZero.bin`);
  assert.equal(context.__flasher.getState().latestRelease, null,
    'Development must not retain Main release metadata.');
  assert.ok(!element('releaseInfo').innerHTML.includes('latest v1.7.5'));
});
