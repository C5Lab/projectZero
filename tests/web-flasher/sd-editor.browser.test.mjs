import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

// Exercise the page's own SD handlers and DOM in Chrome. Only FS/1 client I/O is fake.
const pageSource = await readFile(new URL('../../docs/janos_flash.html', import.meta.url), 'utf8');
const meterSource = await readFile(new URL('../../docs/sd-transfer-stats.mjs', import.meta.url), 'utf8');
const sdFilesSource = await readFile(new URL('../../docs/sd-files.mjs', import.meta.url), 'utf8');
const textSource = await readFile(new URL('../../docs/sd-text.mjs', import.meta.url), 'utf8')
  .catch(error => {
    if (error.code === 'ENOENT') return ''; // The action test is RED before the helper exists.
    throw error;
  });
const section = (start, end) => {
  const from = pageSource.indexOf(start);
  const to = pageSource.indexOf(end, from + start.length);
  assert.ok(from >= 0 && to > from, `Missing page section: ${start}`);
  return pageSource.slice(from, to);
};
const heading = pageSource.indexOf('<h2>SD file manager</h2>');
const cardStart = pageSource.lastIndexOf('<details class="card disclosure" id="sdPanel">', heading);
const cardEnd = pageSource.indexOf('</details>', heading) + '</details>'.length;
assert.ok(heading >= 0 && cardStart >= 0 && cardEnd > heading, 'Missing SD card markup');
const sdMarkup = pageSource.slice(cardStart, cardEnd);
const pageCode = [
  section('    const ui = {', '    const state = {'),
  section('    const state = {', '    const PAGE_VERSION ='),
  section('    const TXT_EDIT_MAX_BYTES =', '    const monitorEncoder ='),
  section('    const setSdStatus =', '    ui.connectBtn.addEventListener'),
  section('    ui.sdConnectBtn.addEventListener', '    ui.branch.addEventListener'),
].join('\n');

async function runInChrome(body) {
  const html = `<html><body>
    ${sdMarkup}
    <button id="connectBtn"></button><button id="monitorBtn"></button><button id="verifyBtn"></button>
    <script>
      const reportPageError = message => {
        const proof = document.createElement('pre');
        proof.id = 'proof';
        proof.textContent = JSON.stringify({error: String(message)});
        document.body.append(proof);
      };
      window.addEventListener('error', event => reportPageError(event.message));
      window.addEventListener('unhandledrejection', event => reportPageError(event.reason));
    </script>
    <script type="module">
      ${meterSource.replace('export class TransferMeter', 'class TransferMeter')}
      const encodePath = (() => {
        ${sdFilesSource.replace(/^export /gm, '')}
        return encodePath;
      })();
      ${textSource.replace(/^export /gm, '')}
      const ensureSupport = () => {};
      class SdFilesClient { constructor() { return client; } }
      document.getElementById('sdPanel').open = true;
      ${pageCode}
      const calls = { downloads: [], uploads: [], lists: [], confirmations: [], events: [], requestPorts: 0 };
      window.confirm = message => { calls.confirmations.push(message); return true; };
      const port = {addEventListener() {}, removeEventListener() {}};
      Object.defineProperty(navigator, 'serial', {configurable: true, value: {
        requestPort: async () => { calls.requestPorts++; return port; },
      }});
      // Relative path is 167 bytes: Base64 is 224 chars. GET fits the CLI,
      // while PUT at the 128 KiB editor limit with " replace" is 255 chars.
      const longTxtName = 'n'.repeat(154) + '.txt';
      const data = new Map([
        ['captures/notes.txt', new TextEncoder().encode('original note\\n')],
        ['captures/table.csv', new TextEncoder().encode('name,comment\\n"Rossi, A.","<img src=x onerror=window.hacked=1> and ""quoted""\\nline 2"\\n')],
        ['captures/archive.bin', new Uint8Array([1, 2])],
        ['captures/huge.txt', new Uint8Array(0)],
        ['captures/bad.txt', new Uint8Array([0x62, 0x61, 0x64])],
      ]);
      data.set('captures/' + longTxtName, new TextEncoder().encode('tiny'));
      const listedSize = name => name === 'captures/huge.txt' ? 128 * 1024 * 1024 : data.get(name).length;
      const client = {
        connected: true, canRemove: true,
        async connect() { this.connected = true; },
        async close() { this.connected = false; },
        async list(path) {
          calls.lists.push(path);
          return [...data].filter(([name]) => name.startsWith(path + '/') && !name.slice(path.length + 1).includes('/'))
            .map(([name]) => ({name: name.slice(path.length + 1), type: 'f', size: listedSize(name)}));
        },
        async download(path, options = {}) {
          calls.downloads.push(path);
          calls.events.push('download ' + path);
          if (path === 'captures/bad.txt') throw new Error('Simulated FS/1 read failure');
          const bytes = data.get(path).slice();
          options.onProgress?.(bytes.length, bytes.length);
          return bytes;
        },
        async upload(path, file, options) {
          calls.events.push('upload ' + path);
          const bytes = new Uint8Array(await file.arrayBuffer());
          calls.uploads.push({path, text: new TextDecoder().decode(bytes), replace: options?.replace});
          if (data.has(path) && !options?.replace) throw new Error('FS/1 exists');
          options?.onProgress?.(bytes.length, bytes.length);
          data.set(path, bytes);
          return {size: bytes.length, backupPending: false};
        },
      };
      state.sdPath = 'captures';
      state.sdClient = client;
      state.sdConnected = true;
      state.sdItems = await client.list(state.sdPath);
      syncSdControls();
      renderSdList();
      const row = name => [...ui.sdList.querySelectorAll('.sd-row')]
        .find(element => element.querySelector('.sd-name')?.textContent === name);
      const action = (name, label) => [...(row(name)?.querySelectorAll('button') || [])]
        .find(button => button.textContent.trim() === label);
      const settle = () => new Promise(resolve => setTimeout(resolve, 30));
      const waitIdle = async () => {
        for (let attempt = 0; attempt < 100 && state.sdBusy; attempt++) await settle();
        if (state.sdBusy) throw new Error('SD action did not finish in the browser test');
      };
      const remoteText = name => new TextDecoder().decode(data.get('captures/' + name));
      const proof = document.createElement('pre');
      proof.id = 'proof';
      try {
        const result = await (${body})();
        proof.textContent = JSON.stringify(result);
      } catch (error) {
        proof.textContent = JSON.stringify({error: error.stack || String(error)});
      }
      document.body.append(proof);
    </script>
  </body></html>`;
  const profile = await mkdtemp(join(tmpdir(), 'janos-sd-editor-'));
  const page = join(profile, 'page.html');
  await writeFile(page, html);
  const child = spawn('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', [
    '--headless=new', '--disable-gpu', '--disable-extensions', '--no-first-run',
    `--user-data-dir=${profile}`, '--virtual-time-budget=5000', '--dump-dom',
    pathToFileURL(page).href,
  ], {windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']});
  let output = '', errors = '';
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', chunk => output += chunk);
  child.stderr.on('data', chunk => errors += chunk);
  const timeout = setTimeout(() => child.kill(), 20000);
  const exit = await new Promise((done, fail) => {
    child.on('error', fail); child.on('exit', done);
  }).finally(() => clearTimeout(timeout));
  if (resolve(profile).startsWith(resolve(tmpdir()) + sep)) {
    await rm(profile, {recursive: true, force: true, maxRetries: 3});
  }
  assert.equal(exit, 0, errors);
  const raw = /<pre id="proof">([^<]*)<\/pre>/.exec(output)?.[1];
  assert.ok(raw, `Browser produced no proof: ${errors}`);
  const result = JSON.parse(raw.replaceAll('&quot;', '"').replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>').replaceAll('&amp;', '&'));
  assert.equal(result.error, undefined, result.error);
  return result;
}

test('TXT files offer Edit and CSV files offer Preview', async () => {
  const result = await runInChrome(`async () => ({
    edit: !!action('notes.txt', 'Edit'),
    preview: !!action('table.csv', 'Preview'),
    binaryEdit: !!action('archive.bin', 'Edit'),
  })`);
  assert.equal(result.edit, true, 'TXT row needs an Edit action');
  assert.equal(result.preview, true, 'CSV row needs a Preview action');
  assert.equal(result.binaryEdit, false, 'Binary row must not offer a text editor');
});

test('TXT Edit is disabled when the worst-case replace command exceeds the CLI limit', async () => {
  const result = await runInChrome(`async () => {
    const edit = action(longTxtName, 'Edit');
    const download = action(longTxtName, 'Download');
    edit?.click();
    await settle();
    return {encodedLength: encodePath('captures/' + longTxtName).length,
      editPresent: !!edit, editDisabled: edit?.disabled, title: edit?.title,
      downloadDisabled: download?.disabled, downloads: calls.downloads, uploads: calls.uploads};
  }`);
  assert.equal(result.encodedLength, 224);
  assert.equal(result.editPresent, true);
  assert.equal(result.editDisabled, true, 'The editor cannot promise a save that exceeds the CLI command limit');
  assert.match(result.title, /path|name|command|long|limit/i);
  assert.equal(result.downloadDisabled, false, 'The shorter GET command is still allowed');
  assert.deepEqual(result.downloads, []);
  assert.deepEqual(result.uploads, []);
});

test('editing stays local until Save to SD and Save uses replace for the same path', async () => {
  const result = await runInChrome(`async () => {
    action('notes.txt', 'Edit')?.click();
    await settle();
    const opened = ui.sdTextEditor?.value;
    ui.sdTextEditor.value = 'revised note\\n';
    ui.sdTextEditor.dispatchEvent(new Event('input', {bubbles: true}));
    await settle();
    const beforeSave = {remote: remoteText('notes.txt'), uploads: calls.uploads.length};
    ui.sdSaveBtn.click();
    await waitIdle();
    return {opened, beforeSave, remoteAfter: remoteText('notes.txt'), uploads: calls.uploads,
      downloads: calls.downloads, events: calls.events, status: ui.sdStatus.textContent,
      saveDisabled: ui.sdSaveBtn.disabled, viewerKind: state.sdViewer?.kind};
  }`);
  assert.equal(result.opened, 'original note\n');
  assert.deepEqual(result.beforeSave, {remote: 'original note\n', uploads: 0});
  assert.deepEqual(result.uploads, [{path: 'captures/notes.txt', text: 'revised note\n', replace: true}],
    JSON.stringify(result));
  assert.deepEqual(result.events, [
    'download captures/notes.txt', 'download captures/notes.txt', 'upload captures/notes.txt',
  ], 'Save must re-read the remote file before replace');
  assert.equal(result.remoteAfter, 'revised note\n');
});

test('Save refuses to replace a TXT file changed on SD after opening', async () => {
  const result = await runInChrome(`async () => {
    action('notes.txt', 'Edit')?.click();
    await settle();
    ui.sdTextEditor.value = 'my edit';
    ui.sdTextEditor.dispatchEvent(new Event('input', {bubbles: true}));
    data.set('captures/notes.txt', new TextEncoder().encode('external change'));
    ui.sdSaveBtn.click();
    await waitIdle();
    return {events: calls.events, uploads: calls.uploads,
      remote: remoteText('notes.txt'), local: ui.sdTextEditor.value,
      status: ui.sdStatus.textContent};
  }`);
  assert.deepEqual(result.events, ['download captures/notes.txt', 'download captures/notes.txt']);
  assert.deepEqual(result.uploads, []);
  assert.equal(result.remote, 'external change');
  assert.equal(result.local, 'my edit');
  assert.match(result.status, /changed|reopen|refresh/i);
});

test('a dirty TXT draft survives disconnect and can be saved after reconnect', async () => {
  const result = await runInChrome(`async () => {
    action('notes.txt', 'Edit')?.click();
    await settle();
    ui.sdTextEditor.value = 'draft after reconnect\\n';
    ui.sdTextEditor.dispatchEvent(new Event('input', {bubbles: true}));
    await disconnectSd({preserveStatus: true});
    const disconnected = {draft: ui.sdTextEditor.value, connectEnabled: !ui.sdConnectBtn.disabled,
      remote: remoteText('notes.txt'), uploads: calls.uploads.length};
    ui.sdConnectBtn.click();
    await waitIdle();
    const reconnected = {connected: state.sdConnected, draft: ui.sdTextEditor.value,
      remote: remoteText('notes.txt'), requestPorts: calls.requestPorts};
    ui.sdSaveBtn.click();
    await waitIdle();
    return {disconnected, reconnected, events: calls.events, uploads: calls.uploads,
      remoteAfter: remoteText('notes.txt')};
  }`);
  assert.deepEqual(result.disconnected, {
    draft: 'draft after reconnect\n', connectEnabled: true,
    remote: 'original note\n', uploads: 0,
  });
  assert.deepEqual(result.reconnected, {
    connected: true, draft: 'draft after reconnect\n',
    remote: 'original note\n', requestPorts: 1,
  });
  assert.deepEqual(result.events, [
    'download captures/notes.txt', 'download captures/notes.txt', 'upload captures/notes.txt',
  ]);
  assert.deepEqual(result.uploads, [
    {path: 'captures/notes.txt', text: 'draft after reconnect\n', replace: true},
  ]);
  assert.equal(result.remoteAfter, 'draft after reconnect\n');
});

test('closing a dirty TXT editor discards the change without an upload', async () => {
  const result = await runInChrome(`async () => {
    action('notes.txt', 'Edit')?.click();
    await settle();
    ui.sdTextEditor.value = 'discard me';
    ui.sdTextEditor.dispatchEvent(new Event('input', {bubbles: true}));
    ui.sdViewerCloseBtn.click();
    await settle();
    action('notes.txt', 'Edit')?.click();
    await settle();
    return {uploads: calls.uploads, remote: remoteText('notes.txt'), reopened: ui.sdTextEditor.value,
      confirmations: calls.confirmations};
  }`);
  assert.deepEqual(result.uploads, []);
  assert.equal(result.remote, 'original note\n');
  assert.equal(result.reopened, 'original note\n');
  assert.ok(result.confirmations.some(text => /unsaved|discard|changes/i.test(text)),
    'Closing a dirty editor should ask before discarding');
});

test('CSV Preview parses quoted fields and renders untrusted cells as text', async () => {
  const result = await runInChrome(`async () => {
    action('table.csv', 'Preview')?.click();
    await settle();
    return {downloads: calls.downloads, uploads: calls.uploads,
      cells: [...(ui.sdCsvTable?.querySelectorAll('th,td') || [])].map(cell => cell.textContent),
      imageCount: ui.sdCsvTable?.querySelectorAll('img').length,
      scriptRan: !!window.hacked};
  }`);
  assert.deepEqual(result.downloads, ['captures/table.csv']);
  assert.deepEqual(result.uploads, []);
  assert.ok(result.cells.includes('Rossi, A.'), 'Quoted comma must stay in one cell');
  assert.ok(result.cells.includes('<img src=x onerror=window.hacked=1> and "quoted"\nline 2'),
    'Quoted HTML and newline must stay in one text cell');
  assert.equal(result.imageCount, 0);
  assert.equal(result.scriptRan, false);
});

test('oversized TXT and FS/1 download errors do not open an editable file', async () => {
  const result = await runInChrome(`async () => {
    const huge = action('huge.txt', 'Edit');
    if (huge && !huge.disabled) huge.click();
    await settle();
    const afterHuge = {downloaded: calls.downloads.includes('captures/huge.txt'),
      reason: [huge?.title, ui.sdStatus.textContent, ui.sdViewerNotice?.textContent].join(' ')};
    action('bad.txt', 'Edit')?.click();
    await settle();
    return {afterHuge, badDownloaded: calls.downloads.includes('captures/bad.txt'),
      status: [ui.sdStatus.textContent, ui.sdViewerNotice?.textContent].join(' '),
      uploads: calls.uploads};
  }`);
  assert.equal(result.afterHuge.downloaded, false, 'Oversized file must be rejected before transfer');
  assert.match(result.afterHuge.reason, /size|large|limit/i);
  assert.equal(result.badDownloaded, true);
  assert.match(result.status, /failed|failure|error/i);
  assert.deepEqual(result.uploads, []);
});
