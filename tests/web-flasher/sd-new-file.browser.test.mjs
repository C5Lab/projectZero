import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

// The page's real SD handlers run in Chrome; only serial device I/O is fake.
const pageSource = await readFile(new URL('../../docs/janos_flash.html', import.meta.url), 'utf8');
const meterSource = await readFile(new URL('../../docs/sd-transfer-stats.mjs', import.meta.url), 'utf8');
const sdFilesSource = await readFile(new URL('../../docs/sd-files.mjs', import.meta.url), 'utf8');
const textSource = await readFile(new URL('../../docs/sd-text.mjs', import.meta.url), 'utf8');
const section = (start, end) => {
  const from = pageSource.indexOf(start);
  const to = pageSource.indexOf(end, from + start.length);
  assert.ok(from >= 0 && to > from, `Missing page section: ${start}`);
  return pageSource.slice(from, to);
};
const heading = pageSource.indexOf('<h2>SD file manager</h2>');
const cardStart = pageSource.lastIndexOf('<details class="card disclosure" id="sdPanel">', heading);
const cardEnd = pageSource.indexOf('</details>', heading) + '</details>'.length;
assert.ok(heading >= 0 && cardStart >= 0 && cardEnd > heading, 'Missing SD manager markup');
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
    <script type="module">
      const missing = ['sdNewFileBtn', 'sdNewFile', 'sdNewFileName', 'sdNewFileContent',
        'sdCreateFileBtn', 'sdCancelNewFileBtn'].filter(id => !document.getElementById(id));
      const proof = document.createElement('pre'); proof.id = 'proof';
      if (missing.length) {
        proof.textContent = JSON.stringify({missing}); document.body.append(proof);
      } else {
        try {
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
          const calls = {uploads: [], lists: [], confirmations: []};
          window.confirm = message => { calls.confirmations.push(message); return true; };
          const data = new Map([['captures/existing.txt', new TextEncoder().encode('existing')]]);
          const client = {
            connected: true, canRemove: true, canCleanupPartial: true,
            async close() { this.connected = false; },
            async list(path) {
              calls.lists.push(path);
              return [...data].filter(([name]) => name.startsWith(path + '/')
                && !name.slice(path.length + 1).includes('/'))
                .map(([name, bytes]) => ({name: name.slice(path.length + 1), type: 'f', size: bytes.length}));
            },
            async upload(path, file, options = {}) {
              const bytes = new Uint8Array(await file.arrayBuffer());
              calls.uploads.push({path, bytes: [...bytes], replace: options.replace});
              if (data.has(path) && !options.replace) {
                throw Object.assign(new Error('exists'), {code: 'exists', fsRecoverable: true});
              }
              options.onProgress?.(bytes.length, bytes.length);
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
          const settle = () => new Promise(resolve => setTimeout(resolve, 40));
          const waitIdle = async () => {
            for (let attempt = 0; attempt < 100 && state.sdBusy; attempt++) await settle();
            await settle();
            if (state.sdBusy) throw new Error('SD action did not finish');
          };
          const fill = (element, value) => {
            element.value = value;
            element.dispatchEvent(new Event('input', {bubbles: true}));
            element.dispatchEvent(new Event('change', {bubbles: true}));
          };
          const result = await (${body})();
          proof.textContent = JSON.stringify(result);
        } catch (error) {
          proof.textContent = JSON.stringify({error: error.stack || String(error)});
        }
        document.body.append(proof);
      }
    </script>
  </body></html>`;
  const profile = await mkdtemp(join(tmpdir(), 'janos-sd-new-file-'));
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

test('new text file is created in the current SD folder without replace', async () => {
  const result = await runInChrome(`async () => {
    ui.sdNewFileBtn.click();
    fill(ui.sdNewFileName, 'notes-é.txt');
    fill(ui.sdNewFileContent, 'Zażółć 😀\\n');
    ui.sdCreateFileBtn.click();
    await waitIdle();
    return {uploads: calls.uploads, lists: calls.lists,
      created: data.has('captures/notes-é.txt'),
      content: new TextDecoder().decode(data.get('captures/notes-é.txt') || new Uint8Array()),
      item: state.sdItems.find(item => item.name === 'notes-é.txt'),
      status: ui.sdStatus.textContent};
  }`);
  assert.deepEqual(result.missing ?? [], [], 'New file controls must exist');
  assert.equal(result.created, true);
  assert.equal(result.content, 'Zażółć 😀\n');
  assert.equal(result.uploads.length, 1);
  assert.equal(result.uploads[0].path, 'captures/notes-é.txt');
  assert.equal(result.uploads[0].replace, false);
  assert.equal(result.item?.type, 'f');
  assert.ok(result.lists.length >= 2, 'Successful creation refreshes the folder');
  assert.equal(result.lists.at(-1), 'captures');
  assert.match(result.status, /created|saved|uploaded/i);
});

test('new file form accepts empty content and keeps the captured destination', async () => {
  const result = await runInChrome(`async () => {
    const initiallyDisabled = ui.sdNewFileBtn.disabled;
    ui.sdNewFileBtn.click();
    const capturedPath = ui.sdNewFilePath.textContent;
    const navigationLocked = ui.sdRootBtn.disabled && ui.sdBackBtn.disabled;
    fill(ui.sdNewFileName, 'empty.csv');
    fill(ui.sdNewFileContent, '');
    state.sdPath = 'changed-after-open';
    ui.sdCreateFileBtn.click();
    await waitIdle();
    return {initiallyDisabled, capturedPath, navigationLocked, uploads: calls.uploads,
      created: data.has('captures/empty.csv'), size: data.get('captures/empty.csv')?.length};
  }`);
  assert.deepEqual(result.missing ?? [], []);
  assert.equal(result.initiallyDisabled, false);
  assert.match(result.capturedPath, /\/sdcard\/lab\/captures/);
  assert.equal(result.navigationLocked, true);
  assert.equal(result.created, true);
  assert.equal(result.size, 0);
  assert.equal(result.uploads[0]?.path, 'captures/empty.csv');
  assert.equal(result.uploads[0]?.replace, false);
});

test('new file never replaces a listed name and keeps the draft on failure', async () => {
  const result = await runInChrome(`async () => {
    ui.sdNewFileBtn.click();
    fill(ui.sdNewFileName, 'existing.txt');
    fill(ui.sdNewFileContent, 'replacement');
    ui.sdCreateFileBtn.click();
    await waitIdle();
    return {uploads: calls.uploads, original: new TextDecoder().decode(data.get('captures/existing.txt')),
      name: ui.sdNewFileName.value, draft: ui.sdNewFileContent.value,
      formVisible: !ui.sdNewFile.hidden, status: ui.sdStatus.textContent};
  }`);
  assert.deepEqual(result.missing ?? [], []);
  assert.equal(result.original, 'existing');
  assert.ok(result.uploads.every(upload => upload.replace === false));
  assert.equal(result.name, 'existing.txt');
  assert.equal(result.draft, 'replacement');
  assert.equal(result.formVisible, true);
  assert.match(result.status, /exists|different name|choose another|already/i);
});

test('FS/1 exists race keeps the remote file and the local draft', async () => {
  const result = await runInChrome(`async () => {
    ui.sdNewFileBtn.click();
    fill(ui.sdNewFileName, 'race.txt');
    fill(ui.sdNewFileContent, 'my draft');
    data.set('captures/race.txt', new TextEncoder().encode('other writer'));
    ui.sdCreateFileBtn.click();
    await waitIdle();
    return {uploads: calls.uploads, remote: new TextDecoder().decode(data.get('captures/race.txt')),
      name: ui.sdNewFileName.value, draft: ui.sdNewFileContent.value,
      formVisible: !ui.sdNewFile.hidden, status: ui.sdStatus.textContent};
  }`);
  assert.deepEqual(result.missing ?? [], []);
  assert.equal(result.remote, 'other writer');
  assert.ok(result.uploads.every(upload => upload.replace === false));
  assert.equal(result.name, 'race.txt');
  assert.equal(result.draft, 'my draft');
  assert.equal(result.formVisible, true);
  assert.match(result.status, /exists|refresh/i);
});

test('invalid basename and oversized content never start an upload', async () => {
  const result = await runInChrome(`async () => {
    ui.sdNewFileBtn.click();
    const attempts = [
      ['subdir/file.txt', 'hello'],
      ['bad😀.txt', 'hello'],
      ['partial.fs-part', 'hello'],
      ['partial.fs-backup', 'hello'],
      ['PHOTO~1.TXT', 'hello'],
      ['trailing.', 'hello'],
      ['n'.repeat(170) + '.txt', 'hello'],
      ['large.txt', 'x'.repeat(128 * 1024 + 1)],
    ];
    const messages = [];
    for (const [name, content] of attempts) {
      fill(ui.sdNewFileName, name);
      fill(ui.sdNewFileContent, content);
      ui.sdCreateFileBtn.click();
      await waitIdle();
      messages.push(ui.sdStatus.textContent);
    }
    return {uploads: calls.uploads, messages, draft: ui.sdNewFileContent.value,
      formVisible: !ui.sdNewFile.hidden};
  }`);
  assert.deepEqual(result.missing ?? [], []);
  assert.deepEqual(result.uploads, []);
  assert.equal(result.messages.length, 8);
  assert.ok(result.messages.every(message => message.length > 0));
  assert.equal(result.draft.length, 128 * 1024 + 1);
  assert.equal(result.formVisible, true);
});

test('new file controls honor connection and editor locks; cancel closes without upload', async () => {
  const result = await runInChrome(`async () => {
    const ready = !ui.sdNewFileBtn.disabled;
    state.sdBusy = true; syncSdControls();
    const busyDisabled = ui.sdNewFileBtn.disabled;
    state.sdBusy = false; state.sdConnected = false; syncSdControls();
    const disconnectedDisabled = ui.sdNewFileBtn.disabled;
    state.sdConnected = true; state.sdViewer = {kind:'csv', path:'captures/existing.txt'};
    syncSdControls();
    const viewerDisabled = ui.sdNewFileBtn.disabled;
    state.sdViewer = null; syncSdControls();
    ui.sdNewFileBtn.click();
    fill(ui.sdNewFileName, 'draft.txt');
    fill(ui.sdNewFileContent, 'unsaved');
    await disconnectSd({preserveStatus: true});
    const afterDisconnect = {draft: ui.sdNewFileContent.value,
      name: ui.sdNewFileName.value, createDisabled: ui.sdCreateFileBtn.disabled,
      formVisible: !ui.sdNewFile.hidden};
    ui.sdCancelNewFileBtn.click();
    return {ready, busyDisabled, disconnectedDisabled, viewerDisabled,
      afterDisconnect, closed: ui.sdNewFile.hidden, uploads: calls.uploads};
  }`);
  assert.deepEqual(result.missing ?? [], []);
  assert.equal(result.ready, true);
  assert.equal(result.busyDisabled, true);
  assert.equal(result.disconnectedDisabled, true);
  assert.equal(result.viewerDisabled, true);
  assert.deepEqual(result.afterDisconnect, {
    draft: 'unsaved', name: 'draft.txt', createDisabled: true, formVisible: true,
  });
  assert.equal(result.closed, true);
  assert.deepEqual(result.uploads, []);
});

test('file chooser uses English page controls while keeping the native input hidden', async () => {
  const result = await runInChrome(`async () => {
    const choose = document.getElementById('sdChooseFileBtn');
    const selected = document.getElementById('sdSelectedFileName');
    if (!choose || !selected) return {missingChooser: true};
    const initial = {label: choose.textContent.trim(), selected: selected.textContent.trim(),
      inputHidden: ui.sdFileInput.hidden, chooseEnabled: !choose.disabled};
    let inputClicks = 0;
    ui.sdFileInput.addEventListener('click', event => { inputClicks++; event.preventDefault(); });
    choose.click();
    await settle();
    const selection = new DataTransfer();
    selection.items.add(new File(['name,age\\nAda,37\\n'], 'people.csv', {type:'text/csv'}));
    ui.sdFileInput.files = selection.files;
    ui.sdFileInput.dispatchEvent(new Event('change', {bubbles:true}));
    await settle();
    const afterSelection = {selected: selected.textContent.trim(), uploadEnabled: !ui.sdUploadBtn.disabled};
    state.sdBusy = true; syncSdControls();
    const busyDisabled = choose.disabled;
    state.sdBusy = false; state.sdConnected = false; syncSdControls();
    const disconnectedDisabled = choose.disabled;
    return {initial, inputClicks, afterSelection, busyDisabled, disconnectedDisabled};
  }`);
  assert.equal(result.missingChooser, undefined, 'English file chooser controls must exist');
  assert.deepEqual(result.initial, {
    label: 'Choose file', selected: 'No file selected', inputHidden: true, chooseEnabled: true,
  });
  assert.equal(result.inputClicks, 1, 'Choose file opens the underlying native picker');
  assert.deepEqual(result.afterSelection, {selected: 'people.csv', uploadEnabled: true});
  assert.equal(result.busyDisabled, true);
  assert.equal(result.disconnectedDisabled, true);
});
