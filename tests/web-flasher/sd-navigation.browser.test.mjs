import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdtemp, realpath, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

// Run the page's actual connection transition, rendering and navigation in Chrome.
// Only device I/O is substituted; this test never opens a physical serial port.
test('SD listing opens a folder, deletes a file, and cleans a failed upload after confirmation', async t => {
  const source = await readFile(new URL('../../docs/janos_flash.html', import.meta.url), 'utf8');
  const section = (start, end) => {
    const from = source.indexOf(start);
    const to = source.indexOf(end, from + start.length);
    assert.ok(from >= 0 && to > from, `Missing page section: ${start}`);
    return source.slice(from, to);
  };
  const pageCode = [
    section('    const sdPathLabel =', '    const sdRate ='),
    section('    const syncSdControls =', '    const disconnectSd ='),
    section('    const connectSd =', '    const downloadSd ='),
  ].join('\n');
  const html = `<html><body><script type="module">
    const ui = Object.fromEntries(['sdConnectBtn','sdRefreshBtn','sdRootBtn','sdBackBtn',
      'sdFileInput','sdChooseFileBtn','sdSelectedFileName','sdUploadBtn',
      'sdNewFileBtn','sdNewFile','sdNewFilePath',
      'sdNewFileName','sdNewFileContent','sdCreateFileBtn','sdCancelNewFileBtn',
      'sdPath','connectBtn','monitorBtn','verifyBtn','sdList']
      .map(name => [name, document.body.appendChild(document.createElement(
        name === 'sdList' ? 'div' : name === 'sdNewFile' ? 'form'
          : name === 'sdNewFileName' ? 'input' : name === 'sdNewFileContent' ? 'textarea' : 'button'))]));
    const calls = [], removed = [], cleaned = [], confirmations = [];
    window.confirm = message => { confirmations.push(message); return confirmations.length % 2 === 0; };
    class SdFilesClient {
      async connect() { this.connected = true; this.canRemove = true; this.canCleanupPartial = false; }
      async list(path) {
        calls.push(path);
        return path === '' ? [{name:'captures',type:'d',size:0}]
          : !removed.length ? [{name:'proof.bin',type:'f',size:4}]
          : !cleaned.length ? [{name:'20260526_164710.jpg.fs-part',type:'f',size:3}] : [];
      }
      async remove(path) { removed.push(path); return {type:'f'}; }
      async cleanupPartial(path) { cleaned.push(path); return {type:'part'}; }
    }
    const state = {sdBusy:false,sdConnected:false,sdPath:'',sdItems:[],sdClient:null,
      sdNewFileOpen:false,sdNewFileFolder:''};
    Object.defineProperty(navigator, 'serial', {value:{requestPort:async () => ({addEventListener(){}})}});
    const ensureSupport = () => {};
    const setSdStatus = () => {};
    const disconnectSd = async () => {state.sdConnected=false;};
    const disconnectMonitor = async () => {};
    const disconnect = async () => {};
    const sdErrorText = error => error.message;
    const downloadSd = async () => {};
    ${pageCode}
    try {
      await connectSd();
      const initial = ui.sdList.querySelector('button');
      const initialDisabled = initial.disabled;
      initial.click();
      await new Promise(resolve => setTimeout(resolve, 0));
      const removeButton = [...ui.sdList.querySelectorAll('button')]
        .find(button => button.textContent === 'Delete');
      if (removeButton) removeButton.click();
      await new Promise(resolve => setTimeout(resolve, 0));
      const cancelDidNotRemove = removed.length === 0;
      if (removeButton) removeButton.click();
      await new Promise(resolve => setTimeout(resolve, 0));
      const stageDelete = [...ui.sdList.querySelectorAll('button')]
        .find(button => button.textContent === 'Delete');
      const stageDeleteDisabled = stageDelete?.disabled;
      const stageItem = state.sdItems[0];
      state.sdItems = [stageItem,
        {name:'20260526_164710.jpg.fs-backup',type:'f',size:4},
        {name:'PHOTO~1.JPG.fs-part',type:'f',size:4}];
      renderSdList();
      const rowFor = filename => [...ui.sdList.querySelectorAll('.sd-row')]
        .find(row => row.querySelector('.sd-name')?.textContent === filename);
      const backupRow = rowFor('20260526_164710.jpg.fs-backup');
      const backupDeleteDisabled = backupRow?.querySelector('.sd-delete')?.disabled;
      const backupCleanupAbsent = ![...backupRow.querySelectorAll('button')]
        .some(button => button.textContent === 'Clean failed upload');
      const aliasRow = rowFor('PHOTO~1.JPG.fs-part');
      const aliasDeleteDisabled = aliasRow?.querySelector('.sd-delete')?.disabled;
      const aliasCleanupDisabled = [...aliasRow.querySelectorAll('button')]
        .find(button => button.textContent === 'Clean failed upload')?.disabled;
      state.sdItems = [stageItem];
      renderSdList();
      const oldCleanup = [...ui.sdList.querySelectorAll('button')]
        .find(button => button.textContent === 'Clean failed upload');
      const cleanupDisabledWithoutCapability = oldCleanup?.disabled;
      state.sdClient.canCleanupPartial = true;
      state.sdItems = [stageItem, {name:'.fs-part',type:'f',size:4}];
      renderSdList();
      const barePartRow = [...ui.sdList.querySelectorAll('.sd-row')]
        .find(row => row.querySelector('.sd-name')?.textContent === '.fs-part');
      const barePartCleanupDisabled = [...barePartRow.querySelectorAll('button')]
        .find(button => button.textContent === 'Clean failed upload')?.disabled;
      state.sdItems = [stageItem];
      renderSdList();
      const cleanButton = [...ui.sdList.querySelectorAll('button')]
        .find(button => button.textContent === 'Clean failed upload');
      const cleanupEnabled = cleanButton && !cleanButton.disabled;
      if (cleanButton) cleanButton.click();
      await new Promise(resolve => setTimeout(resolve, 0));
      const cancelDidNotClean = cleaned.length === 0;
      if (cleanButton) cleanButton.click();
      await new Promise(resolve => setTimeout(resolve, 0));
      const result = {initialDisabled, calls, path:state.sdPath,
        removed, cleaned, confirmations, cancelDidNotRemove, removeVisible:!!removeButton,
        stageDeleteDisabled, backupDeleteDisabled, backupCleanupAbsent,
        aliasDeleteDisabled, aliasCleanupDisabled,
        cleanupDisabledWithoutCapability, barePartCleanupDisabled, cleanupEnabled, cancelDidNotClean,
        emptyAfterClean:ui.sdList.textContent.includes('This folder is empty.')};
      const proof = document.createElement('pre'); proof.id='proof';
      proof.textContent=JSON.stringify(result); document.body.append(proof);
    } catch(error) {
      const proof=document.createElement('pre'); proof.id='proof';
      proof.textContent=JSON.stringify({error:error.message}); document.body.append(proof);
    }
  </script></body></html>`;
  const temp = await mkdtemp(join(tmpdir(), 'janos-navigation-test-'));
  const page = join(temp, 'page.html');
  const profile = join(temp, 'chrome-profile');
  await writeFile(page, html, 'utf8');
  t.after(async () => {
    const root = await realpath(tmpdir());
    const target = await realpath(temp);
    assert.ok(target.startsWith(root + sep), 'Test cleanup must stay inside the temporary directory');
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
  const child = spawn('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', [
    '--headless=new','--disable-gpu','--disable-extensions','--no-first-run',
    `--user-data-dir=${profile}`,'--virtual-time-budget=1000','--dump-dom',
    pathToFileURL(page).href,
  ], { windowsHide:true, stdio:['ignore','pipe','pipe'] });
  let output='', errors='';
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', chunk => output += chunk);
  child.stderr.on('data', chunk => errors += chunk);
  const timeout = setTimeout(() => child.kill(), 20000);
  const exit = await new Promise((resolve,reject) => {
    child.on('error', reject); child.on('exit', resolve);
  }).finally(() => clearTimeout(timeout));
  assert.equal(exit, 0, errors);
  const raw = /<pre id="proof">([^<]*)<\/pre>/.exec(output)?.[1];
  assert.ok(raw, `Browser produced no proof: ${errors}`);
  const result = JSON.parse(raw.replaceAll('&quot;', '"').replaceAll('&amp;', '&'));
  assert.equal(result.error, undefined, JSON.stringify(result));
  assert.equal(result.initialDisabled, false, 'Initial Open must be enabled after connectSd completes');
  assert.equal(result.path, 'captures');
  assert.equal(result.removeVisible, true, 'Delete must appear for a file with rm capability');
  assert.equal(result.cancelDidNotRemove, true, 'Cancelling Delete must not send fs rm');
  assert.match(result.confirmations[0], /\/sdcard\/lab\/captures\/proof\.bin/);
  assert.deepEqual(result.removed, ['captures/proof.bin']);
  assert.equal(result.stageDeleteDisabled, true, 'Normal Delete stays disabled for .fs-part');
  assert.equal(result.backupDeleteDisabled, true, 'Normal Delete stays disabled for .fs-backup');
  assert.equal(result.backupCleanupAbsent, true, 'Backup is never offered cleanup');
  assert.equal(result.aliasDeleteDisabled, true, 'FAT aliases stay protected');
  assert.equal(result.aliasCleanupDisabled, true, 'FAT aliases cannot be cleaned');
  assert.equal(result.cleanupDisabledWithoutCapability, true, 'Old firmware cannot clean .fs-part');
  assert.equal(result.barePartCleanupDisabled, true, 'A bare .fs-part name has no target stem');
  assert.equal(result.cleanupEnabled, true, 'Cleanup is available with the advertised capability');
  assert.equal(result.cancelDidNotClean, true, 'Cancelling cleanup must not send a command');
  assert.equal(result.confirmations.length, 4);
  assert.match(result.confirmations[2], /\/sdcard\/lab\/captures\/20260526_164710\.jpg\.fs-part/);
  assert.deepEqual(result.cleaned, ['captures/20260526_164710.jpg.fs-part']);
  assert.deepEqual(result.calls, ['', 'captures', 'captures', 'captures']);
  assert.equal(result.emptyAfterClean, true);
});
