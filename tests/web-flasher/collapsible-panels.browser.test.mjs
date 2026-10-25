import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, realpath, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const chrome = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';

async function until(callback, label) {
  const deadline = Date.now() + 12000;
  while (Date.now() < deadline) {
    try {
      const value = await callback();
      if (value) return value;
    } catch (error) {
      if (Date.now() >= deadline) throw error;
    }
    await delay(50);
  }
  throw new Error(`Timed out waiting for ${label}.`);
}

async function attachDebugger(profile, pageUrl) {
  const port = await until(async () => {
    const active = await readFile(join(profile, 'DevToolsActivePort'), 'utf8');
    return Number(active.split(/\r?\n/)[0]) || null;
  }, 'Chrome debugger');
  const target = await until(async () => {
    const response = await fetch(`http://127.0.0.1:${port}/json/list`);
    const pages = await response.json();
    return pages.find(page => page.type === 'page' && page.url === pageUrl);
  }, 'test page');
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  let nextId = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (!message.id) return;
    const job = pending.get(message.id);
    if (!job) return;
    pending.delete(message.id);
    if (message.error) job.reject(new Error(message.error.message));
    else job.resolve(message.result);
  });
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  return { socket, send };
}

test('Serial monitor and SD file panels collapse and open by mouse and keyboard', async t => {
  const source = await readFile(new URL('../../docs/janos_flash.html', import.meta.url), 'utf8');
  // This tests the real markup and CSS. Remove app scripts so the test has no
  // network dependency and cannot open a real serial port.
  const markup = source.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
  const temp = await mkdtemp(join(tmpdir(), 'janos-panels-test-'));
  const page = join(temp, 'page.html');
  const profile = join(temp, 'chrome-profile');
  await writeFile(page, markup, 'utf8');
  const url = pathToFileURL(page).href;
  const child = spawn(chrome, [
    '--headless=new', '--disable-gpu', '--disable-extensions', '--no-first-run',
    '--remote-debugging-port=0', `--user-data-dir=${profile}`, url,
  ], { windowsHide: true, stdio: 'ignore' });
  t.after(async () => {
    child.kill();
    const root = await realpath(tmpdir());
    const target = await realpath(temp);
    assert.ok(target.startsWith(root + sep), 'Test cleanup must stay inside the temporary directory');
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const { socket, send } = await attachDebugger(profile, url);
  t.after(() => socket.close());
  const evaluate = async expression => {
    const response = await send('Runtime.evaluate', { expression, returnByValue: true });
    if (response.exceptionDetails) throw new Error(response.exceptionDetails.text);
    return response.result.value;
  };
  // The debugger target appears before Chrome finishes parsing the page.
  await until(async () => await evaluate("document.readyState === 'complete'"), 'panel page load');
  const state = () => evaluate(`(() => {
    const monitor = document.getElementById('monitorPanel');
    const sd = document.getElementById('sdPanel');
    return {
      monitorTag: monitor?.tagName, sdTag: sd?.tagName,
      monitorOpen: monitor?.open, sdOpen: sd?.open,
      monitorSummary: monitor?.querySelector(':scope > summary')?.tagName,
      sdSummary: sd?.querySelector(':scope > summary')?.tagName,
      monitorVisible: document.getElementById('monitorBtn')?.checkVisibility({ contentVisibilityAuto: true, visibilityProperty: true }),
      sdVisible: document.getElementById('sdConnectBtn')?.checkVisibility({ contentVisibilityAuto: true, visibilityProperty: true }),
      monitorAncestor: document.getElementById('monitorBtn')?.closest('details')?.id,
      sdAncestor: document.getElementById('sdConnectBtn')?.closest('details')?.id,
      monitorButtonPresent: !!document.getElementById('monitorBtn'),
      sdButtonPresent: !!document.getElementById('sdConnectBtn'),
    };
  })()`);

  const initial = await state();
  assert.equal(initial.monitorTag, 'DETAILS');
  assert.equal(initial.sdTag, 'DETAILS');
  assert.equal(initial.monitorSummary, 'SUMMARY');
  assert.equal(initial.sdSummary, 'SUMMARY');
  assert.equal(initial.monitorAncestor, 'monitorPanel');
  assert.equal(initial.sdAncestor, 'sdPanel');
  assert.equal(initial.monitorOpen, false);
  assert.equal(initial.sdOpen, false);
  assert.equal(initial.monitorVisible, false);
  assert.equal(initial.sdVisible, false);
  assert.equal(initial.monitorButtonPresent, true);
  assert.equal(initial.sdButtonPresent, true);

  const expectState = (matches, label) => until(async () => {
    const current = await state();
    return Object.entries(matches).every(([key, value]) => current[key] === value) ? current : null;
  }, label);

  await evaluate("document.querySelector('#monitorPanel > summary').click()");
  await expectState({ monitorOpen: true, monitorVisible: true }, 'monitor panel to open');
  assert.equal((await state()).sdOpen, false, 'Panels toggle independently');
  await evaluate("document.querySelector('#monitorPanel > summary').click()");
  await expectState({ monitorOpen: false, monitorVisible: false }, 'monitor panel to close');

  await evaluate("document.querySelector('#monitorPanel > summary').focus()");
  assert.equal(await evaluate("document.activeElement === document.querySelector('#monitorPanel > summary')"), true);
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter',
    text: '\r', unmodifiedText: '\r', nativeVirtualKeyCode: 13, windowsVirtualKeyCode: 13 });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter',
    nativeVirtualKeyCode: 13, windowsVirtualKeyCode: 13 });
  await expectState({ monitorOpen: true, monitorVisible: true }, 'Enter to open monitor panel');

  await evaluate("document.querySelector('#sdPanel > summary').focus()");
  assert.equal(await evaluate("document.activeElement === document.querySelector('#sdPanel > summary')"), true);
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: ' ', code: 'Space',
    text: ' ', unmodifiedText: ' ', nativeVirtualKeyCode: 32, windowsVirtualKeyCode: 32 });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: ' ', code: 'Space',
    nativeVirtualKeyCode: 32, windowsVirtualKeyCode: 32 });
  await expectState({ sdOpen: true, sdVisible: true }, 'Space to open SD panel');
  assert.equal((await state()).monitorOpen, true, 'Opening SD does not close the monitor panel');
  await evaluate("document.querySelector('#sdPanel > summary').click()");
  await expectState({ sdOpen: false, sdVisible: false }, 'SD panel to close');

  await evaluate("document.querySelector('#monitorPanel > summary').click()");
  await expectState({ monitorOpen: false, monitorVisible: false }, 'monitor panel to close');
  await send('Emulation.setDeviceMetricsOverride', {
    width: 390, height: 844, deviceScaleFactor: 1, mobile: true,
  });
  await until(async () => await evaluate('window.innerWidth === 390'), '390 px viewport');
  const viewport = () => evaluate(`({
    width: window.innerWidth,
    scrollWidth: document.documentElement.scrollWidth,
  })`);
  const collapsedWidth = await viewport();
  assert.ok(collapsedWidth.scrollWidth <= collapsedWidth.width,
    `Collapsed panels overflow the ${collapsedWidth.width} px viewport: ${collapsedWidth.scrollWidth} px`);

  await evaluate("document.querySelector('#sdPanel > summary').click()");
  await expectState({ sdOpen: true, sdVisible: true }, 'SD panel to open on mobile');
  const expandedWidth = await viewport();
  assert.ok(expandedWidth.scrollWidth <= expandedWidth.width,
    `Open SD panel overflows the ${expandedWidth.width} px viewport: ${expandedWidth.scrollWidth} px`);
});
