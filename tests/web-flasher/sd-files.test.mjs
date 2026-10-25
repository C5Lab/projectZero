import test from 'node:test';
import assert from 'node:assert/strict';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const sd = await import('../../docs/sd-files.mjs').catch(() => null);

class FakePort {
  constructor(onWrite = () => {}) {
    this.onWrite = onWrite;
    this.writes = [];
    this.queue = [];
    this.waiters = [];
    this.closed = false;
    this.readable = { getReader: () => ({
      read: () => this.queue.length ? Promise.resolve(this.queue.shift()) : new Promise(resolve => this.waiters.push(resolve)),
      cancel: async () => { this.feedDone(); },
      releaseLock: () => {},
    }) };
    this.writable = { getWriter: () => ({
      write: async data => {
        const bytes = Uint8Array.from(data);
        this.writes.push(bytes);
        await this.onWrite(bytes, this);
      },
      releaseLock: () => {},
    }) };
  }
  async open(options) { this.openOptions = options; }
  async close() { this.closed = true; this.feedDone(); }
  feed(data, sizes = [1, 2, 3, 5]) {
    const bytes = typeof data === 'string' ? encoder.encode(data) : data;
    for (let offset = 0, i = 0; offset < bytes.length; i++) {
      const chunk = bytes.slice(offset, offset + sizes[i % sizes.length]);
      offset += chunk.length;
      const value = { value: chunk, done: false };
      if (this.waiters.length) this.waiters.shift()(value);
      else this.queue.push(value);
    }
  }
  feedDone() {
    while (this.waiters.length) this.waiters.shift()({ done: true });
  }
  textWrites() { return this.writes.map(bytes => decoder.decode(bytes)); }
}

const u32 = (bytes, offset, value) => new DataView(bytes.buffer).setUint32(offset, value >>> 0, true);
const u64 = (bytes, offset, value) => new DataView(bytes.buffer).setBigUint64(offset, BigInt(value), true);
const frame = (index, payload, crc = sd.crc32(payload)) => {
  const bytes = new Uint8Array(16 + payload.length);
  bytes.set([70, 84, 66, 1]);
  u32(bytes, 4, index); u32(bytes, 8, payload.length); u32(bytes, 12, crc);
  bytes.set(payload, 16);
  return bytes;
};
const ack32 = (index, status, offset, badCrc = false) => {
  const bytes = new Uint8Array(32);
  bytes.set([70, 84, 65, 1]);
  u32(bytes, 4, index);
  bytes[8] = status;
  u64(bytes, 12, offset);
  u32(bytes, 20, (sd.crc32(bytes.slice(0, 20)) ^ (badCrc ? 1 : 0)) >>> 0);
  return bytes;
};
const hello = (bytes, port) => {
  if (decoder.decode(bytes) === 'fs hello\r\n') {
    port.feed('[FS/1] HELLO root=/sdcard/lab get=ftb1 put=ftb1_ack32 bsize=1024 encoding=cp437\r\n[FS/1] END\r\n');
    return true;
  }
  return false;
};

test('CRC32 and reversible CP437 path encoding match FS/1', () => {
  assert.ok(sd, 'sd-files.mjs must exist');
  assert.equal(sd.crc32(encoder.encode('123456789')), 0xcbf43926);
  assert.equal(sd.encodePath('ü'), 'gQ==');
  assert.equal(sd.decodeName('gQ=='), 'ü');
  assert.equal(sd.encodePath('café.txt'), 'Y2Fmgi50eHQ=');
  assert.throws(() => sd.encodePath('żółć.txt'), /CP437/i);
  for (let byte = 128; byte <= 255; byte++) {
    const encoded = btoa(String.fromCharCode(byte));
    assert.equal(sd.encodePath(sd.decodeName(encoded)), encoded);
  }
});

test('app-mode connection probes fs hello and lists a CP437 directory', async () => {
  let port;
  port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes) === 'fs ls -\r\n') {
      p.feed('[FS/1] BEGIN\r\n');
      p.feed(`[FS/1] ITEM type=d size=0 name64=${sd.encodePath('obrazy')}\r\n`);
      p.feed('[FS/1] ITEM type=f size=17 name64=Y2Fmgi50eHQ=\r\n');
      p.feed('[FS/1] END status=ok count=2\r\n');
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 50 });
  await client.connect();
  const items = await client.list('');
  assert.deepEqual(items, [
    { name: 'obrazy', type: 'd', size: 0 },
    { name: 'café.txt', type: 'f', size: 17 },
  ]);
  assert.deepEqual(port.openOptions, { baudRate: 115200 });
  assert.ok(!port.textWrites().some(write => /download|ping|esptool/i.test(write)));
  await client.close();
  assert.equal(port.closed, true);
});

test('FS/1 rm removes a file or empty folder only when firmware advertises support', async () => {
  const port = new FakePort((bytes, p) => {
    const command = decoder.decode(bytes);
    if (command === 'fs hello\r\n') {
      p.feed('[FS/1] HELLO root=/sdcard/lab get=ftb1 put=ftb1_ack32 bsize=1024 encoding=cp437 rm=file_empty_dir\r\n[FS/1] END\r\n');
    } else if (command === 'fs rm Y2FwdHVyZXMvbm90ZS50eHQ=\r\n') {
      p.feed('[FS/1] DONE type=f\r\n[FS/1] END\r\n');
    } else if (command === 'fs rm Y2FwdHVyZXMvb2xk\r\n') {
      p.feed('[FS/1] DONE type=d\r\n[FS/1] END\r\n');
    } else if (command === 'fs rm Y2FwdHVyZXMvY2Fmgi50eHQ=\r\n') {
      p.feed('[FS/1] DONE type=f\r\n[FS/1] END\r\n');
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 50 });
  await client.connect();
  assert.equal(client.canRemove, true);
  assert.deepEqual(await client.remove('captures/note.txt'), { type: 'f' });
  assert.deepEqual(await client.remove('captures/old'), { type: 'd' });
  assert.deepEqual(await client.remove('captures/café.txt'), { type: 'f' });
  assert.deepEqual(port.textWrites().slice(1), [
    'fs rm Y2FwdHVyZXMvbm90ZS50eHQ=\r\n',
    'fs rm Y2FwdHVyZXMvb2xk\r\n',
    'fs rm Y2FwdHVyZXMvY2Fmgi50eHQ=\r\n',
  ]);
  await client.close();
});

test('FS/1 cleanup removes only an advertised partial upload path', async () => {
  const partial = 'captures/20260526_164710.jpg.fs-part';
  const command = `fs cleanup ${sd.encodePath(partial)}\r\n`;
  const port = new FakePort((bytes, p) => {
    const text = decoder.decode(bytes);
    if (text === 'fs hello\r\n') {
      p.feed('[FS/1] HELLO root=/sdcard/lab get=ftb1 put=ftb1_ack32 bsize=1024 encoding=cp437 rm=file_empty_dir cleanup=part_only\r\n[FS/1] END\r\n');
    } else if (text === command) {
      p.feed('[FS/1] CLEANED type=part\r\n[FS/1] END\r\n');
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 50 });
  await client.connect();
  assert.equal(client.canCleanupPartial, true);
  await assert.rejects(client.remove(partial), /reserved/i);
  await assert.rejects(client.remove('captures/photo.jpg.fs-backup'), /reserved/i);
  await assert.rejects(client.cleanupPartial('captures/photo.jpg'), /partial|\.fs-part/i);
  await assert.rejects(client.cleanupPartial('captures/photo.jpg.fs-backup'), /partial|\.fs-part/i);
  await assert.rejects(client.cleanupPartial('captures/PHOTO~1.JPG.fs-part'), /alias|reserved/i);
  assert.deepEqual(await client.cleanupPartial(partial), { type: 'part' });
  assert.deepEqual(port.textWrites(), ['fs hello\r\n', command]);
  await client.close();

  const oldPort = new FakePort((bytes, p) => { hello(bytes, p); });
  const oldClient = new sd.SdFilesClient(oldPort, { timeoutMs: 50 });
  await oldClient.connect();
  assert.equal(oldClient.canCleanupPartial, false);
  await assert.rejects(oldClient.cleanupPartial(partial), /does not support|firmware/i);
  assert.deepEqual(oldPort.textWrites(), ['fs hello\r\n']);
  await oldClient.close();
});

test('old FS/1 firmware cannot delete, and recovery requires an explicit retry', async () => {
  const oldPort = new FakePort((bytes, p) => { hello(bytes, p); });
  const oldClient = new sd.SdFilesClient(oldPort, { timeoutMs: 50 });
  await oldClient.connect();
  assert.equal(oldClient.canRemove, false);
  await assert.rejects(oldClient.remove('note.txt'), /does not support|firmware/i);
  assert.deepEqual(oldPort.textWrites(), ['fs hello\r\n']);
  await oldClient.close();

  const port = new FakePort((bytes, p) => {
    const command = decoder.decode(bytes);
    if (command === 'fs hello\r\n') {
      p.feed('[FS/1] HELLO root=/sdcard/lab get=ftb1 put=ftb1_ack32 bsize=1024 encoding=cp437 rm=file_empty_dir\r\n[FS/1] END\r\n');
    } else if (command === 'fs rm bm90ZS50eHQ=\r\n') {
      p.feed('[FS/1] ERROR code=recovered_retry\r\n[FS/1] END\r\n');
    } else if (command === 'fs ls -\r\n') {
      p.feed('[FS/1] BEGIN\r\n[FS/1] END status=ok\r\n');
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 50 });
  await client.connect();
  await assert.rejects(client.remove('note.txt'), /recovered_retry/);
  assert.deepEqual(await client.list(''), []);
  assert.deepEqual(port.textWrites().slice(1), ['fs rm bm90ZS50eHQ=\r\n', 'fs ls -\r\n']);
  await client.close();
});

test('ROM or unrelated serial device never passes the FS/1 probe', async () => {
  const port = new FakePort((bytes, p) => {
    if (decoder.decode(bytes) === 'fs hello\r\n') p.feed('waiting for download\r\n');
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await assert.rejects(client.connect(), /FS\/1|JanOS|timeout/i);
  assert.equal(port.closed, true);
  assert.deepEqual(port.textWrites(), ['fs hello\r\n']);
});

test('FS/1 hello rejects a different root or transfer variant', async () => {
  const port = new FakePort((bytes, p) => {
    if (decoder.decode(bytes) === 'fs hello\r\n') {
      p.feed('[FS/1] HELLO root=/sdcard/other get=ftb1 put=ftb1_ack32 bsize=1024 encoding=cp437\r\n[FS/1] END\r\n');
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await assert.rejects(client.connect(), /root|FS\/1/i);
  assert.equal(port.closed, true);
});

test('FS/1 hello rejects an unsupported filesystem encoding', async () => {
  const port = new FakePort((bytes, p) => {
    if (decoder.decode(bytes) === 'fs hello\r\n') {
      p.feed('[FS/1] HELLO root=/sdcard/lab get=ftb1 put=ftb1_ack32 bsize=1024 encoding=utf8\r\n[FS/1] END\r\n');
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await assert.rejects(client.connect(), /encoding|FS\/1/i);
  assert.equal(port.closed, true);
});

test('serial lines tolerate VFS-expanded CRCRLF endings', async () => {
  const port = new FakePort((bytes, p) => {
    if (decoder.decode(bytes) === 'fs hello\r\n') {
      p.feed('[FS/1] HELLO root=/sdcard/lab get=ftb1 put=ftb1_ack32 bsize=1024 encoding=cp437\r\r\n[FS/1] END\r\r\n');
    } else if (decoder.decode(bytes) === 'fs ls -\r\n') {
      p.feed('[FS/1] BEGIN\r\r\n[FS/1] END status=ok\r\r\n');
    } else if (decoder.decode(bytes) === `fs get ${sd.encodePath('empty.bin')}\r\n`) {
      p.feed('[FT] begin size=0 offset=0 bsize=1024 crc32=00000000 prefix_crc=00000000 ack_ms=8000\r\r\n[FT] END\r\r\n\r\r\n[FT] done sent=0 crc32=00000000\r\r\n[FT] END\r\r\n');
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  assert.deepEqual(await client.list(''), []);
  assert.deepEqual(await client.download('empty.bin'), new Uint8Array(0));
  await client.close();
});

test('FS/1 error consumes END so the next directory request can succeed', async () => {
  let listing = 0;
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes) === 'fs ls -\r\n') {
      if (++listing === 1) p.feed('[FS/1] ERROR code=sd_unavailable\r\n[FS/1] END\r\n');
      else p.feed('[FS/1] BEGIN\r\n[FS/1] END status=ok\r\n');
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  await assert.rejects(client.list(''), /sd_unavailable/);
  assert.deepEqual(await client.list(''), []);
  await client.close();
});

test('download verifies fragmented FTB/1 blocks, NAKs corrupt block, then checks final CRC', async () => {
  const payload = encoder.encode('download data');
  const wholeCrc = sd.crc32(payload).toString(16).padStart(8, '0');
  let attempts = 0;
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes) === `fs get ${sd.encodePath('test.bin')}\r\n`) {
      p.feed(`[FT] begin size=${payload.length} offset=0 bsize=1024 crc32=00000000 prefix_crc=00000000 ack_ms=2000\r\n[FT] END\r\n\r\n`);
      p.feed(frame(0, payload, sd.crc32(payload) ^ 1));
    } else if (bytes.length === 1 && bytes[0] === 0x15) {
      attempts++;
      p.feed(frame(0, payload));
    } else if (bytes.length === 1 && bytes[0] === 0x06) {
      p.feed(`[FT] done sent=${payload.length} crc32=${wholeCrc}\r\n[FT] END\r\n`);
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 50 });
  await client.connect();
  const progress = [];
  const result = await client.download('test.bin', { onProgress: (done, total) => progress.push([done, total]) });
  assert.deepEqual(result, payload);
  assert.equal(attempts, 1);
  assert.deepEqual(progress.at(-1), [payload.length, payload.length]);
  await client.close();
});

test('bounded download rejects the actual FT size when the listing is stale', async () => {
  const payload = encoder.encode('larger');
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    const command = decoder.decode(bytes);
    if (command === 'fs ls -\r\n') {
      p.feed(`[FS/1] BEGIN\r\n[FS/1] ITEM type=f size=2 name64=${sd.encodePath('note.txt')}\r\n[FS/1] END status=ok count=1\r\n`);
    } else if (command === `fs get ${sd.encodePath('note.txt')}\r\n`) {
      p.feed(`[FT] begin size=${payload.length} offset=0 bsize=1024 crc32=00000000 prefix_crc=00000000 ack_ms=8000\r\n[FT] END\r\n\r\n`);
      p.feed(frame(0, payload));
    } else if (bytes.length === 1 && bytes[0] === 0x18) {
      p.feed('[FT] cancelled\r\n[FT] END\r\n');
    } else if (bytes.length === 1 && bytes[0] === 0x06) {
      p.feed(`[FT] done sent=${payload.length} crc32=${sd.crc32(payload).toString(16).padStart(8, '0')}\r\n[FT] END\r\n`);
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 50 });
  await client.connect();
  assert.deepEqual(await client.list(''), [{ name: 'note.txt', type: 'f', size: 2 }]);
  const progress = [];
  await assert.rejects(client.download('note.txt', {
    maxBytes: 5,
    onProgress: (done, total) => progress.push([done, total]),
  }), /size|limit|5/i);
  assert.deepEqual(progress, []);
  assert.equal(port.closed, true);
  assert.deepEqual(port.writes.filter(bytes => bytes.length === 1).map(bytes => bytes[0]), [0x18]);
  await assert.rejects(client.list(''), /Connect to running JanOS/i);
});

test('bounded download accepts an FT size exactly at maxBytes', async () => {
  const payload = encoder.encode('equal');
  const crc = sd.crc32(payload).toString(16).padStart(8, '0');
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes) === `fs get ${sd.encodePath('exact.txt')}\r\n`) {
      p.feed(`[FT] begin size=${payload.length} offset=0 bsize=1024 crc32=00000000 prefix_crc=00000000 ack_ms=8000\r\n[FT] END\r\n\r\n`);
      p.feed(frame(0, payload));
    } else if (bytes.length === 1 && bytes[0] === 0x06) {
      p.feed(`[FT] done sent=${payload.length} crc32=${crc}\r\n[FT] END\r\n`);
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 50 });
  await client.connect();
  const progress = [];
  assert.deepEqual(await client.download('exact.txt', {
    maxBytes: payload.length,
    onProgress: (done, total) => progress.push([done, total]),
  }), payload);
  assert.deepEqual(progress, [[payload.length, payload.length]]);
  assert.equal(port.closed, false);
  assert.deepEqual(port.writes.filter(bytes => bytes.length === 1).map(bytes => bytes[0]), [0x06]);
  await client.close();
});

test('bounded download rejects invalid byte limits before issuing fs get', async () => {
  const port = new FakePort(hello);
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  for (const maxBytes of [-1, 1.5, Infinity, '5']) {
    await assert.rejects(client.download('note.txt', { maxBytes }), /maxBytes|byte limit/i);
  }
  assert.deepEqual(port.textWrites(), ['fs hello\r\n']);
  assert.equal(port.closed, false);
  await client.close();
});

test('download waits within negotiated ack_ms for a delayed SD block', async () => {
  const payload = encoder.encode('slow SD');
  const crc = sd.crc32(payload).toString(16).padStart(8, '0');
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes) === `fs get ${sd.encodePath('slow.bin')}\r\n`) {
      p.feed(`[FT] begin size=${payload.length} offset=0 bsize=1024 crc32=00000000 prefix_crc=00000000 ack_ms=1000\r\n[FT] END\r\n\r\n`);
      setTimeout(() => p.feed(frame(0, payload)), 60);
    } else if (bytes.length === 1 && bytes[0] === 0x06) {
      p.feed(`[FT] done sent=${payload.length} crc32=${crc}\r\n[FT] END\r\n`);
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  assert.deepEqual(await client.download('slow.bin'), payload);
  await client.close();
});

test('pre-transfer get and put refusals consume END without losing the session', async () => {
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    const command = decoder.decode(bytes);
    if (command.startsWith('fs get ')) p.feed('[FS/1] ERROR code=not_found\r\n[FS/1] END\r\n');
    else if (command.startsWith('fs put ')) p.feed('[FS/1] ERROR code=exists\r\n[FS/1] END\r\n');
    else if (command === 'fs ls -\r\n') p.feed('[FS/1] BEGIN\r\n[FS/1] END status=ok\r\n');
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  await assert.rejects(client.download('missing.bin'), /not_found/);
  await assert.rejects(client.upload('exists.bin', new Blob(['a'])), /exists/);
  assert.deepEqual(await client.list(''), []);
  await client.close();
});

test('legacy FT error consumes its END before another FS/1 command', async () => {
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    const command = decoder.decode(bytes);
    if (command.startsWith('fs get ')) p.feed('[FT] error read failed\r\n[FT] END\r\n');
    else if (command === 'fs ls -\r\n') p.feed('[FS/1] BEGIN\r\n[FS/1] END status=ok\r\n');
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  await assert.rejects(client.download('fault.bin'), /read failed/);
  assert.equal(decoder.decode(client.bytes).includes('[FT] END'), false);
  assert.deepEqual(await client.list(''), []);
  await client.close();
});

test('invalid FT begin and FS READY both send CAN and close binary sessions', async () => {
  for (const operation of ['get', 'put']) {
    const port = new FakePort((bytes, p) => {
      if (hello(bytes, p)) return;
      const command = decoder.decode(bytes);
      if (operation === 'get' && command.startsWith('fs get ')) {
        p.feed('[FT] begin size=3 offset=0 bsize=2048 crc32=00000000 prefix_crc=00000000 ack_ms=8000\r\n[FT] END\r\n\r\n');
      } else if (operation === 'put' && command.startsWith('fs put ')) {
        p.feed('[FS/1] READY size=3 crc32=352441c2 offset=0 bsize=2048 ack_size=32 rx_ms=2000\r\n[FS/1] END\r\n\r\n');
      }
    });
    const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
    await client.connect();
    if (operation === 'get') await assert.rejects(client.download('bad.bin'), /block size|bsize|offset/i);
    else await assert.rejects(client.upload('bad.bin', new Blob(['abc'])), /block size|bsize|parameters/i);
    assert.equal(port.closed, true);
    assert.ok(port.writes.some(bytes => bytes.length === 1 && bytes[0] === 0x18), `${operation} should send CAN`);
  }
});

test('upload sends 1024-byte FTB/1 blocks, validates fragmented ACK32, FIN, CAN and DONE', async () => {
  const data = Uint8Array.from({ length: 1040 }, (_, i) => i & 255);
  const totalCrc = sd.crc32(data).toString(16).padStart(8, '0');
  const frames = [];
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes) === `fs put ${sd.encodePath('file.bin')} ${data.length} ${totalCrc}\r\n`) {
      p.feed(`[FS/1] READY size=${data.length} crc32=${totalCrc} offset=0 bsize=1024 ack_size=32 rx_ms=2000\r\n[FS/1] END\r\n\r\n`);
    } else if (bytes[0] === 70 && bytes[1] === 84 && bytes[2] === 66 && bytes[3] === 1) {
      const view = new DataView(bytes.buffer, bytes.byteOffset);
      const index = view.getUint32(4, true);
      const length = view.getUint32(8, true);
      assert.equal(sd.crc32(bytes.slice(16)), view.getUint32(12, true));
      frames.push([index, length]);
      p.feed(ack32(index, 0x06, Math.min(data.length, index * 1024 + length)));
    } else if (bytes.length === 1 && bytes[0] === 0x18) {
      p.feed(`[FS/1] DONE size=${data.length} crc32=${totalCrc} status=ok\r\n[FS/1] END\r\n`);
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 50 });
  await client.connect();
  const progress = [];
  await client.upload('file.bin', new Blob([data]), { onProgress: (done, total) => progress.push([done, total]) });
  assert.deepEqual(frames, [[0, 1024], [1, 16], [2, 0]]);
  assert.deepEqual(progress.at(-1), [data.length, data.length]);
  assert.equal(port.writes.at(-1)[0], 0x18);
  await client.close();
});

test('recovered_retry refusal leaves the prior file and permits an explicit retry', async () => {
  let putCount = 0;
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    const command = decoder.decode(bytes);
    if (command.startsWith('fs put ')) {
      putCount++;
      p.feed('[FS/1] ERROR code=recovered_retry\r\n[FS/1] END\r\n');
    } else if (command === 'fs ls -\r\n') {
      p.feed('[FS/1] BEGIN\r\n[FS/1] END status=ok\r\n');
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  await assert.rejects(client.upload('restore.bin', new Blob(['abc']), { replace: true }), /recovered_retry/);
  assert.equal(putCount, 1);
  assert.ok(!port.writes.some(bytes => bytes.length > 16 && decoder.decode(bytes.slice(0, 3)) === 'FTB'));
  assert.deepEqual(await client.list(''), []);
  await client.close();
});

test('DONE backup_pending=1 is reported after a successful upload', async () => {
  const payload = encoder.encode('abc');
  const crc = sd.crc32(payload).toString(16).padStart(8, '0');
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes).startsWith('fs put ')) {
      p.feed(`[FS/1] READY size=3 offset=0 crc32=${crc} bsize=1024 ack_size=32 rx_ms=1273 prepare_ms=10000\r\n[FS/1] END\r\n\r\n`);
    } else if (bytes[0] === 70 && bytes[1] === 84 && bytes[2] === 66 && bytes[3] === 1) {
      const view = new DataView(bytes.buffer, bytes.byteOffset);
      p.feed(ack32(view.getUint32(4, true), 0x06, 3));
    } else if (bytes.length === 1 && bytes[0] === 0x18) {
      p.feed(`[FS/1] DONE size=3 crc32=${crc} backup_pending=1\r\n[FS/1] END\r\n`);
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  const result = await client.upload('restore.bin', new Blob([payload]), { replace: true });
  assert.equal(result.backupPending, true);
  assert.equal(result.size, 3);
  await client.close();
});

test('upload tolerates a late replay ACK32 for the previous data block', async () => {
  const data = Uint8Array.from({ length: 1040 }, (_, i) => i & 255);
  const crc = sd.crc32(data).toString(16).padStart(8, '0');
  let firstBlockWrites = 0;
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes).startsWith('fs put ')) {
      p.feed(`[FS/1] READY size=${data.length} offset=0 crc32=${crc} bsize=1024 ack_size=32 rx_ms=20 prepare_ms=10000\r\n[FS/1] END\r\n\r\n`);
    } else if (bytes[0] === 70 && bytes[1] === 84 && bytes[2] === 66 && bytes[3] === 1) {
      const index = new DataView(bytes.buffer, bytes.byteOffset).getUint32(4, true);
      if (index === 0 && ++firstBlockWrites === 1) return; // Lost first ACK.
      if (index === 0) {
        p.feed(ack32(0, 0x06, 1024));
        p.feed(ack32(0, 0x06, 1024)); // Replay ACK arrives after next write.
      } else p.feed(ack32(index, 0x06, data.length));
    } else if (bytes.length === 1 && bytes[0] === 0x18) {
      p.feed(`[FS/1] DONE size=${data.length} crc32=${crc}\r\n[FS/1] END\r\n`);
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  await client.upload('late.bin', new Blob([data]));
  assert.equal(firstBlockWrites, 2);
  await client.close();
});

test('lost FIN ACK32 retries the same FIN during JanOS linger', async () => {
  const data = encoder.encode('fin');
  const crc = sd.crc32(data).toString(16).padStart(8, '0');
  let finWrites = 0;
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes).startsWith('fs put ')) {
      p.feed(`[FS/1] READY size=3 offset=0 crc32=${crc} bsize=1024 ack_size=32 rx_ms=20 prepare_ms=10000\r\n[FS/1] END\r\n\r\n`);
    } else if (bytes[0] === 70 && bytes[1] === 84 && bytes[2] === 66 && bytes[3] === 1) {
      const view = new DataView(bytes.buffer, bytes.byteOffset);
      const index = view.getUint32(4, true);
      if (view.getUint32(8, true) === 0) {
        if (++finWrites === 2) p.feed(ack32(index, 0x06, data.length));
      } else p.feed(ack32(index, 0x06, data.length));
    } else if (bytes.length === 1 && bytes[0] === 0x18) {
      p.feed(`[FS/1] DONE size=3 crc32=${crc}\r\n[FS/1] END\r\n`);
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  await client.upload('fin.bin', new Blob([data]));
  assert.equal(finWrites, 2);
  await client.close();
});

test('late original FIN ACK32 and replay ACK32 both arrive before DONE', async () => {
  const emptyCrc = sd.crc32(new Uint8Array(0)).toString(16).padStart(8, '0');
  let finWrites = 0;
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes).startsWith('fs put ')) {
      p.feed(`[FS/1] READY size=0 offset=0 crc32=${emptyCrc} bsize=1024 ack_size=32 rx_ms=20\r\n[FS/1] END\r\n\r\n`);
    } else if (bytes[0] === 70 && bytes[1] === 84 && bytes[2] === 66 && bytes[3] === 1) {
      const view = new DataView(bytes.buffer, bytes.byteOffset);
      assert.equal(view.getUint32(4, true), 0);
      assert.equal(view.getUint32(8, true), 0);
      if (++finWrites === 2) {
        p.feed(ack32(0, 0x06, 0)); // Late ACK to the first FIN.
        p.feed(ack32(0, 0x06, 0)); // Replay ACK to the retransmitted FIN.
      }
    } else if (bytes.length === 1 && bytes[0] === 0x18) {
      p.feed(`[FS/1] DONE size=0 crc32=${emptyCrc}\r\n[FS/1] END\r\n`);
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  const result = await client.upload('empty.bin', new Blob([]));
  assert.equal(finWrites, 2);
  assert.equal(result.size, 0);
  assert.equal(port.closed, false);
  await client.close();
});

test('invalid replay FIN ACK32 cannot be mistaken for upload completion', async () => {
  let finWrites = 0;
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes).startsWith('fs put ')) {
      p.feed('[FS/1] READY size=0 offset=0 crc32=00000000 bsize=1024 ack_size=32 rx_ms=20\r\n[FS/1] END\r\n\r\n');
    } else if (bytes[0] === 70 && bytes[1] === 84 && bytes[2] === 66 && bytes[3] === 1) {
      if (++finWrites === 2) {
        p.feed(ack32(0, 0x06, 0));
        p.feed(ack32(0, 0x06, 0, true));
      }
    } else if (bytes.length === 1 && bytes[0] === 0x18) {
      p.feed('[FS/1] DONE size=0 crc32=00000000\r\n[FS/1] END\r\n');
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  await assert.rejects(client.upload('empty.bin', new Blob([])), /ACK32 CRC/i);
  assert.equal(port.closed, true);
});

test('bad ACK32 CRC aborts upload and closes the desynchronized session', async () => {
  const data = encoder.encode('abc');
  const crc = sd.crc32(data).toString(16).padStart(8, '0');
  const port = new FakePort((bytes, p) => {
    if (hello(bytes, p)) return;
    if (decoder.decode(bytes).startsWith('fs put ')) {
      p.feed(`[FS/1] READY size=3 crc32=${crc} offset=0 bsize=1024 ack_size=32 rx_ms=2000\r\n[FS/1] END\r\n\r\n`);
    } else if (bytes[0] === 70 && bytes[1] === 84 && bytes[2] === 66 && bytes[3] === 1) {
      p.feed(ack32(0, 0x06, 3, true));
    }
  });
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  await assert.rejects(client.upload('a', new Blob([data])), /ACK32|CRC/i);
  assert.equal(port.closed, true);
});

test('a stalled directory listing times out', async () => {
  const port = new FakePort(hello);
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  await assert.rejects(client.list(''), /timeout/i);
  assert.equal(port.closed, true);
  port.feed('[FS/1] BEGIN\r\n[FS/1] END status=ok\r\n');
  await assert.rejects(client.list(''), /Connect to running JanOS/i);
});

test('unattended serial output is bounded and closes the session on overflow', async () => {
  const port = new FakePort(hello);
  const client = new sd.SdFilesClient(port, { timeoutMs: 20, maxBufferBytes: 256 });
  await client.connect();
  port.feed(encoder.encode('x'.repeat(300)), [300]);
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(port.closed, true);
  assert.match(client.readError.message, /buffer|overflow/i);
});

test('oversized fs ls, get and put commands fail locally without writing to JanOS', async () => {
  const port = new FakePort(hello);
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  const longPath = 'a'.repeat(200);
  await assert.rejects(client.list(longPath), /command|long|256/i);
  await assert.rejects(client.download(longPath), /command|long|256/i);
  await assert.rejects(client.upload(longPath, new Blob(['a']), { replace: true }), /command|long|256/i);
  assert.deepEqual(port.textWrites(), ['fs hello\r\n']);
  await client.close();
});

test('tilde names may be browsed but cannot be uploaded over FS/1', async () => {
  const port = new FakePort(hello);
  const client = new sd.SdFilesClient(port, { timeoutMs: 20 });
  await client.connect();
  assert.equal(sd.encodePath('OUI~1.BIN'), 'T1VJfjEuQklO');
  await assert.rejects(client.upload('OUI~1.BIN', new Blob(['a'])), /tilde|~/i);
  assert.deepEqual(port.textWrites(), ['fs hello\r\n']);
  await client.close();
});
