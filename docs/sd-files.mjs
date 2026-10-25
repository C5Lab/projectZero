// FS/1 app-mode SD transfers. This module owns raw Web Serial bytes throughout
// a session; binary FTB/1 and FTA/1 frames must never pass through a decoder.
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const ACK = 0x06;
const NAK = 0x15;
const CAN = 0x18;
const BLOCK_SIZE = 1024;
// JanOS currently mounts FatFS with OEM code page 437. path64 and name64 carry
// those filesystem bytes, not UTF-8. Keep every high-byte mapping reversible.
const CP437_HIGH = [
  199, 252, 233, 226, 228, 224, 229, 231, 234, 235, 232, 239, 238, 236, 196, 197,
  201, 230, 198, 244, 246, 242, 251, 249, 255, 214, 220, 162, 163, 165, 8359, 402,
  225, 237, 243, 250, 241, 209, 170, 186, 191, 8976, 172, 189, 188, 161, 171, 187,
  9617, 9618, 9619, 9474, 9508, 9569, 9570, 9558, 9557, 9571, 9553, 9559, 9565, 9564, 9563, 9488,
  9492, 9524, 9516, 9500, 9472, 9532, 9566, 9567, 9562, 9556, 9577, 9574, 9568, 9552, 9580, 9575,
  9576, 9572, 9573, 9561, 9560, 9554, 9555, 9579, 9578, 9496, 9484, 9608, 9604, 9612, 9616, 9600,
  945, 223, 915, 960, 931, 963, 181, 964, 934, 920, 937, 948, 8734, 966, 949, 8745,
  8801, 177, 8805, 8804, 8992, 8993, 247, 8776, 176, 8729, 183, 8730, 8319, 178, 9632, 160,
];
const CP437_BYTE = new Map(CP437_HIGH.map((point, index) => [point, index + 128]));

export function crc32(bytes, previous = 0) {
  let crc = (previous ^ 0xffffffff) >>> 0;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

const hex32 = value => (value >>> 0).toString(16).padStart(8, '0');
const asUint8 = value => value instanceof Uint8Array ? value : new Uint8Array(value);

function checkRelativePath(path, allowRoot = false) {
  if (allowRoot && (path === '' || path === null || path === undefined)) return '';
  if (typeof path !== 'string' || !path || path.startsWith('/') || path.includes('\\')
      || /[\x00-\x1f\x7f]/.test(path)
      || path.split('/').some(part => !part || part === '.' || part === '..')) {
    throw new Error('Choose a relative SD path inside /sdcard/lab.');
  }
  return path;
}

export function encodePath(path) {
  checkRelativePath(path);
  const bytes = [];
  for (const character of path) {
    const point = character.codePointAt(0);
    const byte = point < 128 ? point : CP437_BYTE.get(point);
    if (byte === undefined) throw new Error(`Filename contains a character unavailable in CP437: ${character}`);
    bytes.push(byte);
  }
  return btoa(String.fromCharCode(...bytes));
}

export function decodeName(base64) {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)) {
    throw new Error('Invalid FS/1 base64 name.');
  }
  return Array.from(atob(base64), character => {
    const byte = character.charCodeAt(0);
    return String.fromCodePoint(byte < 128 ? byte : CP437_HIGH[byte - 128]);
  }).join('');
}

function fields(line) {
  const result = {};
  for (const token of line.split(/\s+/).slice(2)) {
    const eq = token.indexOf('=');
    if (eq > 0) result[token.slice(0, eq)] = token.slice(eq + 1);
  }
  return result;
}

function unsigned(value, label) {
  if (!/^(?:0|[1-9][0-9]*)$/.test(String(value))) throw new Error(`Invalid ${label} in transfer response.`);
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throw new Error(`Invalid ${label} in transfer response.`);
  return number;
}

function parseHex32(value, label) {
  if (!/^[0-9a-fA-F]{8}$/.test(String(value))) throw new Error(`Invalid ${label} in transfer response.`);
  return parseInt(value, 16) >>> 0;
}

function makeFrame(index, payload) {
  const bytes = new Uint8Array(16 + payload.length);
  bytes.set([0x46, 0x54, 0x42, 0x01]);
  const view = new DataView(bytes.buffer);
  view.setUint32(4, index, true);
  view.setUint32(8, payload.length, true);
  view.setUint32(12, crc32(payload), true);
  bytes.set(payload, 16);
  return bytes;
}

export class SdFilesClient {
  constructor(port, { timeoutMs = 2500, maxBufferBytes = 1024 * 1024, onFault = null } = {}) {
    this.port = port;
    this.timeoutMs = timeoutMs;
    this.maxBufferBytes = maxBufferBytes;
    this.onFault = onFault;
    this.bytes = new Uint8Array(0);
    this.waiter = null;
    this.reader = null;
    this.writer = null;
    this.connected = false;
    this.canRemove = false;
    this.canCleanupPartial = false;
    this.stopped = false;
    this.readError = null;
  }

  async connect() {
    if (this.connected || this.reader) throw new Error('SD serial session is already open.');
    try {
      await this.port.open({ baudRate: 115200 });
      this.reader = this.port.readable.getReader();
      this.writer = this.port.writable.getWriter();
      this.readLoop = this.pump();
      await this.write(encoder.encode('fs hello\r\n'));
      const hello = await this.tagged('FS/1', this.timeoutMs);
      if (!/^\[FS\/1\] HELLO\b/.test(hello)) throw new Error('No FS/1 response from running JanOS.');
      const capabilities = fields(hello);
      if (capabilities.root !== '/sdcard/lab' || capabilities.get !== 'ftb1'
          || capabilities.put !== 'ftb1_ack32' || capabilities.bsize !== '1024'
          || capabilities.encoding !== 'cp437') {
        throw new Error('Unsupported JanOS FS/1 root, encoding, or transfer variant.');
      }
      this.canRemove = capabilities.rm === 'file_empty_dir';
      this.canCleanupPartial = capabilities.cleanup === 'part_only';
      const end = await this.tagged('FS/1', this.timeoutMs);
      if (!/^\[FS\/1\] END\b/.test(end)) throw new Error('Incomplete FS/1 hello response.');
      this.connected = true;
      return hello;
    } catch (error) {
      await this.close();
      throw new Error(`JanOS FS/1 probe failed: ${error.message || error}`);
    }
  }

  async pump() {
    let fatal = null;
    try {
      while (!this.stopped) {
        const { value, done } = await this.reader.read();
        if (done) break;
        if (!value?.length) continue;
        if (this.bytes.length + value.length > this.maxBufferBytes) {
          throw new Error('JanOS serial buffer limit exceeded. Reconnect SD files.');
        }
        const next = new Uint8Array(this.bytes.length + value.length);
        next.set(this.bytes);
        next.set(value, this.bytes.length);
        this.bytes = next;
        this.wake();
      }
      if (!this.stopped) fatal = new Error('Serial port closed during FS/1 transfer.');
    } catch (error) {
      if (!this.stopped) fatal = error;
    } finally {
      if (fatal) this.readError = fatal;
      this.wake();
      if (fatal) queueMicrotask(() => {
        this.close().finally(() => this.onFault?.(fatal));
      });
    }
  }

  wake() {
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = null;
      waiter();
    }
  }

  async waitForBytes(deadline) {
    if (this.readError) throw this.readError;
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error('Serial response timeout.');
    await new Promise(resolve => {
      const timer = setTimeout(() => {
        if (this.waiter === notify) this.waiter = null;
        resolve();
      }, remaining);
      const notify = () => { clearTimeout(timer); resolve(); };
      this.waiter = notify;
    });
    if (this.readError) throw this.readError;
  }

  async exact(length, timeoutMs = this.timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (this.bytes.length < length) await this.waitForBytes(deadline);
    const result = this.bytes.slice(0, length);
    this.bytes = this.bytes.slice(length);
    return result;
  }

  async line(timeoutMs = this.timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (true) {
      const end = this.bytes.indexOf(0x0a);
      if (end >= 0) {
        const raw = this.bytes.slice(0, end);
        this.bytes = this.bytes.slice(end + 1);
        let length = raw.length;
        while (length && raw[length - 1] === 0x0d) length--;
        return decoder.decode(raw.slice(0, length));
      }
      if (this.bytes.length > 8192) throw new Error('Serial line exceeds FS/1 limit.');
      await this.waitForBytes(deadline);
    }
  }

  async tagged(tag, timeoutMs = this.timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (true) {
      const line = await this.line(Math.max(1, deadline - Date.now()));
      const start = line.indexOf(`[${tag}]`);
      if (start >= 0) return line.slice(start);
      if (tag !== 'FS/1' && line.includes('[FS/1] ERROR')) {
        await this.rejectFsError(line.slice(line.indexOf('[FS/1]')));
      }
    }
  }

  async rejectFsError(line) {
    const end = await this.tagged('FS/1');
    if (!/^\[FS\/1\] END\b/.test(end)) throw new Error(`Invalid FS/1 error terminator: ${end}`);
    const error = new Error(line);
    error.code = fields(line).code;
    error.fsRecoverable = true;
    throw error;
  }

  async write(bytes) {
    if (!this.writer) throw new Error('SD serial session is closed.');
    await this.writer.write(bytes);
  }

  requireConnected() {
    if (!this.connected || !this.writer || this.stopped) throw new Error('Connect to running JanOS first.');
  }

  command(text) {
    const bytes = encoder.encode(text);
    // JanOS CLI has a 256-byte input buffer, including its terminating NUL.
    if (bytes.length > 254) throw new Error('FS/1 command is too long for the JanOS 256-byte CLI.');
    return encoder.encode(`${text}\r\n`);
  }

  async list(path = '') {
    this.requireConnected();
    const relative = checkRelativePath(path, true);
    const command = this.command(`fs ls ${relative ? encodePath(relative) : '-'}`);
    try {
      await this.write(command);
      const begin = await this.tagged('FS/1');
      if (/^\[FS\/1\] ERROR\b/.test(begin)) await this.rejectFsError(begin);
      if (!/^\[FS\/1\] BEGIN\b/.test(begin)) throw new Error(`Unexpected FS/1 listing response: ${begin}`);
      const items = [];
      while (true) {
        const line = await this.tagged('FS/1');
        if (/^\[FS\/1\] ITEM\b/.test(line)) {
          if (items.length >= 4096) throw new Error('FS/1 directory exceeds 4096 entries.');
          const item = fields(line);
          if (item.type !== 'd' && item.type !== 'f') throw new Error('Invalid FS/1 item type.');
          const name = decodeName(item.name64);
          if (!name || name.includes('/') || name.includes('\\') || name === '.' || name === '..') {
            throw new Error('Invalid FS/1 item name.');
          }
          items.push({ name, type: item.type, size: unsigned(item.size, 'item size') });
        } else if (/^\[FS\/1\] END\b/.test(line)) {
          const end = fields(line);
          if (end.status !== 'ok') throw new Error(`FS/1 listing failed: ${line}`);
          if (end.count !== undefined && unsigned(end.count, 'item count') !== items.length) {
            throw new Error('FS/1 listing count mismatch.');
          }
          return items;
        } else if (/^\[FS\/1\] ERROR\b/.test(line)) {
          await this.rejectFsError(line);
        } else {
          throw new Error(`Unexpected FS/1 listing response: ${line}`);
        }
      }
    } catch (error) {
      if (!error.fsRecoverable) await this.close();
      throw error;
    }
  }

  async remove(path) {
    this.requireConnected();
    if (!this.canRemove) throw new Error('This JanOS firmware does not support FS/1 delete.');
    const relative = checkRelativePath(path);
    if (relative.includes('~') || /\.fs-(?:part|backup)$/i.test(relative)) {
      throw new Error('This SD path is reserved for JanOS transfer recovery.');
    }
    const command = this.command(`fs rm ${encodePath(relative)}`);
    try {
      await this.write(command);
      const done = await this.tagged('FS/1');
      if (/^\[FS\/1\] ERROR\b/.test(done)) await this.rejectFsError(done);
      if (!/^\[FS\/1\] DONE\b/.test(done)) throw new Error(`Unexpected FS/1 delete response: ${done}`);
      const { type } = fields(done);
      if (type !== 'f' && type !== 'd') throw new Error(`Invalid FS/1 delete type: ${done}`);
      if (await this.tagged('FS/1') !== '[FS/1] END') throw new Error('Missing FS/1 delete end.');
      return { type };
    } catch (error) {
      if (!error.fsRecoverable) await this.close();
      throw error;
    }
  }

  async cleanupPartial(path) {
    this.requireConnected();
    if (!this.canCleanupPartial) throw new Error('This JanOS firmware does not support FS/1 partial upload cleanup.');
    const relative = checkRelativePath(path);
    if (relative.includes('~')) throw new Error('FAT alias paths are reserved for JanOS transfer recovery.');
    if (!/\.fs-part$/i.test(relative) || /(?:^|\/)\.fs-part$/i.test(relative)) {
      throw new Error('Choose a partial upload ending in .fs-part.');
    }
    const command = this.command(`fs cleanup ${encodePath(relative)}`);
    try {
      await this.write(command);
      const cleaned = await this.tagged('FS/1');
      if (/^\[FS\/1\] ERROR\b/.test(cleaned)) await this.rejectFsError(cleaned);
      if (cleaned !== '[FS/1] CLEANED type=part') {
        throw new Error(`Unexpected FS/1 cleanup response: ${cleaned}`);
      }
      if (await this.tagged('FS/1') !== '[FS/1] END') throw new Error('Missing FS/1 cleanup end.');
      return { type: 'part' };
    } catch (error) {
      if (!error.fsRecoverable) await this.close();
      throw error;
    }
  }

  async download(path, { onProgress = () => {}, maxBytes } = {}) {
    this.requireConnected();
    if (maxBytes !== undefined && (!Number.isSafeInteger(maxBytes) || maxBytes < 0)) {
      throw new Error('Download maxBytes must be a non-negative safe integer.');
    }
    const command = this.command(`fs get ${encodePath(path)}`);
    await this.write(command);
    let started = false;
    try {
      const begin = await this.tagged('FT');
      if (/^\[FT\] error\b/.test(begin)) {
        if (await this.tagged('FT') !== '[FT] END') throw new Error('Missing FT error end.');
        throw new Error(begin);
      }
      if (!/^\[FT\] begin\b/.test(begin)) throw new Error(`Unexpected download response: ${begin}`);
      started = true;
      const params = fields(begin);
      const size = unsigned(params.size, 'download size');
      if (maxBytes !== undefined && size > maxBytes) {
        throw new Error(`Download size ${size} exceeds the ${maxBytes}-byte limit.`);
      }
      if (unsigned(params.offset, 'download offset') !== 0 || unsigned(params.bsize, 'download bsize') !== BLOCK_SIZE) {
        throw new Error('Unsupported FS/1 download offset or block size.');
      }
      const ackMs = unsigned(params.ack_ms, 'download ACK timeout');
      if (ackMs < 500) throw new Error('FT download ACK timeout is too short.');
      // Send the ACK before JanOS's ack_ms expires, while allowing slow SD reads.
      const blockReceiveMs = Math.min(30000, Math.max(200,
        ackMs - Math.min(2000, Math.floor(ackMs / 3))));
      const end = await this.tagged('FT');
      if (end !== '[FT] END') throw new Error(`Unexpected download header end: ${end}`);
      if (await this.line() !== '') throw new Error('Missing blank line before binary download.');
      const chunks = [];
      let offset = 0;
      let runningCrc = 0;
      let index = 0;
      while (offset < size) {
        let retries = 0;
        while (true) {
          const blockDeadline = Date.now() + blockReceiveMs;
          const header = await this.exact(16, blockReceiveMs);
          const view = new DataView(header.buffer, header.byteOffset);
          if (header[0] !== 0x46 || header[1] !== 0x54 || header[2] !== 0x42 || header[3] !== 1
              || view.getUint32(4, true) !== index) throw new Error('Invalid FTB/1 download header.');
          const length = view.getUint32(8, true);
          if (!length || length > BLOCK_SIZE || length > size - offset) throw new Error('Invalid FTB/1 download length.');
          const payload = await this.exact(length, Math.max(1, blockDeadline - Date.now()));
          if (crc32(payload) !== view.getUint32(12, true)) {
            await this.write(Uint8Array.of(NAK));
            if (++retries > 3) throw new Error('FTB/1 download block CRC failed after retries.');
            continue;
          }
          chunks.push(payload);
          runningCrc = crc32(payload, runningCrc);
          offset += length;
          index++;
          await this.write(Uint8Array.of(ACK));
          onProgress(offset, size);
          break;
        }
      }
      const done = await this.tagged('FT');
      if (!/^\[FT\] done\b/.test(done)) throw new Error(`Missing FT download completion: ${done}`);
      const result = fields(done);
      if (unsigned(result.sent, 'download sent bytes') !== size
          || parseHex32(result.crc32, 'download CRC') !== runningCrc) {
        throw new Error('FT download size or CRC mismatch.');
      }
      if (await this.tagged('FT') !== '[FT] END') throw new Error('Missing FT download end.');
      const bytes = new Uint8Array(size);
      let cursor = 0;
      for (const chunk of chunks) { bytes.set(chunk, cursor); cursor += chunk.length; }
      return bytes;
    } catch (error) {
      if (started) {
        try { await this.write(Uint8Array.of(CAN)); } catch {}
        await this.close();
      }
      throw error;
    }
  }

  parseAck32(raw) {
    if (raw.length !== 32 || raw[0] !== 0x46 || raw[1] !== 0x54 || raw[2] !== 0x41 || raw[3] !== 1) {
      throw new Error('Invalid FTA/1 ACK32 magic.');
    }
    const view = new DataView(raw.buffer, raw.byteOffset);
    if (view.getUint32(20, true) !== crc32(raw.slice(0, 20))
        || raw.slice(9, 12).some(byte => byte !== 0)
        || raw.slice(24).some(byte => byte !== 0)) {
      throw new Error('Invalid FTA/1 ACK32 CRC or reserved bytes.');
    }
    const index = view.getUint32(4, true);
    const offset = view.getBigUint64(12, true);
    if (offset > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Invalid FTA/1 ACK32 offset.');
    if (raw[8] !== ACK && raw[8] !== NAK && raw[8] !== CAN) throw new Error('Invalid FTA/1 ACK32 status.');
    return { index, status: raw[8], offset: Number(offset) };
  }

  async ack32(expectedIndex, expectedOffset, timeoutMs, previousOffset = null) {
    const deadline = Date.now() + timeoutMs;
    let stale = 0;
    while (true) {
      const { index, status, offset } = this.parseAck32(
        await this.exact(32, Math.max(1, deadline - Date.now())));
      if (index === expectedIndex) {
        if (status === ACK && offset !== expectedOffset) throw new Error('FTA/1 ACK32 offset mismatch.');
        return status;
      }
      if (previousOffset !== null && index === expectedIndex - 1
          && status === ACK && offset === previousOffset && stale++ < 3) continue;
      throw new Error('Invalid FTA/1 ACK32 index or offset.');
    }
  }

  async uploadDone(finIndex, finOffset, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    let replayAcks = 0;
    while (true) {
      while (!this.bytes.length) await this.waitForBytes(deadline);
      if (this.bytes[0] === 0x46) {
        while (this.bytes.length < 4) await this.waitForBytes(deadline);
        if (this.bytes[1] === 0x54 && this.bytes[2] === 0x41 && this.bytes[3] === 1) {
          if (++replayAcks > 3) throw new Error('Too many replay FIN ACK32 frames.');
          const replay = this.parseAck32(await this.exact(32, Math.max(1, deadline - Date.now())));
          if (replay.index !== finIndex || replay.status !== ACK || replay.offset !== finOffset) {
            throw new Error('Invalid replay FIN ACK32 index, status or offset.');
          }
          continue;
        }
      }
      const line = await this.line(Math.max(1, deadline - Date.now()));
      const start = line.indexOf('[FS/1]');
      if (start >= 0) return line.slice(start);
    }
  }

  async upload(path, file, { replace = false, onProgress = () => {} } = {}) {
    this.requireConnected();
    checkRelativePath(path);
    if (path.includes('~')) throw new Error('JanOS SD upload names cannot contain a tilde (~).');
    if (!file || !Number.isSafeInteger(file.size) || file.size < 0 || typeof file.slice !== 'function') {
      throw new Error('Choose a file to upload.');
    }
    let totalCrc = 0;
    for (let offset = 0; offset < file.size; offset += 65536) {
      const chunk = new Uint8Array(await file.slice(offset, offset + 65536).arrayBuffer());
      totalCrc = crc32(chunk, totalCrc);
    }
    const crcHex = hex32(totalCrc);
    const command = this.command(`fs put ${encodePath(path)} ${file.size} ${crcHex}${replace ? ' replace' : ''}`);
    await this.write(command);
    let started = false;
    try {
      const ready = await this.tagged('FS/1');
      if (/^\[FS\/1\] ERROR\b/.test(ready)) await this.rejectFsError(ready);
      if (!/^\[FS\/1\] READY\b/.test(ready)) throw new Error(`Unexpected FS/1 upload response: ${ready}`);
      started = true;
      const params = fields(ready);
      if (unsigned(params.size, 'upload size') !== file.size
          || parseHex32(params.crc32, 'upload CRC') !== totalCrc
          || unsigned(params.offset, 'upload offset') !== 0
          || unsigned(params.bsize, 'upload block size') !== BLOCK_SIZE
          || unsigned(params.ack_size, 'upload ACK size') !== 32) {
        throw new Error('FS/1 upload READY parameters differ from request.');
      }
      const rxMs = unsigned(params.rx_ms, 'upload RX timeout');
      if (await this.tagged('FS/1') !== '[FS/1] END') throw new Error('Missing FS/1 READY end.');
      if (await this.line() !== '') throw new Error('Missing blank line before binary upload.');
      let offset = 0;
      let index = 0;
      while (offset < file.size) {
        const payload = new Uint8Array(await file.slice(offset, offset + BLOCK_SIZE).arrayBuffer());
        const dataFrame = makeFrame(index, payload);
        let acknowledged = false;
        for (let retries = 0; retries < 4 && !acknowledged; retries++) {
          await this.write(dataFrame);
          let status;
          try { status = await this.ack32(index, offset + payload.length,
            Math.max(this.timeoutMs, rxMs), index > 0 ? offset : null); }
          catch (error) {
            if (/timeout/i.test(error.message) && retries < 3) continue;
            throw error;
          }
          if (status === CAN) throw new Error('JanOS cancelled the upload.');
          acknowledged = status === ACK;
        }
        if (!acknowledged) throw new Error('JanOS rejected an upload block after retries.');
        offset += payload.length;
        index++;
        onProgress(offset, file.size);
      }
      const fin = makeFrame(index, new Uint8Array(0));
      let finAcked = false;
      for (let attempt = 0; attempt < 3 && !finAcked; attempt++) {
        await this.write(fin);
        let status;
        try {
          // All three attempts finish inside JanOS's seven-second FIN linger.
          status = await this.ack32(index, file.size,
            Math.min(1800, Math.max(this.timeoutMs, rxMs)), index > 0 ? file.size : null);
        } catch (error) {
          if (/timeout/i.test(error.message) && attempt < 2) continue;
          throw error;
        }
        if (status === CAN) throw new Error('JanOS cancelled the upload FIN frame.');
        finAcked = status === ACK;
      }
      if (!finAcked) throw new Error('JanOS rejected the upload FIN frame.');
      await this.write(Uint8Array.of(CAN)); // Leave ACK32 replay linger after successful FIN.
      const done = await this.uploadDone(index, file.size, Math.max(this.timeoutMs, rxMs));
      if (!/^\[FS\/1\] DONE\b/.test(done)) throw new Error(`Missing FS/1 upload completion: ${done}`);
      const result = fields(done);
      if (result.status && result.status !== 'ok') throw new Error(`FS/1 upload failed: ${done}`);
      if (result.size !== undefined && unsigned(result.size, 'uploaded size') !== file.size) {
        throw new Error('FS/1 upload size mismatch.');
      }
      if (result.crc32 !== undefined && parseHex32(result.crc32, 'uploaded CRC') !== totalCrc) {
        throw new Error('FS/1 upload CRC mismatch.');
      }
      if (result.backup_pending !== undefined && result.backup_pending !== '0'
          && result.backup_pending !== '1') throw new Error('Invalid FS/1 backup_pending value.');
      const end = await this.tagged('FS/1');
      if (!/^\[FS\/1\] END\b/.test(end)) throw new Error('Missing FS/1 upload end.');
      return { size: file.size, crc32: crcHex, backupPending: result.backup_pending === '1' };
    } catch (error) {
      if (started) {
        try { await this.write(Uint8Array.of(CAN)); } catch {}
        await this.close();
      }
      throw error;
    }
  }

  async close() {
    if (this.stopped) return;
    this.stopped = true;
    this.connected = false;
    this.canRemove = false;
    this.canCleanupPartial = false;
    this.readError ||= new Error('SD serial session closed.');
    this.wake();
    try { await this.reader?.cancel(); } catch {}
    try { await this.readLoop; } catch {}
    try { this.reader?.releaseLock(); } catch {}
    try { this.writer?.releaseLock(); } catch {}
    try { await this.port?.close(); } catch {}
    this.reader = null;
    this.writer = null;
  }
}
