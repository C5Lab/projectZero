// Text formats used by the JanOS SD file viewer. All functions are pure and
// leave rendering (including escaping cell content) to their caller.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();
const BOM = Uint8Array.of(0xef, 0xbb, 0xbf);
const FORBIDDEN_CONTROLS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u;

function checkText(text) {
  if (FORBIDDEN_CONTROLS.test(text)) {
    throw new Error('File contains binary or control characters.');
  }
}

function hasBom(bytes) {
  return bytes.length >= 3 && bytes[0] === BOM[0] && bytes[1] === BOM[1] && bytes[2] === BOM[2];
}

/** Decode a read-only preview as strict UTF-8, retaining all line endings. */
export function decodeUtf8Preview(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('Expected Uint8Array file bytes.');
  let text;
  try {
    text = decoder.decode(bytes.subarray(hasBom(bytes) ? 3 : 0));
  } catch {
    throw new Error('File is not valid UTF-8 text.');
  }
  checkText(text);
  return text;
}

/** Decode editable UTF-8 into LF text plus the original BOM and newline style. */
export function decodeEditableText(bytes) {
  const bom = hasBom(bytes);
  const text = decodeUtf8Preview(bytes);
  let sawCrLf = false;
  let sawLf = false;
  for (let index = 0; index < text.length; index++) {
    if (text[index] === '\r') {
      if (text[index + 1] !== '\n') throw new Error('Bare CR line endings cannot be edited safely.');
      sawCrLf = true;
      index++;
    } else if (text[index] === '\n') {
      sawLf = true;
    }
  }
  if (sawCrLf && sawLf) throw new Error('Mixed line endings cannot be edited safely.');
  return {
    text: sawCrLf ? text.replace(/\r\n/g, '\n') : text,
    bom,
    newline: sawCrLf ? 'CRLF' : 'LF',
  };
}

function checkWellFormedUnicode(text) {
  for (let index = 0; index < text.length; index++) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('Text contains an unpaired Unicode surrogate.');
      index++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error('Text contains an unpaired Unicode surrogate.');
    }
  }
}

/** Encode edited LF text, restoring the selected BOM and newline style. */
export function encodeEditableText(text, { bom = false, newline = 'LF' } = {}) {
  if (typeof text !== 'string') throw new TypeError('Expected text to save.');
  if (newline !== 'LF' && newline !== 'CRLF') throw new Error('Unsupported line ending style.');
  checkText(text);
  checkWellFormedUnicode(text);
  const normalized = text.replace(/\r\n/g, '\n');
  if (normalized.includes('\r')) throw new Error('Bare CR line endings cannot be saved.');
  const payload = encoder.encode(newline === 'CRLF' ? normalized.replace(/\n/g, '\r\n') : normalized);
  if (!bom) return payload;
  const result = new Uint8Array(BOM.length + payload.length);
  result.set(BOM);
  result.set(payload, BOM.length);
  return result;
}

/** Parse RFC-style CSV into bounded literal cells; truncation covers any cap. */
export function parseCsvPreview(text, { maxRows = 200, maxColumns = 32, maxCellChars = 512 } = {}) {
  if (typeof text !== 'string') throw new TypeError('Expected CSV text.');
  for (const [label, value] of Object.entries({ maxRows, maxColumns, maxCellChars })) {
    if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`${label} must be a positive integer.`);
  }
  checkText(text);

  const rows = [];
  let row = [];
  let cell = '';
  let cellChars = 0;
  let column = 0;
  let state = 'start';
  let rowStarted = false;
  let truncated = false;

  const append = character => {
    if (rows.length >= maxRows || column >= maxColumns || cellChars >= maxCellChars) {
      truncated = true;
      return;
    }
    cell += character;
    cellChars++;
  };
  const finishCell = () => {
    if (rows.length < maxRows && column < maxColumns) row.push(cell);
    else truncated = true;
    column++;
    cell = '';
    cellChars = 0;
    state = 'start';
  };
  const finishRow = () => {
    finishCell();
    if (rows.length < maxRows) rows.push(row);
    else truncated = true;
    row = [];
    column = 0;
    rowStarted = false;
  };

  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (state !== 'quoted' && (character === '\n' || character === '\r')) {
      if (character === '\r' && text[index + 1] === '\n') index++;
      finishRow();
      continue;
    }
    if (state === 'quoted') {
      if (character === '"') {
        if (text[index + 1] === '"') {
          append('"');
          index++;
        } else {
          state = 'after_quote';
        }
      } else {
        const codePoint = String.fromCodePoint(text.codePointAt(index));
        append(codePoint);
        index += codePoint.length - 1;
      }
    } else if (character === ',') {
      finishCell();
      rowStarted = true;
    } else if (state === 'after_quote') {
      throw new Error('Malformed CSV quote: unexpected text after a closing quote.');
    } else if (character === '"') {
      if (state !== 'start') throw new Error('Malformed CSV quote inside an unquoted field.');
      state = 'quoted';
      rowStarted = true;
    } else {
      const codePoint = String.fromCodePoint(text.codePointAt(index));
      append(codePoint);
      index += codePoint.length - 1;
      state = 'unquoted';
      rowStarted = true;
    }
  }
  if (state === 'quoted') throw new Error('Malformed CSV quote: field is not closed.');
  if (rowStarted) finishRow();
  return { rows, truncated };
}
