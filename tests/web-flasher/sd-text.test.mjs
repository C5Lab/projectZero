import test from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeEditableText,
  decodeUtf8Preview,
  encodeEditableText,
  parseCsvPreview,
} from '../../docs/sd-text.mjs';

const utf8 = text => new TextEncoder().encode(text);

test('editor round trips a UTF-8 BOM and CRLF without changing the saved bytes', () => {
  const original = Uint8Array.from([0xef, 0xbb, 0xbf, ...utf8('zażółć\r\nsecond\r\n')]);
  const decoded = decodeEditableText(original);
  assert.deepEqual(decoded, { text: 'zażółć\nsecond\n', bom: true, newline: 'CRLF' });
  assert.deepEqual(encodeEditableText(decoded.text, decoded), original);
});

test('editor defaults plain text without line endings to LF and no BOM', () => {
  const decoded = decodeEditableText(utf8('hello'));
  assert.deepEqual(decoded, { text: 'hello', bom: false, newline: 'LF' });
  assert.deepEqual(encodeEditableText('hello\nworld', decoded), utf8('hello\nworld'));
});

test('editor rejects invalid UTF-8 and binary control characters', () => {
  assert.throws(() => decodeEditableText(Uint8Array.of(0xc3, 0x28)), /UTF-8/i);
  assert.throws(() => decodeEditableText(utf8('a\0b')), /binary|control/i);
  assert.throws(() => decodeEditableText(utf8('a\u0085b')), /binary|control/i);
  assert.throws(() => decodeEditableText(utf8('a\u007fb')), /binary|control/i);
});

test('editor refuses mixed or bare-CR line endings', () => {
  assert.throws(() => decodeEditableText(utf8('a\r\nb\n')), /mixed|line ending/i);
  assert.throws(() => decodeEditableText(utf8('a\rb')), /bare CR|line ending/i);
});

test('editor save preserves the chosen newline style after editing', () => {
  assert.deepEqual(
    encodeEditableText('first\nnew\n', { bom: true, newline: 'CRLF' }),
    Uint8Array.from([0xef, 0xbb, 0xbf, ...utf8('first\r\nnew\r\n')]),
  );
  assert.throws(() => encodeEditableText('one\rb', { bom: false, newline: 'LF' }), /bare CR|line ending/i);
  assert.throws(() => encodeEditableText('a\0b', { bom: false, newline: 'LF' }), /binary|control/i);
  assert.throws(() => encodeEditableText('a\ud800', { bom: false, newline: 'LF' }), /surrogate|Unicode/i);
});

test('read-only CSV decode accepts mixed newlines and removes only an initial BOM', () => {
  const bytes = Uint8Array.from([0xef, 0xbb, 0xbf, ...utf8('a,b\r\n"one\ntwo",c\n')]);
  assert.equal(decodeUtf8Preview(bytes), 'a,b\r\n"one\ntwo",c\n');
  assert.throws(() => decodeUtf8Preview(Uint8Array.of(0xff)), /UTF-8/i);
  assert.throws(() => decodeUtf8Preview(utf8('a\0b')), /binary|control/i);
});

test('CSV preview parses quoted commas, escaped quotes, and embedded newlines', () => {
  assert.deepEqual(
    parseCsvPreview('name,notes\r\n"a,b","line 1\r\nline ""2"""\r\nx,y\n'),
    {
      rows: [
        ['name', 'notes'],
        ['a,b', 'line 1\r\nline "2"'],
        ['x', 'y'],
      ],
      truncated: false,
    },
  );
});

test('CSV preview returns dangerous-looking cells as literal text', () => {
  const formula = '=HYPERLINK("https://example.invalid", "go")';
  const markup = '<img src=x onerror=alert(1)>';
  assert.deepEqual(
    parseCsvPreview(`"${formula.replaceAll('"', '""')}",${markup}`),
    { rows: [[formula, markup]], truncated: false },
  );
});

test('CSV preview keeps empty fields and does not invent a row after a final newline', () => {
  assert.deepEqual(parseCsvPreview('a,,\n\n'), {
    rows: [['a', '', ''], ['']],
    truncated: false,
  });
  assert.deepEqual(parseCsvPreview(''), { rows: [], truncated: false });
});

test('CSV preview limits rows, columns, and cell characters while reporting truncation', () => {
  assert.deepEqual(
    parseCsvPreview('12345,a,b\nnext,ok\nlast,end', { maxRows: 2, maxColumns: 2, maxCellChars: 3 }),
    { rows: [['123', 'a'], ['nex', 'ok']], truncated: true },
  );
  assert.deepEqual(parseCsvPreview('ab,cd\n', { maxRows: 1, maxColumns: 2, maxCellChars: 2 }), {
    rows: [['ab', 'cd']], truncated: false,
  });
  assert.deepEqual(parseCsvPreview('😀x', { maxCellChars: 1 }), {
    rows: [['😀']], truncated: true,
  });
});

test('CSV preview applies default limits', () => {
  const wide = Array.from({ length: 33 }, (_, index) => String(index)).join(',');
  const tall = Array.from({ length: 201 }, () => 'x').join('\n');
  assert.equal(parseCsvPreview(wide).rows[0].length, 32);
  assert.equal(parseCsvPreview(wide).truncated, true);
  assert.equal(parseCsvPreview(tall).rows.length, 200);
  assert.equal(parseCsvPreview(tall).truncated, true);
  assert.equal(parseCsvPreview('x'.repeat(513)).rows[0][0].length, 512);
  assert.equal(parseCsvPreview('x'.repeat(513)).truncated, true);
});

test('CSV preview rejects malformed quoting instead of guessing at cell boundaries', () => {
  assert.throws(() => parseCsvPreview('"unterminated'), /CSV|quote/i);
  assert.throws(() => parseCsvPreview('a"b,c'), /CSV|quote/i);
  assert.throws(() => parseCsvPreview('"a"junk,b'), /CSV|quote/i);
});
