import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tokenize } from '../src/tokenizer.ts';

test('basic ident, number, dimension, percentage', () => {
  const t = tokenize('margin: 1.5px 20% -3 .5e2');
  assert.deepEqual(
    t.map((x) => x.type),
    ['ident', 'colon', 'whitespace', 'dimension', 'whitespace', 'percentage', 'whitespace', 'number', 'whitespace', 'number'],
  );
  const dim = t[3];
  assert.equal(dim.type, 'dimension');
  assert.equal(dim.value, 1.5);
  assert.equal(dim.unit, 'px');
  const num = t[9];
  assert.equal(num.type, 'number');
  assert.equal(num.value, 50);
});

test('escapes are decoded inside identifiers', () => {
  const t = tokenize('.\\66 oo { }');
  assert.equal(t[0].type, 'delim');
  assert.deepEqual(t[1], { type: 'ident', value: 'foo' });
});

test('escape-split url keyword still produces a url token', () => {
  // `u\72 l(...)` decodes to `url(` and must be seen as a url token.
  const t = tokenize('u\\72 l(evil)');
  assert.equal(t.length, 1);
  assert.equal(t[0].type, 'url');
  assert.equal((t[0] as { value: string }).value, 'evil');
});

test('comment-split keyword does NOT become a url token', () => {
  // Browsers see ident + function here; we must see the same.
  const t = tokenize('u/**/rl(evil)');
  assert.deepEqual(
    t.map((x) => x.type),
    ['ident', 'function', 'ident', ')'],
  );
  assert.equal((t[0] as { value: string }).value, 'u');
  assert.equal((t[1] as { value: string }).value, 'rl');
});

test('comments vanish between tokens without creating whitespace', () => {
  const t = tokenize('a/**/b');
  assert.deepEqual(
    t.map((x) => x.type),
    ['ident', 'ident'],
  );
});

test('unterminated comment consumes to EOF', () => {
  const t = tokenize('a /* never closed b');
  assert.deepEqual(
    t.map((x) => x.type),
    ['ident', 'whitespace'],
  );
});

test('quoted url( is a function token, unquoted is a url token', () => {
  const q = tokenize('url("a b")');
  assert.equal(q[0].type, 'function');
  const u = tokenize('url(a%20b)');
  assert.equal(u[0].type, 'url');
  assert.equal((u[0] as { value: string }).value, 'a%20b');
  const spaced = tokenize('url(  "x"  )');
  assert.equal(spaced[0].type, 'function');
});

test('url with escape decodes', () => {
  const t = tokenize('url(j\\61 vascript:x)');
  assert.equal(t[0].type, 'url');
  assert.equal((t[0] as { value: string }).value, 'javascript:x');
});

test('bad url on quote/paren inside unquoted url', () => {
  const t = tokenize('url(a"b) ;');
  assert.equal(t[0].type, 'bad-url');
});

test('bad string on newline, recovery at next token', () => {
  const t = tokenize('"abc\ndef"');
  assert.equal(t[0].type, 'bad-string');
  assert.equal(t[t.length - 1].type, 'string');
});

test('string line continuation', () => {
  const t = tokenize('"a\\\nb"');
  assert.deepEqual(t[0], { type: 'string', value: 'ab' });
});

test('CRLF/CR/FF normalized, NUL replaced', () => {
  const t = tokenize('a\r\nb\rc\fd');
  const idents = t.filter((x) => x.type === 'ident').map((x) => (x as { value: string }).value);
  assert.deepEqual(idents, ['a', 'b', 'c', 'd']);
  const nul = tokenize('\0');
  assert.equal((nul[0] as { value: string }).value, '�');
});

test('at-keyword, hash, CDO/CDC', () => {
  const t = tokenize('@media <!-- #x -->');
  assert.equal(t[0].type, 'at-keyword');
  assert.equal(t[2].type, 'CDO');
  assert.equal(t[4].type, 'hash');
  assert.equal(t[6].type, 'CDC');
});

test('unicode-range token', () => {
  const t = tokenize('U+0025-00FF U+4??');
  assert.equal(t[0].type, 'unicode-range');
  assert.equal((t[0] as { repr: string }).repr, 'U+0025-00FF');
  assert.equal(t[2].type, 'unicode-range');
});

test('exponent and signed numbers', () => {
  const t = tokenize('1e+3 -2.5E-1');
  assert.equal((t[0] as { value: number }).value, 1000);
  assert.equal((t[2] as { value: number }).value, -0.25);
});

test('custom property name is an ident token', () => {
  const t = tokenize('--theme-color');
  assert.deepEqual(t[0], { type: 'ident', value: '--theme-color' });
});
