import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseStylesheet } from '../src/parser.ts';
import { tokenize } from '../src/tokenizer.ts';
import { serializeStylesheet } from '../src/serialize.ts';
import { isBlockValue } from '../src/parser.ts';
import type { AtRule, Declaration, QualifiedRule } from '../src/parser.ts';

const parse = (css: string) => parseStylesheet(tokenize(css));

test('simple rule with declarations', () => {
  const sheet = parse('a { color: red; margin: 0 }');
  assert.equal(sheet.rules.length, 1);
  const rule = sheet.rules[0] as QualifiedRule;
  assert.equal(rule.kind, 'qualified');
  const decls = rule.block.filter((i) => i.kind === 'declaration') as Declaration[];
  assert.equal(decls.length, 2);
  assert.equal(decls[0].name, 'color');
  assert.equal(decls[1].name, 'margin');
});

test('important detection, case-insensitive, comment-split', () => {
  const sheet = parse('a { color: red !/**/ IMPORTANT }');
  const rule = sheet.rules[0] as QualifiedRule;
  const decl = rule.block[0] as Declaration;
  assert.equal(decl.important, true);
});

test('custom property with block value', () => {
  const sheet = parse(':root { --x: { color: red }; color: blue }');
  const rule = sheet.rules[0] as QualifiedRule;
  const decls = rule.block.filter((i) => i.kind === 'declaration') as Declaration[];
  assert.equal(decls.length, 2);
  assert.equal(decls[0].name, '--x');
  assert.ok(isBlockValue(decls[0].value[0]));
});

test('invalid declaration dropped, siblings survive', () => {
  const sheet = parse('a { color red; background: blue; }');
  const rule = sheet.rules[0] as QualifiedRule;
  const decls = rule.block.filter((i) => i.kind === 'declaration') as Declaration[];
  assert.equal(decls.length, 1);
  assert.equal(decls[0].name, 'background');
});

test('nested type-selector rule inside style rule', () => {
  const sheet = parse('.card { color: red; div { margin: 0 } &:hover { color: blue } }');
  const rule = sheet.rules[0] as QualifiedRule;
  assert.equal(rule.block.length, 3);
  assert.equal(rule.block[0].kind, 'declaration');
  assert.equal(rule.block[1].kind, 'qualified');
  assert.equal(rule.block[2].kind, 'qualified');
});

test('@media with nested rules', () => {
  const sheet = parse('@media (min-width: 100px) { a { color: red } }');
  const at = sheet.rules[0] as AtRule;
  assert.equal(at.kind, 'at');
  assert.equal(at.name, 'media');
  assert.equal(at.block!.length, 1);
  assert.equal(at.block![0].kind, 'qualified');
});

test('@keyframes parses keyframe blocks as qualified rules', () => {
  const sheet = parse('@keyframes spin { from { transform: rotate(0) } 50% { opacity: .5 } to { transform: rotate(360deg) } }');
  const at = sheet.rules[0] as AtRule;
  assert.equal(at.name, 'keyframes');
  assert.equal(at.block!.length, 3);
  assert.equal(at.block![1].kind, 'qualified');
});

test('@import without block', () => {
  const sheet = parse('@import url("x.css"); a { color: red }');
  const at = sheet.rules[0] as AtRule;
  assert.equal(at.name, 'import');
  assert.equal(at.block, null);
  assert.equal(sheet.rules.length, 2);
});

test('unclosed constructs auto-close at EOF', () => {
  const sheet = parse('a { color: red; background: url(x');
  const rule = sheet.rules[0] as QualifiedRule;
  const decls = rule.block.filter((i) => i.kind === 'declaration') as Declaration[];
  assert.equal(decls.length, 2);
});

test('stray semicolons and whitespace are skipped', () => {
  const sheet = parse(';; a { ; color: red;; } ;');
  assert.equal(sheet.rules.length, 1);
});

test('round-trip: parse + serialize preserves typical css', () => {
  const css = '@media (min-width: 100px) {\n  a:hover { color: red; }\n}\n';
  const out = serializeStylesheet(parse(css).rules);
  const reparsed = parse(out);
  assert.equal(serializeStylesheet(reparsed.rules), out);
});

test('serializer never merges comment-separated tokens into url(', () => {
  // `url/**/(x)` is ident + paren block, NOT a url. Serialization must not
  // create `url(x)`.
  const out = serializeStylesheet(parse('a { background: url/**/(x) }').rules);
  assert.ok(!out.includes('url(x)'), out);
  assert.ok(out.includes('url/**/(x)'), out);
});

test('escape-obfuscated identifiers serialize in canonical form', () => {
  const out = serializeStylesheet(parse('.\\66 oo { color: red }').rules);
  assert.ok(out.startsWith('.foo'), out);
});
