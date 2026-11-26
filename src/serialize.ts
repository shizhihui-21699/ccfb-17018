/**
 * Canonical CSS serializer.
 *
 * Two security-relevant properties:
 *  - Identifiers/strings/urls are re-emitted in canonical escaped form, so
 *    obfuscated input like `\75 rl(evil)` comes out as plain `url("evil")`
 *    (and would already have been judged by the sanitizer before this).
 *  - When two adjacent tokens would merge into a different token if emitted
 *    back-to-back (e.g. ident `url` + paren block, which the input spelled
 *    with a comment between them), a comment separator is inserted so
 *    serialization never *creates* constructs the sanitizer did not see.
 */

import type { ComponentValue, Declaration, BlockItem, Rule } from './parser.ts';
import { isBlockValue, isFunctionValue } from './parser.ts';

export function serializeIdentifier(value: string): string {
  const chars = Array.from(value);
  let out = '';
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    const cp = ch.codePointAt(0)!;
    if (cp === 0) {
      out += '�';
    } else if ((cp >= 0x01 && cp <= 0x1f) || cp === 0x7f) {
      out += `\\${cp.toString(16)} `;
    } else if (i === 0 && cp >= 0x30 && cp <= 0x39) {
      out += `\\${cp.toString(16)} `;
    } else if (i === 0 && ch === '-' && chars.length === 1) {
      out += '\\-';
    } else if (i === 1 && cp >= 0x30 && cp <= 0x39 && chars[0] === '-') {
      out += `\\${cp.toString(16)} `;
    } else if (
      cp >= 0x80 ||
      ch === '-' ||
      ch === '_' ||
      (cp >= 0x30 && cp <= 0x39) ||
      (cp >= 0x41 && cp <= 0x5a) ||
      (cp >= 0x61 && cp <= 0x7a)
    ) {
      out += ch;
    } else {
      out += `\\${ch}`;
    }
  }
  return out;
}

/** Like serializeIdentifier but without leading-digit rules (for hashes). */
function serializeName(value: string): string {
  let out = '';
  for (const ch of Array.from(value)) {
    const cp = ch.codePointAt(0)!;
    if (
      cp >= 0x80 ||
      ch === '-' ||
      ch === '_' ||
      (cp >= 0x30 && cp <= 0x39) ||
      (cp >= 0x41 && cp <= 0x5a) ||
      (cp >= 0x61 && cp <= 0x7a)
    ) {
      out += ch;
    } else if ((cp >= 0x01 && cp <= 0x1f) || cp === 0x7f) {
      out += `\\${cp.toString(16)} `;
    } else {
      out += `\\${ch}`;
    }
  }
  return out;
}

export function serializeStringValue(value: string): string {
  let out = '"';
  for (const ch of Array.from(value)) {
    if (ch === '"' || ch === '\\') out += `\\${ch}`;
    else if (ch === '\n') out += '\\a ';
    else out += ch;
  }
  return out + '"';
}

function serializeUrlValue(value: string): string {
  return `url(${serializeStringValue(value)})`;
}

function serializeToken(t: ComponentValue): string {
  if (isFunctionValue(t)) {
    return `${serializeIdentifier(t.name)}(${serializeComponentValues(t.value)})`;
  }
  if (isBlockValue(t)) {
    const close = t.start === '{' ? '}' : t.start === '[' ? ']' : ')';
    return `${t.start}${serializeComponentValues(t.value)}${close}`;
  }
  switch (t.type) {
    case 'ident':
      return serializeIdentifier(t.value);
    case 'function':
      return serializeIdentifier(t.value) + '(';
    case 'at-keyword':
      return '@' + serializeIdentifier(t.value);
    case 'hash':
      return '#' + (t.isId ? serializeIdentifier(t.value) : serializeName(t.value));
    case 'string':
      return serializeStringValue(t.value);
    case 'url':
      return serializeUrlValue(t.value);
    case 'bad-string':
    case 'bad-url':
      return ''; // never survives sanitization; emit nothing
    case 'delim':
      return t.value === '\\' ? '\\\\' : t.value;
    case 'number':
    case 'percentage':
      return t.type === 'number' ? t.repr : `${t.repr}%`;
    case 'dimension':
      return t.repr + serializeIdentifier(t.unit);
    case 'unicode-range':
      return t.repr;
    case 'whitespace':
      return ' ';
    case 'colon':
      return ':';
    case 'semicolon':
      return ';';
    case 'comma':
      return ',';
    case '(':
    case ')':
    case '[':
    case ']':
    case '{':
    case '}':
      return t.type;
    case 'CDO':
      return '<!--';
    case 'CDC':
      return '-->';
    case 'EOF':
      return '';
  }
}

const NAME_CHAR = /[\-a-zA-Z0-9_\u0080-\uFFFF]/;

/** Would emitting `a` immediately followed by `b` re-tokenize differently? */
function needsSeparator(a: string, b: string): boolean {
  const last = a[a.length - 1];
  const first = b[0];
  if (!last || !first) return false;
  if (last === ' ' || first === ' ') return false;
  // ident-ish + ident-ish/`(` merges (e.g. `url` + `(` -> url token)
  if (NAME_CHAR.test(last) && (NAME_CHAR.test(first) || first === '(')) return true;
  // `1` + `.5` -> single number
  if (/[0-9]/.test(last) && first === '.') return true;
  // `@`/`#` delim + ident -> at-keyword/hash
  if ((last === '@' || last === '#') && NAME_CHAR.test(first)) return true;
  // `+`/`-` delim + number -> signed number; `--` -> ident/CDC start
  if ((last === '+' || last === '-') && /[0-9.]/.test(first)) return true;
  if (last === '-' && first === '-') return true;
  // `<` + `!--` -> CDO
  if (last === '<' && first === '!') return true;
  // `/` + `*` -> comment start
  if (last === '/' && first === '*') return true;
  return false;
}

export function serializeComponentValues(values: ComponentValue[]): string {
  let out = '';
  for (const v of values) {
    const s = serializeToken(v);
    if (out && needsSeparator(out, s)) out += '/**/';
    out += s;
  }
  return out;
}

function serializeDeclaration(d: Declaration, indent: string): string {
  const value = serializeComponentValues(d.value).trim();
  const important = d.important ? ' !important' : '';
  return `${indent}${d.name}: ${value}${important};`;
}

export function serializeRule(rule: Rule, level = 0): string {
  const indent = '  '.repeat(level);
  if (rule.kind === 'at') {
    const prelude = serializeComponentValues(rule.prelude).trim();
    const head = `${indent}@${serializeIdentifier(rule.name)}${prelude ? ' ' + prelude : ''}`;
    if (rule.block === null) return `${head};`;
    const body = serializeBlockItems(rule.block, level + 1);
    return body ? `${head} {\n${body}\n${indent}}` : `${head} {}`;
  }
  const selector = serializeComponentValues(rule.prelude).trim();
  const body = serializeBlockItems(rule.block, level + 1);
  return body ? `${indent}${selector} {\n${body}\n${indent}}` : `${indent}${selector} {}`;
}

function serializeBlockItems(items: BlockItem[], level: number): string {
  const indent = '  '.repeat(level);
  const parts: string[] = [];
  for (const item of items) {
    if (item.kind === 'declaration') parts.push(serializeDeclaration(item, indent));
    else parts.push(serializeRule(item, level));
  }
  return parts.join('\n');
}

export function serializeStylesheet(rules: Rule[]): string {
  return rules.map((r) => serializeRule(r, 0)).join('\n') + '\n';
}
