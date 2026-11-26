/**
 * CSS tokenizer, following CSS Syntax Module Level 3
 * (https://drafts.csswg.org/css-syntax-3/#tokenization).
 *
 * Security-relevant properties:
 *  - Input is preprocessed (CR/CRLF/FF -> LF, NUL -> U+FFFD) exactly like a
 *    browser, so the token stream matches what the browser will see.
 *  - Comments are consumed during tokenization and produce NO token, so a
 *    keyword split by a comment tokenizes as two separate identifiers — the
 *    same non-url construct a browser sees.
 *  - Escapes are decoded inside identifiers/strings/urls, so `\75 rl(` and
 *    `url(` both produce a url token with the same canonical form. Keyword
 *    comparisons downstream always operate on decoded values.
 */

export type Token =
  | { type: 'ident'; value: string }
  | { type: 'function'; value: string }
  | { type: 'at-keyword'; value: string }
  | { type: 'hash'; value: string; isId: boolean }
  | { type: 'string'; value: string }
  | { type: 'bad-string' }
  | { type: 'url'; value: string }
  | { type: 'bad-url' }
  | { type: 'delim'; value: string }
  | { type: 'number'; value: number; repr: string; isInteger: boolean }
  | { type: 'percentage'; value: number; repr: string }
  | { type: 'dimension'; value: number; repr: string; unit: string }
  | { type: 'unicode-range'; repr: string }
  | { type: 'whitespace' }
  | { type: 'colon' }
  | { type: 'semicolon' }
  | { type: 'comma' }
  | { type: '(' }
  | { type: ')' }
  | { type: '[' }
  | { type: ']' }
  | { type: '{' }
  | { type: '}' }
  | { type: 'CDO' }
  | { type: 'CDC' }
  | { type: 'EOF' };

const EOF = '';
const REPLACEMENT = '�';

function preprocess(input: string): string {
  return input.replace(/\r\n|[\r\f]/g, '\n').replace(/\0/g, REPLACEMENT);
}

const isWhitespace = (c: string): boolean => c === ' ' || c === '\n' || c === '\t';
const isDigit = (c: string): boolean => c >= '0' && c <= '9';
const isHexDigit = (c: string): boolean =>
  isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
const isAsciiLetter = (c: string): boolean =>
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
const isNonAscii = (c: string): boolean => c !== EOF && c.codePointAt(0)! >= 0x80;
const isNameStart = (c: string): boolean =>
  isAsciiLetter(c) || c === '_' || isNonAscii(c);
const isNameChar = (c: string): boolean => isNameStart(c) || isDigit(c) || c === '-';
const isNonPrintable = (c: string): boolean => {
  if (c === EOF) return false;
  const cp = c.codePointAt(0)!;
  return cp <= 0x08 || cp === 0x0b || (cp >= 0x0e && cp <= 0x1f) || cp === 0x7f;
};

export function tokenize(input: string): Token[] {
  const tz = new Tokenizer(input);
  const out: Token[] = [];
  for (;;) {
    const t = tz.nextToken();
    if (t.type === 'EOF') break;
    out.push(t);
  }
  return out;
}

class Tokenizer {
  private readonly s: string[]; // code points
  private pos = 0;

  constructor(input: string) {
    this.s = Array.from(preprocess(input));
  }

  private c(offset = 0): string {
    return this.s[this.pos + offset] ?? EOF;
  }

  /** A valid escape is `\` not followed by a newline (or EOF). */
  private startsValidEscape(offset = 0): boolean {
    if (this.c(offset) !== '\\') return false;
    const next = this.c(offset + 1);
    return next !== '\n' && next !== EOF;
  }

  private startsIdentSequence(offset = 0): boolean {
    const c1 = this.c(offset);
    if (c1 === '-') {
      const c2 = this.c(offset + 1);
      return isNameStart(c2) || c2 === '-' || this.startsValidEscape(offset + 1);
    }
    if (isNameStart(c1)) return true;
    if (c1 === '\\') return this.startsValidEscape(offset);
    return false;
  }

  private startsNumber(offset = 0): boolean {
    const c1 = this.c(offset);
    if (c1 === '+' || c1 === '-') {
      const c2 = this.c(offset + 1);
      return isDigit(c2) || (c2 === '.' && isDigit(this.c(offset + 2)));
    }
    if (c1 === '.') return isDigit(this.c(offset + 1));
    return isDigit(c1);
  }

  /** Assumes current code point is `\` and the escape is valid. */
  private consumeEscapedCodePoint(): string {
    this.pos++; // consume the backslash
    let c = this.c();
    if (isHexDigit(c)) {
      let hex = '';
      while (hex.length < 6 && isHexDigit(this.c())) {
        hex += this.c();
        this.pos++;
      }
      if (isWhitespace(this.c())) this.pos++; // one trailing whitespace is consumed
      const cp = parseInt(hex, 16);
      if (cp === 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return REPLACEMENT;
      return String.fromCodePoint(cp);
    }
    if (c === EOF) return REPLACEMENT;
    this.pos++;
    return c;
  }

  private consumeIdentSequence(): string {
    let result = '';
    for (;;) {
      const c = this.c();
      if (isNameChar(c)) {
        result += c;
        this.pos++;
      } else if (this.startsValidEscape()) {
        result += this.consumeEscapedCodePoint();
      } else {
        return result;
      }
    }
  }

  private consumeNumber(): { value: number; repr: string; isInteger: boolean } {
    let repr = '';
    let isInteger = true;
    if (this.c() === '+' || this.c() === '-') {
      repr += this.c();
      this.pos++;
    }
    while (isDigit(this.c())) {
      repr += this.c();
      this.pos++;
    }
    if (this.c() === '.' && isDigit(this.c(1))) {
      repr += this.c();
      this.pos++;
      while (isDigit(this.c())) {
        repr += this.c();
        this.pos++;
      }
      isInteger = false;
    }
    const e = this.c();
    if (
      (e === 'e' || e === 'E') &&
      (isDigit(this.c(1)) ||
        ((this.c(1) === '+' || this.c(1) === '-') && isDigit(this.c(2))))
    ) {
      repr += this.c();
      this.pos++;
      if (this.c() === '+' || this.c() === '-') {
        repr += this.c();
        this.pos++;
      }
      while (isDigit(this.c())) {
        repr += this.c();
        this.pos++;
      }
      isInteger = false;
    }
    return { value: parseFloat(repr), repr, isInteger };
  }

  private consumeNumericToken(): Token {
    const n = this.consumeNumber();
    if (this.startsIdentSequence()) {
      const unit = this.consumeIdentSequence();
      return { type: 'dimension', value: n.value, repr: n.repr, unit };
    }
    if (this.c() === '%') {
      this.pos++;
      return { type: 'percentage', value: n.value, repr: n.repr };
    }
    return { type: 'number', value: n.value, repr: n.repr, isInteger: n.isInteger };
  }

  private consumeStringToken(ending: string): Token {
    let value = '';
    for (;;) {
      const c = this.c();
      if (c === EOF) return { type: 'string', value }; // parse error: EOF in string
      if (c === ending) {
        this.pos++;
        return { type: 'string', value };
      }
      if (c === '\n') {
        // parse error: newline in string. Do not consume the newline.
        return { type: 'bad-string' };
      }
      if (c === '\\') {
        if (this.c(1) === EOF) {
          this.pos++; // consume backslash; do nothing
        } else if (this.c(1) === '\n') {
          this.pos += 2; // line continuation
        } else {
          value += this.consumeEscapedCodePoint();
        }
      } else {
        value += c;
        this.pos++;
      }
    }
  }

  private consumeUrlToken(): Token {
    let value = '';
    // Consume as much whitespace as possible.
    while (isWhitespace(this.c())) this.pos++;
    for (;;) {
      const c = this.c();
      if (c === EOF) return { type: 'url', value }; // parse error: EOF in url
      if (c === ')') {
        this.pos++;
        return { type: 'url', value };
      }
      if (isWhitespace(c)) {
        while (isWhitespace(this.c())) this.pos++;
        const next = this.c();
        if (next === ')') {
          this.pos++;
          return { type: 'url', value };
        }
        if (next === EOF) return { type: 'url', value }; // parse error
        this.consumeBadUrlRemnants();
        return { type: 'bad-url' };
      }
      if (c === '"' || c === "'" || c === '(' || isNonPrintable(c)) {
        this.consumeBadUrlRemnants();
        return { type: 'bad-url' };
      }
      if (c === '\\') {
        if (this.startsValidEscape()) {
          value += this.consumeEscapedCodePoint();
        } else {
          this.consumeBadUrlRemnants();
          return { type: 'bad-url' };
        }
      } else {
        value += c;
        this.pos++;
      }
    }
  }

  private consumeBadUrlRemnants(): void {
    for (;;) {
      const c = this.c();
      if (c === EOF) return;
      if (c === ')') {
        this.pos++;
        return;
      }
      if (this.startsValidEscape()) {
        this.consumeEscapedCodePoint();
      } else {
        this.pos++;
      }
    }
  }

  private consumeIdentLikeToken(): Token {
    const name = this.consumeIdentSequence();
    if (this.c() !== '(') return { type: 'ident', value: name };
    this.pos++; // consume '('
    if (name.toLowerCase() === 'url') {
      // url( followed by a quote (possibly after one whitespace) is a
      // function token; otherwise it is an unquoted url token.
      while (isWhitespace(this.c()) && isWhitespace(this.c(1))) this.pos++;
      const c0 = this.c();
      const c1 = this.c(1);
      if (
        c0 === '"' ||
        c0 === "'" ||
        (isWhitespace(c0) && (c1 === '"' || c1 === "'"))
      ) {
        return { type: 'function', value: name };
      }
      return this.consumeUrlToken();
    }
    return { type: 'function', value: name };
  }

  private consumeUnicodeRangeToken(): Token {
    const start = this.pos;
    this.pos += 2; // u+
    let consumed = 0;
    let sawQuestion = false;
    while (consumed < 6 && (isHexDigit(this.c()) || this.c() === '?')) {
      if (this.c() === '?') sawQuestion = true;
      this.pos++;
      consumed++;
    }
    if (!sawQuestion && this.c() === '-' && isHexDigit(this.c(1))) {
      this.pos++;
      let n = 0;
      while (n < 6 && isHexDigit(this.c())) {
        this.pos++;
        n++;
      }
    }
    return { type: 'unicode-range', repr: this.s.slice(start, this.pos).join('') };
  }

  nextToken(): Token {
    // Comments are consumed here and produce no token at all.
    for (;;) {
      if (this.c() === '/' && this.c(1) === '*') {
        this.pos += 2;
        while (!(this.c() === '*' && this.c(1) === '/')) {
          if (this.c() === EOF) break; // parse error: EOF in comment
          this.pos++;
        }
        if (this.c() !== EOF) this.pos += 2;
        continue;
      }
      break;
    }

    const c = this.c();
    if (c === EOF) return { type: 'EOF' };
    if (isWhitespace(c)) {
      while (isWhitespace(this.c())) this.pos++;
      return { type: 'whitespace' };
    }
    if (c === '"') {
      this.pos++;
      return this.consumeStringToken('"');
    }
    if (c === "'") {
      this.pos++;
      return this.consumeStringToken("'");
    }
    if (c === '#') {
      if (isNameChar(this.c(1)) || this.startsValidEscape(1)) {
        const isId = this.startsIdentSequence(1);
        this.pos++;
        return { type: 'hash', value: this.consumeIdentSequence(), isId };
      }
      this.pos++;
      return { type: 'delim', value: '#' };
    }
    if (c === '(') {
      this.pos++;
      return { type: '(' };
    }
    if (c === ')') {
      this.pos++;
      return { type: ')' };
    }
    if (c === '+') {
      if (this.startsNumber()) return this.consumeNumericToken();
      this.pos++;
      return { type: 'delim', value: '+' };
    }
    if (c === ',') {
      this.pos++;
      return { type: 'comma' };
    }
    if (c === '-') {
      if (this.startsNumber()) return this.consumeNumericToken();
      if (this.c(1) === '-' && this.c(2) === '>') {
        this.pos += 3;
        return { type: 'CDC' };
      }
      if (this.startsIdentSequence()) return this.consumeIdentLikeToken();
      this.pos++;
      return { type: 'delim', value: '-' };
    }
    if (c === '.') {
      if (this.startsNumber()) return this.consumeNumericToken();
      this.pos++;
      return { type: 'delim', value: '.' };
    }
    if (c === ':') {
      this.pos++;
      return { type: 'colon' };
    }
    if (c === ';') {
      this.pos++;
      return { type: 'semicolon' };
    }
    if (c === '<') {
      if (this.c(1) === '!' && this.c(2) === '-' && this.c(3) === '-') {
        this.pos += 4;
        return { type: 'CDO' };
      }
      this.pos++;
      return { type: 'delim', value: '<' };
    }
    if (c === '@') {
      if (this.startsIdentSequence(1)) {
        this.pos++;
        return { type: 'at-keyword', value: this.consumeIdentSequence() };
      }
      this.pos++;
      return { type: 'delim', value: '@' };
    }
    if (c === '[') {
      this.pos++;
      return { type: '[' };
    }
    if (c === ']') {
      this.pos++;
      return { type: ']' };
    }
    if (c === '{') {
      this.pos++;
      return { type: '{' };
    }
    if (c === '}') {
      this.pos++;
      return { type: '}' };
    }
    if (c === '\\') {
      if (this.startsValidEscape()) return this.consumeIdentLikeToken();
      this.pos++; // parse error: backslash before newline/EOF
      return { type: 'delim', value: '\\' };
    }
    if (isDigit(c)) return this.consumeNumericToken();
    if (
      (c === 'u' || c === 'U') &&
      this.c(1) === '+' &&
      (isHexDigit(this.c(2)) || this.c(2) === '?')
    ) {
      return this.consumeUnicodeRangeToken();
    }
    if (isNameStart(c)) return this.consumeIdentLikeToken();
    this.pos++;
    return { type: 'delim', value: c };
  }
}
