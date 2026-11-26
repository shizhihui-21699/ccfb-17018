/**
 * CSS parser, following CSS Syntax Module Level 3
 * (https://drafts.csswg.org/css-syntax-3/#parsing) with the CSS Nesting
 * "mixed block" content model (declarations + nested rules in one block).
 *
 * Error tolerance matches browsers:
 *  - EOF auto-closes any open block/string/rule.
 *  - An invalid declaration is dropped without affecting its siblings.
 *  - An ident-starting block item is first tried as a declaration; if it has
 *    no top-level colon but contains a `{}` block it is reparsed as a nested
 *    qualified rule (this is how `div { ... }` nesting works).
 */

import type { Token } from './tokenizer.ts';

export interface FunctionValue {
  kind: 'function';
  name: string;
  value: ComponentValue[];
}

export interface BlockValue {
  kind: 'block';
  start: '{' | '[' | '(';
  value: ComponentValue[];
}

export type ComponentValue = Token | FunctionValue | BlockValue;

export interface Declaration {
  kind: 'declaration';
  name: string;
  value: ComponentValue[];
  important: boolean;
}

export interface QualifiedRule {
  kind: 'qualified';
  prelude: ComponentValue[];
  block: BlockItem[];
}

export interface AtRule {
  kind: 'at';
  name: string;
  prelude: ComponentValue[];
  block: BlockItem[] | null;
}

export type Rule = QualifiedRule | AtRule;
export type BlockItem = Declaration | Rule;

export interface Stylesheet {
  rules: Rule[];
}

export const isToken = (cv: ComponentValue): cv is Token => !('kind' in cv);
export const isFunctionValue = (cv: ComponentValue): cv is FunctionValue =>
  'kind' in cv && cv.kind === 'function';
export const isBlockValue = (cv: ComponentValue): cv is BlockValue =>
  'kind' in cv && cv.kind === 'block';
export const isBraceBlock = (cv: ComponentValue): cv is BlockValue =>
  isBlockValue(cv) && cv.start === '{';

const EOF_TOKEN: Token = { type: 'EOF' };

export function parseStylesheet(tokens: Token[]): Stylesheet {
  const p = new Parser(tokens);
  const rules: Rule[] = [];
  for (;;) {
    p.skipWhitespace();
    const t = p.peek();
    if (t.type === 'EOF') break;
    if (t.type === 'CDO' || t.type === 'CDC') {
      p.next();
      continue;
    }
    if (t.type === 'at-keyword') {
      const r = p.consumeAtRule();
      if (r) rules.push(r);
      continue;
    }
    const r = p.consumeQualifiedRule();
    if (r) rules.push(r);
  }
  return { rules };
}

class Parser {
  private pos = 0;
  private readonly tokens: Token[];
  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  peek(): Token {
    return this.tokens[this.pos] ?? EOF_TOKEN;
  }

  next(): Token {
    const t = this.tokens[this.pos] ?? EOF_TOKEN;
    if (this.pos < this.tokens.length) this.pos++;
    return t;
  }

  skipWhitespace(): void {
    while (this.peek().type === 'whitespace') this.pos++;
  }

  private static readonly BLOCK_END: Record<string, string> = {
    '(': ')',
    '[': ']',
    '{': '}',
  };

  consumeComponentValue(): ComponentValue {
    const t = this.next();
    if (t.type === '(' || t.type === '[' || t.type === '{') {
      const end = Parser.BLOCK_END[t.type];
      const value: ComponentValue[] = [];
      for (;;) {
        const n = this.peek();
        if (n.type === 'EOF') break; // parse error: EOF auto-closes
        if (n.type === end) {
          this.next();
          break;
        }
        value.push(this.consumeComponentValue());
      }
      return { kind: 'block', start: t.type, value };
    }
    if (t.type === 'function') {
      const value: ComponentValue[] = [];
      for (;;) {
        const n = this.peek();
        if (n.type === 'EOF') break;
        if (n.type === ')') {
          this.next();
          break;
        }
        value.push(this.consumeComponentValue());
      }
      return { kind: 'function', name: t.value, value };
    }
    return t;
  }

  consumeAtRule(): AtRule | null {
    const at = this.next();
    if (at.type !== 'at-keyword') return null;
    const prelude: ComponentValue[] = [];
    for (;;) {
      const t = this.peek();
      if (t.type === 'EOF') return { kind: 'at', name: at.value, prelude, block: null };
      if (t.type === 'semicolon') {
        this.next();
        return { kind: 'at', name: at.value, prelude, block: null };
      }
      if (t.type === '{') {
        this.next();
        return {
          kind: 'at',
          name: at.value,
          prelude,
          block: this.consumeMixedBlock(),
        };
      }
      prelude.push(this.consumeComponentValue());
    }
  }

  consumeQualifiedRule(): QualifiedRule | null {
    const prelude: ComponentValue[] = [];
    for (;;) {
      const t = this.peek();
      if (t.type === 'EOF') return null; // parse error: rule without block
      if (t.type === '{') {
        this.next();
        return { kind: 'qualified', prelude, block: this.consumeMixedBlock() };
      }
      prelude.push(this.consumeComponentValue());
    }
  }

  /** Block contents: a mix of declarations, nested rules and at-rules. */
  consumeMixedBlock(): BlockItem[] {
    const items: BlockItem[] = [];
    for (;;) {
      const t = this.peek();
      if (t.type === 'EOF') return items;
      if (t.type === '}') {
        this.next();
        return items;
      }
      if (t.type === 'whitespace' || t.type === 'semicolon') {
        this.next();
        continue;
      }
      if (t.type === 'at-keyword') {
        const r = this.consumeAtRule();
        if (r) items.push(r);
        continue;
      }
      if (t.type === 'ident') {
        const mark = this.pos;
        const attempt = this.tryConsumeDeclaration();
        if (attempt.declaration) {
          items.push(attempt.declaration);
          continue;
        }
        if (attempt.sawBraceBlock) {
          // e.g. `div { ... }` nested inside a style rule
          this.pos = mark;
          const r = this.consumeQualifiedRule();
          if (r) items.push(r);
          continue;
        }
        // Invalid declaration: already skipped past `;` (or at block end).
        continue;
      }
      // Anything else starts a nested qualified rule (e.g. `&:hover`, `.x`).
      const r = this.consumeQualifiedRule();
      if (r) items.push(r);
    }
  }

  /**
   * Consumes tokens up to `;` / block end / EOF. Returns the declaration if
   * it is well-formed (ident name + colon), otherwise reports whether the
   * consumed region contained a top-level `{}` block (nested-rule signal).
   */
  private tryConsumeDeclaration(): {
    declaration: Declaration | null;
    sawBraceBlock: boolean;
  } {
    const nameTok = this.next();
    if (nameTok.type !== 'ident') return { declaration: null, sawBraceBlock: false };

    // Skip whitespace between name and colon.
    while (this.peek().type === 'whitespace') this.next();
    if (this.peek().type !== 'colon') {
      // Not a declaration. Consume the rest of this "declaration-like" region
      // so the parser recovers at the next `;` or the end of the block.
      let sawBraceBlock = false;
      for (;;) {
        const t = this.peek();
        if (t.type === 'EOF') break;
        if (t.type === '}') break;
        if (t.type === 'semicolon') {
          this.next();
          break;
        }
        const cv = this.consumeComponentValue();
        if (isBraceBlock(cv)) sawBraceBlock = true;
      }
      return { declaration: null, sawBraceBlock };
    }
    this.next(); // consume ':'

    const value: ComponentValue[] = [];
    let sawBraceBlock = false;
    for (;;) {
      const t = this.peek();
      if (t.type === 'EOF') break;
      if (t.type === '}') break;
      if (t.type === 'semicolon') {
        this.next();
        break;
      }
      const cv = this.consumeComponentValue();
      if (isBraceBlock(cv)) sawBraceBlock = true;
      value.push(cv);
    }

    // Trim trailing whitespace, then detect `!important`.
    while (value.length && isToken(value[value.length - 1]) && (value[value.length - 1] as Token).type === 'whitespace') value.pop();
    let important = false;
    if (value.length >= 2) {
      const last = value[value.length - 1];
      if (isToken(last) && last.type === 'ident' && last.value.toLowerCase() === 'important') {
        let j = value.length - 2;
        while (j >= 0 && isToken(value[j]) && (value[j] as Token).type === 'whitespace') j--;
        const bang = j >= 0 ? value[j] : null;
        if (bang && isToken(bang) && bang.type === 'delim' && bang.value === '!') {
          important = true;
          value.length = j;
          while (value.length && isToken(value[value.length - 1]) && (value[value.length - 1] as Token).type === 'whitespace') value.pop();
        }
      }
    }
    // Trim leading whitespace.
    while (value.length && isToken(value[0]) && (value[0] as Token).type === 'whitespace') value.shift();

    return {
      declaration: { kind: 'declaration', name: nameTok.value, value, important },
      sawBraceBlock,
    };
  }
}
