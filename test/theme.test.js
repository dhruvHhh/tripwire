// Run with: node --test

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { TOKENS, CONTRAST_PAIRS, contrast, declarations } = require('../src/lib/theme.js');

const root = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

// The custom properties declared in one CSS block.
const tokensIn = (block) =>
  Object.fromEntries([...block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})\s*;/g)].map((match) => [match[1], match[2]]));

test('light and dark define the same tokens, as six-digit hex colours', () => {
  assert.deepEqual(Object.keys(TOKENS.dark), Object.keys(TOKENS.light));
  for (const theme of ['light', 'dark']) {
    for (const [name, value] of Object.entries(TOKENS[theme])) {
      assert.match(value, /^#[0-9a-f]{6}$/, `${theme} ${name}`);
    }
  }
});

test('contrast: the WCAG formula', () => {
  assert.equal(Math.round(contrast('#000000', '#ffffff')), 21);
  assert.equal(contrast('#777777', '#777777'), 1);
  assert.equal(contrast('#ffffff', '#000000'), contrast('#000000', '#ffffff'));
  // A well-known boundary: #767676 on white is the lightest grey that passes AA.
  assert.ok(contrast('#767676', '#ffffff') >= 4.5);
  assert.ok(contrast('#777777', '#ffffff') < 4.5);
});

test('every colour pairing meets WCAG AA in both themes', () => {
  for (const theme of ['light', 'dark']) {
    for (const [foreground, background, minimum, use] of CONTRAST_PAIRS) {
      const ratio = contrast(TOKENS[theme][foreground], TOKENS[theme][background]);
      assert.ok(
        ratio >= minimum,
        `${theme}: ${use} (${foreground} on ${background}) is ${ratio.toFixed(2)}:1, needs ${minimum}:1`,
      );
    }
  }
});

test('the contrast list covers every token', () => {
  const checked = new Set(CONTRAST_PAIRS.flatMap(([foreground, background]) => [foreground, background]));
  // `line` is a hairline between rows: decoration, not something to read.
  const unchecked = Object.keys(TOKENS.light).filter((name) => !checked.has(name) && name !== 'line');
  assert.deepEqual(unchecked, []);
});

test('the logo red is not used for text: it fails AA on white', () => {
  assert.ok(contrast('#fd3833', '#ffffff') < 4.5);
  assert.ok(contrast(TOKENS.light['danger-text'], '#ffffff') >= 4.5);
});

test('src/ui/theme.css has the same colours as src/lib/theme.js', () => {
  const css = read('src/ui/theme.css');
  const darkStart = css.indexOf('@media (prefers-color-scheme: dark)');
  assert.ok(darkStart > 0, 'theme.css has a dark block');
  const lightBlock = css.slice(css.indexOf(':root'), darkStart);
  const darkBlock = css.slice(darkStart, css.indexOf('}', css.indexOf('}', darkStart)) + 1);

  assert.deepEqual(tokensIn(lightBlock), TOKENS.light);
  assert.deepEqual(tokensIn(darkBlock), TOKENS.dark);
});

test('every var() in the stylesheets and the overlay names a real token', () => {
  const files = ['src/ui/theme.css', 'src/ui/page.css', 'src/popup/popup.css', 'src/content/styles.js'];
  for (const file of files) {
    for (const [, name] of read(file).matchAll(/var\(--([a-z-]+)\)/g)) {
      assert.ok(name in TOKENS.light, `${file} uses --${name}, which is not a token`);
    }
  }
});

test('declarations: one custom property per token', () => {
  const css = declarations('dark');
  assert.deepEqual(tokensIn(css), TOKENS.dark);
  assert.ok(css.includes('--danger-text: #ff8078;'));
});
