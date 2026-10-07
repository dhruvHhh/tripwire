// Run with: node --test

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  MODES,
  DEFAULT_MODE,
  resolveMode,
  resolveDefaultMode,
  shouldDisplay,
  toolbarBadge,
  siteKey,
} = require('../src/lib/settings.js');

test('the default mode is "risky"', () => {
  assert.equal(DEFAULT_MODE, 'risky');
  assert.equal(resolveMode(), 'risky');
  assert.equal(resolveMode({}), 'risky');
});

test('resolveMode: a site override beats the global default', () => {
  const cases = [
    [{ defaultMode: 'risky', siteMode: 'all' }, 'all'],
    [{ defaultMode: 'all', siteMode: 'risky' }, 'risky'],
    [{ defaultMode: 'all', siteMode: 'off' }, 'off'],
    [{ defaultMode: 'click', siteMode: undefined }, 'click'],
    [{ defaultMode: 'all' }, 'all'],
    // Unknown values fall back instead of breaking the page.
    [{ defaultMode: 'nonsense', siteMode: 'also nonsense' }, 'risky'],
    [{ defaultMode: 'all', siteMode: 42 }, 'all'],
    // "off" is per-site only.
    [{ defaultMode: 'off' }, 'risky'],
  ];
  for (const [input, expected] of cases) {
    assert.equal(resolveMode(input), expected, JSON.stringify(input));
  }
});

test('resolveDefaultMode never returns "off"', () => {
  assert.equal(resolveDefaultMode('off'), 'risky');
  assert.equal(resolveDefaultMode('click'), 'click');
  assert.equal(resolveDefaultMode(undefined), 'risky');
});

test('shouldDisplay: which levels get a badge in each mode', () => {
  //            mode     revealed  ok     suspicious  dangerous
  const table = [
    ['risky', false, false, true, true],
    ['all', false, true, true, true],
    ['click', false, false, false, false],
    ['off', false, false, false, false],
    // The popup's one-off reveal shows everything...
    ['risky', true, true, true, true],
    ['click', true, true, true, true],
    // ...except on a site that is switched off.
    ['off', true, false, false, false],
  ];
  for (const [mode, revealed, ok, suspicious, dangerous] of table) {
    const label = `${mode}${revealed ? ' (revealed)' : ''}`;
    assert.equal(shouldDisplay('ok', mode, revealed), ok, `${label}: ok`);
    assert.equal(shouldDisplay('suspicious', mode, revealed), suspicious, `${label}: suspicious`);
    assert.equal(shouldDisplay('dangerous', mode, revealed), dangerous, `${label}: dangerous`);
  }
});

test('every mode has a label', () => {
  assert.deepEqual(Object.keys(MODES), ['risky', 'all', 'click', 'off']);
  for (const label of Object.values(MODES)) assert.ok(label.length > 0);
});

test('toolbarBadge: red count wins, then amber, then nothing', () => {
  assert.deepEqual(toolbarBadge({ dangerous: 3, suspicious: 7 }), { text: '3', color: '#d93025', textColor: '#ffffff' });
  assert.deepEqual(toolbarBadge({ dangerous: 0, suspicious: 7 }), { text: '7', color: '#f9ab00', textColor: '#202124' });
  assert.deepEqual(toolbarBadge({ dangerous: 0, suspicious: 0 }), { text: '', color: null, textColor: null });
  assert.equal(toolbarBadge().text, '');
});

test('toolbarBadge caps large counts', () => {
  assert.equal(toolbarBadge({ dangerous: 99 }).text, '99');
  assert.equal(toolbarBadge({ dangerous: 100 }).text, '99+');
  assert.equal(toolbarBadge({ suspicious: 2500 }).text, '99+');
});

test('siteKey is per hostname and case-insensitive', () => {
  assert.equal(siteKey('Example.COM'), 'site:example.com');
  assert.notEqual(siteKey('a.example.com'), siteKey('b.example.com'));
});
