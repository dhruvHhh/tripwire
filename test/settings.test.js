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

test('toolbarBadge: a listed page is always red', () => {
  const red = { color: '#d93025', textColor: '#ffffff' };
  // No red links to count: an exclamation mark.
  assert.deepEqual(toolbarBadge({ dangerous: 0, suspicious: 0, pageListed: true }), { text: '!', ...red });
  // Amber links alone would have been amber; the listing wins.
  assert.deepEqual(toolbarBadge({ dangerous: 0, suspicious: 7, pageListed: true }), { text: '!', ...red });
  // Red links: their count, as usual.
  assert.deepEqual(toolbarBadge({ dangerous: 4, suspicious: 7, pageListed: true }), { text: '4', ...red });
  assert.equal(toolbarBadge({ dangerous: 250, pageListed: true }).text, '99+');
  // Not listed: unchanged behaviour.
  assert.equal(toolbarBadge({ dangerous: 0, suspicious: 0, pageListed: false }).text, '');
  assert.equal(toolbarBadge({ dangerous: 0, suspicious: 7, pageListed: false }).color, '#f9ab00');
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

const { listSiteModes, isFirstInstall, MODE_DESCRIPTIONS, WELCOME_PAGE } = require('../src/lib/settings.js');

test('listSiteModes: reads site settings out of a storage dump, by name', () => {
  const stored = {
    defaultMode: 'all',
    'site:zebra.example': 'off',
    'site:apple.example': 'click',
    'site:broken.example': 'nonsense',
    'site:': 'all',
    'trust:apple.example': { addedAt: 1 },
  };
  assert.deepEqual(listSiteModes(stored), [
    { hostname: 'apple.example', mode: 'click' },
    { hostname: 'zebra.example', mode: 'off' },
  ]);
  assert.deepEqual(listSiteModes({}), []);
  assert.deepEqual(listSiteModes(undefined), []);
});

test('isFirstInstall: the welcome page opens on a first install only', () => {
  const cases = [
    [{ reason: 'install' }, true],
    [{ reason: 'update', previousVersion: '0.5.1' }, false],
    [{ reason: 'chrome_update' }, false],
    [{ reason: 'shared_module_update' }, false],
    [{}, false],
    [undefined, false],
    [null, false],
  ];
  for (const [details, expected] of cases) {
    assert.equal(isFirstInstall(details), expected, JSON.stringify(details));
  }
});

test('every mode has a description, and the welcome page exists', () => {
  assert.deepEqual(Object.keys(MODE_DESCRIPTIONS).sort(), Object.keys(MODES).sort());
  const fs = require('node:fs');
  const path = require('node:path');
  assert.ok(fs.existsSync(path.join(__dirname, '..', WELCOME_PAGE)));
});
