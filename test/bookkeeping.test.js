// Run with: node --test

const test = require('node:test');
const assert = require('node:assert/strict');

const { createTally, createBoundedCache, sameVerdict } = require('../src/lib/bookkeeping.js');
const { toolbarBadge } = require('../src/lib/settings.js');

const A = 'https://a.example/';
const B = 'https://b.example/';

test('tally: starts empty', () => {
  assert.deepEqual(createTally().summary(), { scanned: 0, ok: 0, suspicious: 0, dangerous: 0 });
});

test('tally: a grouped pair (same address, same verdict) is one destination', () => {
  const tally = createTally();
  tally.add(A, 'dangerous'); // result title
  tally.add(A, 'dangerous'); // its URL line
  assert.deepEqual(tally.summary(), { scanned: 2, ok: 0, suspicious: 0, dangerous: 1 });
});

test('tally: different addresses count separately', () => {
  const tally = createTally();
  tally.add(A, 'dangerous');
  tally.add(B, 'dangerous');
  assert.equal(tally.summary().dangerous, 2);
});

test('tally: the same address with two verdicts counts under each', () => {
  // Same href, but one link's text names a different domain.
  const tally = createTally();
  tally.add(A, 'ok');
  tally.add(A, 'suspicious');
  assert.deepEqual(tally.summary(), { scanned: 2, ok: 1, suspicious: 1, dangerous: 0 });
});

test('tally: a destination stays counted until its last link is removed', () => {
  const tally = createTally();
  tally.add(A, 'suspicious');
  tally.add(A, 'suspicious');
  tally.add(A, 'suspicious');

  tally.remove(A, 'suspicious');
  assert.deepEqual(tally.summary(), { scanned: 2, ok: 0, suspicious: 1, dangerous: 0 });
  tally.remove(A, 'suspicious');
  assert.equal(tally.summary().suspicious, 1);
  tally.remove(A, 'suspicious');
  assert.deepEqual(tally.summary(), { scanned: 0, ok: 0, suspicious: 0, dangerous: 0 });
});

test('tally: a link whose href turns bad moves between levels', () => {
  const tally = createTally();
  tally.add(A, 'ok');
  // The scanner removes the old entry, then adds the new one.
  tally.remove(A, 'ok');
  tally.add(B, 'dangerous');
  assert.deepEqual(tally.summary(), { scanned: 1, ok: 0, suspicious: 0, dangerous: 1 });
});

test('tally: removing something never added changes nothing', () => {
  const tally = createTally();
  tally.add(A, 'ok');
  tally.remove(B, 'ok');
  tally.remove(A, 'dangerous');
  tally.remove(A, 'no-such-level');
  assert.deepEqual(tally.summary(), { scanned: 1, ok: 1, suspicious: 0, dangerous: 0 });
});

test('tally: adding an unknown level is ignored', () => {
  const tally = createTally();
  tally.add(A, 'unknown');
  assert.equal(tally.summary().scanned, 0);
});

test('tally: clear', () => {
  const tally = createTally();
  tally.add(A, 'ok');
  tally.add(B, 'dangerous');
  tally.clear();
  assert.deepEqual(tally.summary(), { scanned: 0, ok: 0, suspicious: 0, dangerous: 0 });
});

test('tally: survives a long churn of adds and removes without drifting', () => {
  const tally = createTally();
  const live = [];
  for (let round = 0; round < 2000; round++) {
    const entry = [`https://site${round % 37}.example/`, ['ok', 'suspicious', 'dangerous'][round % 3]];
    tally.add(...entry);
    live.push(entry);
    if (round % 2 === 1) tally.remove(...live.shift());
  }
  for (const entry of live) tally.remove(...entry);
  assert.deepEqual(tally.summary(), { scanned: 0, ok: 0, suspicious: 0, dangerous: 0 });
});

test('toolbar count uses distinct destinations, red before amber', () => {
  const tally = createTally();
  for (let i = 0; i < 5; i++) tally.add(A, 'dangerous'); // five links, one destination
  tally.add(B, 'suspicious');
  assert.equal(toolbarBadge(tally.summary()).text, '1');

  tally.clear();
  tally.add(A, 'suspicious');
  tally.add(A, 'suspicious');
  tally.add(B, 'suspicious');
  assert.deepEqual(toolbarBadge(tally.summary()), { text: '2', color: '#f9ab00', textColor: '#202124' });
});

test('bounded cache: get and set', () => {
  const cache = createBoundedCache(3);
  assert.equal(cache.get('missing'), undefined);
  cache.set('a', 1);
  assert.equal(cache.get('a'), 1);
  cache.set('a', 2);
  assert.equal(cache.get('a'), 2);
  assert.equal(cache.size, 1);
});

test('bounded cache: never holds more than its limit', () => {
  const cache = createBoundedCache(100);
  for (let i = 0; i < 10000; i++) cache.set(`key${i}`, i);
  assert.equal(cache.size, 100);
  assert.equal(cache.get('key9999'), 9999);
  assert.equal(cache.get('key0'), undefined);
});

test('bounded cache: evicts the least recently used entry', () => {
  const cache = createBoundedCache(3);
  cache.set('a', 1);
  cache.set('b', 2);
  cache.set('c', 3);
  cache.get('a'); // "a" is now the most recently used
  cache.set('d', 4);
  assert.equal(cache.get('b'), undefined, 'b was the oldest');
  assert.equal(cache.get('a'), 1);
  assert.equal(cache.get('c'), 3);
  assert.equal(cache.get('d'), 4);
});

test('bounded cache: clear', () => {
  const cache = createBoundedCache(3);
  cache.set('a', 1);
  cache.clear();
  assert.equal(cache.size, 0);
  assert.equal(cache.get('a'), undefined);
});

test('sameVerdict', () => {
  const verdict = { level: 'suspicious', score: 40, reasons: ['one', 'two'] };
  assert.equal(sameVerdict(verdict, verdict), true);
  assert.equal(sameVerdict(verdict, { level: 'suspicious', score: 40, reasons: ['one', 'two'] }), true);
  assert.equal(sameVerdict(verdict, { ...verdict, level: 'dangerous' }), false);
  assert.equal(sameVerdict(verdict, { ...verdict, score: 41 }), false);
  assert.equal(sameVerdict(verdict, { ...verdict, reasons: ['one'] }), false);
  assert.equal(sameVerdict(verdict, { ...verdict, reasons: ['one', 'other'] }), false);
  assert.equal(sameVerdict(verdict, null), false);
  assert.equal(sameVerdict(null, null), true);
});
