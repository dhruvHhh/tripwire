// Run with: node --test

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  BADGE_INSET,
  BADGE_RISE,
  rectGap,
  onSameLine,
  placeBadge,
  placeTooltip,
  pickGroupLeaders,
} = require('../src/lib/geometry.js');

const rect = (left, top, width, height) => ({ left, top, right: left + width, bottom: top + height });

const SIZE = 9;
const VIEWPORT = 1000;
const GAP = 48;

test('rectGap', () => {
  const a = rect(0, 0, 100, 20);
  assert.equal(rectGap(a, a), 0);
  assert.equal(rectGap(a, rect(50, 10, 100, 20)), 0, 'overlapping');
  assert.equal(rectGap(a, rect(0, 20, 100, 20)), 0, 'touching');
  assert.equal(rectGap(a, rect(0, 50, 100, 20)), 30, 'stacked');
  assert.equal(rectGap(a, rect(140, 0, 100, 20)), 40, 'side by side');
  assert.equal(rectGap(a, rect(140, 80, 100, 20)), 60, 'diagonal: the wider axis');
  assert.equal(rectGap(rect(140, 80, 100, 20), a), 60, 'symmetric');
});

test('onSameLine', () => {
  const word = rect(100, 200, 60, 18);
  assert.equal(onSameLine(word, rect(170, 200, 40, 18)), true, 'next word on the line');
  assert.equal(onSameLine(word, rect(170, 203, 20, 12)), true, 'smaller text on the same line');
  assert.equal(onSameLine(word, rect(100, 226, 60, 18)), false, 'the line below');
  assert.equal(onSameLine(word, rect(100, 214, 60, 18)), false, 'barely overlapping lines');
});

test('placeBadge: straddles the top-right corner', () => {
  const text = rect(200, 300, 120, 18);
  const { x, y } = placeBadge(text, VIEWPORT, SIZE);
  assert.equal(x, text.right - BADGE_INSET);
  assert.equal(y, text.top - BADGE_RISE);
});

test('placeBadge: stays inside the viewport width', () => {
  const atRightEdge = rect(900, 300, 100, 18);
  const { x } = placeBadge(atRightEdge, VIEWPORT, SIZE);
  assert.equal(x, VIEWPORT - SIZE);
  assert.ok(x + SIZE <= VIEWPORT);
});

test('placeBadge: stays below the top of the viewport', () => {
  const atTop = rect(200, 2, 120, 18);
  assert.equal(placeBadge(atTop, VIEWPORT, SIZE).y, 0);
});

const SCREEN = { width: 1000, height: 700 };
const TIP = { width: 300, height: 80 };

// A badge at (x, top) on a line of link text that ends at `bottom`.
const target = (x, top) => ({ x, top, bottom: top + 24 });

test('placeTooltip: below the badge and its line of text by default', () => {
  const t = target(400, 200);
  const { x, y } = placeTooltip(t, TIP, SCREEN);
  assert.ok(y >= t.bottom, 'clear of the link text');
  assert.ok(x <= t.x && x + TIP.width >= t.x + SIZE, 'spans the badge horizontally');
});

test('placeTooltip: flips above when there is no room below', () => {
  const t = target(400, 650);
  const { y } = placeTooltip(t, TIP, SCREEN);
  assert.ok(y + TIP.height <= t.top, 'above the badge');
  assert.ok(y >= 0);
});

test('placeTooltip: stays inside the viewport at the left and right edges', () => {
  for (const badgeX of [0, 2, 990]) {
    const { x } = placeTooltip(target(badgeX, 200), TIP, SCREEN);
    assert.ok(x >= 0, `left edge, badge at ${badgeX}`);
    assert.ok(x + TIP.width <= SCREEN.width, `right edge, badge at ${badgeX}`);
  }
});

test('placeTooltip: goes below when it fits neither above nor below', () => {
  const t = target(400, 30);
  const { y } = placeTooltip(t, { width: 300, height: 690 }, SCREEN);
  assert.ok(y >= t.bottom);
});

test('pickGroupLeaders: a result title and its URL line share one badge', () => {
  const items = [
    { key: 'https://a.example/\nsuspicious', rect: rect(100, 100, 300, 24) }, // title
    { key: 'https://a.example/\nsuspicious', rect: rect(100, 128, 180, 16) }, // URL line
  ];
  assert.deepEqual(pickGroupLeaders(items, GAP), [true, false]);
});

test('pickGroupLeaders: the same link far away gets its own badge', () => {
  const items = [
    { key: 'k', rect: rect(100, 100, 300, 24) },
    { key: 'k', rect: rect(100, 600, 300, 24) },
  ];
  assert.deepEqual(pickGroupLeaders(items, GAP), [true, true]);
});

test('pickGroupLeaders: different keys never share', () => {
  const items = [
    { key: 'https://a.example/\nsuspicious', rect: rect(100, 100, 300, 24) },
    { key: 'https://b.example/\nsuspicious', rect: rect(100, 128, 180, 16) },
    // Same href, different verdict (e.g. different link text).
    { key: 'https://a.example/\ndangerous', rect: rect(100, 150, 180, 16) },
  ];
  assert.deepEqual(pickGroupLeaders(items, GAP), [true, true, true]);
});

test('pickGroupLeaders: a group grows as links join it', () => {
  // Image, title, "read more": each is close to the one before, but the last
  // is far from the first.
  const items = [
    { key: 'k', rect: rect(0, 0, 200, 100) },
    { key: 'k', rect: rect(0, 110, 200, 24) },
    { key: 'k', rect: rect(0, 170, 80, 16) },
  ];
  assert.deepEqual(pickGroupLeaders(items, GAP), [true, false, false]);
});

test('pickGroupLeaders: interleaved groups', () => {
  const items = [
    { key: 'a', rect: rect(0, 0, 100, 20) },
    { key: 'b', rect: rect(0, 24, 100, 20) },
    { key: 'a', rect: rect(0, 48, 100, 20) },
    { key: 'b', rect: rect(0, 72, 100, 20) },
    { key: 'a', rect: rect(0, 500, 100, 20) },
  ];
  assert.deepEqual(pickGroupLeaders(items, GAP), [true, true, false, false, true]);
});

test('pickGroupLeaders: empty input', () => {
  assert.deepEqual(pickGroupLeaders([], GAP), []);
});
