// Keeps demo/links.html honest: every link marked data-expect="..."
// must get that level from the analyzer.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { analyzeLink } = require('../src/lib/analyzer.js');

const PAGE_URL = 'http://localhost:8080/';
const html = fs.readFileSync(path.join(__dirname, '..', 'demo', 'links.html'), 'utf8');

function decodeEntities(value) {
  return value
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&');
}

// A link's content is plain text or a single <img>, which has no text.
const LINK_RE = /<a href="([^"]*)" data-expect="(\w+)">((?:<img[^>]*>)?[^<]*)<\/a>/g;
const links = [...html.matchAll(LINK_RE)].map(([, href, expect, content]) => ({
  href: decodeEntities(href),
  text: decodeEntities(content.replace(/<img[^>]*>/, '')),
  expect,
}));

test('demo page covers all three levels', () => {
  for (const level of ['ok', 'suspicious', 'dangerous']) {
    assert.ok(links.some((link) => link.expect === level), `no ${level} links found`);
  }
});

for (const { href, text, expect } of links) {
  test(`demo page: "${text || '(image)'}" -> ${expect}`, () => {
    const result = analyzeLink({ href, text, pageUrl: PAGE_URL });
    assert.equal(result.level, expect, `score ${result.score}, reasons: ${JSON.stringify(result.reasons)}`);
  });
}

// The page tells the reader to open it as paypa1.localhost to see the
// lookalike-page behaviour: its same-site links must then be red.
test('demo page on its lookalike hostname: same-site links turn dangerous', () => {
  const pageUrl = 'http://paypa1.localhost:8080/';
  const sameSite = links.filter((link) => link.href.startsWith('/'));
  assert.ok(sameSite.length >= 2, 'expected relative links on the demo page');
  for (const { href, text } of sameSite) {
    const result = analyzeLink({ href, text, pageUrl });
    assert.equal(result.level, 'dangerous', `${href}: ${JSON.stringify(result.reasons)}`);
    assert.match(result.reasons[0], /this page itself looks dangerous/i);
  }
});
