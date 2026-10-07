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

const LINK_RE = /<a href="([^"]*)" data-expect="(\w+)">([^<]*)<\/a>/g;
const links = [...html.matchAll(LINK_RE)].map(([, href, expect, text]) => ({
  href: decodeEntities(href),
  text: decodeEntities(text),
  expect,
}));

test('demo page covers all three levels', () => {
  for (const level of ['ok', 'suspicious', 'dangerous']) {
    assert.ok(links.some((link) => link.expect === level), `no ${level} links found`);
  }
});

for (const { href, text, expect } of links) {
  test(`demo page: "${text}" -> ${expect}`, () => {
    const result = analyzeLink({ href, text, pageUrl: PAGE_URL });
    assert.equal(result.level, expect, `score ${result.score}, reasons: ${JSON.stringify(result.reasons)}`);
  });
}
