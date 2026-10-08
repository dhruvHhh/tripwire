// Keeps demo/links.html honest: every link marked data-expect="..."
// must get that level from the analyzer.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { analyzeLink, analyzePage } = require('../src/lib/analyzer.js');
const blocklist = require('../src/lib/blocklist.js');

const PAGE_URL = 'http://localhost:8080/';
const html = fs.readFileSync(path.join(__dirname, '..', 'demo', 'links.html'), 'utf8');

function decodeEntities(value) {
  return value
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&');
}

// A link's content is plain text or a single <img>, which has no text.
// data-expect is what the heuristics alone say; data-listed says whether the
// bundled test blocklist should match the link.
const LINK_RE = /<a href="([^"]*)" data-expect="(\w+)"(?: data-listed="(\w+)")?>((?:<img[^>]*>)?[^<]*)<\/a>/g;
const links = [...html.matchAll(LINK_RE)].map(([, href, expect, listed, content]) => ({
  href: decodeEntities(href),
  text: decodeEntities(content.replace(/<img[^>]*>/, '')),
  expect,
  listed,
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

// The page's single-page-navigation demo relies on this hostname being fine at
// its short address and suspicious at the long one the button pushes.
test('demo page on its many-subdomains hostname: the long address flips the page verdict', () => {
  const short = 'http://one.two.three.four.tripwire.localhost:8080/';
  const long = `${short}spa/${'section-'.repeat(40)}end`;
  assert.equal(analyzePage(short).level, 'ok');
  assert.equal(analyzePage(long).level, 'suspicious');

  const sameSite = { href: `${short}about`, text: 'About this page' };
  assert.equal(analyzeLink({ ...sameSite, pageUrl: short }).level, 'ok');
  const onLongPage = analyzeLink({ ...sameSite, pageUrl: long });
  assert.equal(onLongPage.level, 'suspicious');
  assert.match(onLongPage.reasons[0], /this page itself looks suspicious/i);
});

// The demo page's blocklist section relies on the bundled test list.
const fixture = fs.readFileSync(path.join(__dirname, 'fixtures', 'blocklist.txt'), 'utf8');
const screened = blocklist.screenEntries(blocklist.parseList(fixture));
const matchFixture = blocklist.createMatcher([
  {
    id: blocklist.CONFIG.fixture.id,
    name: blocklist.CONFIG.fixture.name,
    category: blocklist.CONFIG.fixture.category,
    publishedAt: Date.now(),
    hosts: new Set(screened.hosts),
    urls: new Set(screened.urls),
  },
]);

const listedLinks = links.filter((link) => link.listed);

test('demo page has both listed and unlisted blocklist examples', () => {
  assert.ok(listedLinks.filter((link) => link.listed === 'yes').length >= 5);
  assert.ok(listedLinks.filter((link) => link.listed === 'no').length >= 4);
});

for (const { href, text, listed } of listedLinks) {
  test(`demo page blocklist: "${text}" is ${listed === 'yes' ? 'listed' : 'not listed'}`, () => {
    const match = matchFixture(href);
    assert.equal(Boolean(match), listed === 'yes', href);
    if (match) {
      const verdict = blocklist.applyListing(analyzeLink({ href, text, pageUrl: PAGE_URL }), match, Date.now());
      assert.equal(verdict.level, 'dangerous');
      assert.match(verdict.reasons[0], /^Listed as phishing by Tripwire test list/);
    }
  });
}

// Every other link on the page must be untouched by the test list, or the
// rest of the demo would stop showing what it says it shows.
test('demo page: the test list matches nothing outside the blocklist section', () => {
  for (const { href, listed } of links) {
    if (!listed) assert.equal(matchFixture(new URL(href, PAGE_URL).href), null, href);
  }
});
