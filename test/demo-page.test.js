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
// bundled test blocklist should match the link. A link may go on to say how
// it opens (target, download) or carry an id for the page's script.
const LINK_RE = /<a href="([^"]*)" data-expect="(\w+)"(?: data-listed="(\w+)")?(?: (?:target|download|id)="[^"]*")*>((?:<img[^>]*>)?[^<]*)<\/a>/g;
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
    const match = matchFixture(new URL(href, PAGE_URL).href);
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

// The demo's "a page that is itself listed" case: at this address the page is
// on the test list, so its same-site links must turn dangerous.
test('demo page at its listed address: the page is listed and same-site links inherit', () => {
  const pageUrl = 'http://listed.localhost:8080/demo';
  const listing = matchFixture(pageUrl);
  assert.ok(listing, 'the test list should name this address');
  assert.equal(matchFixture('http://localhost:8080/'), null, 'the normal address is not listed');
  assert.equal(matchFixture('http://listed.localhost:8080/'), null, 'only the one address is listed, not the host');

  assert.equal(analyzePage(pageUrl).level, 'ok', 'nothing about the address itself is suspicious');
  const pageVerdict = blocklist.applyListing(analyzePage(pageUrl), listing, Date.now());
  const sameSite = links.filter((link) => link.href.startsWith('/'));
  assert.ok(sameSite.length >= 2);
  for (const { href, text } of sameSite) {
    const result = analyzeLink({ href: new URL(href, pageUrl).href, text, pageUrl, pageVerdict });
    assert.equal(result.level, 'dangerous', href);
    assert.match(result.reasons[0], /this page itself looks dangerous: listed as phishing by Tripwire test list/i);
  }

  // Links that leave the site keep their own verdict.
  const outside = analyzeLink({ href: 'https://en.wikipedia.org/wiki/Phishing', text: 'Read about phishing', pageUrl, pageVerdict });
  assert.equal(outside.level, 'ok');
});

// The demo's "Trusted domains" section.
const trust = require('../src/lib/trust.js');

test('demo page: trusting phonepay.example turns both of its links ok', () => {
  const ours = links.filter((link) => trust.domainOf(link.href) === 'phonepay.example');
  assert.ok(ours.length >= 2, 'the main domain and a subdomain');
  for (const { href, text } of ours) {
    const verdict = analyzeLink({ href, text, pageUrl: PAGE_URL });
    assert.notEqual(verdict.level, 'ok', `${href} is flagged before it is trusted`);
    assert.deepEqual(trust.resolveVerdict({ verdict, trusted: true }).reasons, [trust.TRUSTED_REASON]);
    assert.equal(trust.resolveVerdict({ verdict, trusted: true }).level, 'ok');
  }
});

test('demo page: a trusted domain on the test list is amber, with both facts', () => {
  const ours = links.filter((link) => trust.domainOf(link.href) === 'partner-portal.example');
  const listed = ours.find((link) => link.listed === 'yes');
  const unlisted = ours.find((link) => link.listed === 'no');
  assert.ok(listed && unlisted);

  const listing = matchFixture(listed.href);
  const verdict = analyzeLink({ href: listed.href, text: listed.text, pageUrl: PAGE_URL });
  const shown = trust.resolveVerdict({ verdict, listing, trusted: true });
  assert.equal(shown.level, 'suspicious');
  assert.match(shown.reasons[0], /^Listed as phishing by Tripwire test list/);
  assert.equal(shown.reasons[1], trust.TRUSTED_REASON);

  // Trusting it needs the confirmation step, because of that listing.
  assert.equal(trust.needsConfirmation('partner-portal.example', [trust.domainOf(listed.href)]), true);

  const other = analyzeLink({ href: unlisted.href, text: unlisted.text, pageUrl: PAGE_URL });
  assert.equal(trust.resolveVerdict({ verdict: other, listing: matchFixture(unlisted.href), trusted: true }).level, 'ok');
});
