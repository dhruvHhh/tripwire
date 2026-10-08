// Run with: node --test

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  TRUSTED_REASON,
  TRUST_KEY_PREFIX,
  domainOf,
  trustKey,
  resolveVerdict,
  needsConfirmation,
  listTrusted,
} = require('../src/lib/trust.js');
const { analyzeLink } = require('../src/lib/analyzer.js');
const { listingReason } = require('../src/lib/blocklist.js');

const NOW = Date.UTC(2026, 9, 9, 12);
const LISTING = {
  source: 'phishing',
  name: 'Phishing URL Blocklist',
  category: 'phishing',
  kind: 'host',
  entry: 'shared-host.example',
  publishedAt: NOW - 3 * 3600000,
};

const OK = { level: 'ok', score: 0, reasons: [] };
const SUSPICIOUS = { level: 'suspicious', score: 40, reasons: ['Host is a raw IP address (203.0.113.9)'] };
const DANGEROUS = { level: 'dangerous', score: 85, reasons: ['Domain imitates paypal.com with look-alike characters'] };

test('domainOf: the registrable domain that trusting an address would trust', () => {
  const cases = [
    ['https://www.example.com/path?x=1', 'example.com'],
    ['http://EXAMPLE.com', 'example.com'],
    ['https://a.b.c.example.co.uk/', 'example.co.uk'],
    // Shared hosting: one person's site, never the whole host.
    ['https://mallory.github.io/page', 'mallory.github.io'],
    ['https://www.paypal.com.secure-login.example/', 'secure-login.example'],
    ['http://203.0.113.9/login', '203.0.113.9'],
    ['https://example.com:8443/', 'example.com'],
    // Nothing to trust.
    ['data:text/html,<p>hi</p>', ''],
    ['javascript:alert(1)', ''],
    ['mailto:someone@example.com', ''],
    ['not a url', ''],
    ['', ''],
  ];
  for (const [url, expected] of cases) assert.equal(domainOf(url), expected, url);
});

test('trustKey: one storage key per domain, case-insensitive', () => {
  assert.equal(trustKey('Example.COM'), `${TRUST_KEY_PREFIX}example.com`);
});

test('resolveVerdict: without trust, the checks and the blocklist decide', () => {
  assert.deepEqual(resolveVerdict({ verdict: DANGEROUS, now: NOW }), DANGEROUS);
  assert.deepEqual(resolveVerdict({ verdict: OK, now: NOW }), OK);

  const listed = resolveVerdict({ verdict: OK, listing: LISTING, now: NOW });
  assert.equal(listed.level, 'dangerous');
  assert.deepEqual(listed.reasons, [listingReason(LISTING, NOW)]);
});

test('resolveVerdict: a trusted link is ok, with the note', () => {
  for (const verdict of [OK, SUSPICIOUS, DANGEROUS]) {
    assert.deepEqual(
      resolveVerdict({ verdict, trusted: true, now: NOW }),
      { level: 'ok', score: 0, reasons: [TRUSTED_REASON] },
      `was ${verdict.level}`,
    );
  }
  assert.equal(TRUSTED_REASON, 'You trusted this domain');
});

test('resolveVerdict: trusted AND on a blocklist is amber, with both facts', () => {
  for (const verdict of [OK, SUSPICIOUS, DANGEROUS]) {
    const result = resolveVerdict({ verdict, listing: LISTING, trusted: true, now: NOW });
    assert.equal(result.level, 'suspicious', `was ${verdict.level}: never ok, never silently green`);
    assert.ok(result.score >= 30 && result.score < 70, 'score sits in the suspicious band');
    assert.equal(result.reasons[0], listingReason(LISTING, NOW), 'the blocklist match is stated first');
    assert.equal(result.reasons[1], TRUSTED_REASON, 'and so is the trust');
    assert.deepEqual(result.reasons.slice(2), verdict.reasons, 'what the checks found is kept');
  }
});

test('resolveVerdict: trust never raises a verdict or hides a listing', () => {
  const levels = ['ok', 'suspicious', 'dangerous'];
  for (const verdict of [OK, SUSPICIOUS, DANGEROUS]) {
    for (const listing of [null, LISTING]) {
      const without = resolveVerdict({ verdict, listing, trusted: false, now: NOW });
      const withTrust = resolveVerdict({ verdict, listing, trusted: true, now: NOW });
      assert.ok(levels.indexOf(withTrust.level) <= levels.indexOf(without.level));
      if (listing) {
        assert.notEqual(withTrust.level, 'ok');
        assert.ok(withTrust.reasons.some((reason) => reason.startsWith('Listed as phishing')));
      }
    }
  }
});

test('resolveVerdict works on real analyzer output', () => {
  const verdict = analyzeLink({ href: 'https://www.paypa1.com/signin', text: 'Sign in', pageUrl: 'https://news.example.org/' });
  assert.equal(verdict.level, 'dangerous');
  assert.equal(resolveVerdict({ verdict, trusted: true, now: NOW }).level, 'ok');
  assert.equal(resolveVerdict({ verdict, trusted: true, listing: LISTING, now: NOW }).level, 'suspicious');
});

test('needsConfirmation: only for a domain with a listed address on the page', () => {
  const listed = ['shared-host.example', 'secure-login.example'];
  assert.equal(needsConfirmation('shared-host.example', listed), true);
  assert.equal(needsConfirmation('paypa1.example', listed), false);
  assert.equal(needsConfirmation('paypa1.example', []), false);
  assert.equal(needsConfirmation('', listed), false);
  assert.equal(needsConfirmation('shared-host.example', undefined), false);
});

test('listTrusted: reads trusted domains out of a storage dump, by name', () => {
  const stored = {
    defaultMode: 'all',
    'site:example.com': 'off',
    [`${TRUST_KEY_PREFIX}zebra.example`]: { addedAt: 2 },
    [`${TRUST_KEY_PREFIX}apple.example`]: { addedAt: 1 },
    [`${TRUST_KEY_PREFIX}old-format.example`]: true,
    [`${TRUST_KEY_PREFIX}removed.example`]: null,
    [TRUST_KEY_PREFIX]: { addedAt: 3 },
  };
  assert.deepEqual(listTrusted(stored), [
    { domain: 'apple.example', addedAt: 1 },
    { domain: 'old-format.example', addedAt: null },
    { domain: 'zebra.example', addedAt: 2 },
  ]);
  assert.deepEqual(listTrusted({}), []);
  assert.deepEqual(listTrusted(undefined), []);
});
