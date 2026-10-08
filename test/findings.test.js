// Run with: node --test

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  splitDestination,
  clipRest,
  inheritsOnly,
  buildRows,
  pageStatus,
  countsLabel,
  MAX_REST_LENGTH,
} = require('../src/lib/findings.js');
const { analyzeLink, analyzePage, isPageReason } = require('../src/lib/analyzer.js');
const { applyListing } = require('../src/lib/blocklist.js');

const NOW = Date.UTC(2026, 9, 9, 12);
const PAGE_LISTING = {
  source: 'phishing',
  name: 'Phishing URL Blocklist',
  category: 'phishing',
  kind: 'host',
  entry: 'secure-login.example',
  publishedAt: NOW - 3 * 3600000,
};
const OTHER_LISTING = { ...PAGE_LISTING, source: 'malware', name: 'Online Malicious URL Blocklist', category: 'malware', entry: 'statement-files.example' };

// --- Addresses -------------------------------------------------------------------

test('splitDestination: the parts join back into the address', () => {
  const cases = [
    'https://www.paypa1.example/signin',
    'https://www.paypal.com.secure-login.example/webapps/login?x=1#top',
    'http://203.0.113.9/login',
    'https://example.co.uk/',
    'https://user:secret@files.example.com:8443/a/b?c=d',
    'http://paypal.com@evil.example/',
  ];
  for (const url of cases) {
    const { scheme, userinfo, subdomains, domain, port, rest } = splitDestination(url);
    assert.equal(scheme + userinfo + subdomains + domain + port + rest, new URL(url).href, url);
  }
});

test('splitDestination: the registrable domain is its own part', () => {
  const cases = [
    ['https://www.paypa1.example/signin', { subdomains: 'www.', domain: 'paypa1.example', rest: '/signin' }],
    ['https://www.paypal.com.secure-login.example/', { subdomains: 'www.paypal.com.', domain: 'secure-login.example' }],
    ['https://example.com/', { subdomains: '', domain: 'example.com' }],
    ['https://a.b.example.co.uk/x', { subdomains: 'a.b.', domain: 'example.co.uk' }],
    ['https://mallory.github.io/x', { subdomains: '', domain: 'mallory.github.io' }],
    ['http://203.0.113.9/login', { subdomains: '', domain: '203.0.113.9', scheme: 'http://' }],
    ['https://example.com:8443/', { domain: 'example.com', port: ':8443' }],
    // The classic disguise: everything before the @ is a username.
    ['http://paypal.com@evil.example/', { userinfo: 'paypal.com@', domain: 'evil.example' }],
    ['HTTPS://WWW.Example.COM/Path', { subdomains: 'www.', domain: 'example.com', rest: '/Path' }],
  ];
  for (const [url, expected] of cases) {
    const parts = splitDestination(url);
    for (const [key, value] of Object.entries(expected)) assert.equal(parts[key], value, `${url}: ${key}`);
  }
});

test('splitDestination: an address with no host comes back whole', () => {
  for (const url of ['data:text/html,<p>hi</p>', 'not a url', '']) {
    assert.deepEqual(splitDestination(url), { scheme: '', userinfo: '', subdomains: '', domain: '', port: '', rest: url });
  }
  assert.equal(splitDestination(undefined).rest, '');
});

test('clipRest: cuts what follows the host, and says so', () => {
  assert.deepEqual(clipRest('/short'), { text: '/short', clipped: false });
  const long = `/${'a'.repeat(200)}`;
  const { text, clipped } = clipRest(long);
  assert.equal(clipped, true);
  assert.equal(text.length, MAX_REST_LENGTH);
  assert.ok(long.startsWith(text));
  assert.deepEqual(clipRest('/abcdef', 3), { text: '/ab', clipped: true });
  assert.deepEqual(clipRest(undefined), { text: '', clipped: false });
});

// --- inheritsOnly ------------------------------------------------------------------

test('inheritsOnly: a link with nothing against it but the page warning', () => {
  const pageReason = 'This page itself looks dangerous: listed as phishing by Phishing URL Blocklist';
  assert.ok(isPageReason(pageReason));

  const cases = [
    [{ reasons: [pageReason] }, true, 'only the page reason'],
    [{ reasons: [pageReason, 'Not HTTPS (connection is not encrypted)'] }, false, 'has a reason of its own'],
    [{ reasons: ['Domain imitates paypal.com with look-alike characters'] }, false, 'no page reason'],
    [{ reasons: [] }, false, 'no reasons at all'],
    [{ reasons: [pageReason], listing: PAGE_LISTING, pageListing: PAGE_LISTING }, true, 'listed by the very entry that lists the page'],
    [{ reasons: [pageReason], listing: OTHER_LISTING, pageListing: PAGE_LISTING }, false, 'listed in its own right'],
    [{ reasons: [pageReason], listing: OTHER_LISTING, pageListing: null }, false, 'listed, page not listed'],
    [{ reasons: [pageReason], listing: { ...PAGE_LISTING, entry: 'secure-login.example/other' }, pageListing: PAGE_LISTING }, false, 'a different entry of the same list'],
  ];
  for (const [input, expected, why] of cases) assert.equal(inheritsOnly(input), expected, why);
});

test('inheritsOnly agrees with what the analyzer says on a flagged page', () => {
  const pageUrl = 'https://www.paypa1.com/';
  const pageVerdict = analyzePage(pageUrl);
  assert.equal(pageVerdict.level, 'dangerous');

  const plain = analyzeLink({ href: '/account', text: 'Account settings', pageUrl, pageVerdict });
  assert.equal(inheritsOnly({ reasons: plain.reasons }), true);

  const elsewhere = analyzeLink({ href: 'https://www.wikipedia.org/', text: 'Wikipedia', pageUrl, pageVerdict });
  assert.equal(inheritsOnly({ reasons: elsewhere.reasons }), false);

  // On a listed page the inherited reason quotes the listing.
  const listedPage = applyListing(analyzePage('https://secure-login.example/'), PAGE_LISTING, NOW);
  const onListed = analyzeLink({ href: '/help', text: 'Help', pageUrl: 'https://secure-login.example/', pageVerdict: listedPage });
  assert.equal(inheritsOnly({ reasons: onListed.reasons, listing: PAGE_LISTING, pageListing: PAGE_LISTING }), true);
});

// --- buildRows ---------------------------------------------------------------------

let nextId = 1;
const link = (level, url, extra = {}) => ({
  id: nextId++,
  level,
  text: `Link to ${url}`,
  url,
  reasons: [`Reason for ${url}`],
  listed: false,
  trusted: false,
  inherited: false,
  ...extra,
});
const describe = ({ rows }) => rows.map((row) => (row.kind === 'group' ? `group:${row.level}:${row.count}` : `${row.level}:${row.url}`));

test('buildRows: blocklist matches first, then other red, then amber', () => {
  const result = buildRows([
    link('suspicious', 'https://amber-1.example/'),
    link('dangerous', 'https://red-1.example/'),
    link('ok', 'https://fine.example/'),
    link('suspicious', 'https://amber-listed.example/', { listed: true, trusted: true }),
    link('dangerous', 'https://red-listed.example/', { listed: true }),
    link('dangerous', 'https://red-2.example/'),
    link('dangerous', 'https://red-listed-2.example/', { listed: true }),
  ]);
  assert.deepEqual(describe(result), [
    'dangerous:https://red-listed.example/',
    'dangerous:https://red-listed-2.example/',
    'dangerous:https://red-1.example/',
    'dangerous:https://red-2.example/',
    'suspicious:https://amber-listed.example/',
    'suspicious:https://amber-1.example/',
  ]);
  assert.equal(result.hidden, 0);
});

test('buildRows: links that only inherit the page warning fold into one row', () => {
  const inherited = ['/account', '/billing', '/help', '/logout'].map((path) =>
    link('dangerous', `https://secure-login.example${path}`, { inherited: true }));
  const result = buildRows(
    [
      inherited[0],
      link('dangerous', 'https://www.paypa1.example/signin'),
      inherited[1],
      link('dangerous', 'https://statement-files.example/s.zip', { listed: true }),
      inherited[2],
      link('suspicious', 'http://203.0.113.9/login'),
      inherited[3],
    ],
    { pageDomain: 'secure-login.example' },
  );

  assert.deepEqual(describe(result), [
    'dangerous:https://statement-files.example/s.zip',
    'dangerous:https://www.paypa1.example/signin',
    'group:dangerous:4',
    'suspicious:http://203.0.113.9/login',
  ]);

  const group = result.rows[2];
  assert.equal(group.domain, 'secure-login.example');
  assert.deepEqual(group.members.map((member) => member.url), inherited.map((item) => item.url), 'in page order');
  assert.deepEqual(Object.keys(group.members[0]).sort(), ['id', 'text', 'url']);
});

test('buildRows: a link with a reason of its own keeps its own row on a flagged page', () => {
  const result = buildRows([
    link('dangerous', 'https://secure-login.example/a', { inherited: true }),
    link('dangerous', 'https://www.paypal.com.secure-login.example/', { inherited: false, listed: true }),
    link('dangerous', 'https://secure-login.example/b', { inherited: true }),
  ]);
  assert.deepEqual(describe(result), [
    'dangerous:https://www.paypal.com.secure-login.example/',
    'group:dangerous:2',
  ]);
});

test('buildRows: one inherited link is a row, not a group of one', () => {
  const result = buildRows([link('dangerous', 'https://secure-login.example/only', { inherited: true })]);
  assert.deepEqual(describe(result), ['dangerous:https://secure-login.example/only']);
  assert.equal(result.rows[0].kind, 'link');
});

test('buildRows: a page that is only suspicious gets the same group in amber', () => {
  const result = buildRows([
    link('suspicious', 'http://203.0.113.9/a', { inherited: true }),
    link('suspicious', 'http://203.0.113.9/b', { inherited: true }),
    link('dangerous', 'https://www.paypa1.example/'),
  ]);
  assert.deepEqual(describe(result), ['dangerous:https://www.paypa1.example/', 'group:suspicious:2']);
});

test('buildRows: the same address and level counts once, in rows and in groups', () => {
  const result = buildRows([
    link('dangerous', 'https://red.example/'),
    link('dangerous', 'https://red.example/'),
    link('suspicious', 'https://red.example/'),
    link('dangerous', 'https://page.example/a', { inherited: true }),
    link('dangerous', 'https://page.example/a', { inherited: true }),
    link('dangerous', 'https://page.example/b', { inherited: true }),
  ]);
  assert.deepEqual(describe(result), [
    'dangerous:https://red.example/',
    'group:dangerous:2',
    'suspicious:https://red.example/',
  ]);
});

test('buildRows: row and member limits, and how many rows were left out', () => {
  const many = Array.from({ length: 30 }, (_, i) => link('dangerous', `https://red-${i}.example/`));
  const inherited = Array.from({ length: 12 }, (_, i) => link('suspicious', `https://page.example/${i}`, { inherited: true }));

  const result = buildRows([...many, ...inherited], { maxRows: 10, maxMembers: 5 });
  assert.equal(result.rows.length, 10);
  assert.equal(result.hidden, 21, '30 links + 1 group - 10 shown');

  const group = buildRows(inherited, { maxMembers: 5 }).rows[0];
  assert.equal(group.count, 12, 'the count is of all of them');
  assert.equal(group.members.length, 5);
});

test('buildRows: a link row carries what the popup shows', () => {
  const [row] = buildRows([link('dangerous', 'https://red.example/', { listed: true, reasons: ['a', 'b'] })]).rows;
  assert.deepEqual(Object.keys(row).sort(), ['id', 'key', 'kind', 'level', 'listed', 'reasons', 'text', 'trusted', 'url']);
  assert.deepEqual(row.reasons, ['a', 'b']);
  assert.equal(row.listed, true);
  assert.deepEqual(buildRows([]), { rows: [], hidden: 0 });
});

// --- pageStatus ----------------------------------------------------------------------

const state = (overrides = {}) => ({
  mode: 'risky',
  counts: { scanned: 128, ok: 123, suspicious: 2, dangerous: 3 },
  pageVerdict: { level: 'ok', score: 0, reasons: [] },
  pageListing: null,
  pageTrusted: false,
  ...overrides,
});

test('pageStatus: one sentence for each situation', () => {
  const cases = [
    [null, 'neutral', 'Tripwire isn’t running on this page'],
    [state({ mode: 'off', counts: null, pageVerdict: null }), 'neutral', 'Tripwire is off for this site'],
    [state({ counts: null }), 'neutral', 'Checking this page…'],
    [state(), 'risky', '3 risky links on this page', 'And 2 suspicious. 128 links checked.'],
    [state({ counts: { scanned: 9, suspicious: 0, dangerous: 1 } }), 'risky', '1 risky link on this page', '9 links checked.'],
    [state({ counts: { scanned: 37, suspicious: 2, dangerous: 0 } }), 'suspicious', '2 suspicious links on this page', 'No risky links. 37 links checked.'],
    [state({ counts: { scanned: 1, suspicious: 1, dangerous: 0 } }), 'suspicious', '1 suspicious link on this page', 'No risky links. 1 link checked.'],
    [state({ counts: { scanned: 1184, suspicious: 0, dangerous: 0 } }), 'clean', 'No risky links found on this page', '1,184 links checked. This is not a guarantee.'],
  ];
  for (const [input, kind, title, detail] of cases) {
    const status = pageStatus(input, NOW);
    assert.equal(status.kind, kind, title);
    assert.equal(status.title, title);
    if (detail !== undefined) assert.equal(status.detail, detail);
  }
});

test('pageStatus: a warning about the page itself comes before its links', () => {
  const listed = pageStatus(
    state({ pageVerdict: { level: 'dangerous', score: 100, reasons: ['Listed as phishing by X'] }, pageListing: PAGE_LISTING }),
    NOW,
  );
  assert.deepEqual(listed, {
    kind: 'page-dangerous',
    title: 'This page is listed as phishing',
    detail: 'By Phishing URL Blocklist, updated 3 hours ago.',
  });

  const lookalike = pageStatus(
    state({ pageVerdict: { level: 'dangerous', score: 85, reasons: ['Domain imitates paypal.com with look-alike characters'] } }),
    NOW,
  );
  assert.deepEqual(lookalike, {
    kind: 'page-dangerous',
    title: 'This page looks dangerous',
    detail: 'Domain imitates paypal.com with look-alike characters.',
  });

  const odd = pageStatus(state({ pageVerdict: { level: 'suspicious', score: 40, reasons: ['Host is a raw IP address (203.0.113.9)'] } }), NOW);
  assert.equal(odd.kind, 'page-suspicious');
  assert.equal(odd.title, 'This page looks suspicious');
});

test('pageStatus: a trusted page that is on a blocklist is amber and says both', () => {
  const status = pageStatus(
    state({
      pageVerdict: { level: 'suspicious', score: 50, reasons: ['Listed as phishing by X', 'You trusted this domain'] },
      pageListing: PAGE_LISTING,
      pageTrusted: true,
    }),
    NOW,
  );
  assert.deepEqual(status, {
    kind: 'page-suspicious',
    title: 'This page is listed as phishing',
    detail: 'By Phishing URL Blocklist, updated 3 hours ago. You trusted this domain.',
  });
});

test('the wording never says "safe"', () => {
  const inputs = [null, state(), state({ counts: { scanned: 5, suspicious: 0, dangerous: 0 } }), state({ mode: 'off' })];
  for (const input of inputs) {
    const { title, detail } = pageStatus(input, NOW);
    assert.doesNotMatch(`${title} ${detail}`, /\bsafe\b/i);
  }
});

test('countsLabel: what the list heading says', () => {
  assert.equal(countsLabel({ dangerous: 11, suspicious: 3 }), '11 risky · 3 suspicious');
  assert.equal(countsLabel({ dangerous: 0, suspicious: 2 }), '2 suspicious');
  assert.equal(countsLabel({ dangerous: 1200, suspicious: 0 }), '1,200 risky');
  assert.equal(countsLabel({}), '');
  assert.equal(countsLabel(), '');
});
