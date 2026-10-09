// Run with: node --test

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  CONFIG,
  normalizeUrl,
  urlCandidates,
  hostCandidates,
  wholeHostIgnoreReason,
  parseEntry,
  parseList,
  screenEntries,
  createMatcher,
  checkDownload,
  updateFromMirrors,
  fingerprintOf,
  retryDelayMinutes,
  formatAge,
  listingReason,
  applyListing,
  isDevelopmentInstall,
  describeSource,
  describeAll,
} = require('../src/lib/blocklist.js');

const HOUR = 3600000;
const NOW = Date.parse('2026-10-08T18:00:00Z');

// --- URL normalization --------------------------------------------------------

const key = (href) => {
  const url = normalizeUrl(href);
  return url && url.host + url.path + url.query;
};

const NORMALIZATION_CASES = [
  // [link as written, normalized key]
  ['https://Example.COM/Path', 'example.com/Path', 'host is lower-cased, path is not'],
  ['http://example.com/', 'example.com/', 'scheme is ignored (http)'],
  ['https://example.com/', 'example.com/', 'scheme is ignored (https)'],
  ['https://example.com', 'example.com/', 'an empty path is "/"'],
  ['https://www.example.com/a', 'example.com/a', 'leading www. is dropped'],
  ['https://example.com./a', 'example.com/a', 'trailing dot on the host is dropped'],
  ['http://example.com:80/a', 'example.com/a', 'default http port is dropped'],
  ['https://example.com:443/a', 'example.com/a', 'default https port is dropped'],
  ['https://example.com:8443/a', 'example.com:8443/a', 'any other port is kept'],
  ['https://example.com/a#section', 'example.com/a', 'fragment is dropped'],
  ['https://example.com/a?x=1#frag', 'example.com/a?x=1', 'query is kept, fragment dropped'],
  ['https://user:secret@example.com/a', 'example.com/a', 'credentials are dropped'],
  ['https://example.com/a/../b/./c', 'example.com/b/c', 'dot segments are resolved'],
  ['https://example.com/a%20b', 'example.com/a%20b', 'percent-encoding is left as written'],
  ['https://example.com/a/', 'example.com/a/', 'a trailing slash is kept here; matching tries both'],
  ['https://EXAMPLE.com/?Q=1', 'example.com/?Q=1', 'query case is kept'],
  ['https://xn--bcher-kva.de/', 'xn--bcher-kva.de/', 'punycode hosts stay punycode'],
  ['https://bücher.de/', 'xn--bcher-kva.de/', 'unicode hosts become punycode'],
];

for (const [href, expected, why] of NORMALIZATION_CASES) {
  test(`normalizeUrl: ${why}`, () => assert.equal(key(href), expected));
}

test('normalizeUrl: only http and https links are looked up', () => {
  for (const href of ['mailto:a@example.com', 'javascript:void(0)', 'data:text/html,hi', 'ftp://example.com/f', 'not a url', '', null]) {
    assert.equal(normalizeUrl(href), null, String(href));
  }
});

test('urlCandidates: the address, then each parent folder, with and without a trailing slash', () => {
  assert.deepEqual(urlCandidates(normalizeUrl('https://example.com/a/b/page.html')), [
    'example.com/a/b/page.html',
    'example.com/a/b/page.html/',
    'example.com/a/b/',
    'example.com/a/b',
    'example.com/a/',
    'example.com/a',
    'example.com/',
  ]);
});

test('urlCandidates: the query is tried whole, then cut at each "&", then dropped', () => {
  assert.deepEqual(urlCandidates(normalizeUrl('https://example.com/get.php?id=42&ref=mail&x=1')).slice(0, 4), [
    'example.com/get.php?id=42&ref=mail&x=1',
    'example.com/get.php?id=42&ref=mail',
    'example.com/get.php?id=42',
    'example.com/get.php',
  ]);
});

test('hostCandidates: the host and its parents, never siblings', () => {
  assert.deepEqual(hostCandidates('a.b.example.com'), ['a.b.example.com', 'b.example.com', 'example.com']);
  assert.deepEqual(hostCandidates('example.com'), ['example.com']);
  assert.deepEqual(hostCandidates('203.0.113.77'), ['203.0.113.77']);
});

// --- Reading entries -----------------------------------------------------------

const ENTRY_CASES = [
  ['bad-host.example', { kind: 'host', host: 'bad-host.example' }],
  ['BAD-Host.Example', { kind: 'host', host: 'bad-host.example' }],
  ['www.bad-host.example', { kind: 'host', host: 'bad-host.example' }],
  ['203.0.113.77', { kind: 'host', host: '203.0.113.77' }],
  ['||bad-host.example^$all', { kind: 'host', host: 'bad-host.example' }],
  ['||bad-host.example/^$all', { kind: 'host', host: 'bad-host.example' }],
  ['bad-host.example:8080', { kind: 'host', host: 'bad-host.example' }],
  ['||host.example/some/path^$all', { kind: 'url', key: 'host.example/some/path' }],
  ['||host.example/some/path/^$all', { kind: 'url', key: 'host.example/some/path/' }],
  ['||host.example/Some/Path.ZIP^$all', { kind: 'url', key: 'host.example/Some/Path.ZIP' }],
  ['||host.example/p?a=1&b=2^$all', { kind: 'url', key: 'host.example/p?a=1&b=2' }],
  ['||host.example/?a=1^$all', { kind: 'url', key: 'host.example/?a=1' }],
  ['||host.example?a=1^$all', { kind: 'url', key: 'host.example/?a=1' }],
  ['||host.example:8443/file.bin^$all', { kind: 'url', key: 'host.example:8443/file.bin' }],
  ['||host.example:443/file.bin^$all', { kind: 'url', key: 'host.example/file.bin' }],
  ['||host.example/page#frag^$all', { kind: 'url', key: 'host.example/page' }],
  ['||host.example/a%20b^$all', { kind: 'url', key: 'host.example/a%20b' }],
  ['||host.example/path$document,popup', { kind: 'url', key: 'host.example/path' }],
  ['  bad-host.example  ', { kind: 'host', host: 'bad-host.example' }],
  // Not usable:
  ['', null],
  ['! a comment', null],
  ['# a comment', null],
  ['[Adblock Plus 2.0]', null],
  ['||wild*card.example/x^$all', null],
  ['@@||allowed.example^', null],
  ['example.com##.ad', null],
  ['localhost-only-label', null],
  ['two words.example', null],
  ['<html>', null],
  ['||[::1]/x^', null],
];

for (const [line, expected] of ENTRY_CASES) {
  test(`parseEntry: ${JSON.stringify(line)}`, () => assert.deepEqual(parseEntry(line), expected));
}

const SAMPLE_LIST = [
  '! Title: Sample List',
  '! Updated: 2026-10-08T12:00:00Z',
  '! Expires: 12 hours (update frequency)',
  'one.example',
  'two.example',
  'one.example',
  '',
  '||three.example/path^$all',
  '||three.example/path^$all',
  '||wild*card.example/x^$all',
].join('\r\n');

test('parseList: header, entries and counts', () => {
  const parsed = parseList(SAMPLE_LIST);
  assert.equal(parsed.title, 'Sample List');
  assert.equal(parsed.publishedAt, Date.parse('2026-10-08T12:00:00Z'));
  assert.deepEqual(parsed.hosts, ['one.example', 'two.example', 'one.example']);
  assert.deepEqual(parsed.urls, ['three.example/path', 'three.example/path']);
  assert.equal(parsed.total, 6);
  assert.equal(parsed.rejected, 1);
});

test('parseList: no date in the header means no publish time', () => {
  assert.equal(parseList('! Title: X\none.example').publishedAt, null);
});

test('parseList: an error page yields almost nothing usable', () => {
  const parsed = parseList('<!doctype html>\n<html><head><title>503</title></head>\n<body><h1>Service Unavailable</h1></body></html>');
  assert.equal(parsed.hosts.length + parsed.urls.length, 0);
  assert.equal(parsed.rejected, parsed.total);
});

test('screenEntries: removes duplicates', () => {
  const screened = screenEntries(parseList(SAMPLE_LIST));
  assert.deepEqual(screened.hosts, ['one.example', 'two.example']);
  assert.deepEqual(screened.urls, ['three.example/path']);
  assert.deepEqual(screened.ignored, []);
});

// --- Hosts that are never matched whole ----------------------------------------

const IGNORED_WHOLE_HOSTS = [
  // [host, reason pattern]
  // Protected: the domain and every subdomain.
  ['google.com', /protected domain \(google\.com\)/],
  ['sites.google.com', /protected domain/],
  ['docs.google.com', /protected domain/],
  ['drive.google.com', /protected domain \(google\.com\)/],
  ['github.com', /protected domain/],
  ['gist.github.com', /protected domain \(github\.com\)/],
  ['raw.githubusercontent.com', /protected domain/],
  ['microsoft.com', /protected domain/],
  ['login.live.com', /protected domain \(live\.com\)/],
  ['apple.com', /protected domain/],
  ['amazon.com', /protected domain/],
  ['en.wikipedia.org', /protected domain \(wikipedia\.org\)/],
  ['youtube.com', /protected domain/],
  ['facebook.com', /protected domain/],
  ['x.com', /protected domain/],
  ['linkedin.com', /protected domain/],
  ['gov.in', /public suffix/], // Also on the protected list; either way it is never matched whole.
  ['incometax.gov.in', /protected domain \(gov\.in\)/],
  ['nic.in', /public suffix/],
  ['mail.nic.in', /protected domain \(nic\.in\)/],
  ['sbi.co.in', /protected domain/],
  ['retail.sbi.co.in', /protected domain \(sbi\.co\.in\)/],
  ['protect-us.mimecast.com', /protected domain \(mimecast\.com\)/],
  // Shared hosting, shorteners, trackers: the bare domain only.
  ['github.io', /shared hosting/],
  ['web.app', /shared hosting/],
  ['weebly.com', /shared hosting/],
  ['blogspot.com', /shared hosting/],
  ['bit.ly', /URL shortener/],
  ['tinyurl.com', /URL shortener/],
  ['list-manage.com', /click-tracking/],
  ['awstrack.me', /click-tracking/],
  // Not real targets at all.
  ['co.uk', /public suffix/],
  ['co.in', /public suffix/],
  ['com', /not a full hostname/],
  ['localhost', /local address/],
  ['router.local', /local address/],
  ['192.168.1.1', /local address/],
  ['127.0.0.1', /local address/],
  ['10.0.0.5', /local address/],
];

for (const [host, pattern] of IGNORED_WHOLE_HOSTS) {
  test(`whole-host entry ignored: ${host}`, () => {
    assert.match(String(wholeHostIgnoreReason(host)), pattern);
  });
}

const ALLOWED_WHOLE_HOSTS = [
  'evil.example',
  'login.evil.example',
  '203.0.113.77',
  // One person's site on shared hosting: each subdomain has its own owner.
  'scammer.github.io',
  'fake-login.web.app',
  'mailboxupdate.weebly.com',
  'phish.blogspot.com',
  'fake-bank.pages.dev',
  // One sender on a click-tracking service.
  '1kbdfrb1.r.eu-west-1.awstrack.me',
  'abc12.app.link',
  // Looks like a protected name, but isn't one.
  'google.com.evil.example',
  'notgoogle.com',
  'sbi.co.in.kyc-update.example',
  'gov.in.example',
];

for (const host of ALLOWED_WHOLE_HOSTS) {
  test(`whole-host entry allowed: ${host}`, () => assert.equal(wholeHostIgnoreReason(host), null));
}

test('screenEntries: reports what it ignored and why', () => {
  const screened = screenEntries(parseList('evil.example\ngithub.com\ngithub.io\nscammer.github.io\nbit.ly\ngov.in'));
  assert.deepEqual(screened.hosts, ['evil.example', 'scammer.github.io']);
  assert.deepEqual(screened.ignored.map((entry) => entry.host), ['github.com', 'github.io', 'bit.ly', 'gov.in']);
  for (const entry of screened.ignored) assert.ok(entry.reason.length > 0);
});

// --- Matching ------------------------------------------------------------------

function matcherFor(text, extra = {}) {
  const parsed = parseList(text);
  const screened = screenEntries(parsed);
  return createMatcher([
    {
      id: 'test',
      name: 'Test List',
      category: 'phishing',
      publishedAt: NOW - 3 * HOUR,
      hosts: new Set(screened.hosts),
      urls: new Set(screened.urls),
      ...extra,
    },
  ]);
}

const MATCH_LIST = `
evil.example
203.0.113.77
scammer.github.io
fake-login.web.app
github.com
github.io
sites.google.com
bit.ly
||shared.example/users/mallory/^$all
||shared.example/files/invoice.pdf^$all
||sites.google.com/view/fake-bank/^$all
||bit.ly/abc123^$all
||dl.example/get.php?id=42^$all
||files.example:8443/payload.bin^$all
`;

const MATCH_CASES = [
  // [link, expected kind or null, why]
  // Whole hosts
  ['https://evil.example/', 'host', 'listed host'],
  ['http://evil.example/login.php?x=1', 'host', 'any page on a listed host'],
  ['https://www.evil.example/', 'host', 'www. of a listed host'],
  ['https://login.evil.example/', 'host', 'subdomain of a listed host'],
  ['https://a.b.evil.example/x', 'host', 'deep subdomain of a listed host'],
  ['https://EVIL.example/', 'host', 'case of the host does not matter'],
  ['https://evil.example:8080/', 'host', 'a port does not hide a listed host'],
  ['http://203.0.113.77/update.exe', 'host', 'listed IP address'],
  ['https://evil.example.org/', null, 'a longer name that merely starts the same'],
  ['https://notevil.example/', null, 'a different name ending the same'],
  ['https://example/', null, 'the parent of a listed host'],
  ['http://203.0.113.78/', null, 'a neighbouring IP address'],

  // Shared hosting: one user's site is listed, the rest is untouched
  ['https://scammer.github.io/login', 'host', 'the listed user site'],
  ['https://docs.scammer.github.io/', 'host', 'a subdomain of the listed user site'],
  ['https://someone-else.github.io/', null, 'another user on the same hosting'],
  ['https://github.io/', null, 'the hosting domain itself, even though the list names it'],
  ['https://fake-login.web.app/', 'host', 'a listed app on shared hosting'],
  ['https://my-real-app.web.app/', null, 'another app on the same hosting'],

  // Protected domains: whole-host entries are ignored, path entries count
  ['https://github.com/', null, 'protected domain named by the list as a whole host'],
  ['https://github.com/nodejs/node', null, 'any page on that protected domain'],
  ['https://sites.google.com/view/my-school', null, 'another page on a protected host'],
  ['https://sites.google.com/view/fake-bank/', 'url', 'the listed page on a protected host'],
  ['https://sites.google.com/view/fake-bank/home', 'url', 'a page beneath the listed one'],
  ['https://sites.google.com/view/fake-bank', 'url', 'the listed page without its trailing slash'],
  ['https://sites.google.com/view/fake-bank-2/', null, 'a page whose name merely starts the same'],

  // Shorteners
  ['https://bit.ly/abc123', 'url', 'the listed short link'],
  ['https://bit.ly/zzz999', null, 'another short link on the same shortener'],

  // Paths
  ['https://shared.example/users/mallory/', 'url', 'the listed folder'],
  ['https://shared.example/users/mallory/invoice.html', 'url', 'a file in the listed folder'],
  ['https://shared.example/users/mallory/a/b/c.html?x=1#top', 'url', 'deep inside the listed folder'],
  ['https://shared.example/users/alice/notes.html', null, 'a different user on the same host'],
  ['https://shared.example/', null, 'the host itself'],
  ['https://shared.example/files/invoice.pdf', 'url', 'the listed file'],
  ['https://shared.example/files/invoice.pdf?download=1', 'url', 'the listed file with a query added'],
  ['https://shared.example/files/invoice.pdf.exe', null, 'a file whose name merely starts the same'],
  ['https://shared.example/files/Invoice.pdf', null, 'paths are case-sensitive'],
  ['http://shared.example/files/invoice.pdf', 'url', 'http and https are the same entry'],

  // Queries
  ['https://dl.example/get.php?id=42', 'url', 'the listed query'],
  ['https://dl.example/get.php?id=42&ref=mail', 'url', 'the listed query with more added'],
  ['https://dl.example/get.php?id=43', null, 'a different query value'],
  ['https://dl.example/get.php?id=420', null, 'a query value that merely starts the same'],
  ['https://dl.example/get.php', null, 'the same page without the listed query'],

  // Ports
  ['https://files.example:8443/payload.bin', 'url', 'the listed port'],
  ['https://files.example/payload.bin', null, 'the same path on the default port'],

  // Not web links
  ['mailto:someone@evil.example', null, 'not an http(s) link'],
  ['not a url', null, 'not a link at all'],
];

const match = matcherFor(MATCH_LIST);
for (const [href, expected, why] of MATCH_CASES) {
  test(`match: ${expected || 'clean'} - ${why}`, () => {
    const result = match(href);
    assert.equal(result ? result.kind : null, expected, href);
  });
}

test('match: reports the list, category and what matched', () => {
  assert.deepEqual(match('https://login.evil.example/x'), {
    source: 'test',
    name: 'Test List',
    category: 'phishing',
    kind: 'host',
    entry: 'evil.example',
    publishedAt: NOW - 3 * HOUR,
  });
  assert.equal(match('https://shared.example/users/mallory/x').entry, 'shared.example/users/mallory/');
});

test('match: a protected host stays unmatched even if it reaches the host set', () => {
  // Belt and braces: screening should have removed it, but matching checks again.
  const unscreened = createMatcher([
    { id: 't', name: 'T', category: 'phishing', publishedAt: NOW, hosts: new Set(['github.com', 'github.io', 'bit.ly']), urls: new Set() },
  ]);
  for (const href of ['https://github.com/a', 'https://someone.github.io/', 'https://bit.ly/x']) {
    assert.equal(unscreened(href), null, href);
  }
});

test('match: lists are consulted in order', () => {
  const both = createMatcher([
    { id: 'first', name: 'First', category: 'phishing', publishedAt: NOW, hosts: new Set(['evil.example']), urls: new Set() },
    { id: 'second', name: 'Second', category: 'malware', publishedAt: NOW, hosts: new Set(['evil.example', 'other.example']), urls: new Set() },
  ]);
  assert.equal(both('https://evil.example/').source, 'first');
  assert.equal(both('https://other.example/').source, 'second');
});

// --- The bundled test list -----------------------------------------------------

const FIXTURE = fs.readFileSync(path.join(__dirname, 'fixtures', 'blocklist.txt'), 'utf8');

test('fixture list: parses, and its "must be ignored" entries are ignored', () => {
  const parsed = parseList(FIXTURE);
  const screened = screenEntries(parsed);
  assert.equal(parsed.title, 'Tripwire test list');
  assert.deepEqual(screened.hosts, ['blocklisted-phish.example', 'malware-drop.test', '203.0.113.77']);
  assert.equal(screened.urls.length, 7);
  assert.deepEqual(
    screened.ignored.map((entry) => entry.host),
    ['github.com', 'sites.google.com', 'docs.google.com', 'github.io', 'bit.ly', 'gov.in', 'list-manage.com', 'co.uk', '192.168.1.1'],
  );
  assert.equal(parsed.rejected, 1, 'the wildcard entry');
  assert.deepEqual(checkDownload({ source: CONFIG.fixture, bytes: FIXTURE.length, parsed, entries: 10 }), { ok: true });
});

// --- Judging a download ----------------------------------------------------------

const PHISHING = CONFIG.sources[0];
const goodParse = { total: 60000, rejected: 30, publishedAt: NOW - HOUR };
const download = (overrides = {}) => ({ source: PHISHING, bytes: 2700000, parsed: goodParse, entries: 59970, ...overrides });

test('checkDownload: a normal download is accepted', () => {
  assert.deepEqual(checkDownload(download()), { ok: true });
  assert.deepEqual(checkDownload(download({ previous: { entries: 61000, publishedAt: NOW - 13 * HOUR } })), { ok: true });
});

test('checkDownload: an empty download is rejected', () => {
  const result = checkDownload(download({ bytes: 0, parsed: { total: 0, rejected: 0, publishedAt: null }, entries: 0 }));
  assert.equal(result.ok, false);
  assert.match(result.reason, /empty/);
});

test('checkDownload: a suspiciously small download is rejected', () => {
  assert.match(checkDownload(download({ bytes: 5000 })).reason, /only 5000 bytes/);
  assert.match(checkDownload(download({ entries: 200, parsed: { total: 200, rejected: 0, publishedAt: NOW } })).reason, /only 200 entries/);
});

test('checkDownload: something that is not a list is rejected', () => {
  const result = checkDownload(download({ parsed: { total: 60000, rejected: 59000, publishedAt: null }, entries: 1000 }));
  assert.equal(result.ok, false);
  assert.match(result.reason, /not list entries/);
});

test('checkDownload: a list that lost most of its entries is rejected', () => {
  const result = checkDownload(download({ entries: 12000, previous: { entries: 60000, publishedAt: NOW - 13 * HOUR } }));
  assert.equal(result.ok, false);
  assert.match(result.reason, /shrank from 60000 to 12000/);
});

test('checkDownload: a copy older than the installed one is rejected as older', () => {
  const result = checkDownload(download({ previous: { entries: 60000, publishedAt: NOW } }));
  assert.equal(result.ok, false);
  assert.equal(result.older, true);
});

test('checkDownload: the first download has nothing to be compared with', () => {
  assert.deepEqual(checkDownload(download({ previous: null })), { ok: true });
  assert.deepEqual(checkDownload(download({ previous: { entries: 0, publishedAt: null } })), { ok: true });
});

// --- Mirrors ---------------------------------------------------------------------

const SMALL_SOURCE = { ...PHISHING, minEntries: 3, minBytes: 10 };
const MIRRORS = ['https://one.example/list.txt', 'https://two.example/list.txt', 'https://three.example/list.txt'];
const listText = (updated, hosts) => [`! Title: L`, `! Updated: ${updated}`, ...hosts].join('\n');
const FRESH = listText('2026-10-08T12:00:00Z', ['a.example', 'b.example', 'c.example', 'd.example']);
const OLDER = listText('2026-10-07T00:00:00Z', ['a.example', 'b.example', 'c.example']);

// A fake network: `routes` maps each URL to a response, an Error, or a function.
function fakeFetch(routes) {
  const calls = [];
  const fetchList = async (url, etag) => {
    calls.push({ url, etag });
    const route = typeof routes[url] === 'function' ? routes[url](etag) : routes[url];
    if (route instanceof Error) throw route;
    if (!route) throw new Error('network unreachable');
    return route;
  };
  return { fetchList, calls };
}

const update = (routes, options = {}) => {
  const { fetchList, calls } = fakeFetch(routes);
  return updateFromMirrors({ source: SMALL_SOURCE, urls: MIRRORS, fetchList, now: NOW, ...options }).then(
    (result) => ({ result, calls }),
    (error) => ({ error, calls }),
  );
};

test('mirrors: the first mirror is enough when it works', async () => {
  const { result, calls } = await update({ [MIRRORS[0]]: { status: 200, text: FRESH, etag: '"v2"' } });
  assert.equal(result.status, 'updated');
  assert.equal(result.list.from, MIRRORS[0]);
  assert.equal(result.list.etag, '"v2"');
  assert.equal(result.list.entries, 4);
  assert.equal(result.list.publishedAt, Date.parse('2026-10-08T12:00:00Z'));
  assert.deepEqual(result.list.hosts, ['a.example', 'b.example', 'c.example', 'd.example']);
  assert.equal(calls.length, 1);
});

test('mirrors: falls back in order when earlier mirrors fail', async () => {
  const { result, calls } = await update({
    [MIRRORS[0]]: new Error('network unreachable'),
    [MIRRORS[1]]: { status: 503, text: 'Service Unavailable' },
    [MIRRORS[2]]: { status: 200, text: FRESH },
  });
  assert.equal(result.status, 'updated');
  assert.equal(result.list.from, MIRRORS[2]);
  assert.deepEqual(calls.map((call) => call.url), MIRRORS);
});

test('mirrors: a mirror serving an error page is skipped', async () => {
  const { result } = await update({
    [MIRRORS[0]]: { status: 200, text: '<html><body><h1>It works!</h1><p>Default page</p></body></html>' },
    [MIRRORS[1]]: { status: 200, text: FRESH },
  });
  assert.equal(result.list.from, MIRRORS[1]);
});

test('mirrors: an empty download does not replace anything', async () => {
  const { error } = await update({
    [MIRRORS[0]]: { status: 200, text: '' },
    [MIRRORS[1]]: { status: 200, text: '! Title: L\n' },
    [MIRRORS[2]]: { status: 200, text: 'a.example' },
  });
  assert.ok(error, 'every mirror was rejected');
  assert.match(error.message, /one\.example: the download is empty/);
  assert.match(error.message, /three\.example: only/);
});

test('mirrors: when all fail, the error names each mirror and nothing is returned to install', async () => {
  const { error, result } = await update({
    [MIRRORS[0]]: new Error('network unreachable'),
    [MIRRORS[1]]: { status: 404 },
    [MIRRORS[2]]: new Error('timed out'),
  });
  assert.equal(result, undefined);
  assert.match(error.message, /one\.example: network unreachable; two\.example: HTTP 404; three\.example: timed out/);
});

test('mirrors: "not modified" means the installed list is current', async () => {
  const previous = { entries: 4, publishedAt: Date.parse('2026-10-08T12:00:00Z'), etag: '"v2"', from: MIRRORS[0] };
  const { result, calls } = await update(
    { [MIRRORS[0]]: (etag) => (etag === '"v2"' ? { status: 304 } : { status: 200, text: FRESH }) },
    { previous },
  );
  assert.equal(result.status, 'unchanged');
  assert.equal(calls[0].etag, '"v2"');
});

test('mirrors: the saved etag is only sent to the mirror it came from, and not when forced', async () => {
  const previous = { entries: 4, publishedAt: Date.parse('2026-10-08T12:00:00Z'), etag: '"v2"', from: MIRRORS[1] };
  const first = await update({ [MIRRORS[0]]: { status: 200, text: FRESH } }, { previous });
  assert.equal(first.calls[0].etag, null);

  const forced = await update({ [MIRRORS[0]]: new Error('down'), [MIRRORS[1]]: { status: 200, text: FRESH } }, { previous, force: true });
  assert.equal(forced.calls[1].etag, null);
});

test('mirrors: the same list again is "unchanged", not a new install', async () => {
  const previous = { entries: 4, publishedAt: Date.parse('2026-10-08T12:00:00Z'), fingerprint: fingerprintOf(FRESH), etag: null, from: MIRRORS[0] };
  const { result } = await update({ [MIRRORS[0]]: { status: 200, text: FRESH, etag: '"v2"' } }, { previous });
  assert.equal(result.status, 'unchanged');
  assert.equal(result.etag, '"v2"');
});

test('mirrors: a list with no date is recognised as unchanged by its content', async () => {
  const text = 'a.example\nb.example\nc.example';
  const first = await update({ [MIRRORS[0]]: { status: 200, text } });
  assert.equal(first.result.status, 'updated');

  const { fingerprint, entries, publishedAt } = first.result.list;
  const previous = { entries, publishedAt, fingerprint, etag: null, from: MIRRORS[0] };
  const again = await update({ [MIRRORS[0]]: { status: 200, text } }, { previous });
  assert.equal(again.result.status, 'unchanged');

  // Same number of entries, different content: that is a new list.
  const edited = await update({ [MIRRORS[0]]: { status: 200, text: 'a.example\nb.example\nz.example' } }, { previous });
  assert.equal(edited.result.status, 'updated');
  assert.deepEqual(edited.result.list.hosts, ['a.example', 'b.example', 'z.example']);
});

test('fingerprintOf: the same text gives the same value, a changed one does not', () => {
  assert.equal(fingerprintOf('a.example\nb.example'), fingerprintOf('a.example\nb.example'));
  assert.notEqual(fingerprintOf('a.example\nb.example'), fingerprintOf('a.example\nc.example'));
  assert.notEqual(fingerprintOf('ab'), fingerprintOf('ba'));
  assert.match(fingerprintOf(''), /^0:[0-9a-f]+$/);
});

test('mirrors: never goes back to an older copy', async () => {
  const previous = { entries: 4, publishedAt: Date.parse('2026-10-08T12:00:00Z'), etag: null, from: MIRRORS[0] };
  const { result, error } = await update(
    { [MIRRORS[0]]: new Error('down'), [MIRRORS[1]]: { status: 200, text: OLDER }, [MIRRORS[2]]: new Error('down') },
    { previous },
  );
  assert.equal(error, undefined);
  assert.equal(result.status, 'unchanged');
  assert.match(result.note, /older than the list already installed/);
});

test('mirrors: a stale mirror is passed over for a current one', async () => {
  const previous = { entries: 4, publishedAt: Date.parse('2026-10-07T12:00:00Z'), etag: null, from: MIRRORS[0] };
  const { result } = await update(
    { [MIRRORS[0]]: { status: 200, text: OLDER }, [MIRRORS[1]]: { status: 200, text: FRESH } },
    { previous },
  );
  assert.equal(result.status, 'updated');
  assert.equal(result.list.from, MIRRORS[1]);
});

test('mirrors: whole-host entries for protected domains are dropped and reported', async () => {
  const text = listText('2026-10-08T12:00:00Z', ['a.example', 'b.example', 'c.example', 'github.com', 'web.app']);
  const { result } = await update({ [MIRRORS[0]]: { status: 200, text } });
  assert.deepEqual(result.list.hosts, ['a.example', 'b.example', 'c.example']);
  assert.deepEqual(result.list.ignored.map((entry) => entry.host), ['github.com', 'web.app']);
});

test('mirrors: a list with no date is stamped with the download time', async () => {
  const { result } = await update({ [MIRRORS[0]]: { status: 200, text: 'a.example\nb.example\nc.example' } });
  assert.equal(result.list.publishedAt, NOW);
});

test('config: three mirrors on three different hosts, all https', () => {
  const hosts = CONFIG.mirrors.map((url) => new URL(url).host);
  assert.equal(new Set(hosts).size, 3);
  for (const url of CONFIG.mirrors) assert.ok(url.startsWith('https://') && url.endsWith('/'), url);
});

test('retryDelayMinutes: doubles from 15 minutes, capped at the normal interval', () => {
  assert.deepEqual([1, 2, 3, 4, 5, 6, 20].map(retryDelayMinutes), [15, 30, 60, 120, 240, 360, 360]);
});

// --- Wording ---------------------------------------------------------------------

test('formatAge', () => {
  const cases = [
    [0, 'just now'],
    [90 * 1000, 'just now'],
    [5 * 60000, '5 minutes ago'],
    [59 * 60000, '59 minutes ago'],
    [HOUR, '1 hour ago'],
    [3 * HOUR + 20 * 60000, '3 hours ago'],
    [47 * HOUR, '47 hours ago'],
    [48 * HOUR, '2 days ago'],
    [9 * 24 * HOUR, '9 days ago'],
    [-5000, 'just now'],
  ];
  for (const [ms, expected] of cases) assert.equal(formatAge(ms), expected, String(ms));
});

const LISTING = { source: 'phishing', name: 'Phishing URL Blocklist', category: 'phishing', kind: 'host', entry: 'evil.example', publishedAt: NOW - 3 * HOUR };

test('listingReason: names the category, the list and its age', () => {
  assert.equal(listingReason(LISTING, NOW), 'Listed as phishing by Phishing URL Blocklist (list updated 3 hours ago)');
  assert.equal(
    listingReason({ ...LISTING, name: 'Online Malicious URL Blocklist', category: 'malware', publishedAt: NOW - 3 * 24 * HOUR }, NOW),
    'Listed as malware by Online Malicious URL Blocklist (list updated 3 days ago)',
  );
});

test('applyListing: always dangerous, with the heuristic reasons kept underneath', () => {
  const clean = applyListing({ level: 'ok', score: 0, reasons: [] }, LISTING, NOW);
  assert.deepEqual(clean, { level: 'dangerous', score: 100, reasons: ['Listed as phishing by Phishing URL Blocklist (list updated 3 hours ago)'] });

  const withNotes = applyListing({ level: 'suspicious', score: 65, reasons: ['Host is a raw IP address (203.0.113.77)', 'Not HTTPS (connection is not encrypted)'] }, LISTING, NOW);
  assert.equal(withNotes.level, 'dangerous');
  assert.equal(withNotes.reasons.length, 3);
  assert.match(withNotes.reasons[0], /^Listed as phishing/);
  assert.match(withNotes.reasons[1], /raw IP address/);
});

test('describeSource: healthy, out of date, failing and missing', () => {
  const healthy = describeSource({ entries: 62680, publishedAt: NOW - 3 * HOUR, error: null }, NOW);
  assert.deepEqual(healthy, { tone: 'ok', text: '62,680 entries, updated 3 hours ago', detail: '' });

  const stale = describeSource({ entries: 62680, publishedAt: NOW - 72 * HOUR, error: null }, NOW);
  assert.equal(stale.tone, 'warn');
  assert.match(stale.text, /^List is out of date: 62,680 entries, updated 3 days ago$/);
  assert.match(stale.detail, /still being used/);

  const borderline = describeSource({ entries: 10, publishedAt: NOW - 47 * HOUR, error: null }, NOW);
  assert.equal(borderline.tone, 'ok', '47 hours is not yet out of date');

  const failing = describeSource({ entries: 62680, publishedAt: NOW - 20 * HOUR, error: 'one.example: HTTP 503' }, NOW);
  assert.equal(failing.tone, 'warn');
  assert.equal(failing.detail, 'Last check failed: one.example: HTTP 503');

  const staleAndFailing = describeSource({ entries: 62680, publishedAt: NOW - 100 * HOUR, error: 'all mirrors down' }, NOW);
  assert.match(staleAndFailing.text, /out of date/);
  assert.match(staleAndFailing.detail, /all mirrors down/);

  assert.deepEqual(describeSource(undefined, NOW), { tone: 'pending', text: 'Not downloaded yet', detail: '' });
  assert.equal(describeSource({ entries: 0, error: 'timed out' }, NOW).tone, 'error');
});

test('describeAll: one line for every list together', () => {
  const fresh = { entries: 60000, publishedAt: NOW - 3 * HOUR, error: null };
  const other = { entries: 25000, publishedAt: NOW - 5 * HOUR, error: null };
  assert.deepEqual(describeAll([fresh, other], NOW), { tone: 'ok', text: '85,000 entries, updated 5 hours ago' });

  const old = { entries: 25000, publishedAt: NOW - 60 * HOUR, error: null };
  const stale = describeAll([fresh, old], NOW);
  assert.equal(stale.tone, 'warn');
  assert.match(stale.text, /out of date/);

  assert.equal(describeAll([fresh, { ...other, error: 'HTTP 503' }], NOW).tone, 'warn');
  assert.equal(describeAll([fresh, undefined], NOW).tone, 'warn');
  assert.deepEqual(describeAll([undefined, undefined], NOW), { tone: 'pending', text: 'not downloaded yet' });
  assert.equal(describeAll([{ entries: 0, error: 'timed out' }, undefined], NOW).tone, 'error');
});

// --- A page that is itself listed ------------------------------------------------

const { analyzeLink, analyzePage } = require('../src/lib/analyzer.js');

// What the scanner does when the page's own address is listed: the page's
// verdict becomes the listing, and links are analysed against that.
const LISTED_PAGE = 'https://evil.example/portal/index.html';
const listedPageVerdict = applyListing(analyzePage(LISTED_PAGE), LISTING, NOW);

test('listed page: the page verdict is dangerous even if its address looks ordinary', () => {
  assert.equal(analyzePage(LISTED_PAGE).level, 'ok');
  assert.equal(listedPageVerdict.level, 'dangerous');
  assert.match(listedPageVerdict.reasons[0], /^Listed as phishing by Phishing URL Blocklist/);
});

const LISTED_PAGE_LINKS = [
  // [href, text, expected level, why]
  ['/login', 'Log in', 'dangerous', 'relative link'],
  ['https://evil.example/account', 'Account', 'dangerous', 'absolute link to the same host'],
  ['https://cdn.evil.example/download.zip', 'Download', 'dangerous', 'a subdomain of the same site'],
  ['https://en.wikipedia.org/wiki/Phishing', 'Read more', 'ok', 'a link that leaves the site'],
  ['https://www.example.org/', 'example.org', 'ok', 'another site named honestly'],
];

for (const [href, text, level, why] of LISTED_PAGE_LINKS) {
  test(`listed page: ${why} is ${level}`, () => {
    const result = analyzeLink({ href, text, pageUrl: LISTED_PAGE, pageVerdict: listedPageVerdict });
    assert.equal(result.level, level, JSON.stringify(result.reasons));
    if (level === 'dangerous') {
      assert.match(result.reasons[0], /^This page itself looks dangerous: listed as phishing by Phishing URL Blocklist/);
    }
  });
}

test('listed page: without the listing, the same links are fine', () => {
  for (const [href, text] of LISTED_PAGE_LINKS) {
    assert.equal(analyzeLink({ href, text, pageUrl: LISTED_PAGE }).level, 'ok', href);
  }
});

test('listed page: a page on a protected host is matched only by its own address', () => {
  const pageMatch = matcherFor(MATCH_LIST);
  assert.equal(pageMatch('https://sites.google.com/view/fake-bank/home').kind, 'url');
  assert.equal(pageMatch('https://sites.google.com/view/my-school'), null);
  assert.equal(pageMatch('https://github.com/nodejs/node'), null);
});

// --- Who gets the bundled test list ------------------------------------------------

const STORE_MANIFEST = { name: 'Tripwire', version: '0.5.1', update_url: 'https://clients2.google.com/service/update2/crx' };
const SOURCE_MANIFEST = { name: 'Tripwire', version: '0.5.1' };

const INSTALL_CASES = [
  // [what, facts, expected]
  ['unpacked in developer mode', { manifest: SOURCE_MANIFEST, self: { installType: 'development' } }, true],

  ['installed from the Web Store', { manifest: STORE_MANIFEST, self: { installType: 'normal' } }, false],
  ['installed by enterprise policy', { manifest: STORE_MANIFEST, self: { installType: 'admin' } }, false],
  ['sideloaded by other software', { manifest: SOURCE_MANIFEST, self: { installType: 'sideload' } }, false],
  ['installed some other way', { manifest: SOURCE_MANIFEST, self: { installType: 'other' } }, false],
  ['a normal install whose manifest has no update_url', { manifest: SOURCE_MANIFEST, self: { installType: 'normal' } }, false],

  // Contradictory or missing facts: not a development install.
  ['"development" but with a store update_url', { manifest: STORE_MANIFEST, self: { installType: 'development' } }, false],
  ['"development" with an empty update_url', { manifest: { ...SOURCE_MANIFEST, update_url: '' }, self: { installType: 'development' } }, false],
  ['Chrome gave no answer', { manifest: SOURCE_MANIFEST, self: null }, false],
  ['Chrome gave an answer without an install type', { manifest: SOURCE_MANIFEST, self: {} }, false],
  ['an install type this code has never heard of', { manifest: SOURCE_MANIFEST, self: { installType: 'unpacked' } }, false],
  ['install type in the wrong case', { manifest: SOURCE_MANIFEST, self: { installType: 'Development' } }, false],
  ['no manifest', { manifest: null, self: { installType: 'development' } }, false],
  ['a manifest that is not an object', { manifest: 'manifest.json', self: { installType: 'development' } }, false],
  ['nothing known at all', {}, false],
];

for (const [what, facts, expected] of INSTALL_CASES) {
  test(`test list: ${expected ? 'loaded' : 'NOT loaded'} when ${what}`, () => {
    assert.equal(isDevelopmentInstall(facts), expected);
  });
}

test('test list: called with nothing, the answer is no', () => {
  assert.equal(isDevelopmentInstall(), false);
});

test('test list: it is not one of the real sources', () => {
  assert.ok(!CONFIG.sources.some((source) => source.id === CONFIG.fixture.id));
  assert.ok(!CONFIG.sources.some((source) => source.local));
  assert.equal(CONFIG.fixture.local, true);
});
