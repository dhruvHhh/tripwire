// Run with: node --test

const test = require('node:test');
const assert = require('node:assert/strict');

const { analyzeLink, getRegistrableDomain, CONFIG } = require('../src/lib/analyzer.js');

const BLOG = 'https://blog.example.org/post/1';

const LONG_TRACKING_URL =
  'https://shop.example.com/products/blue-widget-deluxe-edition?' +
  'utm_source=newsletter&utm_medium=email&utm_campaign=spring_sale_2026&utm_content=hero_banner' +
  '&utm_term=blue+widget&gclid=EAIaIQobChMI8fKq1eXQ_gIVzQutBh0x5QZWEAAYASAAEgJx7PD_BwE' +
  '&fbclid=IwAR2xJ9d8H3kLmN5pQrStUvWxYz0aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567' +
  '&mc_cid=a1b2c3d4e5&mc_eid=f6g7h8i9j0&ref=homepage_recommendations_carousel_slot_3';

// Each case: what goes in, the level that must come out, and optionally a
// pattern one of the reasons must match. `clean: true` means no reasons at all.
const CASES = [
  // --- Must stay green: false-positive guards ------------------------------
  { name: 'ordinary https link with "click here" text', level: 'ok', clean: true,
    input: { href: 'https://example.com/about', text: 'click here', pageUrl: BLOG } },
  { name: 'ordinary link with descriptive text', level: 'ok', clean: true,
    input: { href: 'https://en.wikipedia.org/wiki/Phishing', text: 'Read more about phishing', pageUrl: BLOG } },
  { name: 'relative same-site link', level: 'ok', clean: true,
    input: { href: '/archive/2026', text: 'Archive', pageUrl: BLOG } },
  { name: 'text is bare domain, href adds www', level: 'ok', clean: true,
    input: { href: 'https://www.example.com/', text: 'example.com', pageUrl: BLOG } },
  { name: 'text has www, href does not', level: 'ok', clean: true,
    input: { href: 'https://example.com/pricing', text: 'www.example.com', pageUrl: BLOG } },
  { name: 'text is parent domain, href is a subdomain', level: 'ok', clean: true,
    input: { href: 'https://docs.python.org/3/library/', text: 'python.org', pageUrl: BLOG } },
  { name: 'text is a subdomain, href is the parent domain', level: 'ok', clean: true,
    input: { href: 'https://www.python.org/downloads/', text: 'docs.python.org', pageUrl: BLOG } },
  { name: 'multi-part suffix: bbc.co.uk vs www.bbc.co.uk', level: 'ok', clean: true,
    input: { href: 'https://www.bbc.co.uk/news', text: 'bbc.co.uk/news', pageUrl: BLOG } },
  { name: 'a real brand domain is not its own lookalike', level: 'ok', clean: true,
    input: { href: 'https://www.paypal.com/signin', text: 'Log in to PayPal', pageUrl: BLOG } },
  { name: 'brand on a country domain (amazon.in)', level: 'ok', clean: true,
    input: { href: 'https://www.amazon.in/gp/cart', text: 'amazon.in', pageUrl: BLOG } },
  { name: 'brand on a multi-part country suffix (google.com.au)', level: 'ok', clean: true,
    input: { href: 'https://www.google.com.au/maps', text: 'Maps', pageUrl: BLOG } },
  { name: 't.co on x.com, even with a domain as the visible text', level: 'ok', clean: true,
    input: { href: 'https://t.co/AbC123xyz', text: 'nytimes.com/2026/03/…', pageUrl: 'https://x.com/home' } },
  { name: 'lnkd.in on linkedin.com', level: 'ok', clean: true,
    input: { href: 'https://lnkd.in/gK3xYz9', text: 'example.com/report', pageUrl: 'https://www.linkedin.com/feed/' } },
  { name: 'shortener with plain text elsewhere is only a minor note', level: 'ok', reason: /shortener/i,
    input: { href: 'https://bit.ly/3xYzAbC', text: 'Sign up for the webinar', pageUrl: BLOG } },
  { name: 'youtu.be link shown as youtube.com', level: 'ok', clean: true,
    input: { href: 'https://youtu.be/dQw4w9WgXcQ', text: 'youtube.com/watch?v=dQw4w9WgXcQ', pageUrl: BLOG } },
  { name: 'long URL full of tracking parameters', level: 'ok',
    input: { href: LONG_TRACKING_URL, text: 'Blue Widget Deluxe', pageUrl: BLOG } },
  { name: 'file name as link text is not a domain (README.md)', level: 'ok', clean: true,
    input: { href: 'https://github.com/nodejs/node/blob/main/README.md', text: 'README.md', pageUrl: BLOG } },
  { name: 'product name with a dot is not a domain (ASP.NET)', level: 'ok', clean: true,
    input: { href: 'https://dotnet.microsoft.com/apps/aspnet', text: 'ASP.NET', pageUrl: BLOG } },
  { name: 'email address as link text', level: 'ok', clean: true,
    input: { href: 'https://example.net/contact', text: 'help@example.com', pageUrl: BLOG } },
  { name: 'sentence that merely mentions a domain', level: 'ok', clean: true,
    input: { href: 'https://partner.example.net/', text: 'Our friends at example.com wrote this', pageUrl: BLOG } },
  { name: 'plain http link is only a minor note', level: 'ok', reason: /not https/i,
    input: { href: 'http://old-forum.example.com/thread/42', text: 'the original thread', pageUrl: BLOG } },
  { name: 'router address in a how-to', level: 'ok', reason: /local network/i,
    input: { href: 'http://192.168.1.1/', text: 'open your router settings', pageUrl: BLOG } },
  { name: 'localhost dev server', level: 'ok', clean: true,
    input: { href: 'http://localhost:3000/', text: 'http://localhost:3000', pageUrl: BLOG } },
  { name: 'legitimate single-script IDN', level: 'ok', reason: /non-ascii/i,
    input: { href: 'https://bücher.de/', text: 'Bücher', pageUrl: BLOG } },
  { name: 'real site near a brand name (telegraph.co.uk)', level: 'ok', clean: true,
    input: { href: 'https://www.telegraph.co.uk/news/', text: 'The Telegraph', pageUrl: BLOG } },
  { name: 'different first letter is not a lookalike (cloud.com / icloud)', level: 'ok', clean: true,
    input: { href: 'https://www.cloud.com/', text: 'Cloud', pageUrl: BLOG } },
  { name: 'two edits from a 6-letter brand is too far (gitlab / github)', level: 'ok', clean: true,
    input: { href: 'https://gitlab.com/gitlab-org', text: 'GitLab', pageUrl: BLOG } },
  { name: 'short brand gets no fuzzy match (sbs vs sbi)', level: 'ok', clean: true,
    input: { href: 'https://www.sbs.com.au/news', text: 'SBS News', pageUrl: BLOG } },
  { name: 'ordinary cloud subdomains', level: 'ok', clean: true,
    input: { href: 'https://s3.ap-south-1.amazonaws.com/my-bucket/report.pdf', text: 'Download the report', pageUrl: BLOG } },
  { name: 'high-abuse TLD alone is only a minor note', level: 'ok', reason: /top-level domain/i,
    input: { href: 'https://abc.xyz/investor/', text: 'Alphabet investor relations', pageUrl: BLOG } },
  { name: 'same-site redirector with a domain as text', level: 'ok', reason: /same site/i,
    input: { href: 'https://l.facebook.com/l.php?u=https%3A%2F%2Fnytimes.com%2F', text: 'nytimes.com', pageUrl: 'https://www.facebook.com/' } },
  { name: 'links between pages of an IP-hosted admin panel', level: 'ok', reason: /same site/i,
    input: { href: 'http://203.0.113.9/settings', text: 'Settings', pageUrl: 'http://203.0.113.9/' } },
  { name: 'app deep link has no host to judge', level: 'ok', clean: true,
    input: { href: 'whatsapp://send?text=hello', text: 'Share on WhatsApp', pageUrl: BLOG } },

  // --- Suspicious -----------------------------------------------------------
  { name: 'text shows one domain, href goes to another', level: 'suspicious', reason: /link text shows myblog\.com/i,
    input: { href: 'https://tracker.example.net/c/123', text: 'myblog.com', pageUrl: BLOG } },
  { name: 'domain text hidden behind a third-party shortener', level: 'suspicious', reason: /through a shortener/i,
    input: { href: 'https://bit.ly/3xYzAbC', text: 'paypal.com', pageUrl: BLOG } },
  { name: 'raw public IP over http', level: 'suspicious', reason: /raw ip address/i,
    input: { href: 'http://203.0.113.9/login', text: 'Log in', pageUrl: BLOG } },
  { name: 'one edit from a brand (gooogle)', level: 'suspicious', reason: /resembles google\.com/i,
    input: { href: 'https://gooogle.example/', text: 'Search', pageUrl: BLOG } },
  { name: 'two edits from a longer brand (phonepay)', level: 'suspicious', reason: /resembles phonepe\.com/i,
    input: { href: 'https://www.phonepay.example/offers', text: 'Cashback offers', pageUrl: BLOG } },
  { name: 'transposed letters (flipkrat)', level: 'suspicious', reason: /resembles flipkart\.com/i,
    input: { href: 'https://www.flipkrat.example/sale', text: 'Big sale', pageUrl: BLOG } },
  { name: 'username and password in the URL', level: 'suspicious', reason: /login details/i,
    input: { href: 'https://admin:hunter2@intranet.example.com/', text: 'Intranet', pageUrl: BLOG } },
  { name: 'data: URI download', level: 'suspicious', reason: /data: link/i,
    input: { href: 'data:image/png;base64,iVBORw0KGgo=', text: 'Download chart', pageUrl: BLOG } },
  { name: 'http on a high-abuse TLD', level: 'suspicious', reason: /top-level domain \(\.tk\)/i,
    input: { href: 'http://free-prizes.tk/claim', text: 'Claim your prize', pageUrl: BLOG } },
  { name: 'deep subdomain chain on a high-abuse TLD', level: 'suspicious', reason: /many subdomains \(4\)/i,
    input: { href: 'https://secure.login.account.verify.example.xyz/', text: 'Verify your account', pageUrl: BLOG } },
  { name: 'IDN over http', level: 'suspicious', reason: /non-ascii/i,
    input: { href: 'http://xn--bcher-kva.de/', text: 'Books', pageUrl: BLOG } },

  // --- Dangerous ------------------------------------------------------------
  { name: 'text names a brand, href goes elsewhere', level: 'dangerous', reason: /link text shows paypal\.com but it goes to evil\.example/i,
    input: { href: 'https://evil.example/signin', text: 'paypal.com', pageUrl: BLOG } },
  { name: 'full URL as text, raw IP as destination', level: 'dangerous', reason: /irctc\.co\.in/i,
    input: { href: 'http://203.0.113.50/irctc/', text: 'https://www.irctc.co.in/nget/train-search', pageUrl: BLOG } },
  { name: 'decimal IP (3232235777)', level: 'dangerous', reason: /disguised ip address \(3232235777 is really 192\.168\.1\.1\)/i,
    input: { href: 'http://3232235777/', text: 'Continue', pageUrl: BLOG } },
  { name: 'hex IP', level: 'dangerous', reason: /disguised ip address/i,
    input: { href: 'http://0xC0A80101/', text: 'Continue', pageUrl: BLOG } },
  { name: 'octal IP', level: 'dangerous', reason: /disguised ip address/i,
    input: { href: 'http://0300.0250.0001.0001/', text: 'Continue', pageUrl: BLOG } },
  { name: 'mixed-script homograph (Cyrillic a in paypal)', level: 'dangerous', reason: /mixes latin and cyrillic/i,
    input: { href: 'https://xn--pypal-4ve.com/', text: 'PayPal', pageUrl: BLOG } },
  { name: 'whole-script homograph (all-Cyrillic apple)', level: 'dangerous', reason: /imitates apple\.com/i,
    input: { href: 'https://xn--80ak6aa92e.com/', text: 'Apple', pageUrl: BLOG } },
  { name: 'non-ASCII href written directly (not pre-encoded)', level: 'dangerous', reason: /imitates paypal\.com/i,
    input: { href: 'https://pаypal.com/', text: 'PayPal', pageUrl: BLOG } },
  { name: 'credentials disguised as a host (google.com@evil)', level: 'dangerous', reason: /looks like google\.com but really goes to evil\.example/i,
    input: { href: 'http://google.com@evil.example/', text: 'Google', pageUrl: BLOG } },
  { name: 'digit substitution (paypa1)', level: 'dangerous', reason: /imitates paypal\.com/i,
    input: { href: 'https://www.paypa1.example/', text: 'Log in', pageUrl: BLOG } },
  { name: 'rn for m (arnazon)', level: 'dangerous', reason: /imitates amazon\.com/i,
    input: { href: 'https://arnazon.example/deals', text: 'Deals', pageUrl: BLOG } },
  { name: 'hyphen inserted into a brand (pay-tm)', level: 'dangerous', reason: /imitates paytm\.com/i,
    input: { href: 'https://pay-tm.example/kyc', text: 'Complete KYC', pageUrl: BLOG } },
  { name: 'brand.com.evil.com subdomain trick', level: 'dangerous', reason: /uses "paypal\.com" as a subdomain of secure-login\.example/i,
    input: { href: 'https://www.paypal.com.secure-login.example/', text: 'Log in', pageUrl: BLOG } },
  { name: 'subdomain trick with a multi-part suffix (sbi.co.in.*)', level: 'dangerous', reason: /uses "sbi\.co\.in" as a subdomain/i,
    input: { href: 'https://sbi.co.in.kyc-update.example/login', text: 'Update KYC', pageUrl: BLOG } },
  { name: 'data: URI that renders as a page', level: 'dangerous', reason: /run as a web page/i,
    input: { href: 'data:text/html;base64,PGgxPkxvZ2luPC9oMT4=', text: 'Open document', pageUrl: BLOG } },
  { name: 'near-brand typo over http on a high-abuse TLD', level: 'dangerous', reason: /resembles hdfcbank\.com/i,
    input: { href: 'http://hdfcbamk.tk/netbanking', text: 'NetBanking', pageUrl: BLOG } },
];

for (const { name, input, level, reason, clean } of CASES) {
  test(`${level}: ${name}`, () => {
    const result = analyzeLink(input);
    const detail = `score ${result.score}, reasons: ${JSON.stringify(result.reasons)}`;

    assert.equal(result.level, level, detail);
    if (reason) {
      assert.ok(result.reasons.some((r) => reason.test(r)), `no reason matches ${reason}; ${detail}`);
    }
    if (clean) {
      assert.deepEqual(result.reasons, []);
      assert.equal(result.score, 0);
    }
  });
}

test('at least a third of the cases are links that stay green', () => {
  const green = CASES.filter((c) => c.level === 'ok').length;
  assert.ok(CASES.length >= 25, `only ${CASES.length} cases`);
  assert.ok(green * 3 >= CASES.length, `${green} of ${CASES.length} cases are green`);
});

test('result always has the documented shape', () => {
  for (const { input } of CASES) {
    const result = analyzeLink(input);
    assert.deepEqual(Object.keys(result).sort(), ['level', 'reasons', 'score']);
    assert.ok(['ok', 'suspicious', 'dangerous'].includes(result.level));
    assert.ok(Number.isInteger(result.score));
    assert.ok(result.score >= 0 && result.score <= CONFIG.maxScore);
    assert.ok(result.reasons.every((r) => typeof r === 'string' && r.length > 0));
  }
});

test('nothing is ever described as safe', () => {
  for (const { input } of CASES) {
    const result = analyzeLink(input);
    assert.notEqual(result.level, 'safe');
    assert.ok(!result.reasons.some((r) => /\bsafe\b/i.test(r)));
  }
});

test('garbage input does not throw and scores nothing', () => {
  for (const input of [undefined, {}, { href: '' }, { href: 'http://' }, { href: 'not a url' }, { href: null, text: null }]) {
    assert.deepEqual(analyzeLink(input), { level: 'ok', score: 0, reasons: [] });
  }
});

test('same link on its own site scores lower than on another site', () => {
  const href = 'http://203.0.113.9/login';
  const elsewhere = analyzeLink({ href, pageUrl: BLOG });
  const sameSite = analyzeLink({ href, pageUrl: 'http://203.0.113.9/' });
  assert.ok(sameSite.score < elsewhere.score);
});

const DOMAIN_CASES = [
  ['example.com', 'example.com'],
  ['www.example.com', 'example.com'],
  ['docs.python.org', 'python.org'],
  ['a.b.c.example.com', 'example.com'],
  ['www.bbc.co.uk', 'bbc.co.uk'],
  ['www.onlinesbi.sbi', 'onlinesbi.sbi'],
  ['retail.sbi.co.in', 'sbi.co.in'],
  ['www.incometax.gov.in', 'incometax.gov.in'],
  ['www.iitb.ac.in', 'iitb.ac.in'],
  ['shop.example.com.au', 'example.com.au'],
  ['alice.github.io', 'alice.github.io'],
  ['EXAMPLE.COM.', 'example.com'],
  ['localhost', 'localhost'],
  ['192.168.1.1', '192.168.1.1'],
  ['co.uk', 'co.uk'],
];

test('getRegistrableDomain', () => {
  for (const [host, expected] of DOMAIN_CASES) {
    assert.equal(getRegistrableDomain(host), expected, host);
  }
});
