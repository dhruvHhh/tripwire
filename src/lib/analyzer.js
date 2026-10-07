// Tripwire link analyzer.
//
// Pure, offline heuristics: analyzeLink() looks only at the strings it is
// given. No DOM, no network, no extension APIs, so the same file runs in the
// content script and under Node's test runner.
//
// Heuristics can raise red flags but can never prove a link is safe, which is
// why the lowest level is "ok" (no red flags found) and not "safe".

(() => {
  'use strict';

  // ---------------------------------------------------------------------------
  // Config: every weight, threshold and list lives here.
  // ---------------------------------------------------------------------------

  const CONFIG = {
    // Score needed to reach each level. Below `suspicious` the link is "ok".
    thresholds: { suspicious: 30, dangerous: 70 },
    maxScore: 100,

    // Applied to the total when the link stays on the page's own registrable
    // domain: if you already trust the page, its own links add little risk.
    sameSiteMultiplier: 0.25,

    weights: {
      // 1. Text / href mismatch
      textMismatch: 55, // text shows a domain, href goes elsewhere
      textMismatchBrand: 25, // ...and the text names a listed brand
      textMismatchViaShortener: 25, // replaces textMismatch when the href is a shortener

      // 2. IP-address hosts
      ipHost: 50,
      ipObfuscated: 40, // decimal / hex / octal / percent-encoded forms
      ipPrivate: 10, // replaces ipHost for plain local addresses (routers, dev servers)

      // 3. Homographs
      idnHost: 25, // punycode / non-ASCII hostname
      mixedScript: 50, // e.g. Latin + Cyrillic inside one label

      // 4. Credentials in the URL
      credentials: 60,
      credentialsLookLikeHost: 30, // the "google.com@evil.com" form

      // 5. URL shorteners (common and usually harmless, so mild)
      shortener: 10,

      // 6. Brand lookalikes
      lookalikeConfusable: 80, // paypa1, pay-pal, Cyrillic "apple"
      lookalikeEditDistance: 45, // 1-2 edits away from a brand
      brandInSubdomain: 80, // paypal.com.evil.com

      // 7. Everything else
      notHttps: 15,
      dataUri: 40,
      dataUriActive: 35, // extra when the data: URI can render as a page
      manySubdomains: 20,
      longUrl: 10,
      riskyTld: 15,
    },

    limits: {
      maxSubdomains: 3, // more than this many labels below the registrable domain
      longUrlLength: 300,
      // Brands shorter than this get no fuzzy matching: one edit away from a
      // 3-letter name like "sbi" hits hundreds of unrelated real sites.
      minFuzzyBrandLength: 5,
      // Brands at least this long tolerate 2 edits; shorter ones only 1.
      twoEditBrandLength: 7,
    },

    // Popular targets, by registrable domain.
    brands: [
      'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
      'whatsapp.com', 'twitter.com', 'linkedin.com', 'microsoft.com',
      'apple.com', 'icloud.com', 'amazon.com', 'amazon.in', 'netflix.com',
      'paypal.com', 'github.com', 'dropbox.com', 'yahoo.com', 'outlook.com',
      'telegram.org', 'paytm.com', 'phonepe.com', 'razorpay.com', 'sbi.co.in',
      'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
      'irctc.co.in', 'flipkart.com', 'uidai.gov.in', 'incometax.gov.in',
      'npci.org.in',
    ],

    // Real sites that happen to sit within edit distance of a brand.
    lookalikeAllowlist: ['telegraph.co.uk', 'telegra.ph', 'paypay.ne.jp', 'apply.com'],

    // Shorteners that can point anywhere, so the destination is hidden.
    shorteners: [
      'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
      'rebrand.ly', 'cutt.ly', 't.ly', 'rb.gy', 'shorturl.at', 'tiny.cc',
      'lnkd.in', 'fb.me', 'dlvr.it', 'trib.al', 'v.gd',
    ],

    // Domains run by the same organisation. A text/href pair inside one group
    // is not a mismatch, and a shortener is first-party on its own platform
    // (t.co on x.com, lnkd.in on linkedin.com).
    relatedDomains: [
      ['twitter.com', 'x.com', 't.co'],
      ['facebook.com', 'fb.com', 'fb.me', 'messenger.com'],
      ['linkedin.com', 'lnkd.in'],
      ['google.com', 'goo.gl', 'g.co'],
      ['youtube.com', 'youtu.be'],
      ['instagram.com', 'instagr.am'],
      ['whatsapp.com', 'wa.me'],
      ['telegram.org', 't.me', 'telegra.ph'],
      ['amazon.com', 'amazon.in', 'amzn.to', 'amzn.in'],
    ],

    riskyTlds: [
      'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'icu', 'click', 'cam',
      'rest', 'buzz', 'cyou', 'sbs', 'zip', 'mov', 'monster', 'quest', 'work',
    ],

    // TODO: replace with the full Public Suffix List (https://publicsuffix.org)
    // once there is a build step. This hand-picked subset covers the common
    // multi-part country suffixes plus shared-hosting suffixes where every
    // subdomain belongs to a different owner.
    multiPartSuffixes: [
      // United Kingdom
      'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk',
      'net.uk', 'sch.uk', 'nhs.uk',
      // India
      'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'gov.in',
      'ac.in', 'edu.in', 'res.in', 'nic.in',
      // Australia / New Zealand
      'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
      'co.nz', 'org.nz', 'net.nz', 'govt.nz', 'ac.nz',
      // Rest of the world
      'co.za', 'org.za', 'gov.za', 'ac.za',
      'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
      'com.br', 'net.br', 'org.br', 'gov.br',
      'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
      'com.sg', 'edu.sg', 'gov.sg', 'com.my', 'com.hk', 'com.tw', 'com.mx',
      'com.ar', 'com.tr', 'com.sa', 'com.pk', 'com.bd', 'com.np', 'com.lk',
      'co.kr', 'or.kr', 'co.id', 'co.th', 'co.il', 'co.ke', 'com.ng',
      'com.eg', 'com.ua', 'com.ph', 'com.vn', 'com.co',
      // Shared hosting
      'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'vercel.app',
      'netlify.app', 'web.app', 'firebaseapp.com', 'herokuapp.com',
      'blogspot.com', 'appspot.com', 'azurewebsites.net', 'cloudfront.net',
      'onrender.com', 'glitch.me', 'weebly.com', 'wixsite.com',
      '000webhostapp.com', 'duckdns.org', 'ngrok.io', 'ngrok-free.app',
    ],

    // TLDs accepted when link text is a bare domain ("paypal.com"). Kept to
    // common ones so file names like README.md or setup.py aren't read as
    // domains.
    textTlds: [
      'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'co',
      'io', 'ai', 'app', 'dev', 'in', 'uk', 'us', 'ca', 'au', 'de', 'fr',
      'jp', 'cn', 'ru', 'br', 'nl', 'es', 'eu', 'ch', 'se', 'sg', 'ae', 'nz',
      'za', 'tv', 'ly', 'xyz', 'online', 'site', 'tech', 'store', 'shop',
      'bank', 'club', 'top', 'live', 'news', 'blog', 'cloud', 'page', 'link',
    ],
  };

  // ---------------------------------------------------------------------------
  // Hostname helpers
  // ---------------------------------------------------------------------------

  const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

  function isIpHost(host) {
    return IPV4_RE.test(host) || host.startsWith('[');
  }

  function isPrivateIp(host) {
    if (host.startsWith('[')) {
      const v6 = host.slice(1, -1);
      return v6 === '::1' || /^f[cd]/.test(v6) || /^fe[89ab]/.test(v6);
    }
    const [a, b] = host.split('.').map(Number);
    return (
      a === 10 ||
      a === 127 ||
      (a === 192 && b === 168) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 169 && b === 254)
    );
  }

  function isLocalName(host) {
    return host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local');
  }

  function normalizeHost(host) {
    return String(host || '').toLowerCase().replace(/\.$/, '');
  }

  const suffixSet = new Set(CONFIG.multiPartSuffixes);

  // Splits a hostname into the registrable domain (the part someone actually
  // registered), its first label, and any subdomain labels below it.
  function splitHost(hostname) {
    const host = normalizeHost(hostname);
    if (host === '' || isIpHost(host)) {
      return { host, domain: host, label: host, suffix: '', subdomains: [] };
    }

    const labels = host.split('.');
    let suffixLength = 1;
    for (let take = Math.min(3, labels.length - 1); take >= 2; take--) {
      if (suffixSet.has(labels.slice(-take).join('.'))) {
        suffixLength = take;
        break;
      }
    }

    const keep = Math.min(labels.length, suffixLength + 1);
    const domainLabels = labels.slice(-keep);
    return {
      host,
      domain: domainLabels.join('.'),
      label: domainLabels[0],
      suffix: labels.slice(-suffixLength).join('.'),
      subdomains: labels.slice(0, labels.length - keep),
    };
  }

  function getRegistrableDomain(hostname) {
    return splitHost(hostname).domain;
  }

  function areRelated(domainA, domainB) {
    if (domainA === domainB) return true;
    return CONFIG.relatedDomains.some(
      (group) => group.includes(domainA) && group.includes(domainB),
    );
  }

  // The host exactly as written in the href, before URL parsing normalises it.
  // Needed because new URL('http://3232235777') already reports 192.168.1.1.
  function rawHostOf(href) {
    const match = /^\s*(?:[a-z][a-z0-9+.-]*:)?[\\/]{2}([^\\/?#]*)/i.exec(href);
    if (!match) return null;
    let host = match[1];
    const at = host.lastIndexOf('@');
    if (at !== -1) host = host.slice(at + 1);
    if (!host.startsWith('[')) host = host.replace(/:\d*$/, '');
    return normalizeHost(host);
  }

  // ---------------------------------------------------------------------------
  // Unicode helpers (punycode, scripts, confusables)
  // ---------------------------------------------------------------------------

  // Punycode decoder (RFC 3492) for a single label, without the "xn--" prefix.
  function punycodeDecode(input) {
    const BASE = 36;
    const T_MIN = 1;
    const T_MAX = 26;
    const output = [];
    let n = 128;
    let i = 0;
    let bias = 72;

    const basicEnd = input.lastIndexOf('-');
    for (let j = 0; j < basicEnd; j++) output.push(input.charCodeAt(j));

    let index = basicEnd > 0 ? basicEnd + 1 : 0;
    let first = true;
    while (index < input.length) {
      const oldI = i;
      let weight = 1;
      for (let k = BASE; ; k += BASE) {
        if (index >= input.length) throw new RangeError('Bad punycode');
        const code = input.charCodeAt(index++);
        let digit;
        if (code >= 48 && code <= 57) digit = code - 22;
        else if (code >= 97 && code <= 122) digit = code - 97;
        else if (code >= 65 && code <= 90) digit = code - 65;
        else throw new RangeError('Bad punycode');

        i += digit * weight;
        const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
        if (digit < t) break;
        weight *= BASE - t;
      }

      const length = output.length + 1;
      let delta = first ? Math.floor((i - oldI) / 700) : (i - oldI) >> 1;
      first = false;
      delta += Math.floor(delta / length);
      let k = 0;
      while (delta > ((BASE - T_MIN) * T_MAX) >> 1) {
        delta = Math.floor(delta / (BASE - T_MIN));
        k += BASE;
      }
      bias = k + Math.floor(((BASE - T_MIN + 1) * delta) / (delta + 38));

      n += Math.floor(i / length);
      i %= length;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  function labelToUnicode(label) {
    if (!label.startsWith('xn--')) return label;
    try {
      return punycodeDecode(label.slice(4));
    } catch {
      return label;
    }
  }

  const SCRIPTS = [
    ['Latin', /\p{Script=Latin}/u],
    ['Cyrillic', /\p{Script=Cyrillic}/u],
    ['Greek', /\p{Script=Greek}/u],
    ['Armenian', /\p{Script=Armenian}/u],
    ['Hebrew', /\p{Script=Hebrew}/u],
    ['Arabic', /\p{Script=Arabic}/u],
    ['Devanagari', /\p{Script=Devanagari}/u],
    ['Bengali', /\p{Script=Bengali}/u],
    ['Tamil', /\p{Script=Tamil}/u],
    ['Telugu', /\p{Script=Telugu}/u],
    ['Thai', /\p{Script=Thai}/u],
    // Chinese, Japanese and Korean routinely combine these, so they count as one.
    ['CJK', /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Bopomofo}]/u],
  ];
  const LETTER_RE = /\p{L}/u;

  function scriptsIn(text) {
    const found = new Set();
    for (const char of text) {
      if (!LETTER_RE.test(char)) continue;
      const entry = SCRIPTS.find(([, re]) => re.test(char));
      found.add(entry ? entry[0] : 'Other');
    }
    return [...found];
  }

  // Characters that render like a Latin letter. Not exhaustive: these are the
  // Cyrillic and Greek lookalikes that show up in real homograph attacks.
  const HOMOGLYPHS = {
    'а': 'a', 'в': 'b', 'с': 'c', 'ԁ': 'd', 'е': 'e', 'һ': 'h', 'і': 'i',
    'ј': 'j', 'к': 'k', 'ӏ': 'l', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p',
    'ԛ': 'q', 'г': 'r', 'ѕ': 's', 'т': 't', 'ѵ': 'v', 'ԝ': 'w', 'х': 'x',
    'у': 'y', 'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v',
    'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
  };

  // Reduces a label to what it looks like at a glance, so "paypa1", "pay-pal"
  // and Cyrillic "раураl" all collapse to "paypal".
  function skeleton(label) {
    const stripped = label
      .toLowerCase()
      .normalize('NFKD')
      .replace(/\p{M}/gu, '')
      .replace(/-/g, '');
    let out = '';
    for (const char of stripped) out += HOMOGLYPHS[char] || char;
    return out.replace(/rn/g, 'm').replace(/vv/g, 'w');
  }

  // Damerau-Levenshtein (optimal string alignment): an adjacent swap is 1 edit.
  function editDistance(a, b) {
    const rows = a.length + 1;
    const cols = b.length + 1;
    const d = Array.from({ length: rows }, (_, i) => {
      const row = new Array(cols).fill(0);
      row[0] = i;
      return row;
    });
    for (let j = 0; j < cols; j++) d[0][j] = j;

    for (let i = 1; i < rows; i++) {
      for (let j = 1; j < cols; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
        }
      }
    }
    return d[a.length][b.length];
  }

  // ---------------------------------------------------------------------------
  // Brand lookups
  // ---------------------------------------------------------------------------

  const brandDomains = new Set(CONFIG.brands);
  // Domains never reported as lookalikes: the brands themselves, their sister
  // domains (youtu.be is two edits from "youtube") and the explicit allowlist.
  const notLookalikes = new Set([
    ...CONFIG.brands,
    ...CONFIG.lookalikeAllowlist,
    ...CONFIG.relatedDomains.flat(),
  ]);
  const shortenerSet = new Set(CONFIG.shorteners);
  const riskyTldSet = new Set(CONFIG.riskyTlds);
  const textTldSet = new Set(CONFIG.textTlds);

  // One entry per distinct brand label ("amazon" covers amazon.com and amazon.in).
  const brandLabels = [];
  for (const domain of CONFIG.brands) {
    const { label } = splitHost(domain);
    if (!brandLabels.some((brand) => brand.label === label)) {
      brandLabels.push({ label, domain, skeleton: skeleton(label) });
    }
  }

  // Returns { brand, kind } when `label` imitates a brand without being it.
  function findLookalike(label) {
    if (brandLabels.some((brand) => brand.label === label)) return null;

    const unicodeLabel = labelToUnicode(label);
    const shape = skeleton(unicodeLabel);

    const confusable = brandLabels.find((brand) => brand.skeleton === shape);
    if (confusable) return { brand: confusable.domain, kind: 'confusable' };

    const { minFuzzyBrandLength, twoEditBrandLength } = CONFIG.limits;
    for (const brand of brandLabels) {
      if (brand.label.length < minFuzzyBrandLength) continue;
      // Typos and squats almost always keep the first letter; requiring it
      // drops coincidences like tomato/zomato.
      if (brand.label[0] !== shape[0]) continue;
      const maxEdits = brand.label.length >= twoEditBrandLength ? 2 : 1;
      if (Math.abs(brand.label.length - shape.length) > maxEdits) continue;
      const distance = editDistance(shape, brand.skeleton);
      if (distance > 0 && distance <= maxEdits) {
        return { brand: brand.domain, kind: 'edit' };
      }
    }
    return null;
  }

  // Finds a brand's full domain used as leading labels: paypal.com.evil.com.
  function findBrandInSubdomain(subdomains) {
    if (subdomains.length < 2) return null;
    const haystack = `.${subdomains.join('.')}.`;
    for (const domain of CONFIG.brands) {
      if (haystack.includes(`.${domain}.`)) return domain;
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // Link text
  // ---------------------------------------------------------------------------

  const TEXT_URL_RE =
    /^(https?:\/\/)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+([a-z]{2,}))(?::\d+)?(?:[/?#]\S*)?$/i;

  // Returns the hostname the link text claims to be, or null when the text is
  // not a URL or bare domain ("click here", "README.md", "john@example.com").
  function hostFromText(text) {
    const cleaned = String(text || '')
      .trim()
      .replace(/^[\s"'“‘(<[]+/, '')
      .replace(/[\s"'”’)>\].,;:!?…]+$/, '');
    if (cleaned === '' || /\s/.test(cleaned) || cleaned.includes('@')) return null;

    const match = TEXT_URL_RE.exec(cleaned);
    if (!match) return null;

    const [, scheme, host, tld] = match;
    const explicit = Boolean(scheme) || /^www\./i.test(host);
    // A bare word.word needs a common, lower-case TLD to count as a domain;
    // otherwise "ASP.NET", "Node.js" and file names would all match.
    if (!explicit && !(tld === tld.toLowerCase() && textTldSet.has(tld))) return null;

    return host.toLowerCase();
  }

  // ---------------------------------------------------------------------------
  // analyzeLink
  // ---------------------------------------------------------------------------

  const ACTIVE_DATA_TYPES = /^data:\s*(?:text\/html|application\/xhtml\+xml|image\/svg\+xml|text\/xml|application\/xml|text\/javascript|application\/javascript)/i;

  function levelFor(score) {
    if (score >= CONFIG.thresholds.dangerous) return 'dangerous';
    if (score >= CONFIG.thresholds.suspicious) return 'suspicious';
    return 'ok';
  }

  // `multiplier` scales the total (same-site links on a clean page).
  // `flaggedPage` is the page's own verdict when the link stays on a page that
  // is itself flagged: the link then inherits at least the page's score.
  function finish(findings, { multiplier = 1, flaggedPage = null } = {}) {
    findings.sort((a, b) => b.points - a.points);
    const total = findings.reduce((sum, finding) => sum + finding.points, 0);
    let score = Math.min(CONFIG.maxScore, Math.round(total * multiplier));
    let reasons = findings.map((finding) => finding.reason);

    if (flaggedPage) {
      score = Math.max(score, flaggedPage.score);
      // The link shares the page's host, so most of its own reasons repeat the
      // page's. Say it once, as a statement about the page.
      const summary = flaggedPage.reasons[0] || 'see the page address';
      reasons = [
        `This page itself looks ${flaggedPage.level}: ${summary[0].toLowerCase()}${summary.slice(1)}`,
        ...reasons.filter((reason) => !flaggedPage.reasons.includes(reason)),
      ];
    } else if (multiplier !== 1 && total > 0) {
      reasons.push('Same site as this page (risk reduced)');
    }
    return { level: levelFor(score), score, reasons };
  }

  function parseUrl(href, base) {
    try {
      return base ? new URL(href, base) : new URL(href);
    } catch {
      return null;
    }
  }

  let lastPage = { url: null, verdict: null };

  /**
   * Scores the page's own address, as if it were a link arriving from
   * elsewhere. Remembers the last page, since every link on it asks again.
   *
   * @param {string} pageUrl
   * @returns {{ level: 'ok'|'suspicious'|'dangerous', score: number, reasons: string[] }}
   */
  function analyzePage(pageUrl) {
    if (lastPage.url !== pageUrl) {
      lastPage = { url: pageUrl, verdict: analyzeLink({ href: pageUrl }) };
    }
    return lastPage.verdict;
  }

  /**
   * Scores one link from its strings alone.
   *
   * @param {{ href: string, text?: string, pageUrl?: string, pageVerdict?: object }} link
   *   href: the link target as written in the page; text: the visible link
   *   text; pageUrl: the URL of the page the link is on; pageVerdict: the
   *   result of analyzePage(pageUrl), if the caller already has it.
   * @returns {{ level: 'ok'|'suspicious'|'dangerous', score: number, reasons: string[] }}
   */
  function analyzeLink({ href, text = '', pageUrl = '', pageVerdict = null } = {}) {
    const W = CONFIG.weights;
    const findings = [];
    const add = (points, reason) => findings.push({ points, reason });

    const rawHref = String(href || '').trim();
    const url = parseUrl(rawHref, pageUrl || undefined);
    if (!url) return finish(findings);

    if (url.protocol === 'data:') {
      add(W.dataUri, 'data: link (content is embedded in the link itself)');
      if (ACTIVE_DATA_TYPES.test(rawHref)) {
        add(W.dataUriActive, 'The embedded content can run as a web page');
      }
      return finish(findings);
    }

    // Other non-web schemes (blob:, sms:, app deep links) have no host to judge.
    if (!['http:', 'https:', 'ftp:'].includes(url.protocol)) return finish(findings);

    const host = normalizeHost(url.hostname);
    const ipHost = isIpHost(host);
    const local = isLocalName(host) || (ipHost && isPrivateIp(host));
    const parts = splitHost(host);

    const page = pageUrl ? parseUrl(pageUrl) : null;
    const pageDomain = page ? getRegistrableDomain(page.hostname) : '';
    const sameSite = pageDomain !== '' && pageDomain === parts.domain;

    // A shortener on its own platform (t.co on x.com) is first-party plumbing.
    const isShortener = shortenerSet.has(parts.domain) || shortenerSet.has(host);
    const firstPartyShortener = isShortener && areRelated(parts.domain, pageDomain);

    // 4. Credentials in the URL
    if (url.username || url.password) {
      let user = url.username;
      try {
        user = decodeURIComponent(user);
      } catch {
        // Keep the encoded form.
      }
      add(W.credentials, 'URL contains embedded login details');
      if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(user)) {
        add(
          W.credentialsLookLikeHost,
          `Looks like ${user.toLowerCase()} but really goes to ${host}`,
        );
      }
    }

    // 2. IP-address hosts
    if (ipHost) {
      const rawHost = rawHostOf(rawHref);
      const obfuscated = IPV4_RE.test(host) && rawHost !== null && rawHost !== host;
      if (obfuscated) {
        add(W.ipHost + W.ipObfuscated, `Disguised IP address (${rawHost} is really ${host})`);
      } else if (local) {
        add(W.ipPrivate, `Local network address (${host})`);
      } else {
        add(W.ipHost, `Host is a raw IP address (${host})`);
      }
    }

    if (!ipHost) {
      // 3. Punycode / non-ASCII / mixed-script hostnames
      const allLabels = host.split('.');
      if (allLabels.some((label) => label.startsWith('xn--'))) {
        const unicodeHost = allLabels.map(labelToUnicode).join('.');
        add(W.idnHost, `Non-ASCII domain name (${unicodeHost}, encoded as ${host})`);

        const mixed = allLabels
          .map((label) => scriptsIn(labelToUnicode(label)))
          .find((scripts) => scripts.length > 1);
        if (mixed) {
          add(W.mixedScript, `Mixes ${mixed.join(' and ')} letters in one name (homograph trick)`);
        }
      }

      // 6. Brand lookalikes
      if (!notLookalikes.has(parts.domain)) {
        const lookalike = findLookalike(parts.label);
        if (lookalike && lookalike.kind === 'confusable') {
          add(W.lookalikeConfusable, `Domain imitates ${lookalike.brand} with look-alike characters`);
        } else if (lookalike) {
          add(W.lookalikeEditDistance, `Domain closely resembles ${lookalike.brand}`);
        }

        const buried = findBrandInSubdomain(parts.subdomains);
        if (buried) {
          add(W.brandInSubdomain, `Uses "${buried}" as a subdomain of ${parts.domain}`);
        }
      }

      // 5. URL shorteners
      if (isShortener && !firstPartyShortener) {
        add(W.shortener, `URL shortener (${parts.domain}) hides the real destination`);
      }

      // 7. Subdomain depth and TLD
      const depth = parts.subdomains.filter((label, i) => !(i === 0 && label === 'www')).length;
      if (depth > CONFIG.limits.maxSubdomains) {
        add(W.manySubdomains, `Unusually many subdomains (${depth})`);
      }

      const tld = allLabels[allLabels.length - 1];
      if (riskyTldSet.has(tld)) {
        add(W.riskyTld, `Frequently abused top-level domain (.${tld})`);
      }
    }

    // 1. Text / href mismatch
    const textHost = hostFromText(text);
    if (textHost && !firstPartyShortener) {
      const textDomain = getRegistrableDomain(textHost);
      if (!areRelated(textDomain, parts.domain)) {
        if (isShortener) {
          add(
            W.textMismatchViaShortener,
            `Link text shows ${textDomain} but the link goes through a shortener`,
          );
        } else {
          add(W.textMismatch, `Link text shows ${textDomain} but it goes to ${parts.domain}`);
          if (brandDomains.has(textDomain)) {
            add(W.textMismatchBrand, `The text names a commonly impersonated site (${textDomain})`);
          }
        }
      }
    }

    // 7. Unencrypted and oversized URLs
    if (url.protocol !== 'https:' && !local) {
      add(W.notHttps, 'Not HTTPS (connection is not encrypted)');
    }
    if (url.href.length > CONFIG.limits.longUrlLength) {
      add(W.longUrl, `Very long URL (${url.href.length} characters)`);
    }

    if (!sameSite) return finish(findings);

    // Staying on the same site only lowers the risk if the site itself looks
    // fine. On a lookalike page, "same site" means "more of the lookalike".
    const verdictOfPage = pageVerdict || analyzePage(pageUrl);
    if (verdictOfPage.level !== 'ok') return finish(findings, { flaggedPage: verdictOfPage });
    return finish(findings, { multiplier: CONFIG.sameSiteMultiplier });
  }

  // ---------------------------------------------------------------------------
  // Exports: a global for the content script, module.exports for Node tests.
  // ---------------------------------------------------------------------------

  const api = { analyzeLink, analyzePage, getRegistrableDomain, CONFIG };

  globalThis.Tripwire = globalThis.Tripwire || {};
  Object.assign(globalThis.Tripwire, api);

  if (typeof module !== 'undefined') module.exports = api;
})();
