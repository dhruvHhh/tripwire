// Tripwire blocklists: which lists are used, how their entries are read and
// matched, and how a download is judged before it replaces the list in use.
//
// Everything here is pure: no network, no storage, no extension APIs. The
// service worker supplies those (src/background/lists.js), and Node's test
// runner can exercise the rest directly.
//
// Privacy: lists are downloaded to the browser and matched there. Nothing in
// this file, or anywhere in Tripwire, sends a page's links to a server.

(() => {
  'use strict';

  const analyzer =
    typeof module !== 'undefined' && typeof require === 'function'
      ? require('./analyzer.js')
      : globalThis.Tripwire;

  // ---------------------------------------------------------------------------
  // Config
  // ---------------------------------------------------------------------------

  const CONFIG = {
    // The lists publish twice a day; checking every 6 hours picks up each
    // release within a few hours without asking more often than is useful.
    updateIntervalMinutes: 360,
    // A list older than this is still used, but the popup says it is out of date.
    staleAfterHours: 48,
    // After a failed update: 15 minutes, then 30, 60... up to the normal interval.
    retryFirstMinutes: 15,
    fetchTimeoutMs: 30000,
    // A download with fewer than this share of the entries already installed
    // is rejected: a list doesn't lose most of its entries overnight.
    minShareOfPrevious: 0.3,
    // More than this share of unreadable lines means it isn't the list at all
    // (an error page, a captive portal).
    maxRejectedShare: 0.1,

    sources: [
      {
        id: 'phishing',
        name: 'Phishing URL Blocklist',
        category: 'phishing',
        file: 'phishing-filter.txt',
        homepage: 'https://gitlab.com/malware-filter/phishing-filter',
        builtFrom: 'OpenPhish, IPThreat and PhishTank',
        licence: 'CC BY-SA 4.0',
        licenceUrl: 'https://creativecommons.org/licenses/by-sa/4.0/',
        minEntries: 10000,
        minBytes: 300000,
      },
      {
        id: 'malware',
        name: 'Online Malicious URL Blocklist',
        category: 'malware',
        file: 'urlhaus-filter-online.txt',
        homepage: 'https://gitlab.com/malware-filter/urlhaus-filter',
        builtFrom: 'URLhaus (abuse.ch)',
        licence: 'CC0 1.0',
        licenceUrl: 'https://creativecommons.org/publicdomain/zero/1.0/',
        minEntries: 3000,
        minBytes: 100000,
      },
    ],

    // The malware-filter project's own mirrors, tried in this order. Three
    // different hosting providers, so one outage doesn't stop updates.
    mirrors: [
      'https://malware-filter.gitlab.io/malware-filter/', // GitLab Pages (primary)
      'https://curbengh.github.io/malware-filter/', // GitHub Pages
      'https://malware-filter.pages.dev/', // Cloudflare Pages
    ],

    // A small fake list bundled with the source tree. It is loaded only in a
    // development install (an unpacked extension), so the demo page can show
    // blocklist hits without depending on what the live lists contain today.
    // See isDevelopmentInstall() for how that is decided.
    fixture: {
      id: 'fixture',
      name: 'Tripwire test list',
      category: 'phishing',
      path: 'test/fixtures/blocklist.txt',
      homepage: '',
      builtFrom: 'made-up entries for the demo page; development installs only',
      licence: '',
      licenceUrl: '',
      minEntries: 1,
      minBytes: 1,
      local: true,
    },

    // Major sites run by one organisation. A list entry naming one of these
    // (or any subdomain of one) as a WHOLE HOST is ignored: one bad page must
    // not turn every link to the site red. Entries for a specific path on
    // them, such as one Google Sites page, still count.
    protectedDomains: [
      'google.com', 'sites.google.com', 'docs.google.com', 'youtube.com',
      'gmail.com', 'microsoft.com', 'live.com', 'office.com', 'outlook.com',
      'microsoftonline.com', 'apple.com', 'icloud.com', 'amazon.com',
      'amazon.in', 'wikipedia.org', 'facebook.com', 'instagram.com',
      'whatsapp.com', 'x.com', 'twitter.com', 'linkedin.com', 'github.com',
      'githubusercontent.com', 'gitlab.com', 'dropbox.com', 'adobe.com',
      'paypal.com', 'netflix.com',
      // Mail security gateways: their subdomains are regions, not customers.
      'urldefense.com', 'proofpoint.com', 'mimecast.com', 'mimecastprotect.com',
      'cudasvc.com',
      // India
      'gov.in', 'nic.in', 'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com',
      'icicibank.com', 'axisbank.com', 'irctc.co.in', 'npci.org.in',
      'paytm.com', 'phonepe.com', 'flipkart.com',
    ],
    // Shared-hosting domains (github.io, web.app...), URL shorteners and
    // click trackers are also never matched as whole hosts. Those lists live
    // in the analyzer's CONFIG. For them only the bare domain is ignored:
    // someone.github.io is one person's site, and a tracker's subdomain is
    // one sender, so those can be listed.
  };

  const LEVEL_FOR_LISTED = 'dangerous';
  const SCORE_FOR_LISTED = 100;

  // ---------------------------------------------------------------------------
  // Normalizing URLs
  // ---------------------------------------------------------------------------
  //
  // A link and a list entry are compared as "host/path?query" keys, built the
  // same way for both:
  //   - only http and https links are looked up; the scheme itself is ignored,
  //     so an entry seen over http also matches the https link
  //   - host in lower case, without a trailing dot or a leading "www."
  //   - default ports (80, 443) dropped; any other port kept as part of the host
  //   - user name and password dropped
  //   - fragment (#...) dropped
  //   - path as the browser's URL parser gives it ("." and ".." resolved,
  //     percent-encoding left as written); an empty path is "/"
  //   - query string kept as written
  // Trailing slashes are handled when matching: a link is tried both with and
  // without one.

  function normalizeHostname(hostname) {
    return String(hostname || '')
      .toLowerCase()
      .replace(/\.$/, '')
      .replace(/^www\./, '');
  }

  /**
   * @returns {{ hostname: string, host: string, path: string, query: string } | null}
   *   `host` includes a non-default port; `query` includes its "?" or is "".
   */
  function normalizeUrl(href) {
    let url;
    try {
      url = new URL(String(href));
    } catch {
      return null;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;

    const hostname = normalizeHostname(url.hostname);
    if (hostname === '') return null;
    return {
      hostname,
      host: url.port ? `${hostname}:${url.port}` : hostname,
      path: url.pathname || '/',
      query: url.search,
    };
  }

  const MAX_PATH_DEPTH = 12;
  const MAX_QUERY_PARTS = 8;

  // The keys a link is looked up under in a list's URL entries, most specific
  // first. An entry stands for itself and everything beneath it, so a link is
  // also tried at each parent folder, and with its query cut at each "&".
  function urlCandidates({ host, path, query }) {
    const keys = [];
    const add = (key) => {
      if (!keys.includes(key)) keys.push(key);
    };

    if (query) {
      add(host + path + query);
      const parts = query.slice(1).split('&');
      for (let count = Math.min(parts.length - 1, MAX_QUERY_PARTS); count >= 1; count--) {
        add(`${host}${path}?${parts.slice(0, count).join('&')}`);
      }
    }

    let current = path;
    for (let depth = 0; depth < MAX_PATH_DEPTH; depth++) {
      add(host + current);
      if (current === '/') break;
      if (current.endsWith('/')) add(host + current.slice(0, -1));
      else add(`${host}${current}/`);

      const trimmed = current.endsWith('/') ? current.slice(0, -1) : current;
      current = trimmed.slice(0, trimmed.lastIndexOf('/') + 1); // Parent folder.
    }
    return keys;
  }

  const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

  // The hosts a link is looked up under in a list's host entries: itself and
  // each parent domain, because a listed host's subdomains belong to the same
  // owner. The walk only goes up, never sideways, so an entry for
  // evil.example-host.com says nothing about other.example-host.com.
  function hostCandidates(hostname) {
    if (IPV4_RE.test(hostname)) return [hostname];
    const labels = hostname.split('.');
    const hosts = [];
    for (let start = 0; start <= labels.length - 2; start++) hosts.push(labels.slice(start).join('.'));
    return hosts;
  }

  // ---------------------------------------------------------------------------
  // Hosts that are never matched whole
  // ---------------------------------------------------------------------------

  const publicSuffixes = new Set(analyzer.CONFIG.multiPartSuffixes);
  const sharedHosting = new Set(analyzer.CONFIG.sharedHostingSuffixes);
  const shorteners = new Set(analyzer.CONFIG.shorteners);
  const clickTrackers = new Set(analyzer.CONFIG.clickTrackers);
  const protectedDomains = new Set(CONFIG.protectedDomains);

  function isLocalHost(hostname) {
    if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
      return true;
    }
    if (!IPV4_RE.test(hostname)) return false;
    const [a, b] = hostname.split('.').map(Number);
    return (
      a === 10 || a === 127 || a === 0 ||
      (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254)
    );
  }

  /**
   * Why a whole-host entry for `hostname` must be ignored, or null if it may
   * be used. Applied when a list is read and again when a link is matched.
   */
  function wholeHostIgnoreReason(hostname) {
    if (isLocalHost(hostname)) return 'local address';
    if (IPV4_RE.test(hostname)) return null;
    if (!hostname.includes('.')) return 'not a full hostname';
    if (publicSuffixes.has(hostname)) return 'public suffix';
    if (sharedHosting.has(hostname)) return 'shared hosting domain';
    if (shorteners.has(hostname)) return 'URL shortener';
    // Only the service's own domain: its subdomains are one per sender, and
    // the lists name individual senders.
    if (clickTrackers.has(hostname)) return 'click-tracking service';

    // Organisation-run sites: the domain and every subdomain of it.
    for (const candidate of hostCandidates(hostname)) {
      if (protectedDomains.has(candidate)) return `protected domain (${candidate})`;
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // Reading a list
  // ---------------------------------------------------------------------------
  //
  // The lists use the uBlock Origin filter format:
  //   ! a comment
  //   bad-host.example                       a whole host
  //   ||host.example/some/path^$all          one address on a host
  // Entries with wildcards are skipped (about 30 in 60,000).

  const OPTIONS_RE = /\$[a-z0-9_,=~|.-]+$/i;
  const ENTRY_HOST_RE = /^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$/;

  /**
   * @returns {null | { kind: 'host', host: string } | { kind: 'url', key: string }}
   *   null for comments, blank lines and anything that can't be used.
   */
  function parseEntry(line) {
    let text = line.trim();
    if (text === '' || text[0] === '!' || text[0] === '#' || text[0] === '[') return null;
    if (text.startsWith('@@') || text.includes('##')) return null; // Exceptions, cosmetic rules.

    if (text.startsWith('||')) text = text.slice(2);
    text = text.replace(OPTIONS_RE, '').replace(/\^$/, '');
    if (text === '' || /[\s*^|]/.test(text)) return null;

    const pathStart = text.search(/[/?#]/);
    let host = (pathStart === -1 ? text : text.slice(0, pathStart)).toLowerCase();
    let rest = pathStart === -1 ? '' : text.slice(pathStart);

    let port = '';
    const portMatch = /:(\d+)$/.exec(host);
    if (portMatch) {
      host = host.slice(0, portMatch.index);
      if (portMatch[1] !== '80' && portMatch[1] !== '443') port = `:${portMatch[1]}`;
    }
    host = normalizeHostname(host);
    if (!ENTRY_HOST_RE.test(host)) return null;

    const hash = rest.indexOf('#');
    if (hash !== -1) rest = rest.slice(0, hash);
    if (rest.startsWith('?')) rest = `/${rest}`;

    if (rest === '' || rest === '/') return { kind: 'host', host };
    return { kind: 'url', key: host + port + rest };
  }

  /**
   * Reads a whole list.
   * @returns {{ title: string, publishedAt: number|null, hosts: string[],
   *   urls: string[], total: number, rejected: number }}
   *   `total` counts non-comment lines; `rejected` those that weren't usable.
   */
  function parseList(text) {
    const result = { title: '', publishedAt: null, hosts: [], urls: [], total: 0, rejected: 0 };
    for (const rawLine of String(text).split(/\r?\n/)) {
      const line = rawLine.trim();
      if (line === '') continue;
      if (line[0] === '!' || line[0] === '#') {
        const header = /^[!#]\s*(Title|Updated|Last modified):\s*(.+)$/i.exec(line);
        if (header && header[1].toLowerCase() === 'title') result.title = header[2].trim();
        else if (header && result.publishedAt === null) {
          const time = Date.parse(header[2].trim());
          if (!Number.isNaN(time)) result.publishedAt = time;
        }
        continue;
      }

      result.total++;
      const entry = parseEntry(line);
      if (!entry) result.rejected++;
      else if (entry.kind === 'host') result.hosts.push(entry.host);
      else result.urls.push(entry.key);
    }
    return result;
  }

  /**
   * Drops whole-host entries that must never be matched, and duplicates.
   * @returns {{ hosts: string[], urls: string[], ignored: { host: string, reason: string }[] }}
   */
  function screenEntries(parsed) {
    const hosts = new Set();
    const ignored = [];
    for (const host of parsed.hosts) {
      const reason = wholeHostIgnoreReason(host);
      if (reason) ignored.push({ host, reason });
      else hosts.add(host);
    }
    return { hosts: [...hosts], urls: [...new Set(parsed.urls)], ignored };
  }

  // ---------------------------------------------------------------------------
  // Matching
  // ---------------------------------------------------------------------------

  /**
   * @param {{ id: string, name: string, category: string, publishedAt: number,
   *   hosts: Set<string>, urls: Set<string> }[]} lists  in order of preference.
   * @returns {(href: string) => null | { source: string, name: string,
   *   category: string, kind: 'url'|'host', entry: string, publishedAt: number }}
   */
  function createMatcher(lists) {
    return function match(href) {
      const url = normalizeUrl(href);
      if (!url) return null;

      const urlKeys = urlCandidates(url);
      const hostKeys = hostCandidates(url.hostname).filter((host) => !wholeHostIgnoreReason(host));

      for (const list of lists) {
        const hit = (kind, entry) => ({
          source: list.id,
          name: list.name,
          category: list.category,
          kind,
          entry,
          publishedAt: list.publishedAt,
        });
        for (const key of urlKeys) if (list.urls.has(key)) return hit('url', key);
        for (const host of hostKeys) if (list.hosts.has(host)) return hit('host', host);
      }
      return null;
    };
  }

  // ---------------------------------------------------------------------------
  // Judging a download, and updating from mirrors
  // ---------------------------------------------------------------------------

  /**
   * Decides whether a freshly downloaded list may replace the one in use.
   * @param {{ source: object, bytes: number, parsed: object, entries: number,
   *   previous?: { entries: number, publishedAt: number|null } }} download
   * @returns {{ ok: true } | { ok: false, reason: string, older?: boolean }}
   */
  function checkDownload({ source, bytes, parsed, entries, previous }) {
    if (parsed.total === 0) return { ok: false, reason: 'the download is empty' };
    if (bytes < source.minBytes) {
      return { ok: false, reason: `only ${bytes} bytes, expected at least ${source.minBytes}` };
    }
    if (parsed.rejected / parsed.total > CONFIG.maxRejectedShare) {
      return { ok: false, reason: `${parsed.rejected} of ${parsed.total} lines are not list entries` };
    }
    if (entries < source.minEntries) {
      return { ok: false, reason: `only ${entries} entries, expected at least ${source.minEntries}` };
    }
    if (previous && previous.entries > 0 && !source.local) {
      if (entries < previous.entries * CONFIG.minShareOfPrevious) {
        return { ok: false, reason: `shrank from ${previous.entries} to ${entries} entries` };
      }
      if (previous.publishedAt && parsed.publishedAt && parsed.publishedAt < previous.publishedAt) {
        return { ok: false, older: true, reason: 'older than the list already installed' };
      }
    }
    return { ok: true };
  }

  // A short signature of a list's text (FNV-1a), to tell "the same list
  // again" from "a new list" without keeping the text around.
  function fingerprintOf(text) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193);
    }
    return `${text.length}:${(hash >>> 0).toString(16)}`;
  }

  const hostOf = (url) => {
    try {
      return new URL(url).host || url;
    } catch {
      return url;
    }
  };

  /**
   * Tries each mirror in turn until one gives a usable list.
   *
   * @param {object} options
   * @param {object} options.source        an entry of CONFIG.sources
   * @param {string[]} options.urls        where to fetch it from, in order
   * @param {object} [options.previous]    the installed list's { entries,
   *   publishedAt, fingerprint, etag, from }, if there is one
   * @param {boolean} [options.force]      skip the "not modified" shortcut
   * @param {(url: string, etag: string|null) => Promise<{ status: number,
   *   text?: string, etag?: string|null }>} options.fetchList
   * @param {number} options.now
   * @returns {Promise<{ status: 'updated', list: object }
   *   | { status: 'unchanged', from: string, etag?: string|null, note?: string }>}
   *   Rejects, with every mirror's failure in the message, if none worked. The
   *   caller then keeps using the list it has.
   */
  async function updateFromMirrors({ source, urls, previous = null, force = false, fetchList, now }) {
    const failures = [];
    let sawOlderCopy = false;

    for (const url of urls) {
      try {
        const etag = !force && previous && previous.from === url ? previous.etag || null : null;
        const response = await fetchList(url, etag);
        if (response.status === 304) return { status: 'unchanged', from: url, etag };
        if (response.status !== 200) throw new Error(`HTTP ${response.status}`);

        const text = response.text || '';
        const parsed = parseList(text);
        const screened = screenEntries(parsed);
        const entries = screened.hosts.length + screened.urls.length;
        const verdict = checkDownload({ source, bytes: text.length, parsed, entries, previous });
        if (!verdict.ok) {
          if (verdict.older) sawOlderCopy = true;
          throw new Error(verdict.reason);
        }

        const fingerprint = fingerprintOf(text);
        if (previous && previous.fingerprint === fingerprint) {
          return { status: 'unchanged', from: url, etag: response.etag || null };
        }
        return {
          status: 'updated',
          list: {
            hosts: screened.hosts,
            urls: screened.urls,
            ignored: screened.ignored,
            entries,
            // A list that doesn't say when it was published counts from now.
            publishedAt: parsed.publishedAt || now,
            fingerprint,
            etag: response.etag || null,
            from: url,
          },
        };
      } catch (error) {
        failures.push(`${hostOf(url)}: ${error && error.message ? error.message : error}`);
      }
    }

    // Every mirror that answered had an older copy than ours: nothing is
    // wrong, there is just nothing newer to fetch from them.
    if (sawOlderCopy && previous && previous.entries > 0) {
      return { status: 'unchanged', from: previous.from, note: failures.join('; ') };
    }
    throw new Error(failures.join('; '));
  }

  // Minutes to wait before trying again after `failures` failed updates in a row.
  function retryDelayMinutes(failures) {
    const delay = CONFIG.retryFirstMinutes * 2 ** Math.max(0, failures - 1);
    return Math.min(delay, CONFIG.updateIntervalMinutes);
  }

  // ---------------------------------------------------------------------------
  // Wording
  // ---------------------------------------------------------------------------

  function formatAge(milliseconds) {
    const minutes = Math.floor(Math.max(0, milliseconds) / 60000);
    if (minutes < 2) return 'just now';
    if (minutes < 60) return `${minutes} minutes ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 48) return hours === 1 ? '1 hour ago' : `${hours} hours ago`;
    return `${Math.floor(hours / 24)} days ago`;
  }

  function listingReason(match, now) {
    return `Listed as ${match.category} by ${match.name} (list updated ${formatAge(now - match.publishedAt)})`;
  }

  // A listed link is always dangerous. The list's reason goes first, and
  // whatever the heuristics found about the link stays underneath.
  function applyListing(verdict, match, now) {
    return {
      level: LEVEL_FOR_LISTED,
      score: SCORE_FOR_LISTED,
      reasons: [listingReason(match, now), ...verdict.reasons],
    };
  }

  // What the popup says when the page itself is on a list.
  function describePageListing(match, now) {
    return {
      title: `This page is listed as ${match.category} by ${match.name}`,
      detail: `The list was updated ${formatAge(now - match.publishedAt)}. Links that stay on this site are marked dangerous too.`,
    };
  }

  /**
   * Whether this is a development install, the only kind that loads the
   * bundled test list. The answer is yes only when everything says so:
   *   - chrome.management.getSelf() reports installType "development", which
   *     Chrome gives only to an unpacked extension loaded in developer mode
   *     (Web Store installs are "normal", policy installs "admin", and
   *     anything else "sideload" or "other");
   *   - and the manifest has no update_url, which the Web Store adds to every
   *     extension it publishes.
   * Anything missing, unreadable or contradictory counts as "no".
   *
   * @param {{ manifest?: object|null, self?: { installType?: string }|null }} facts
   */
  function isDevelopmentInstall({ manifest, self } = {}) {
    if (!self || self.installType !== 'development') return false;
    if (!manifest || typeof manifest !== 'object') return false;
    return !('update_url' in manifest);
  }

  const isStale = (publishedAt, now) => now - publishedAt > CONFIG.staleAfterHours * 3600000;

  /**
   * What the popup says about one list.
   * @param {object|undefined} state  that list's entry in the stored status
   * @returns {{ tone: 'ok'|'warn'|'error'|'pending', text: string, detail: string }}
   */
  function describeSource(state, now) {
    if (!state || !state.entries) {
      if (state && state.error) {
        return { tone: 'error', text: 'Not downloaded', detail: `Last attempt failed: ${state.error}` };
      }
      return { tone: 'pending', text: 'Not downloaded yet', detail: '' };
    }

    const size = `${state.entries.toLocaleString('en')} entries`;
    const age = formatAge(now - state.publishedAt);
    const failed = state.error ? `Last check failed: ${state.error}` : '';
    if (isStale(state.publishedAt, now)) {
      return {
        tone: 'warn',
        text: `List is out of date: ${size}, updated ${age}`,
        detail: failed || 'It is still being used. Newer threats may be missing.',
      };
    }
    return { tone: failed ? 'warn' : 'ok', text: `${size}, updated ${age}`, detail: failed };
  }

  // One line for all lists together.
  function describeAll(sourceStates, now) {
    const descriptions = sourceStates.map((state) => describeSource(state, now));
    const loaded = sourceStates.filter((state) => state && state.entries);
    const entries = loaded.reduce((sum, state) => sum + state.entries, 0);

    if (loaded.length === 0) {
      const failed = descriptions.some((d) => d.tone === 'error');
      return { tone: failed ? 'error' : 'pending', text: failed ? 'download failed' : 'not downloaded yet' };
    }
    const oldest = Math.min(...loaded.map((state) => state.publishedAt));
    const size = `${entries.toLocaleString('en')} entries`;
    if (loaded.some((state) => isStale(state.publishedAt, now))) {
      return { tone: 'warn', text: `out of date (${size}, updated ${formatAge(now - oldest)})` };
    }
    if (loaded.length < sourceStates.length || descriptions.some((d) => d.tone !== 'ok')) {
      return { tone: 'warn', text: `${size}, last check had a problem` };
    }
    return { tone: 'ok', text: `${size}, updated ${formatAge(now - oldest)}` };
  }

  const api = {
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
    describePageListing,
    isDevelopmentInstall,
    describeSource,
    describeAll,
  };

  globalThis.Tripwire = globalThis.Tripwire || {};
  globalThis.Tripwire.blocklist = api;

  if (typeof module !== 'undefined') module.exports = api;
})();
