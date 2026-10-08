// Trusted domains: the user's own "I know this one" list.
//
// A domain here is a registrable domain (example.com, or someone.github.io on
// shared hosting), so trusting it covers its subdomains and nothing else.
//
// The rules, in resolveVerdict():
//   - a trusted link is treated as ok, with the note "You trusted this domain";
//   - unless it is on a blocklist. Then it is shown as suspicious, with the
//     blocklist match and the trust both stated. Trust never hides a listing.
//
// Stored in chrome.storage.sync, one key per domain, next to the display
// settings.

(() => {
  'use strict';

  const inNode = typeof module !== 'undefined' && typeof require === 'function';
  const { getRegistrableDomain } = inNode ? require('./analyzer.js') : globalThis.Tripwire;
  const blocklist = inNode ? require('./blocklist.js') : globalThis.Tripwire.blocklist;

  const TRUST_KEY_PREFIX = 'trust:';
  const TRUSTED_REASON = 'You trusted this domain';
  // Anywhere inside the "suspicious" band.
  const SCORE_TRUSTED_AND_LISTED = 50;

  // The domain that trusting this address would trust, or '' if the address
  // isn't one that can be trusted (not http/https, or unreadable).
  function domainOf(url) {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return '';
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    return getRegistrableDomain(parsed.hostname);
  }

  function trustKey(domain) {
    return TRUST_KEY_PREFIX + String(domain).toLowerCase();
  }

  /**
   * The verdict that is shown for a link (or for the page itself).
   *
   * @param {object} input
   * @param {{ level: string, score: number, reasons: string[] }} input.verdict
   *   what the checks on the address say
   * @param {object|null} [input.listing]  the blocklist match, if there is one
   * @param {boolean} [input.trusted]  whether the user trusts the domain
   * @param {number} [input.now]
   */
  function resolveVerdict({ verdict, listing = null, trusted = false, now = Date.now() }) {
    if (!trusted) return listing ? blocklist.applyListing(verdict, listing, now) : verdict;
    if (!listing) return { level: 'ok', score: 0, reasons: [TRUSTED_REASON] };
    return {
      level: 'suspicious',
      score: SCORE_TRUSTED_AND_LISTED,
      reasons: [blocklist.listingReason(listing, now), TRUSTED_REASON, ...verdict.reasons],
    };
  }

  // Trusting a domain that has a link on a blocklist takes a second, explicit
  // step. `listedDomains` are the domains with a listed address on this page.
  function needsConfirmation(domain, listedDomains) {
    return Boolean(domain) && Array.isArray(listedDomains) && listedDomains.includes(domain);
  }

  // The trusted domains in a dump of chrome.storage.sync, by name.
  function listTrusted(stored) {
    return Object.entries(stored || {})
      .filter(([key, value]) => key.startsWith(TRUST_KEY_PREFIX) && key.length > TRUST_KEY_PREFIX.length && value)
      .map(([key, value]) => ({
        domain: key.slice(TRUST_KEY_PREFIX.length),
        addedAt: value && typeof value.addedAt === 'number' ? value.addedAt : null,
      }))
      .sort((a, b) => a.domain.localeCompare(b.domain));
  }

  async function load() {
    const stored = await chrome.storage.sync.get(null);
    return new Set(listTrusted(stored).map((entry) => entry.domain));
  }

  function add(domain, now = Date.now()) {
    return chrome.storage.sync.set({ [trustKey(domain)]: { addedAt: now } });
  }

  function remove(domain) {
    return chrome.storage.sync.remove(trustKey(domain));
  }

  const api = {
    TRUST_KEY_PREFIX,
    TRUSTED_REASON,
    domainOf,
    trustKey,
    resolveVerdict,
    needsConfirmation,
    listTrusted,
    load,
    add,
    remove,
  };

  globalThis.Tripwire = globalThis.Tripwire || {};
  globalThis.Tripwire.trust = api;

  if (typeof module !== 'undefined') module.exports = api;
})();
