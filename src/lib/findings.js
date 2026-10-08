// How Tripwire's findings are put in front of the user: the popup's status
// sentence, the order and grouping of its list of flagged links, and how an
// address is split so the part that says whose site it is can be made bold.
//
// Pure functions: the popup, the tooltip and the tests all use them.

(() => {
  'use strict';

  const inNode = typeof module !== 'undefined' && typeof require === 'function';
  const { getRegistrableDomain, isPageReason } = inNode ? require('./analyzer.js') : globalThis.Tripwire;
  const blocklist = inNode ? require('./blocklist.js') : globalThis.Tripwire.blocklist;

  const FLAGGED_LEVELS = ['dangerous', 'suspicious'];
  // How much of an address is shown after the host before it is cut.
  const MAX_REST_LENGTH = 60;

  // --- Addresses ---------------------------------------------------------------

  /**
   * Splits an address around its registrable domain:
   *   https://  user@  www.paypal.com.  secure-login.example  :8080  /path?query
   *   scheme    userinfo  subdomains    domain                port   rest
   * Joined in that order the parts give the address back. An address with no
   * host (data:, blob:) or one that can't be read comes back whole in `rest`.
   */
  function splitDestination(url) {
    const whole = { scheme: '', userinfo: '', subdomains: '', domain: '', port: '', rest: String(url || '') };
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return whole;
    }
    const host = parsed.hostname;
    if (!host) return whole;

    const registrable = getRegistrableDomain(host);
    const at = registrable ? host.lastIndexOf(registrable) : -1;
    const domain = at >= 0 ? host.slice(at) : host;
    let userinfo = parsed.username;
    if (parsed.password) userinfo += `:${parsed.password}`;

    return {
      scheme: `${parsed.protocol}//`,
      userinfo: userinfo ? `${userinfo}@` : '',
      subdomains: at > 0 ? host.slice(0, at) : '',
      domain,
      port: parsed.port ? `:${parsed.port}` : '',
      rest: parsed.pathname + parsed.search + parsed.hash,
    };
  }

  // Cuts the part after the host. The host itself is never cut: padding the
  // front of a host is how the real domain gets pushed out of sight.
  function clipRest(rest, max = MAX_REST_LENGTH) {
    const text = String(rest || '');
    if (text.length <= max) return { text, clipped: false };
    return { text: text.slice(0, max), clipped: true };
  }

  // --- The list of flagged links -----------------------------------------------

  /**
   * Whether a link has nothing against it except the warning on the page it
   * is on. `reasons` are what the checks on the link said, before any
   * blocklist match or trust was applied. A link that matches the same
   * blocklist entry as the page itself counts too: it is listed because the
   * site is, not for anything of its own.
   */
  function inheritsOnly({ reasons, listing = null, pageListing = null }) {
    if (!Array.isArray(reasons) || reasons.length === 0) return false;
    if (!reasons.every(isPageReason)) return false;
    if (!listing) return true;
    return Boolean(pageListing) && listing.source === pageListing.source && listing.entry === pageListing.entry;
  }

  // Blocklist matches first, then the rest.
  const rank = (link) => (link.listed ? 0 : 1);

  /**
   * Turns the page's flagged links into the popup's rows.
   *
   * Order: dangerous before suspicious; within each, blocklist matches first.
   * Links that only inherit the page's warning (`inherited`) are folded into
   * one row per level, placed after that level's other links, so they can't
   * bury the links that have reasons of their own.
   *
   * @param {Iterable<{ id, level, text, url, reasons, listed, trusted, inherited }>} links
   *   in page order. Links with the same address and level count once.
   * @param {{ pageDomain?: string, maxRows?: number, maxMembers?: number }} [options]
   * @returns {{ rows: object[], hidden: number }}  `hidden` is how many rows
   *   were left out to stay within `maxRows`.
   */
  function buildRows(links, { pageDomain = '', maxRows = 50, maxMembers = 50 } = {}) {
    const seen = new Set();
    const singles = { dangerous: [], suspicious: [] };
    const inherited = { dangerous: [], suspicious: [] };

    for (const link of links) {
      if (!FLAGGED_LEVELS.includes(link.level)) continue;
      const key = `${link.url}\n${link.level}`;
      if (seen.has(key)) continue;
      seen.add(key);
      (link.inherited ? inherited : singles)[link.level].push({ ...link, key });
    }

    const rows = [];
    for (const level of FLAGGED_LEVELS) {
      // One link is not a group.
      if (inherited[level].length === 1) singles[level].push(inherited[level].pop());

      // Array.prototype.sort is stable, so page order holds within a rank.
      for (const link of singles[level].sort((a, b) => rank(a) - rank(b))) {
        rows.push({
          kind: 'link',
          key: link.key,
          id: link.id,
          level,
          text: link.text,
          url: link.url,
          reasons: link.reasons,
          listed: Boolean(link.listed),
          trusted: Boolean(link.trusted),
        });
      }

      if (inherited[level].length > 0) {
        rows.push({
          kind: 'group',
          key: `group\n${level}`,
          level,
          domain: pageDomain,
          count: inherited[level].length,
          members: inherited[level].slice(0, maxMembers).map(({ id, text, url }) => ({ id, text, url })),
        });
      }
    }

    return { rows: rows.slice(0, maxRows), hidden: Math.max(0, rows.length - maxRows) };
  }

  // --- The status sentence -------------------------------------------------------

  const plural = (count, one, many) => `${count.toLocaleString('en')} ${count === 1 ? one : many}`;
  const sentence = (text) => (/[.!?]$/.test(text) ? text : `${text}.`);

  /**
   * The one sentence at the top of the popup, and the line under it.
   *
   * A warning about the page itself comes before anything about its links.
   * `kind` picks the look: "page-dangerous" is the solid red block; the
   * others are tinted. The wording never says "safe".
   *
   * @param {object|null} state  the content script's state, or null where it
   *   isn't running
   * @returns {{ kind: string, title: string, detail: string }}
   */
  function pageStatus(state, now = Date.now()) {
    if (!state) {
      return {
        kind: 'neutral',
        title: 'Tripwire isn’t running on this page',
        detail: 'It works on http and https pages. If this is one, reload it.',
      };
    }
    if (state.mode === 'off') {
      return { kind: 'neutral', title: 'Tripwire is off for this site', detail: 'Nothing is checked here.' };
    }
    if (!state.counts || !state.pageVerdict) {
      return { kind: 'neutral', title: 'Checking this page…', detail: '' };
    }

    const { scanned = 0, dangerous = 0, suspicious = 0 } = state.counts;
    const checked = `${plural(scanned, 'link', 'links')} checked.`;
    const page = state.pageVerdict;

    if (page.level !== 'ok') {
      const kind = page.level === 'dangerous' ? 'page-dangerous' : 'page-suspicious';
      if (state.pageListing) {
        const { category, name, publishedAt } = state.pageListing;
        const by = `By ${name}, updated ${blocklist.formatAge(now - publishedAt)}.`;
        return {
          kind,
          title: `This page is listed as ${category}`,
          detail: state.pageTrusted ? `${by} You trusted this domain.` : by,
        };
      }
      return {
        kind,
        title: `This page looks ${page.level}`,
        detail: sentence(page.reasons[0] || 'See the page address'),
      };
    }

    if (dangerous > 0) {
      return {
        kind: 'risky',
        title: `${plural(dangerous, 'risky link', 'risky links')} on this page`,
        detail: suspicious > 0 ? `And ${suspicious.toLocaleString('en')} suspicious. ${checked}` : checked,
      };
    }
    if (suspicious > 0) {
      return {
        kind: 'suspicious',
        title: `${plural(suspicious, 'suspicious link', 'suspicious links')} on this page`,
        detail: `No risky links. ${checked}`,
      };
    }
    return {
      kind: 'clean',
      title: 'No risky links found on this page',
      detail: `${checked} This is not a guarantee.`,
    };
  }

  // "11 risky · 3 suspicious", leaving out whichever is zero.
  function countsLabel({ dangerous = 0, suspicious = 0 } = {}) {
    const parts = [];
    if (dangerous > 0) parts.push(`${dangerous.toLocaleString('en')} risky`);
    if (suspicious > 0) parts.push(`${suspicious.toLocaleString('en')} suspicious`);
    return parts.join(' · ');
  }

  const api = {
    MAX_REST_LENGTH,
    splitDestination,
    clipRest,
    inheritsOnly,
    buildRows,
    pageStatus,
    countsLabel,
  };

  globalThis.Tripwire = globalThis.Tripwire || {};
  globalThis.Tripwire.findings = api;

  if (typeof module !== 'undefined') module.exports = api;
})();
