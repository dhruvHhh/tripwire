// Tripwire content script.
// Finds every usable link on the page, scores it with the offline analyzer,
// and puts a coloured badge after it.

(() => {
  'use strict';

  const { analyzeLink, createBadge } = Tripwire;

  const PROCESSED_ATTR = 'data-tripwire-processed';
  const SKIPPED_PROTOCOLS = new Set(['javascript:', 'mailto:', 'tel:']);
  const MAX_TEXT_LENGTH = 300;
  // An href that names its own host: has a scheme, or starts with "//".
  const ABSOLUTE_HREF_RE = /^(?:[a-z][a-z0-9+.-]*:|[\\/]{2})/i;

  // Link -> badge handle, so later steps can update a verdict in place.
  const badgeByLink = new WeakMap();

  // Verdicts keyed by href AND link text: the text/href mismatch check means
  // two links to the same URL can deserve different verdicts.
  const verdictCache = new Map();

  function isUsableLink(link) {
    // SVG <a> elements match a[href] too, but an HTML badge can't render
    // inside an <svg>.
    if (!(link instanceof HTMLAnchorElement)) return false;

    // Never write into editable regions (email composers, rich-text editors),
    // or the badge would become part of the user's content.
    if (link.isContentEditable) return false;

    const raw = (link.getAttribute('href') || '').trim();
    if (raw === '' || raw.startsWith('#')) return false;

    let url;
    try {
      url = new URL(raw, document.baseURI);
    } catch {
      return false;
    }
    return !SKIPPED_PROTOCOLS.has(url.protocol);
  }

  function getVerdict(link) {
    const raw = link.getAttribute('href').trim();
    // Absolute hrefs are passed as written: link.href has already normalised
    // away disguises like http://3232235777. Relative ones are left to the
    // browser to resolve, since it honours <base>.
    const href = ABSOLUTE_HREF_RE.test(raw) ? raw : link.href;
    const text = link.textContent.replace(/\s+/g, ' ').trim().slice(0, MAX_TEXT_LENGTH);

    const key = `${href}\n${text}`;
    let verdict = verdictCache.get(key);
    if (!verdict) {
      verdict = analyzeLink({ href, text, pageUrl: location.href });
      verdictCache.set(key, verdict);
    }
    return verdict;
  }

  // Returns the verdict level, or null when the link gets no badge.
  function badgeLink(link) {
    if (link.hasAttribute(PROCESSED_ATTR)) return null;
    link.setAttribute(PROCESSED_ATTR, '');

    if (!isUsableLink(link)) return null;

    const verdict = getVerdict(link);
    const badge = createBadge();
    badge.setVerdict(verdict.level, verdict.reasons);
    link.after(badge.element);
    badgeByLink.set(link, badge);
    return verdict.level;
  }

  function scan(root = document) {
    const links = root.querySelectorAll(`a[href]:not([${PROCESSED_ATTR}])`);
    const counts = { checked: links.length, ok: 0, suspicious: 0, dangerous: 0 };
    for (const link of links) {
      const level = badgeLink(link);
      if (level) counts[level]++;
    }
    return counts;
  }

  const { checked, ok, suspicious, dangerous } = scan();
  console.debug(
    `[Tripwire] checked ${checked} link(s): ${ok} ok, ${suspicious} suspicious, ${dangerous} dangerous`,
  );
})();
