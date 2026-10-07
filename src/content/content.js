// Tripwire content script.
//
// Scans the page's links with the offline analyzer, hands the results to the
// overlay to draw, reports counts for the toolbar icon, and answers the popup.
// The display mode only changes which badges are drawn; scanning runs on every
// page unless the site is switched off.

(() => {
  'use strict';

  const { analyzeLink, analyzePage, createOverlay, settings } = Tripwire;
  const { MESSAGES } = settings;

  const PROCESSED_ATTR = 'data-tripwire-processed';
  const SKIPPED_PROTOCOLS = new Set(['javascript:', 'mailto:', 'tel:']);
  const MAX_TEXT_LENGTH = 300;
  // An href that names its own host: has a scheme, or starts with "//".
  const ABSOLUTE_HREF_RE = /^(?:[a-z][a-z0-9+.-]*:|[\\/]{2})/i;

  // What the popup's list shows.
  const MAX_FLAGGED_LINKS = 10;
  const MAX_LISTED_TEXT_LENGTH = 80;

  const hostname = location.hostname;

  // Raw values from storage; settings.resolveMode() turns them into a mode.
  let stored = { defaultMode: undefined, siteMode: undefined };
  // The popup's "Show badges on this page": lasts until the page reloads, or
  // until the user picks a different mode for this page.
  let revealed = false;
  let appliedMode = null;
  // Everything from one scan: { pageVerdict, records, counts, overlay }.
  // Null while the site is switched off.
  let scan = null;

  function isUsableLink(link) {
    // SVG <a> elements match a[href] too, but they have no HTML box to mark.
    if (!(link instanceof HTMLAnchorElement)) return false;

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

  // A name for a link with no text of its own, for the popup's list only.
  // The analyzer still sees the link's real (empty) text.
  function describeTextless(link) {
    const image = link.querySelector('img[alt]');
    const name = (image && image.alt) || link.getAttribute('aria-label') || link.title || '';
    return name.replace(/s+/g, ' ').trim();
  }

  function runScan() {
    // The page's own address is judged once; every same-site link depends on it.
    const pageUrl = location.href;
    const pageVerdict = analyzePage(pageUrl);

    // Verdicts keyed by href AND link text: the text/href mismatch check means
    // two links to the same URL can deserve different verdicts.
    const verdictCache = new Map();
    const overlay = createOverlay();
    const records = [];
    const counts = { scanned: 0, ok: 0, suspicious: 0, dangerous: 0 };

    for (const link of document.querySelectorAll(`a[href]:not([${PROCESSED_ATTR}])`)) {
      // Leave editable regions (email composers, rich-text editors) untouched:
      // even the marker attribute would become part of the user's content.
      if (link.isContentEditable) continue;

      link.setAttribute(PROCESSED_ATTR, '');
      if (!isUsableLink(link)) continue;

      const raw = link.getAttribute('href').trim();
      // Absolute hrefs are passed as written: link.href has already normalised
      // away disguises like http://3232235777. Relative ones are left to the
      // browser to resolve, since it honours <base>.
      const href = ABSOLUTE_HREF_RE.test(raw) ? raw : link.href;
      const text = link.textContent.replace(/\s+/g, ' ').trim().slice(0, MAX_TEXT_LENGTH);

      const cacheKey = `${href}\n${text}`;
      let verdict = verdictCache.get(cacheKey);
      if (!verdict) {
        verdict = analyzeLink({ href, text, pageUrl, pageVerdict });
        verdictCache.set(cacheKey, verdict);
      }

      records.push({ link, text, label: text || describeTextless(link), url: link.href, verdict });
      counts.scanned++;
      counts[verdict.level]++;
      overlay.add(link, {
        level: verdict.level,
        reasons: verdict.reasons,
        // Links with the same destination and verdict can share a badge.
        key: `${link.href}\n${verdict.level}`,
      });
    }

    console.debug(
      `[Tripwire] scanned ${counts.scanned} link(s): ${counts.ok} ok, ` +
        `${counts.suspicious} suspicious, ${counts.dangerous} dangerous`,
    );
    return { pageVerdict, records, counts, overlay };
  }

  function endScan() {
    scan.overlay.destroy();
    for (const link of document.querySelectorAll(`[${PROCESSED_ATTR}]`)) {
      link.removeAttribute(PROCESSED_ATTR);
    }
    scan = null;
  }

  // Tells the service worker what to show on the toolbar icon for this tab.
  function reportCounts() {
    const { dangerous = 0, suspicious = 0 } = scan ? scan.counts : {};
    try {
      chrome.runtime.sendMessage({ type: MESSAGES.COUNTS, dangerous, suspicious }).catch(() => {});
    } catch {
      // The extension was reloaded or removed; this page's script is orphaned.
    }
  }

  // Brings the page in line with the current settings.
  function apply() {
    const mode = settings.resolveMode(stored);
    // Choosing a mode is a newer instruction than an earlier one-off reveal.
    if (appliedMode !== null && mode !== appliedMode) revealed = false;
    appliedMode = mode;

    if (mode === 'off') {
      if (scan) endScan();
    } else {
      if (!scan) scan = runScan();
      scan.overlay.setFilter((item) => settings.shouldDisplay(item.level, mode, revealed));
    }
    reportCounts();
  }

  // --- Popup ------------------------------------------------------------------

  function destinationOf(url) {
    try {
      const parsed = new URL(url);
      return parsed.hostname || parsed.protocol;
    } catch {
      return '';
    }
  }

  // Red first, then amber; one entry per destination and level.
  function flaggedLinks() {
    const seen = new Set();
    const flagged = [];
    for (const level of ['dangerous', 'suspicious']) {
      scan.records.forEach((record, id) => {
        if (record.verdict.level !== level || flagged.length >= MAX_FLAGGED_LINKS) return;
        const key = `${record.url}\n${level}`;
        if (seen.has(key)) return;
        seen.add(key);
        flagged.push({
          id,
          level,
          text: record.label.slice(0, MAX_LISTED_TEXT_LENGTH),
          destination: destinationOf(record.url),
          reason: record.verdict.reasons[0] || '',
        });
      });
    }
    return flagged;
  }

  function getState() {
    const state = {
      hostname,
      mode: settings.resolveMode(stored),
      siteMode: settings.isMode(stored.siteMode) ? stored.siteMode : null,
      defaultMode: settings.resolveDefaultMode(stored.defaultMode),
      revealed,
      pageVerdict: null,
      counts: null,
      flagged: [],
    };
    if (scan) {
      state.pageVerdict = scan.pageVerdict;
      state.counts = scan.counts;
      state.flagged = flaggedLinks();
    }
    return state;
  }

  function focusLink(id) {
    const record = scan && scan.records[id];
    if (!record || !record.link.isConnected) return false;
    // Scroll and outline only: the link is never activated.
    record.link.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'smooth' });
    scan.overlay.highlight(record.link);
    return true;
  }

  async function reloadSettings() {
    try {
      stored = await settings.load(hostname);
    } catch {
      // Storage unavailable: keep what we have (the defaults, at startup).
    }
    apply();
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message && message.type) {
      case MESSAGES.GET_STATE:
        sendResponse(getState());
        return false;
      case MESSAGES.SETTINGS_CHANGED:
        reloadSettings().then(() => sendResponse(getState()));
        return true; // Reply comes after the storage read.
      case MESSAGES.REVEAL:
        revealed = true;
        apply();
        sendResponse(getState());
        return false;
      case MESSAGES.FOCUS_LINK:
        sendResponse({ found: focusLink(message.id) });
        return false;
      default:
        return false;
    }
  });

  // Settings changed in another tab or window: apply them here without a reload.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'sync') return;
    const siteKey = settings.siteKey(hostname);
    if (!(settings.DEFAULT_MODE_KEY in changes) && !(siteKey in changes)) return;

    if (settings.DEFAULT_MODE_KEY in changes) {
      stored.defaultMode = changes[settings.DEFAULT_MODE_KEY].newValue;
    }
    if (siteKey in changes) stored.siteMode = changes[siteKey].newValue;
    apply();
  });

  // A page restored from the back/forward cache keeps its scan, but the
  // toolbar count was cleared when the tab navigated away.
  window.addEventListener('pageshow', (event) => {
    if (event.persisted) reportCounts();
  });

  reloadSettings();
})();
