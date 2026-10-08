// Tripwire scanner: finds the page's links, keeps up as the page changes,
// and hands each link's verdict to the overlay.
//
// Nothing is analysed where it is noticed. The first scan, DOM mutations and
// page-URL changes all just add to a queue, and the queue is worked through
// in idle time, a few milliseconds at a time, so a page that inserts
// thousands of links at once (or never stops inserting them) stays smooth.
//
// Memory: per-link state hangs off WeakMaps keyed by the element. The one
// strong collection of live links is pruned whenever the page removes nodes,
// and the verdict cache is capped.

(() => {
  'use strict';

  const {
    analyzeLink,
    analyzePage,
    createOverlay,
    createTally,
    createBoundedCache,
    sameVerdict,
    OVERLAY_TAG,
  } = Tripwire;

  const LINK_SELECTOR = 'a[href]';
  const PROCESSED_ATTR = 'data-tripwire-processed';
  const SKIPPED_PROTOCOLS = new Set(['javascript:', 'mailto:', 'tel:', ':']); // ":" = unparseable
  const MAX_TEXT_LENGTH = 300;
  // An href that names its own host: has a scheme, or starts with "//".
  const ABSOLUTE_HREF_RE = /^(?:[a-z][a-z0-9+.-]*:|[\\/]{2})/i;

  // A busy page may never be idle; queued links wait at most this long.
  const IDLE_TIMEOUT_MS = 300;
  // Longest stretch of work in one go. An idle period can offer up to 50ms,
  // but a click or keypress may arrive in the middle of it.
  const MAX_SLICE_MS = 12;
  // Stretch of work when the timeout fired because the page was never idle.
  const BUSY_SLICE_MS = 6;
  // How many items to handle between looks at the clock.
  const LINKS_PER_CLOCK_CHECK = 16;
  const ELEMENTS_PER_CLOCK_CHECK = 128;

  const VERDICT_CACHE_SIZE = 2000;
  // Custom elements seen before their definition loaded. They are re-checked
  // for a shadow root as the page keeps changing.
  const MAX_UNDEFINED_HOSTS = 500;

  const MAX_FLAGGED_LINKS = 10;
  const MAX_LISTED_TEXT_LENGTH = 80;

  const OBSERVE_OPTIONS = {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ['href'],
  };

  const requestIdle =
    typeof requestIdleCallback === 'function'
      ? (callback) => requestIdleCallback(callback, { timeout: IDLE_TIMEOUT_MS })
      : (callback) => setTimeout(callback, 50);
  const cancelIdle = typeof cancelIdleCallback === 'function' ? cancelIdleCallback : clearTimeout;

  // What the analyzer needs to know about a link, or null if the link gets no
  // verdict (wrong kind of element, no real destination, inside an editor).
  function describe(link) {
    // SVG <a> elements match a[href] too, but they have no HTML box to mark.
    if (!(link instanceof HTMLAnchorElement)) return null;
    // Leave editable regions (email composers, rich-text editors) untouched:
    // even the marker attribute would become part of the user's content.
    if (link.isContentEditable) return null;

    const raw = (link.getAttribute('href') || '').trim();
    if (raw === '' || raw.startsWith('#')) return null;
    if (SKIPPED_PROTOCOLS.has(link.protocol)) return null;

    const url = link.href;
    return {
      // Absolute hrefs are passed as written: link.href has already normalised
      // away disguises like http://3232235777. Relative ones are left to the
      // browser to resolve, since it honours <base>.
      href: ABSOLUTE_HREF_RE.test(raw) ? raw : url,
      url,
      text: link.textContent.replace(/\s+/g, ' ').trim().slice(0, MAX_TEXT_LENGTH),
    };
  }

  // A name for a link with no text of its own, for the popup's list only.
  // The analyzer still sees the link's real (empty) text.
  function nameOfTextless(link) {
    const image = link.querySelector('img[alt]');
    const name = (image && image.alt) || link.getAttribute('aria-label') || link.title || '';
    return name.replace(/\s+/g, ' ').trim();
  }

  function destinationOf(url) {
    try {
      const parsed = new URL(url);
      return parsed.hostname || parsed.protocol;
    } catch {
      return '';
    }
  }

  /**
   * Starts scanning. `onChange` is called after any stretch of work that
   * changed the counts, the flagged links or the page verdict.
   */
  function createScanner({ onChange }) {
    const overlay = createOverlay();
    const tally = createTally();
    // Verdicts keyed by href AND link text: the text/href mismatch check means
    // two links to the same URL can deserve different verdicts.
    const verdicts = createBoundedCache(VERDICT_CACHE_SIZE);

    let pageUrl = location.href;
    // The page's own address is judged once per URL; every same-site link
    // depends on it.
    let pageVerdict = analyzePage(pageUrl);

    // One record per link that has a verdict: { id, link, text, url, verdict, item }.
    const records = new Set();
    const recordByLink = new WeakMap();
    const recordById = new Map();
    let nextId = 1;

    // The document and every open shadow root being watched.
    const watchedRoots = new WeakSet([document]);
    const undefinedHosts = new Set();

    // The queue, in the order it is worked: links first, then subtrees to
    // search for links, then walks looking for shadow roots.
    const pendingLinks = new Set();
    // Oldest first, so the original document is scanned before later arrivals.
    // `nextSubtree` is the read position; popping from the front of a long
    // array would cost more than the work itself.
    const pendingSubtrees = [];
    let nextSubtree = 0;
    const pendingHostWalks = [];
    let needsPrune = false;
    let needsHostRecheck = false;

    let idleHandle = 0;
    let stopped = false;
    let changed = false;

    const stats = {
      linksAnalysed: 0, // Links given (or re-given) a verdict.
      analyserRuns: 0, // Of those, how many missed the cache and ran the analyzer.
      analyseMs: 0,
      mutationBatches: 0,
      workSlices: 0,
      longestSliceMs: 0,
    };

    // --- Records --------------------------------------------------------------

    function dropRecord(record) {
      records.delete(record);
      recordById.delete(record.id);
      recordByLink.delete(record.link);
      tally.remove(record.url, record.verdict.level);
      overlay.remove(record.item);
      if (record.link.isConnected) record.link.removeAttribute(PROCESSED_ATTR);
      changed = true;
    }

    // Gives a link its verdict, or brings an existing one up to date. Safe to
    // call on any link at any time; it works out what, if anything, changed.
    function processLink(link) {
      let record = recordByLink.get(link);
      const info = link.isConnected ? describe(link) : null;
      if (!info) {
        if (record) dropRecord(record);
        return;
      }

      const cacheKey = `${info.href}\n${info.text}`;
      let verdict = verdicts.get(cacheKey);
      if (!verdict) {
        verdict = analyzeLink({ href: info.href, text: info.text, pageUrl, pageVerdict });
        verdicts.set(cacheKey, verdict);
        stats.analyserRuns++;
      }
      stats.linksAnalysed++;

      const display = {
        level: verdict.level,
        reasons: verdict.reasons,
        // Links with the same destination and verdict can share a badge.
        key: `${info.url}\n${verdict.level}`,
      };

      if (!record) {
        record = { id: nextId++, link, text: info.text, url: info.url, verdict, item: null };
        record.item = overlay.add(link, display);
        records.add(record);
        recordByLink.set(link, record);
        recordById.set(record.id, record);
        tally.add(record.url, verdict.level);
        link.setAttribute(PROCESSED_ATTR, '');
        changed = true;
        return;
      }

      const same =
        record.url === info.url && record.text === info.text && sameVerdict(record.verdict, verdict);
      if (same) return;

      tally.remove(record.url, record.verdict.level);
      record.text = info.text;
      record.url = info.url;
      record.verdict = verdict;
      tally.add(record.url, verdict.level);
      overlay.update(record.item, display);
      changed = true;
    }

    // Drops links the page has removed. Cheap enough to run over everything:
    // it is one flag check per link.
    function prune() {
      needsPrune = false;
      for (const record of records) {
        if (!record.link.isConnected) dropRecord(record);
      }
      for (const host of undefinedHosts) {
        if (!host.isConnected) undefinedHosts.delete(host);
      }
    }

    // --- Shadow roots ---------------------------------------------------------

    // Open shadow roots are scanned and watched like the document. Closed
    // ones are not: element.shadowRoot is null for them.
    function watchRoot(root) {
      if (watchedRoots.has(root)) return;
      watchedRoots.add(root);
      observer.observe(root, OBSERVE_OPTIONS);
      pendingSubtrees.push(root);
    }

    function checkForShadowRoot(element) {
      if (element.shadowRoot) {
        watchRoot(element.shadowRoot);
      } else if (
        undefinedHosts.size < MAX_UNDEFINED_HOSTS &&
        element.localName.includes('-') &&
        !element.matches(':defined')
      ) {
        // Its definition hasn't loaded yet; it may get a shadow root when it does.
        undefinedHosts.add(element);
      }
    }

    // Attaching a shadow root fires no mutation, so elements that were waiting
    // for their definition are looked at again whenever there is other work.
    function recheckUndefinedHosts() {
      needsHostRecheck = false;
      for (const host of undefinedHosts) {
        if (host.shadowRoot) {
          watchRoot(host.shadowRoot);
          undefinedHosts.delete(host);
        } else if (!host.isConnected || host.matches(':defined')) {
          undefinedHosts.delete(host);
        }
      }
    }

    // --- The queue --------------------------------------------------------------

    function hasPendingWork() {
      return (
        needsPrune ||
        needsHostRecheck ||
        pendingLinks.size > 0 ||
        nextSubtree < pendingSubtrees.length ||
        pendingHostWalks.length > 0
      );
    }

    function scheduleWork() {
      if (!idleHandle && !stopped && hasPendingWork()) idleHandle = requestIdle(work);
    }

    function analysePendingLinks(outOfTime) {
      const started = performance.now();
      let handled = 0;
      for (const link of pendingLinks) {
        pendingLinks.delete(link);
        processLink(link);
        if (++handled % LINKS_PER_CLOCK_CHECK === 0 && outOfTime()) break;
      }
      stats.analyseMs += performance.now() - started;
    }

    // Queues every link in a subtree, and a walk of it for shadow roots.
    function expandSubtree(root) {
      if (!root.isConnected) return;
      if (root.nodeType === Node.ELEMENT_NODE) {
        if (root.matches(LINK_SELECTOR)) pendingLinks.add(root);
        checkForShadowRoot(root);
      }
      for (const link of root.querySelectorAll(LINK_SELECTOR)) pendingLinks.add(link);
      // A TreeWalker can stop and pick up again, unlike a query for "*".
      pendingHostWalks.push(document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT));
    }

    function walkForShadowRoots(outOfTime) {
      const walker = pendingHostWalks[pendingHostWalks.length - 1];
      let handled = 0;
      while (walker.nextNode()) {
        checkForShadowRoot(walker.currentNode);
        if (++handled % ELEMENTS_PER_CLOCK_CHECK === 0 && outOfTime()) return;
      }
      pendingHostWalks.pop();
    }

    function takeSubtree() {
      const subtree = pendingSubtrees[nextSubtree++];
      if (nextSubtree === pendingSubtrees.length) {
        pendingSubtrees.length = 0;
        nextSubtree = 0;
      }
      return subtree;
    }

    function work(deadline) {
      idleHandle = 0;
      if (stopped) return;

      const started = performance.now();
      const idle = deadline && !deadline.didTimeout && typeof deadline.timeRemaining === 'function';
      const budget = idle ? Math.min(deadline.timeRemaining(), MAX_SLICE_MS) : BUSY_SLICE_MS;
      const outOfTime = () => performance.now() - started >= budget;

      checkPageUrl();
      if (needsPrune) prune();
      if (needsHostRecheck) recheckUndefinedHosts();

      do {
        if (pendingLinks.size > 0) analysePendingLinks(outOfTime);
        else if (nextSubtree < pendingSubtrees.length) expandSubtree(takeSubtree());
        else if (pendingHostWalks.length > 0) walkForShadowRoots(outOfTime);
        else break;
      } while (!outOfTime());

      const elapsed = performance.now() - started;
      stats.workSlices++;
      stats.longestSliceMs = Math.max(stats.longestSliceMs, elapsed);

      scheduleWork();
      flushChanges();
    }

    function flushChanges() {
      if (!changed) return;
      changed = false;
      onChange();
    }

    // --- Watching the page ----------------------------------------------------

    const observer = new MutationObserver((mutations) => {
      stats.mutationBatches++;
      checkPageUrl(); // A page that changes its address nearly always changes its DOM too.
      for (const mutation of mutations) {
        const { target } = mutation;

        if (mutation.type === 'attributes') {
          // An href appeared, changed or went away.
          pendingLinks.add(target);
          continue;
        }

        if (mutation.removedNodes.length > 0) needsPrune = true;
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE && node.localName !== OVERLAY_TAG) {
            pendingSubtrees.push(node);
          }
        }

        // Something changed inside a link we track: its text may have changed.
        if (target.nodeType === Node.ELEMENT_NODE) {
          const owner = target.closest(LINK_SELECTOR);
          if (owner && recordByLink.has(owner)) pendingLinks.add(owner);
        }
      }
      if (undefinedHosts.size > 0) needsHostRecheck = true;
      // Added or removed content usually moves the links around it.
      overlay.nudge();
      scheduleWork();
    });

    // Single-page apps change the address without loading a new page. If the
    // new address changes what we think of the page, every link is looked at
    // again, because same-site links depend on it.
    function checkPageUrl() {
      if (location.href === pageUrl) return;
      pageUrl = location.href;
      const verdict = analyzePage(pageUrl);
      if (sameVerdict(verdict, pageVerdict)) return;

      pageVerdict = verdict;
      verdicts.clear();
      for (const record of records) pendingLinks.add(record.link);
      changed = true;
      scheduleWork();
      flushChanges();
    }

    // The Navigation API reports pushState and replaceState, which fire no
    // event of their own. The mutation observer's URL check is the backstop.
    const navigationApi = typeof navigation === 'object' && navigation ? navigation : null;
    if (navigationApi) navigationApi.addEventListener('currententrychange', checkPageUrl);
    window.addEventListener('popstate', checkPageUrl);
    window.addEventListener('hashchange', checkPageUrl);

    observer.observe(document, OBSERVE_OPTIONS);
    pendingSubtrees.push(document);
    scheduleWork();

    // --- Public API -------------------------------------------------------------

    // Red first, then amber; one entry per destination and level.
    function flaggedLinks() {
      const seen = new Set();
      const flagged = [];
      for (const level of ['dangerous', 'suspicious']) {
        for (const record of records) {
          if (flagged.length >= MAX_FLAGGED_LINKS) return flagged;
          if (record.verdict.level !== level) continue;
          const key = `${record.url}\n${level}`;
          if (seen.has(key)) continue;
          seen.add(key);
          flagged.push({
            id: record.id,
            level,
            text: (record.text || nameOfTextless(record.link)).slice(0, MAX_LISTED_TEXT_LENGTH),
            destination: destinationOf(record.url),
            reason: record.verdict.reasons[0] || '',
          });
        }
      }
      return flagged;
    }

    function getCounts() {
      return tally.summary();
    }

    function getSnapshot() {
      return { pageVerdict, counts: tally.summary(), flagged: flaggedLinks() };
    }

    function getStats() {
      return {
        linksTracked: records.size,
        linksAnalysed: stats.linksAnalysed,
        analyserRuns: stats.analyserRuns,
        analyseMs: Math.round(stats.analyseMs * 10) / 10,
        mutationBatches: stats.mutationBatches,
        workSlices: stats.workSlices,
        longestSliceMs: Math.round(stats.longestSliceMs * 10) / 10,
        queued: pendingLinks.size + (pendingSubtrees.length - nextSubtree) + pendingHostWalks.length,
        cachedVerdicts: verdicts.size,
        overlay: overlay.getStats(),
      };
    }

    function focusLink(id) {
      const record = recordById.get(id);
      if (!record || !record.link.isConnected) return false;
      // Scroll and outline only: the link is never activated.
      record.link.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'smooth' });
      overlay.highlight(record.link);
      return true;
    }

    // `wantsBadge(level)` decides which verdict levels are drawn.
    function setDisplayFilter(wantsBadge) {
      overlay.setFilter((item) => wantsBadge(item.level));
    }

    function stop() {
      stopped = true;
      observer.disconnect();
      if (idleHandle) cancelIdle(idleHandle);
      if (navigationApi) navigationApi.removeEventListener('currententrychange', checkPageUrl);
      window.removeEventListener('popstate', checkPageUrl);
      window.removeEventListener('hashchange', checkPageUrl);
      overlay.destroy();
      for (const record of records) {
        if (record.link.isConnected) record.link.removeAttribute(PROCESSED_ATTR);
      }
      records.clear();
      recordById.clear();
      pendingLinks.clear();
      undefinedHosts.clear();
      pendingSubtrees.length = 0;
      nextSubtree = 0;
      pendingHostWalks.length = 0;
    }

    return { getCounts, getSnapshot, getStats, focusLink, setDisplayFilter, stop };
  }

  Tripwire.createScanner = createScanner;
})();
