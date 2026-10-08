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
    createDescriber,
    createTally,
    createBoundedCache,
    sameVerdict,
    OVERLAY_TAG,
    NOTES_TAG,
    WARNING_ATTR,
  } = Tripwire;
  const { resolveVerdict, domainOf } = Tripwire.trust;
  const { inheritsOnly, buildRows } = Tripwire.findings;

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
  // Blocklist answers remembered per address, and how many are asked at once.
  const LISTING_CACHE_SIZE = 5000;
  const LOOKUP_BATCH_SIZE = 400;
  const LOOKUPABLE_RE = /^https?:\/\//i;
  // Custom elements seen before their definition loaded. They are re-checked
  // for a shadow root as the page keeps changing.
  const MAX_UNDEFINED_HOSTS = 500;

  // What the popup is sent: at most this many rows, and this many links in a
  // group row. An address longer than the limit (a data: link, say) is cut.
  const MAX_ROWS = 50;
  const MAX_GROUP_MEMBERS = 50;
  const MAX_LISTED_TEXT_LENGTH = 80;
  const MAX_LISTED_URL_LENGTH = 2000;
  // How many reasons a screen reader is read for a dangerous link.
  const MAX_DESCRIBED_REASONS = 3;

  const OBSERVE_OPTIONS = {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ['href'],
    // Text edited in place: a page could swap a link's visible text for a
    // trusted-looking domain after it has been scanned.
    characterData: true,
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

  // What a screen reader says about a dangerous link (see describer.js).
  function descriptionOf(verdict, url) {
    const parts = ['Tripwire warning: likely dangerous link', ...verdict.reasons.slice(0, MAX_DESCRIBED_REASONS)];
    const host = destinationOf(url);
    if (host) parts.push(`Goes to ${host}`);
    return `${parts.map((part) => part.replace(/[.\s]+$/, '')).join('. ')}.`;
  }

  /**
   * Starts scanning. `onChange` is called after any stretch of work that
   * changed the counts, the flagged links or the page verdict.
   *
   * `lookup(urls)` asks the service worker which addresses are on a
   * blocklist. It resolves to { ready, results }, with one match or null per
   * address, or to null if the worker can't be reached.
   *
   * `trusted` is the user's trusted domains; setTrusted() replaces them.
   */
  function createScanner({ onChange, lookup, trusted = [] }) {
    const overlay = createOverlay();
    const describer = createDescriber();
    const tally = createTally();
    // What the checks say about a link, keyed by href AND link text: the
    // text/href mismatch check means two links to the same URL can deserve
    // different verdicts.
    const verdicts = createBoundedCache(VERDICT_CACHE_SIZE);

    let trustedDomains = new Set(trusted);
    const isTrusted = (url) => trustedDomains.size > 0 && trustedDomains.has(domainOf(url));
    // Dangerous links are described to screen readers whenever their badges
    // are drawn; setDisplayFilter() decides.
    let describeDangerous = false;

    let pageUrl = location.href;
    // The page's own address is judged once per URL; every same-site link
    // depends on it. `pageVerdict` is what is shown for the page: what the
    // checks on the address say, then any blocklist match, then the user's
    // trust (trust.resolveVerdict has the rules).
    let pageHeuristics = analyzePage(pageUrl);
    let pageListing = null;
    let pageTrusted = isTrusted(pageUrl);
    let pageVerdict = resolveVerdict({ verdict: pageHeuristics, trusted: pageTrusted });

    // One record per link that has a verdict:
    // { id, link, text, url, verdict, listing, trusted, inherited, item }.
    // `verdict` is what is shown, resolved the same way as the page's.
    // `inherited` means the link has nothing against it but the page's warning.
    const records = new Set();
    const recordByLink = new WeakMap();
    const recordById = new Map();
    let nextId = 1;

    // Blocklist state. An address is undefined in `listings` until the
    // service worker has answered for it; then it is a match or null.
    const listings = createBoundedCache(LISTING_CACHE_SIZE);
    const recordsByUrl = new Map(); // address -> Set of records pointing there
    const pendingLookups = new Set();
    let lookupInFlight = false;
    // False once the worker says it has no lists yet; lookups resume when
    // recheckListings() is called.
    let listsReady = true;

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
      lookupBatches: 0, // Messages sent to the service worker.
      addressesLookedUp: 0,
      linksAnalysed: 0, // Links given (or re-given) a verdict.
      analyserRuns: 0, // Of those, how many missed the cache and ran the analyzer.
      analyseMs: 0,
      mutationBatches: 0,
      workSlices: 0,
      longestSliceMs: 0,
    };

    // --- Records --------------------------------------------------------------

    function indexByUrl(record) {
      let group = recordsByUrl.get(record.url);
      if (!group) {
        group = new Set();
        recordsByUrl.set(record.url, group);
      }
      group.add(record);
    }

    function unindexByUrl(record) {
      const group = recordsByUrl.get(record.url);
      if (!group) return;
      group.delete(record);
      if (group.size === 0) recordsByUrl.delete(record.url);
    }

    function dropRecord(record) {
      records.delete(record);
      recordById.delete(record.id);
      recordByLink.delete(record.link);
      unindexByUrl(record);
      tally.remove(record.url, record.verdict.level);
      overlay.remove(record.item);
      describer.describe(record.link, null);
      if (record.link.isConnected) record.link.removeAttribute(PROCESSED_ATTR);
      changed = true;
    }

    function syncDescription(record) {
      const wanted = describeDangerous && record.verdict.level === 'dangerous';
      describer.describe(record.link, wanted ? descriptionOf(record.verdict, record.url) : null);
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
      let heuristics = verdicts.get(cacheKey);
      if (!heuristics) {
        heuristics = analyzeLink({ href: info.href, text: info.text, pageUrl, pageVerdict });
        verdicts.set(cacheKey, heuristics);
        stats.analyserRuns++;
      }
      stats.linksAnalysed++;

      // A blocklist match overrides the heuristics. If the answer for this
      // address isn't known yet, ask; the link is processed again when it is.
      let listing = null;
      if (lookup && LOOKUPABLE_RE.test(info.url)) {
        listing = listings.get(info.url);
        if (listing === undefined) {
          listing = null;
          if (listsReady) pendingLookups.add(info.url);
        }
      }

      const trusted = isTrusted(info.url);
      const verdict = resolveVerdict({ verdict: heuristics, listing, trusted, now: Date.now() });
      const inherited = inheritsOnly({ reasons: heuristics.reasons, listing, pageListing });

      const display = {
        level: verdict.level,
        reasons: verdict.reasons,
        url: info.url,
        trusted,
        // Links with the same destination and verdict can share a badge.
        key: `${info.url}\n${verdict.level}`,
      };

      if (!record) {
        record = { id: nextId++, link, text: info.text, url: info.url, verdict, listing, trusted, inherited, item: null };
        record.item = overlay.add(link, display);
        records.add(record);
        recordByLink.set(link, record);
        recordById.set(record.id, record);
        indexByUrl(record);
        tally.add(record.url, verdict.level);
        link.setAttribute(PROCESSED_ATTR, '');
        syncDescription(record);
        changed = true;
        return;
      }

      const same =
        record.url === info.url &&
        record.text === info.text &&
        record.trusted === trusted &&
        record.inherited === inherited &&
        sameVerdict(record.verdict, verdict);
      if (same) {
        syncDescription(record); // The page may have moved the link or rewritten its attributes.
        return;
      }

      tally.remove(record.url, record.verdict.level);
      if (record.url !== info.url) {
        unindexByUrl(record);
        record.url = info.url;
        indexByUrl(record);
      }
      record.text = info.text;
      record.verdict = verdict;
      record.listing = listing;
      record.trusted = trusted;
      record.inherited = inherited;
      tally.add(record.url, verdict.level);
      overlay.update(record.item, display);
      syncDescription(record);
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

    // --- Blocklist lookups ------------------------------------------------------

    // Sends the next batch of addresses to the service worker. One batch is
    // in flight at a time; the answers decide which links to look at again.
    function flushLookups() {
      if (!lookup || lookupInFlight || stopped || pendingLookups.size === 0) return;

      const urls = [];
      for (const url of pendingLookups) {
        pendingLookups.delete(url);
        urls.push(url);
        if (urls.length >= LOOKUP_BATCH_SIZE) break;
      }

      lookupInFlight = true;
      stats.lookupBatches++;
      stats.addressesLookedUp += urls.length;
      Promise.resolve(lookup(urls))
        .catch(() => null)
        .then((reply) => {
          lookupInFlight = false;
          if (stopped) return;

          if (!reply || !reply.ready) {
            // No lists yet (first install) or no worker: stop asking until
            // told the lists have changed.
            listsReady = false;
            pendingLookups.clear();
            return;
          }

          urls.forEach((url, index) => {
            const listing = reply.results[index] || null;
            listings.set(url, listing);
            for (const record of recordsByUrl.get(url) || []) {
              // Only links whose listed state actually changed need another look.
              if (listing || record.listing) pendingLinks.add(record.link);
            }
          });
          scheduleWork();
          flushLookups();
        });
    }

    // Works out the page's verdict again. If it changed, every link is looked
    // at again, because same-site links inherit from it.
    function refreshPageVerdict() {
      const wasTrusted = pageTrusted;
      pageTrusted = isTrusted(pageUrl);
      if (pageTrusted !== wasTrusted) changed = true;
      const verdict = resolveVerdict({
        verdict: pageHeuristics,
        listing: pageListing,
        trusted: pageTrusted,
        now: Date.now(),
      });
      if (sameVerdict(verdict, pageVerdict)) return;
      pageVerdict = verdict;
      verdicts.clear();
      for (const record of records) pendingLinks.add(record.link);
      changed = true;
      scheduleWork();
    }

    // Asks whether the page's own address is on a blocklist. Until the answer
    // for a new address arrives, the previous answer stands.
    function lookupPage() {
      if (!lookup || stopped || !LOOKUPABLE_RE.test(pageUrl)) return;
      const asked = pageUrl;
      Promise.resolve(lookup([asked]))
        .catch(() => null)
        .then((reply) => {
          if (stopped || asked !== pageUrl || !reply || !reply.ready) return;
          const listing = reply.results[0] || null;
          if (Boolean(listing) !== Boolean(pageListing)) changed = true;
          pageListing = listing;
          refreshPageVerdict();
          flushChanges();
        });
    }

    // The lists changed (first download, an update, "Check now"): forget the
    // answers and ask again for the page and every address on it.
    function recheckListings() {
      if (!lookup || stopped) return;
      lookupPage();
      listings.clear();
      listsReady = true;
      for (const url of recordsByUrl.keys()) {
        if (LOOKUPABLE_RE.test(url)) pendingLookups.add(url);
      }
      flushLookups();
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
      flushLookups();
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
      // Text edits outside links are common (clocks, counters, typing) and
      // move nothing we draw; only the rest is worth a repositioning pass.
      let layoutMayHaveChanged = false;
      for (const mutation of mutations) {
        const { target } = mutation;
        // Our own notes for screen readers (describer.js): nothing to scan.
        if (target.localName === NOTES_TAG) continue;

        if (mutation.type === 'characterData') {
          const parent = target.parentElement;
          const owner = parent && parent.closest(LINK_SELECTOR);
          if (owner && recordByLink.has(owner)) {
            pendingLinks.add(owner);
            layoutMayHaveChanged = true;
          }
          continue;
        }
        layoutMayHaveChanged = true;

        if (mutation.type === 'attributes') {
          // An href appeared, changed or went away.
          pendingLinks.add(target);
          continue;
        }

        if (mutation.removedNodes.length > 0) needsPrune = true;
        for (const node of mutation.addedNodes) {
          if (
            node.nodeType === Node.ELEMENT_NODE &&
            node.localName !== OVERLAY_TAG &&
            node.localName !== NOTES_TAG &&
            !node.hasAttribute(WARNING_ATTR)
          ) {
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
      if (layoutMayHaveChanged) overlay.nudge();
      scheduleWork();
    });

    // Single-page apps change the address without loading a new page. If the
    // new address changes what we think of the page, every link is looked at
    // again, because same-site links depend on it.
    function checkPageUrl() {
      if (location.href === pageUrl) return;
      pageUrl = location.href;
      pageHeuristics = analyzePage(pageUrl);
      refreshPageVerdict();
      lookupPage();
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
    lookupPage();

    // --- Public API -------------------------------------------------------------

    // Every link that isn't "ok", as findings.buildRows() wants them. It
    // sorts, groups and removes repeats.
    function* flaggedLinks() {
      for (const record of records) {
        if (record.verdict.level === 'ok') continue;
        yield {
          id: record.id,
          level: record.verdict.level,
          text: (record.text || nameOfTextless(record.link)).slice(0, MAX_LISTED_TEXT_LENGTH),
          url: record.url.slice(0, MAX_LISTED_URL_LENGTH),
          reasons: record.verdict.reasons,
          listed: Boolean(record.listing),
          trusted: record.trusted,
          inherited: record.inherited,
        };
      }
    }

    // Domains with an address on a blocklist on this page, the page's own
    // included. Trusting one of them takes a confirmation in the popup.
    function listedDomains() {
      const domains = new Set();
      if (pageListing) domains.add(domainOf(pageUrl));
      for (const record of records) {
        if (record.listing) domains.add(domainOf(record.url));
      }
      domains.delete('');
      return [...domains];
    }

    function getCounts() {
      return tally.summary();
    }

    // For the toolbar icon. A listed page the user trusts is amber, like its
    // links, so it doesn't count here.
    function isPageListed() {
      return pageListing !== null && !pageTrusted;
    }

    function getSnapshot() {
      const pageDomain = domainOf(pageUrl);
      const { rows, hidden } = buildRows(flaggedLinks(), {
        pageDomain,
        maxRows: MAX_ROWS,
        maxMembers: MAX_GROUP_MEMBERS,
      });
      return {
        pageVerdict,
        pageListing,
        pageTrusted,
        pageDomain,
        counts: tally.summary(),
        rows,
        hiddenRows: hidden,
        listedDomains: listedDomains(),
      };
    }

    function getStats() {
      return {
        linksTracked: records.size,
        linksAnalysed: stats.linksAnalysed,
        lookupBatches: stats.lookupBatches,
        addressesLookedUp: stats.addressesLookedUp,
        listed: [...records].filter((record) => record.listing).length,
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

    /**
     * The link's verdict at this moment, for the click-time warning, or null
     * if it has none.
     *
     * The link is looked at again first, in the middle of the click. A page
     * can swap a link's address just before the click lands (on mousedown,
     * say); this way it is judged on where the click will really go. It also
     * covers a link the queue hasn't reached yet. Only the checks that need
     * no waiting run here: a blocklist answer that isn't known yet stays
     * unknown.
     */
    function verdictAt(link) {
      if (stopped) return null;
      pendingLinks.delete(link);
      processLink(link);
      flushLookups();
      flushChanges();
      const record = recordByLink.get(link);
      if (!record) return null;
      return {
        level: record.verdict.level,
        reasons: record.verdict.reasons,
        url: record.url,
        listing: record.listing,
      };
    }

    // `wantsBadge(level)` decides which verdict levels are drawn. Dangerous
    // links are described to screen readers exactly when they get a badge.
    function setDisplayFilter(wantsBadge) {
      overlay.setFilter((item) => wantsBadge(item.level));
      describeDangerous = Boolean(wantsBadge('dangerous'));
      for (const record of records) syncDescription(record);
    }

    // The user's trusted domains changed: every link is looked at again.
    function setTrusted(domains) {
      trustedDomains = new Set(domains);
      refreshPageVerdict();
      for (const record of records) pendingLinks.add(record.link);
      scheduleWork();
      flushChanges();
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
        describer.describe(record.link, null);
        if (record.link.isConnected) record.link.removeAttribute(PROCESSED_ATTR);
      }
      records.clear();
      recordById.clear();
      recordsByUrl.clear();
      pendingLookups.clear();
      pendingLinks.clear();
      undefinedHosts.clear();
      pendingSubtrees.length = 0;
      nextSubtree = 0;
      pendingHostWalks.length = 0;
    }

    return {
      getCounts,
      isPageListed,
      getSnapshot,
      getStats,
      focusLink,
      verdictAt,
      setDisplayFilter,
      setTrusted,
      recheckListings,
      stop,
    };
  }

  Tripwire.createScanner = createScanner;
})();
