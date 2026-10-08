// Tripwire content script.
//
// Applies the display mode, reports counts for the toolbar icon, and answers
// the popup. The scanning itself lives in scanner.js; it runs on every page
// unless the site is switched off, and the mode only decides which badges are
// drawn.

(() => {
  'use strict';

  const { createScanner, createWarning, settings, trust, clickguard, CONFIG } = Tripwire;
  const { MESSAGES } = settings;

  // Counts change in bursts while a page loads or scrolls. The toolbar and
  // popup hear about them at most this often.
  const REPORT_INTERVAL_MS = 250;
  const DEBUG_LOG_INTERVAL_MS = 2000;

  const hostname = location.hostname;

  // Raw values from storage; settings.resolveMode() turns them into a mode.
  let stored = { defaultMode: undefined, siteMode: undefined, clickWarning: undefined };
  // The user's trusted domains (trust.js).
  let trusted = new Set();
  // The popup's "Show all on this page": lasts until the page reloads, or
  // until the user picks a different mode for this page.
  let revealed = false;
  let appliedMode = null;
  // Null while the site is switched off.
  let scanner = null;

  let reportTimer = 0;
  let lastToolbarCounts = '';
  let debugTimer = 0;
  // Open popups showing this tab. They are sent the new state as it changes.
  const popupPorts = new Set();

  // Sends out what changed: the toolbar numbers to the service worker (only
  // when those numbers differ, so it isn't woken for nothing), and the full
  // state to any open popup.
  function report() {
    reportTimer = 0;

    const { dangerous = 0, suspicious = 0 } = scanner ? scanner.getCounts() : {};
    const pageListed = Boolean(scanner && scanner.isPageListed());
    const toolbarCounts = `${dangerous}/${suspicious}/${pageListed}`;
    if (toolbarCounts !== lastToolbarCounts) {
      lastToolbarCounts = toolbarCounts;
      try {
        chrome.runtime
          .sendMessage({ type: MESSAGES.COUNTS, dangerous, suspicious, pageListed })
          .catch(() => {});
      } catch {
        // The extension was reloaded or removed; this page's script is orphaned.
      }
    }

    if (popupPorts.size > 0) {
      const state = getState();
      for (const port of popupPorts) {
        try {
          port.postMessage(state);
        } catch {
          popupPorts.delete(port);
        }
      }
    }
  }

  // With CONFIG.debug on, logs what the scanner and overlay have done so far.
  // One line per burst of changes, a moment after the burst starts, so it
  // always describes the latest state.
  function logPerformance() {
    if (!CONFIG.debug || debugTimer) return;
    debugTimer = setTimeout(() => {
      debugTimer = 0;
      if (!scanner) return;
      const stats = scanner.getStats();
      console.debug(
        `[Tripwire perf] ${stats.linksTracked} links tracked, ${stats.linksAnalysed} analysed ` +
          `(${stats.analyserRuns} analyzer runs) in ${stats.analyseMs}ms; ` +
          `${stats.overlay.passes} positioning passes in ${stats.overlay.positionMs}ms; ` +
          `${stats.mutationBatches} mutation batches; ${stats.workSlices} work slices, ` +
          `longest ${stats.longestSliceMs}ms; ${stats.overlay.drawn} badges drawn; ` +
          `${stats.addressesLookedUp} addresses checked against the blocklists in ` +
          `${stats.lookupBatches} batches, ${stats.listed} listed`,
      );
    }, DEBUG_LOG_INTERVAL_MS);
  }

  // Asks the service worker which of these addresses are on a blocklist.
  // The message goes to this extension's own worker and no further.
  function lookupListings(urls) {
    try {
      return chrome.runtime.sendMessage({ type: MESSAGES.LOOKUP, urls }).catch(() => null);
    } catch {
      return Promise.resolve(null); // The extension was reloaded or removed.
    }
  }

  // Called by the scanner whenever its results changed.
  function onScanChange() {
    if (!reportTimer) reportTimer = setTimeout(report, REPORT_INTERVAL_MS);
    logPerformance();
  }

  // Brings the page in line with the current settings.
  function apply() {
    const mode = settings.resolveMode(stored);
    // Choosing a mode is a newer instruction than an earlier one-off reveal.
    if (appliedMode !== null && mode !== appliedMode) revealed = false;
    appliedMode = mode;

    if (mode === 'off') {
      if (scanner) scanner.stop();
      scanner = null;
    } else {
      if (!scanner) scanner = createScanner({ onChange: onScanChange, lookup: lookupListings, trusted });
      scanner.setDisplayFilter((level) => settings.shouldDisplay(level, mode, revealed));
    }

    clearTimeout(reportTimer);
    report();
  }

  // --- Click-time warning -------------------------------------------------------
  //
  // early.js put listeners on `window` before the page's own scripts ran, and
  // passes every click, middle-click and key press here first. A link with a
  // "dangerous" verdict is stopped and the warning shown; "Continue anyway"
  // then follows it the way the stopped click would have.
  //
  // Whatever goes wrong, the click goes through: early.js catches anything
  // thrown here, and the click is only stopped once the warning is really up.

  const warning = createWarning();

  const isLink = (node) => node instanceof HTMLAnchorElement && node.hasAttribute('href');

  // Stops the event for the browser (no navigation) and for the page (its
  // own handlers never see it).
  function swallow(event) {
    event.preventDefault();
    event.stopImmediatePropagation();
  }

  // Follows a link from a clean copy of it: the address that was shown in the
  // warning, with the original link's target, rel and referrer policy, so the
  // browser applies its usual rules. The copy is never in the page, so the
  // page's handlers don't run and nothing the page changed after the warning
  // opened can redirect it.
  function followLink({ url, disposition, target, rel, referrerPolicy, download }, inNewTab) {
    const anchor = document.createElement('a');
    anchor.href = url;
    if (rel) anchor.rel = rel;
    if (referrerPolicy) anchor.referrerPolicy = referrerPolicy;
    if (disposition === 'download') anchor.download = download;
    if (inNewTab) anchor.target = '_blank';
    else if (target) anchor.target = target;
    anchor.click();
  }

  function proceed(pending) {
    if (!clickguard.opensElsewhere(pending.disposition)) {
      followLink(pending, false);
      return;
    }
    // A new tab or window is opened by the service worker, which Chrome's
    // popup blocker has no say over. If the worker can't be reached, or
    // declines (not a web address), the browser is asked the ordinary way.
    const ordinaryWay = () => followLink(pending, true);
    try {
      chrome.runtime
        .sendMessage({ type: MESSAGES.OPEN_LINK, url: pending.url, disposition: pending.disposition })
        .then((reply) => {
          if (!reply || !reply.opened) ordinaryWay();
        }, ordinaryWay);
    } catch {
      ordinaryWay(); // The extension was reloaded or removed.
    }
  }

  // The page's own modal dialog, if the click came from inside one.
  // Everything outside a modal dialog can't be clicked, so that is where the
  // warning has to go.
  function modalAround(path) {
    try {
      return path.find((node) => node instanceof Element && node.matches(':modal')) || null;
    } catch {
      return null;
    }
  }

  function onActivation(event) {
    if (warning.isOpen()) {
      // Escape means "Go back". Handled here, ahead of the page, so a page
      // can't leave the user stuck behind the warning.
      if (event.type === 'keydown' && event.key === 'Escape' && event.isTrusted) {
        warning.escape(event);
        swallow(event);
        return;
      }
      if (warning.owns(event)) return; // The warning's own buttons.
    }

    if (!scanner || !warning.supported) return;
    if (!settings.resolveClickWarning(stored.clickWarning)) return;
    if (event.type === 'keydown' && event.key !== 'Enter') return;

    const path = event.composedPath();
    const link = path.find(isLink);
    if (!link) return;
    // Enter follows a link only when the link itself has the focus.
    if (event.type === 'keydown' && path[0] !== link) return;

    const verdict = scanner.verdictAt(link);
    const warn = clickguard.shouldWarn({
      enabled: true,
      mode: appliedMode,
      level: verdict ? verdict.level : null,
      type: event.type,
      button: event.button,
      key: event.key,
      isTrusted: event.isTrusted,
      defaultPrevented: event.defaultPrevented,
    });
    if (!warn) return;

    // One warning at a time. With one open, only a script can be clicking.
    if (warning.isOpen()) {
      swallow(event);
      return;
    }

    const target = link.getAttribute('target') || '';
    const base = document.querySelector('base[target]');
    let sameOrigin = false;
    try {
      sameOrigin = new URL(verdict.url).origin === location.origin;
    } catch {
      // Not an address with an origin.
    }
    const disposition = clickguard.dispositionOf({
      type: event.type,
      button: event.button,
      ctrlKey: event.ctrlKey,
      metaKey: event.metaKey,
      shiftKey: event.shiftKey,
      altKey: event.altKey,
      target: target || (base ? base.target : ''),
      hasDownload: link.hasAttribute('download'),
      sameOrigin,
    });
    // Everything "Continue anyway" needs is fixed now. What the page does to
    // the link while the warning is open changes nothing.
    const pending = {
      url: verdict.url,
      disposition,
      target,
      rel: link.getAttribute('rel') || '',
      referrerPolicy: link.referrerPolicy || '',
      download: link.getAttribute('download') || '',
    };

    const shown = warning.show({
      container: modalAround(path) || document.documentElement,
      heading: clickguard.headingFor(verdict.listing),
      url: verdict.url,
      reasons: verdict.reasons,
      effect: clickguard.effectText(disposition),
      onBack: () => {
        if (link.isConnected) link.focus({ preventScroll: true });
      },
      onContinue: () => proceed(pending),
    });
    // Only now is the click stopped. If the warning could not be shown, the
    // click carries on as if Tripwire weren't here.
    if (shown) swallow(event);
  }

  if (Tripwire.early) Tripwire.early.setHandler(onActivation);

  // --- Popup ------------------------------------------------------------------

  function getState() {
    const state = {
      hostname,
      mode: settings.resolveMode(stored),
      siteMode: settings.isMode(stored.siteMode) ? stored.siteMode : null,
      defaultMode: settings.resolveDefaultMode(stored.defaultMode),
      revealed,
      pageVerdict: null,
      pageListing: null,
      pageTrusted: false,
      pageDomain: '',
      counts: null,
      rows: [],
      hiddenRows: 0,
      listedDomains: [],
      stats: null,
    };
    if (scanner) Object.assign(state, scanner.getSnapshot(), { stats: scanner.getStats() });
    return state;
  }

  async function reloadSettings() {
    try {
      stored = await settings.load(hostname);
    } catch {
      // Storage unavailable: keep what we have (the defaults, at startup).
    }
    try {
      setTrusted(await trust.load());
    } catch {
      // Same: keep the trusted domains we have.
    }
    apply();
  }

  // Tells the scanner only when the set really differs: it looks at every
  // link again when it is told.
  function setTrusted(domains) {
    const same = domains.size === trusted.size && [...domains].every((domain) => trusted.has(domain));
    if (same) return;
    trusted = domains;
    if (scanner) scanner.setTrusted(trusted);
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
        sendResponse({ found: Boolean(scanner && scanner.focusLink(message.id)) });
        return false;
      default:
        return false;
    }
  });

  // An open popup keeps a connection for as long as it is showing this tab.
  chrome.runtime.onConnect.addListener((port) => {
    if (port.name !== settings.POPUP_PORT) return;
    popupPorts.add(port);
    port.onDisconnect.addListener(() => popupPorts.delete(port));
  });

  // The blocklists changed (first download, an update, "Check now"): check
  // this page's links against the new ones.
  let listVersion = null;
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local' || !(settings.LIST_STATUS_KEY in changes)) return;
    const status = changes[settings.LIST_STATUS_KEY].newValue;
    const version = status ? status.version : null;
    if (version === listVersion) return;
    listVersion = version;
    if (scanner) scanner.recheckListings();
  });

  // Settings changed in another tab or window: apply them here without a reload.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'sync') return;

    // Trusted domains, added in the popup or removed on the options page.
    const next = new Set(trusted);
    for (const [key, change] of Object.entries(changes)) {
      if (!key.startsWith(trust.TRUST_KEY_PREFIX)) continue;
      const domain = key.slice(trust.TRUST_KEY_PREFIX.length);
      if (change.newValue) next.add(domain);
      else next.delete(domain);
    }
    setTrusted(next);

    // The click-time warning, switched on or off on the options page.
    if (settings.CLICK_WARNING_KEY in changes) {
      stored.clickWarning = changes[settings.CLICK_WARNING_KEY].newValue;
    }

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
    if (!event.persisted) return;
    lastToolbarCounts = '';
    report();
  });

  reloadSettings();
})();
