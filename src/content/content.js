// Tripwire content script.
//
// Applies the display mode, reports counts for the toolbar icon, and answers
// the popup. The scanning itself lives in scanner.js; it runs on every page
// unless the site is switched off, and the mode only decides which badges are
// drawn.

(() => {
  'use strict';

  const { createScanner, settings, CONFIG } = Tripwire;
  const { MESSAGES } = settings;

  // Counts change in bursts while a page loads or scrolls. The toolbar and
  // popup hear about them at most this often.
  const REPORT_INTERVAL_MS = 250;
  const DEBUG_LOG_INTERVAL_MS = 2000;

  const hostname = location.hostname;

  // Raw values from storage; settings.resolveMode() turns them into a mode.
  let stored = { defaultMode: undefined, siteMode: undefined };
  // The popup's "Show badges on this page": lasts until the page reloads, or
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
    const toolbarCounts = `${dangerous}/${suspicious}`;
    if (toolbarCounts !== lastToolbarCounts) {
      lastToolbarCounts = toolbarCounts;
      try {
        chrome.runtime.sendMessage({ type: MESSAGES.COUNTS, dangerous, suspicious }).catch(() => {});
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
      if (!scanner) scanner = createScanner({ onChange: onScanChange, lookup: lookupListings });
      scanner.setDisplayFilter((level) => settings.shouldDisplay(level, mode, revealed));
    }

    clearTimeout(reportTimer);
    report();
  }

  // --- Popup ------------------------------------------------------------------

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
