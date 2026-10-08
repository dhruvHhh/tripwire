// Tripwire list keeper: the service worker's side of the blocklists.
//
// Downloads the lists on install and every few hours, keeps them in
// IndexedDB, and answers lookups from content scripts. The rules for reading,
// matching and accepting a list are in src/lib/blocklist.js; this file is the
// network, the storage and the scheduling around them.
//
// Privacy: the only requests made here are downloads of the list files
// themselves. Lookups arrive from this browser's own tabs and are answered
// from memory. No link is ever sent anywhere.

(() => {
  'use strict';

  const { blocklist, settings } = Tripwire;
  const { MESSAGES, LIST_STATUS_KEY } = settings;
  const LISTS = blocklist.CONFIG;
  const DEBUG = Tripwire.CONFIG.debug;

  const DB_NAME = 'tripwire';
  const STORE = 'lists';
  const UPDATE_ALARM = 'tripwire:update-lists';
  const RETRY_ALARM = 'tripwire:retry-lists';
  // "Check now" can be pressed repeatedly; the mirrors are only asked this often.
  const MIN_FORCED_GAP_MS = 30000;
  const MAX_LOOKUP_BATCH = 2000;
  const MAX_IGNORED_LOGGED = 40;
  const MINUTE = 60000;

  // An unpacked (development) install has no update_url; the Web Store adds
  // one. Only development installs load the bundled test list.
  const isDevInstall = !('update_url' in chrome.runtime.getManifest());

  function activeSources() {
    return isDevInstall ? [...LISTS.sources, LISTS.fixture] : LISTS.sources;
  }

  function urlsFor(source) {
    if (source.local) return [chrome.runtime.getURL(source.path)];
    return LISTS.mirrors.map((mirror) => mirror + source.file);
  }

  // --- IndexedDB: one record per list ------------------------------------------
  // { id, hosts, urls, entries, publishedAt, fingerprint, etag, from }, with hosts and urls
  // stored as newline-joined text, which is far quicker to save and load than
  // an array of 60,000 strings.

  let dbPromise = null;

  function openDb() {
    if (!dbPromise) {
      dbPromise = new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, 1);
        request.onupgradeneeded = () => request.result.createObjectStore(STORE, { keyPath: 'id' });
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      dbPromise.catch(() => {
        dbPromise = null;
      });
    }
    return dbPromise;
  }

  async function dbRequest(mode, run) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE, mode);
      const request = run(transaction.objectStore(STORE));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  }

  const readList = (id) => dbRequest('readonly', (store) => store.get(id));
  const writeList = (record) => dbRequest('readwrite', (store) => store.put(record));

  // --- Status, for the popup -----------------------------------------------------
  // chrome.storage.local[LIST_STATUS_KEY] = {
  //   version,   bumped whenever the lists in use change; content scripts
  //              watch it and re-check their links
  //   sources: { [id]: { entries, ignored, publishedAt, checkedAt, error,
  //                      failures, nextAttemptAt, from } }
  // }

  async function readStatus() {
    const stored = await chrome.storage.local.get(LIST_STATUS_KEY);
    const status = stored[LIST_STATUS_KEY];
    return status && typeof status === 'object' ? status : { version: 0, sources: {} };
  }

  // --- Looking links up ----------------------------------------------------------

  // Built on first use after the worker wakes, and again after an update.
  let matcherPromise = null;

  async function loadMatcher() {
    const lists = [];
    for (const source of activeSources()) {
      const record = await readList(source.id);
      if (!record || !record.entries) continue;
      lists.push({
        id: source.id,
        name: source.name,
        category: source.category,
        publishedAt: record.publishedAt,
        hosts: new Set(record.hosts ? record.hosts.split('\n') : []),
        urls: new Set(record.urls ? record.urls.split('\n') : []),
      });
    }
    return { match: blocklist.createMatcher(lists), ready: lists.length > 0 };
  }

  function getMatcher() {
    if (!matcherPromise) {
      matcherPromise = loadMatcher();
      matcherPromise.catch(() => {
        matcherPromise = null;
      });
    }
    return matcherPromise;
  }

  async function lookup(urls) {
    const [{ match, ready }, status] = await Promise.all([getMatcher(), readStatus()]);
    const results = ready ? urls.map((url) => (typeof url === 'string' ? match(url) : null)) : [];
    return { ready, version: status.version, results };
  }

  // --- Downloading ----------------------------------------------------------------

  async function fetchList(url, etag) {
    const response = await fetch(url, {
      cache: 'no-store',
      credentials: 'omit', // No cookies: the request says nothing about the user.
      referrerPolicy: 'no-referrer',
      headers: etag ? { 'If-None-Match': etag } : {},
      signal: AbortSignal.timeout(LISTS.fetchTimeoutMs),
    });
    if (response.status === 304) return { status: 304 };
    return {
      status: response.status,
      text: response.ok ? await response.text() : '',
      etag: response.headers.get('etag'),
    };
  }

  function logIgnored(source, ignored) {
    if (!DEBUG || ignored.length === 0) return;
    console.debug(`[Tripwire lists] ${source.name}: ignored ${ignored.length} whole-host entries`);
    for (const { host, reason } of ignored.slice(0, MAX_IGNORED_LOGGED)) {
      console.debug(`[Tripwire lists]   ${host} (${reason})`);
    }
    if (ignored.length > MAX_IGNORED_LOGGED) {
      console.debug(`[Tripwire lists]   ...and ${ignored.length - MAX_IGNORED_LOGGED} more`);
    }
  }

  // Updates one list. Returns its new status entry and whether the list in
  // use changed. On failure the stored list is left exactly as it was.
  async function updateSource(source, previousState, force) {
    const now = Date.now();
    const record = await readList(source.id).catch(() => undefined);
    const previous = record
      ? {
          entries: record.entries,
          publishedAt: record.publishedAt,
          fingerprint: record.fingerprint,
          etag: record.etag,
          from: record.from,
        }
      : null;
    const installed = record
      ? { entries: record.entries, publishedAt: record.publishedAt, from: record.from }
      : { entries: 0, publishedAt: null, from: null };
    const ignoredBefore = (previousState && previousState.ignored) || 0;

    try {
      const result = await blocklist.updateFromMirrors({
        source,
        urls: urlsFor(source),
        previous,
        force,
        fetchList,
        now,
      });

      if (result.status === 'updated') {
        const { list } = result;
        await writeList({
          id: source.id,
          hosts: list.hosts.join('\n'),
          urls: list.urls.join('\n'),
          entries: list.entries,
          publishedAt: list.publishedAt,
          fingerprint: list.fingerprint,
          etag: list.etag,
          from: list.from,
        });
        logIgnored(source, list.ignored);
        if (DEBUG) console.debug(`[Tripwire lists] ${source.name}: ${list.entries} entries from ${list.from}`);
        return {
          changed: true,
          state: {
            entries: list.entries,
            ignored: list.ignored.length,
            publishedAt: list.publishedAt,
            checkedAt: now,
            error: null,
            failures: 0,
            nextAttemptAt: null,
            from: list.from,
          },
        };
      }

      // Unchanged. Remember a newer etag so the next check can be a cheap one.
      if (record && result.etag && (result.etag !== record.etag || result.from !== record.from)) {
        await writeList({ ...record, etag: result.etag, from: result.from });
      }
      if (DEBUG) console.debug(`[Tripwire lists] ${source.name}: unchanged${result.note ? ` (${result.note})` : ''}`);
      return {
        changed: false,
        state: { ...installed, ignored: ignoredBefore, checkedAt: now, error: null, failures: 0, nextAttemptAt: null },
      };
    } catch (error) {
      // A missing test list just means this isn't a source checkout.
      if (source.local && installed.entries === 0) return { changed: false, state: null };

      const failures = ((previousState && previousState.failures) || 0) + 1;
      const message = error && error.message ? error.message : String(error);
      console.warn(`[Tripwire lists] ${source.name}: update failed (${message}). Keeping the list already installed.`);
      return {
        changed: false,
        state: {
          ...installed,
          ignored: ignoredBefore,
          checkedAt: (previousState && previousState.checkedAt) || null,
          error: message,
          failures,
          nextAttemptAt: now + blocklist.retryDelayMinutes(failures) * MINUTE,
        },
      };
    }
  }

  // When a list should next be fetched: on its retry time after a failure,
  // otherwise one interval after its last successful check.
  function isDue(state, now) {
    if (!state) return true;
    if (state.error) return now >= (state.nextAttemptAt || 0);
    return now >= (state.checkedAt || 0) + LISTS.updateIntervalMinutes * MINUTE - MINUTE;
  }

  let updateInFlight = null;

  // Updates every list (or only those that are due) and saves the new status.
  function updateAll({ force = false, onlyDue = false } = {}) {
    if (updateInFlight) return updateInFlight;

    updateInFlight = (async () => {
      const status = await readStatus();
      const now = Date.now();
      let anyChanged = false;

      const sources = {};
      for (const source of activeSources()) {
        const before = status.sources[source.id];
        if (onlyDue && !isDue(before, now)) {
          sources[source.id] = before;
          continue;
        }
        const { state, changed } = await updateSource(source, before, force);
        if (state) sources[source.id] = state;
        anyChanged = anyChanged || changed;
      }

      const next = { version: status.version + (anyChanged ? 1 : 0), sources };
      if (anyChanged) matcherPromise = null;
      await chrome.storage.local.set({ [LIST_STATUS_KEY]: next });
      await scheduleRetry(next);
      return next;
    })().finally(() => {
      updateInFlight = null;
    });
    return updateInFlight;
  }

  // --- Scheduling -----------------------------------------------------------------

  async function ensureUpdateAlarm() {
    const existing = await chrome.alarms.get(UPDATE_ALARM);
    if (existing) return;
    chrome.alarms.create(UPDATE_ALARM, {
      delayInMinutes: LISTS.updateIntervalMinutes,
      periodInMinutes: LISTS.updateIntervalMinutes,
    });
  }

  // After a failure, a one-off alarm brings the worker back at the retry time
  // instead of waiting for the next regular update.
  async function scheduleRetry(status) {
    const times = Object.values(status.sources)
      .filter((state) => state && state.error && state.nextAttemptAt)
      .map((state) => state.nextAttemptAt);
    if (times.length === 0) {
      await chrome.alarms.clear(RETRY_ALARM);
      return;
    }
    chrome.alarms.create(RETRY_ALARM, { when: Math.max(Date.now() + MINUTE, Math.min(...times)) });
  }

  chrome.runtime.onInstalled.addListener(() => {
    ensureUpdateAlarm();
    updateAll();
  });

  chrome.runtime.onStartup.addListener(() => {
    ensureUpdateAlarm();
    updateAll({ onlyDue: true });
  });

  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === UPDATE_ALARM || alarm.name === RETRY_ALARM) updateAll({ onlyDue: true });
  });

  // Every time the worker starts: the alarm should exist, and if nothing was
  // ever downloaded (the install event was missed), start now.
  ensureUpdateAlarm();
  readStatus().then((status) => {
    if (Object.keys(status.sources).length === 0) updateAll();
  });

  // --- Messages -------------------------------------------------------------------

  let lastForcedAt = 0;

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || sender.id !== chrome.runtime.id) return false;

    if (message.type === MESSAGES.LOOKUP) {
      const urls = Array.isArray(message.urls) ? message.urls.slice(0, MAX_LOOKUP_BATCH) : [];
      lookup(urls).then(sendResponse, () => sendResponse({ ready: false, version: 0, results: [] }));
      return true; // Answered once the lists are loaded.
    }

    if (message.type === MESSAGES.UPDATE_LISTS) {
      const tooSoon = Date.now() - lastForcedAt < MIN_FORCED_GAP_MS;
      if (!tooSoon) lastForcedAt = Date.now();
      const done = tooSoon ? readStatus() : updateAll({ force: true });
      done.then(
        (status) => sendResponse({ status, tooSoon }),
        (error) => sendResponse({ status: null, error: String(error) }),
      );
      return true;
    }

    return false;
  });
})();
