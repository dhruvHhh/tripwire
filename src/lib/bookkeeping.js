// Tripwire bookkeeping helpers: what the scanner needs to keep its numbers
// and memory in check on pages that live for hours. Pure, so they run under
// Node's test runner as well as in the content script.

(() => {
  'use strict';

  const LEVELS = ['ok', 'suspicious', 'dangerous'];

  /**
   * Counts links as they come and go.
   *
   * `scanned` is the number of links being tracked. The per-level numbers are
   * distinct destinations: two links to the same address with the same verdict
   * count once, so a search result's title and URL line are one risky
   * destination, not two.
   */
  function createTally() {
    // level -> Map(destination -> number of links pointing there)
    const byLevel = new Map(LEVELS.map((level) => [level, new Map()]));
    let links = 0;

    function add(destination, level) {
      const destinations = byLevel.get(level);
      if (!destinations) return;
      destinations.set(destination, (destinations.get(destination) || 0) + 1);
      links++;
    }

    function remove(destination, level) {
      const destinations = byLevel.get(level);
      const count = destinations && destinations.get(destination);
      if (!count) return; // Never added: nothing to undo.
      if (count === 1) destinations.delete(destination);
      else destinations.set(destination, count - 1);
      links--;
    }

    function clear() {
      for (const destinations of byLevel.values()) destinations.clear();
      links = 0;
    }

    function summary() {
      return {
        scanned: links,
        ok: byLevel.get('ok').size,
        suspicious: byLevel.get('suspicious').size,
        dangerous: byLevel.get('dangerous').size,
      };
    }

    return { add, remove, clear, summary };
  }

  /**
   * A Map that forgets its least recently used entry once it holds
   * `maxEntries`, so a cache can't grow without limit on an endless feed.
   */
  function createBoundedCache(maxEntries) {
    const entries = new Map(); // Oldest first.

    function get(key) {
      if (!entries.has(key)) return undefined;
      const value = entries.get(key);
      // Move to the newest end.
      entries.delete(key);
      entries.set(key, value);
      return value;
    }

    function set(key, value) {
      entries.delete(key);
      if (entries.size >= maxEntries) entries.delete(entries.keys().next().value);
      entries.set(key, value);
    }

    return {
      get,
      set,
      clear: () => entries.clear(),
      get size() {
        return entries.size;
      },
    };
  }

  // True if two verdicts say the same thing, even if they are different objects.
  function sameVerdict(a, b) {
    if (a === b) return true;
    if (!a || !b) return false;
    return (
      a.level === b.level &&
      a.score === b.score &&
      a.reasons.length === b.reasons.length &&
      a.reasons.every((reason, index) => reason === b.reasons[index])
    );
  }

  const api = { createTally, createBoundedCache, sameVerdict };

  globalThis.Tripwire = globalThis.Tripwire || {};
  Object.assign(globalThis.Tripwire, api);

  if (typeof module !== 'undefined') module.exports = api;
})();
