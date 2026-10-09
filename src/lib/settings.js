// Tripwire display settings: the modes, how they resolve, where they are
// stored, and the message names the popup, content script and service worker
// use to talk to each other.
//
// Scanning runs on every page unless the site's mode is "off". The mode only
// decides which badges are drawn.

(() => {
  'use strict';

  // Mode id -> label shown in the popup.
  const MODES = {
    risky: 'Risky only',
    all: 'Show all',
    click: 'Only when I click',
    off: 'Off for this site',
  };

  // One line each, for the options page.
  const MODE_DESCRIPTIONS = {
    risky: 'A badge on suspicious and dangerous links only.',
    all: 'A badge on every link, including the ones with no red flags.',
    click: 'No badges until you choose "Show all on this page" in the popup. The toolbar icon still counts risky links.',
    off: 'Nothing is checked on that site.',
  };

  const DEFAULT_MODE = 'risky';
  // "off" is a per-site choice, so it can't be the global default.
  const DEFAULT_MODE_CHOICES = ['risky', 'all', 'click'];

  // chrome.storage.sync layout: one key for the default, one key per site with
  // an override. Separate keys keep each item far below the per-item quota.
  const DEFAULT_MODE_KEY = 'defaultMode';
  const SITE_KEY_PREFIX = 'site:';
  // Whether clicking a dangerous link shows a warning first. On unless the
  // user has turned it off on the options page.
  const CLICK_WARNING_KEY = 'clickWarning';

  const MESSAGES = {
    GET_STATE: 'tripwire:get-state', // popup -> content: what did you find?
    SETTINGS_CHANGED: 'tripwire:settings-changed', // popup -> content: re-read storage
    REVEAL: 'tripwire:reveal', // popup -> content: show every badge until reload
    FOCUS_LINK: 'tripwire:focus-link', // popup -> content: scroll to a link
    COUNTS: 'tripwire:counts', // content -> service worker: toolbar numbers
    LOOKUP: 'tripwire:lookup', // content -> service worker: are these links on a blocklist?
    UPDATE_LISTS: 'tripwire:update-lists', // popup -> service worker: "Check now"
    OPEN_LINK: 'tripwire:open-link', // content -> service worker: open this link in a new tab
  };

  // Where the service worker keeps the blocklists' status, in
  // chrome.storage.local. The popup shows it; content scripts watch its
  // version to know when to check their links again.
  const LIST_STATUS_KEY = 'blocklistStatus';

  // Name of the connection an open popup holds to its tab's content script,
  // over which the content script pushes state as it changes.
  const POPUP_PORT = 'tripwire:popup';

  const TOOLBAR_COLORS = {
    dangerous: { color: '#d93025', textColor: '#ffffff' },
    suspicious: { color: '#f9ab00', textColor: '#202124' },
  };
  const MAX_TOOLBAR_COUNT = 99;

  function isMode(value) {
    return typeof value === 'string' && Object.hasOwn(MODES, value);
  }

  function siteKey(hostname) {
    return SITE_KEY_PREFIX + String(hostname).toLowerCase();
  }

  function resolveDefaultMode(defaultMode) {
    return DEFAULT_MODE_CHOICES.includes(defaultMode) ? defaultMode : DEFAULT_MODE;
  }

  // The site's override wins; otherwise the global default applies.
  function resolveMode({ defaultMode, siteMode } = {}) {
    return isMode(siteMode) ? siteMode : resolveDefaultMode(defaultMode);
  }

  // Whether a link at `level` gets a badge. `revealed` is the popup's one-off
  // "Show all on this page", which lasts until the page reloads.
  function shouldDisplay(level, mode, revealed = false) {
    if (mode === 'off') return false;
    if (revealed || mode === 'all') return true;
    if (mode === 'risky') return level === 'suspicious' || level === 'dangerous';
    return false;
  }

  // What the toolbar icon shows: red links if there are any, otherwise amber
  // ones, otherwise nothing.
  //
  // A page that is itself on a blocklist is always red, with "!" if it has no
  // red links to count.
  function toolbarBadge({ dangerous = 0, suspicious = 0, pageListed = false } = {}) {
    const level = dangerous > 0 || pageListed ? 'dangerous' : suspicious > 0 ? 'suspicious' : null;
    if (!level) return { text: '', color: null, textColor: null };

    const count = level === 'dangerous' ? dangerous : suspicious;
    let text = count > MAX_TOOLBAR_COUNT ? `${MAX_TOOLBAR_COUNT}+` : String(count);
    if (count === 0) text = '!';
    return { text, ...TOOLBAR_COLORS[level] };
  }

  // Anything but an explicit "off" means on: a missing or damaged value must
  // not quietly switch the warning off.
  function resolveClickWarning(value) {
    return value !== false;
  }

  async function load(hostname) {
    const key = siteKey(hostname);
    const stored = await chrome.storage.sync.get([DEFAULT_MODE_KEY, CLICK_WARNING_KEY, key]);
    return { defaultMode: stored[DEFAULT_MODE_KEY], siteMode: stored[key], clickWarning: stored[CLICK_WARNING_KEY] };
  }

  function saveClickWarning(enabled) {
    return enabled === false
      ? chrome.storage.sync.set({ [CLICK_WARNING_KEY]: false })
      : chrome.storage.sync.remove(CLICK_WARNING_KEY);
  }

  async function loadDefaultMode() {
    const stored = await chrome.storage.sync.get(DEFAULT_MODE_KEY);
    return resolveDefaultMode(stored[DEFAULT_MODE_KEY]);
  }

  function saveDefaultMode(mode) {
    return chrome.storage.sync.set({ [DEFAULT_MODE_KEY]: resolveDefaultMode(mode) });
  }

  // Passing a non-mode (such as "") removes the override.
  function saveSiteMode(hostname, mode) {
    const key = siteKey(hostname);
    return isMode(mode) ? chrome.storage.sync.set({ [key]: mode }) : chrome.storage.sync.remove(key);
  }

  // The sites with a mode of their own in a dump of chrome.storage.sync, by
  // name. For the options page.
  function listSiteModes(stored) {
    return Object.entries(stored || {})
      .filter(([key, mode]) => key.startsWith(SITE_KEY_PREFIX) && key.length > SITE_KEY_PREFIX.length && isMode(mode))
      .map(([key, mode]) => ({ hostname: key.slice(SITE_KEY_PREFIX.length), mode }))
      .sort((a, b) => a.hostname.localeCompare(b.hostname));
  }

  // Whether chrome.runtime.onInstalled is reporting a first install, the only
  // time the welcome page opens. Updates and browser updates are not.
  function isFirstInstall(details) {
    return Boolean(details) && details.reason === 'install';
  }

  const WELCOME_PAGE = 'src/welcome/welcome.html';

  const api = {
    MODES,
    MODE_DESCRIPTIONS,
    DEFAULT_MODE,
    DEFAULT_MODE_CHOICES,
    DEFAULT_MODE_KEY,
    CLICK_WARNING_KEY,
    MESSAGES,
    LIST_STATUS_KEY,
    POPUP_PORT,
    isMode,
    siteKey,
    resolveDefaultMode,
    resolveMode,
    shouldDisplay,
    toolbarBadge,
    load,
    loadDefaultMode,
    saveDefaultMode,
    saveSiteMode,
    resolveClickWarning,
    saveClickWarning,
    listSiteModes,
    isFirstInstall,
    WELCOME_PAGE,
  };

  globalThis.Tripwire = globalThis.Tripwire || {};
  globalThis.Tripwire.settings = api;

  if (typeof module !== 'undefined') module.exports = api;
})();
