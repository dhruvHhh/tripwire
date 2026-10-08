// Tripwire service worker.
//
// Three jobs:
//   - keep the toolbar icon's count in step with what each tab's content
//     script found (content scripts can't call chrome.action themselves);
//   - keep the blocklists downloaded and answer lookups against them
//     (lists.js);
//   - open the welcome page the first time Tripwire is installed;
//   - open a new tab when the click-time warning's "Continue anyway" needs one.

importScripts('../lib/analyzer.js', '../lib/settings.js', '../lib/blocklist.js', '../lib/clickguard.js', 'lists.js');

const { MESSAGES, toolbarBadge, isFirstInstall, WELCOME_PAGE } = Tripwire.settings;

console.log('Tripwire service worker started');

// A first install only: not an update of Tripwire, and not a browser update.
chrome.runtime.onInstalled.addListener((details) => {
  if (!isFirstInstall(details)) return;
  chrome.tabs.create({ url: chrome.runtime.getURL(WELCOME_PAGE) }).catch(() => {});
});

// "Continue anyway" on a link that opens in a new tab or window. The tab is
// opened from here because Chrome's popup blocker applies to pages, not to
// this: the user has just asked for the tab, and it must open. Only the
// extension's own content scripts can send this message.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== MESSAGES.OPEN_LINK) return false;
  if (sender.id !== chrome.runtime.id) return false;

  const plan = Tripwire.clickguard.openPlan(message, sender);
  if (!plan) {
    sendResponse({ opened: false });
    return false;
  }
  const opening = plan.window ? chrome.windows.create(plan.window) : chrome.tabs.create(plan.tab);
  opening.then(
    () => sendResponse({ opened: true }),
    () => sendResponse({ opened: false }),
  );
  return true; // The reply comes once the tab exists.
});

chrome.runtime.onMessage.addListener((message, sender) => {
  if (!message || message.type !== MESSAGES.COUNTS) return;
  // Only tabs have a toolbar count; the sender's tab comes with the message,
  // so no "tabs" permission is needed.
  if (!sender.tab || typeof sender.tab.id !== 'number') return;

  const tabId = sender.tab.id;
  const { text, color, textColor } = toolbarBadge({
    dangerous: Number(message.dangerous) || 0,
    suspicious: Number(message.suspicious) || 0,
    pageListed: message.pageListed === true,
  });

  // The tab can close before these land; that's not an error worth reporting.
  const ignore = () => {};
  chrome.action.setBadgeText({ tabId, text }).catch(ignore);
  if (text) {
    chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(ignore);
    chrome.action.setBadgeTextColor({ tabId, color: textColor }).catch(ignore);
  }
});
