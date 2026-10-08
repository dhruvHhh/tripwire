// Tripwire service worker.
//
// Two jobs:
//   - keep the toolbar icon's count in step with what each tab's content
//     script found (content scripts can't call chrome.action themselves);
//   - keep the blocklists downloaded and answer lookups against them
//     (lists.js).

importScripts('../lib/analyzer.js', '../lib/settings.js', '../lib/blocklist.js', 'lists.js');

const { MESSAGES, toolbarBadge } = Tripwire.settings;

console.log('Tripwire service worker started');

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
