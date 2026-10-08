// The click-time warning's decisions, as pure functions:
//   - whether a click on a link is stopped for a warning (shouldWarn);
//   - what that click would have done, so "Continue anyway" can do the same
//     (dispositionOf, effectText);
//   - what a press on one of the warning's own controls is allowed to do
//     (controlAction);
//   - whether the warning is still intact on the page (integrityProblem);
//   - what the service worker opens when asked for a new tab (openPlan).
//
// The rules that matter most:
//   - Only links with a "dangerous" verdict are stopped. A link with no
//     verdict yet is never stopped, and nothing is stopped on a site that is
//     switched off or when the warning is turned off in the options.
//   - The warning's controls act only on real user input (event.isTrusted).
//     An event made by a page script does nothing.
//   - If the warning has been removed, hidden or covered, "Continue anyway"
//     means "Go back". Tampering can only ever cancel a navigation.

(() => {
  'use strict';

  // "Continue anyway" ignores presses this soon after the warning appears, so
  // the second half of a double-click can't land on it.
  const CONTINUE_ARM_MS = 500;

  // --- Is this click stopped? ----------------------------------------------------

  /**
   * @param {object} click
   * @param {boolean} click.enabled  the global "warn before dangerous links" setting
   * @param {string} click.mode  the site's display mode
   * @param {string|null} click.level  the link's verdict level, null if it has none yet
   * @param {string} click.type  'click', 'auxclick' or 'keydown'
   * @param {number} [click.button]  0 = main, 1 = middle
   * @param {string} [click.key]  for keydown
   * @param {boolean} [click.isTrusted]  event.isTrusted
   * @param {boolean} [click.defaultPrevented]  something already cancelled the event
   */
  function shouldWarn({ enabled, mode, level, type, button, key, isTrusted = true, defaultPrevented = false } = {}) {
    if (enabled === false || mode === 'off') return false;
    if (level !== 'dangerous') return false;
    // Already cancelled: the browser won't follow the link, so there is
    // nothing to warn about.
    if (defaultPrevented) return false;
    if (type === 'click') return button === 0;
    // Middle-click opens a link in a new tab. Other extra buttons don't follow links.
    if (type === 'auxclick') return button === 1;
    // Enter on a focused link. Stopping it here, before the browser turns it
    // into a click, also keeps it from the page's own key handlers. A key
    // event made by a script follows no link, so it is left alone.
    if (type === 'keydown') return key === 'Enter' && isTrusted === true;
    return false;
  }

  // --- What would the click have done? ---------------------------------------------

  const NAMED_TARGETS = new Set(['', '_self', '_top', '_parent']);

  /**
   * @param {object} click  the event's button and modifier keys, plus:
   * @param {string} [click.target]  the link's target, or the page's <base target>
   * @param {boolean} [click.hasDownload]  the link has a download attribute
   * @param {boolean} [click.sameOrigin]  the link stays on the page's origin.
   *   Chrome ignores `download` on links to another origin and opens them.
   * @returns {'same'|'named'|'foreground-tab'|'background-tab'|'new-window'|'download'}
   */
  function dispositionOf({
    type = 'click',
    button = 0,
    ctrlKey = false,
    metaKey = false,
    shiftKey = false,
    altKey = false,
    target = '',
    hasDownload = false,
    sameOrigin = false,
  } = {}) {
    if (hasDownload && sameOrigin) return 'download';

    const middle = type === 'auxclick' && button === 1;
    if (middle || ctrlKey || metaKey) return shiftKey ? 'foreground-tab' : 'background-tab';
    if (shiftKey) return 'new-window';
    if (altKey) return 'download';

    const name = String(target || '').trim().toLowerCase();
    if (name === '_blank') return 'foreground-tab';
    return NAMED_TARGETS.has(name) ? 'same' : 'named';
  }

  const EFFECTS = {
    same: 'If you continue, it opens in this tab.',
    named: 'If you continue, it opens in the tab or frame this page chose for it.',
    'foreground-tab': 'If you continue, it opens in a new tab.',
    'background-tab': 'If you continue, it opens in a new tab.',
    'new-window': 'If you continue, it opens in a new window.',
    download: 'If you continue, it downloads a file.',
  };

  function effectText(disposition) {
    return EFFECTS[disposition] || EFFECTS.same;
  }

  const opensElsewhere = (disposition) =>
    disposition === 'foreground-tab' || disposition === 'background-tab' || disposition === 'new-window';

  // "This link is listed as phishing", or the general heading.
  function headingFor(listing) {
    return listing && listing.category ? `This link is listed as ${listing.category}` : 'This link looks dangerous';
  }

  // --- The warning's own controls -----------------------------------------------------

  /**
   * What a press on one of the warning's controls does.
   *
   * @param {object} press
   * @param {'back'|'escape'|'outside'|'continue'|'toggle-address'} press.control
   * @param {boolean} press.isTrusted  event.isTrusted: made by the user, not by a script
   * @param {number} [press.sinceShownMs]  how long the warning has been open
   * @param {string|null} [press.problem]  integrityProblem()'s answer right now
   * @returns {'back'|'continue'|'toggle-address'|null}  null: ignored
   */
  function controlAction({ control, isTrusted, sinceShownMs = 0, problem = null } = {}) {
    if (isTrusted !== true) return null;
    if (control === 'back' || control === 'escape' || control === 'outside') return 'back';
    if (control === 'toggle-address') return 'toggle-address';
    if (control !== 'continue') return null;

    // A warning that has been tampered with can't vouch for what the user
    // saw: the press cancels the navigation instead.
    if (isTampering(problem)) return 'back';
    // Too soon, or the browser hasn't yet confirmed the button is on show.
    if (problem || !(sinceShownMs >= CONTINUE_ARM_MS)) return null;
    return 'continue';
  }

  // --- Is the warning still intact? -----------------------------------------------------

  /**
   * Checks what the page could have done to the open warning. Any answer but
   * null means "treat it as Go back": the navigation is cancelled, and
   * nothing is put back or shown again.
   *
   * @param {object} facts  read from the page by the content script
   * @param {boolean} facts.connected  the warning's element is still in the document
   * @param {boolean} facts.inPlace  and still where Tripwire put it
   * @param {boolean} facts.onTop  it is still in the browser's top layer
   * @param {string} facts.display  its computed styles
   * @param {string} facts.visibility
   * @param {number} facts.opacity
   * @param {{ left, top, right, bottom }|null} facts.box  where the dialog is drawn
   * @param {{ width, height }} facts.viewport
   * @param {boolean} facts.hit  a hit test on each button lands on that button
   * @param {boolean|null} facts.visible  the browser's own answer to "is the
   *   Continue button drawn, with nothing over it and no effects applied?"
   *   (IntersectionObserver v2). null while it hasn't answered yet.
   * @returns {null|'removed'|'moved'|'closed'|'hidden'|'offscreen'|'covered'|'unconfirmed'}
   */
  function integrityProblem({ connected, inPlace, onTop, display, visibility, opacity, box, viewport, hit, visible } = {}) {
    if (!connected) return 'removed';
    if (!inPlace) return 'moved';
    if (!onTop) return 'closed';
    if (display === 'none' || visibility !== 'visible' || !(Number(opacity) >= 1)) return 'hidden';

    const drawn = box && box.right - box.left >= 1 && box.bottom - box.top >= 1;
    if (!drawn) return 'hidden';
    const inView = viewport && box.left >= -1 && box.top >= -1 && box.right <= viewport.width + 1 && box.bottom <= viewport.height + 1;
    if (!inView) return 'offscreen';

    if (!hit || visible === false) return 'covered';
    // No answer from the browser yet: not a sign of tampering, but not
    // something to continue on either.
    if (visible !== true) return 'unconfirmed';
    return null;
  }

  // Problems that close the warning by themselves. "unconfirmed" doesn't: it
  // only means the browser hasn't answered yet.
  function isTampering(problem) {
    return Boolean(problem) && problem !== 'unconfirmed';
  }

  // --- Opening a new tab from the service worker ------------------------------------------

  /**
   * Turns a content script's request to open a link in a new tab or window
   * into arguments for chrome.tabs.create / chrome.windows.create, or null if
   * the request isn't one the worker should act on.
   *
   * Going through the worker keeps Chrome's popup blocker out of it: the user
   * has just pressed "Continue anyway", and the tab must open.
   */
  function openPlan(message, sender) {
    const tab = sender && sender.tab;
    if (!message || !tab || typeof tab.id !== 'number') return null;
    if (!opensElsewhere(message.disposition)) return null;

    let url;
    try {
      url = new URL(message.url);
    } catch {
      return null;
    }
    // Only web addresses. Chrome itself decides about every other kind of
    // link, which stay with the page.
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;

    if (message.disposition === 'new-window') {
      return { window: { url: url.href, incognito: tab.incognito === true } };
    }
    const plan = { url: url.href, active: message.disposition === 'foreground-tab', openerTabId: tab.id };
    if (typeof tab.windowId === 'number') plan.windowId = tab.windowId;
    if (typeof tab.index === 'number') plan.index = tab.index + 1;
    return { tab: plan };
  }

  const api = {
    CONTINUE_ARM_MS,
    shouldWarn,
    dispositionOf,
    effectText,
    opensElsewhere,
    headingFor,
    controlAction,
    integrityProblem,
    isTampering,
    openPlan,
  };

  globalThis.Tripwire = globalThis.Tripwire || {};
  globalThis.Tripwire.clickguard = api;

  if (typeof module !== 'undefined') module.exports = api;
})();
