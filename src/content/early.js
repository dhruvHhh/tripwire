// Tripwire's first content script: the listeners for the click-time warning.
//
// The manifest runs this file at document_start, before any of the page's own
// scripts. Listeners on the same target and phase run in the order they were
// added, so adding these to `window` in the capture phase, this early, puts
// them ahead of every listener the page can add: a click on a link reaches
// Tripwire before it reaches the page.
//
// The rest of Tripwire loads later, once the page has been parsed, and hands
// its handler over with Tripwire.early.setHandler(). Until then, and whenever
// the handler fails, events pass through untouched: a problem in Tripwire
// must never stop a page's links from working.
//
// What a page can still do first, because it happens before any click event:
//   - act on mousedown, pointerdown, touchstart or (for a mouse) mouseup;
//   - navigate from a script, a redirect or a form, none of which is a link
//     being followed.
// The context menu's "Open link in new tab", and dragging a link to the tab
// strip, are the browser's own actions and send the page no click at all.

(() => {
  'use strict';

  globalThis.Tripwire = globalThis.Tripwire || {};

  let handler = null;

  function onEvent(event) {
    if (!handler) return;
    try {
      handler(event);
    } catch {
      // Fail open: the event carries on as if Tripwire weren't here.
    }
  }

  // "click" covers the main button, with or without modifier keys.
  // "auxclick" is the middle button, which opens a link in a new tab.
  // "keydown" is Enter on a focused link, and Escape while a warning is open.
  for (const type of ['click', 'auxclick', 'keydown']) {
    window.addEventListener(type, onEvent, true);
  }

  Tripwire.early = {
    setHandler(next) {
      handler = typeof next === 'function' ? next : null;
    },
  };
})();
