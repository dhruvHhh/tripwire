// The click-time warning: the box shown over the page when a dangerous link
// is activated, with "Go back" and "Continue anyway".
//
// This file draws it and guards it. Deciding when to show it, and following
// the link afterwards, is content.js's job; every decision made here goes
// through the pure functions in lib/clickguard.js.
//
// The warning sits in the page, so the page can attack it. The defences:
//   - Its controls act only on real user input (event.isTrusted). They are
//     inside a closed shadow root, so a page can't reach them anyway; this is
//     the second lock.
//   - It is shown in the browser's top layer, above anything a page can
//     position with z-index, and unaffected by filters or opacity on <html>.
//   - While it is open it is checked several times a second, and whenever its
//     element changes: still in the document, still where Tripwire put it,
//     still in the top layer, still visible, its buttons still what a click
//     would land on, and (asking the browser, via IntersectionObserver v2)
//     nothing drawn over "Continue anyway". If any of that fails, the warning
//     closes as "Go back". Tampering can cancel a navigation; it can never
//     cause one. Nothing is put back or shown again.
//   - "Continue anyway" ignores presses in the first half second, so the
//     second half of a double-click can't land on it.

(() => {
  'use strict';

  const { styles, clickguard, findings } = Tripwire;

  const WARNING_ATTR = 'data-tripwire-warning';
  const CHECK_INTERVAL_MS = 200;
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const ALERT_ICON_PATH = 'M12 2.5 22.8 21H1.2L12 2.5Zm-1.15 6.7v5.9h2.3V9.2h-2.3Zm0 7.5v2.3h2.3v-2.3h-2.3Z';
  const LOGO_SIZE = 48;

  // The browser's own occlusion check. Without it the other checks still run.
  const canTrackVisibility =
    typeof IntersectionObserverEntry === 'function' && 'isVisible' in IntersectionObserverEntry.prototype;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  // The logo, decoded once from the text in logo.js. Painted on a canvas so
  // that no file is loaded: see tools/make-icons.js for why.
  let logo = null;
  function paintLogo(canvas) {
    try {
      if (!logo) {
        const bytes = Uint8Array.from(atob(Tripwire.LOGO_PNG_BASE64), (char) => char.charCodeAt(0));
        logo = createImageBitmap(new Blob([bytes], { type: 'image/png' }));
      }
      logo.then((bitmap) => canvas.getContext('2d').drawImage(bitmap, 0, 0, LOGO_SIZE, LOGO_SIZE)).catch(() => {});
    } catch {
      // No logo: the bar still says "Tripwire".
    }
  }

  function alertIcon() {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS(SVG_NS, 'path');
    path.setAttribute('fill', 'currentColor');
    path.setAttribute('fill-rule', 'evenodd');
    path.setAttribute('d', ALERT_ICON_PATH);
    svg.appendChild(path);
    return svg;
  }

  // The address, with the registrable domain in bold. `clip` cuts what
  // follows the host; the host itself is always whole.
  function addressLine(parts, className, clip) {
    const rest = clip ? findings.clipRest(parts.rest) : { text: parts.rest, clipped: false };
    const line = el('p', className);
    line.append(
      parts.scheme + parts.userinfo + parts.subdomains,
      parts.domain ? el('b', '', parts.domain) : '',
      parts.port + rest.text + (rest.clipped ? '…' : ''),
    );
    return line;
  }

  function createWarning() {
    // The open warning, or null.
    let current = null;

    // --- Building ---------------------------------------------------------------
    // Everything from the page (address, reasons) goes in as text.

    function build({ heading, url, reasons, effect }) {
      const host = document.createElement('div');
      host.setAttribute(WARNING_ATTR, '');
      host.setAttribute('popover', 'manual');
      host.style.cssText = styles.WARNING_INLINE_STYLE;
      const shadow = host.attachShadow({ mode: 'closed' });
      styles.attach(shadow, styles.WARNING_CSS);

      const title = el('h2', 'cw-title', heading);
      title.id = 'title';

      const brand = el('div', 'cw-brand');
      const canvas = document.createElement('canvas');
      canvas.width = LOGO_SIZE;
      canvas.height = LOGO_SIZE;
      canvas.setAttribute('aria-hidden', 'true');
      paintLogo(canvas);
      brand.append(canvas, el('span', '', 'Tripwire'), el('span', 'where', 'Link warning'));

      const alert = el('div', 'cw-alert');
      alert.append(alertIcon(), title);

      const parts = findings.splitDestination(url);
      const domain = el('p', 'cw-domain', parts.domain || url.split(':')[0] + ': link');
      domain.id = 'destination';

      const address = el('div', 'cw-address');
      const isLong = findings.clipRest(parts.rest).clipped;
      const short = addressLine(parts, 'cw-dest', true);
      address.appendChild(short);
      let full = null;
      let toggle = null;
      if (isLong) {
        full = addressLine(parts, 'cw-dest cw-dest--full', false);
        full.hidden = true;
        full.tabIndex = 0; // It scrolls, so the keyboard has to be able to reach it.
        toggle = el('button', 'cw-show', 'Show full address');
        toggle.type = 'button';
        toggle.setAttribute('aria-expanded', 'false');
        address.append(full, toggle);
      }

      const reasonList = el('ul', 'cw-reasons');
      for (const reason of reasons) reasonList.appendChild(el('li', '', reason));

      const body = el('div', 'cw-body');
      body.append(el('p', 'cw-label', 'This link goes to'), domain, address);
      if (reasons.length > 0) body.append(el('p', 'cw-label', 'Why it is flagged'), reasonList);

      const effectLine = el('p', 'cw-effect', effect);
      effectLine.id = 'effect';
      const back = el('button', 'cw-btn cw-btn--primary', 'Go back');
      back.type = 'button';
      const proceed = el('button', 'cw-btn', 'Continue anyway');
      proceed.type = 'button';
      const actions = el('div', 'cw-actions');
      actions.append(back, proceed);
      const foot = el('div', 'cw-foot');
      foot.append(effectLine, actions, el('p', 'cw-note', 'You can turn this warning off in Tripwire’s options.'));

      const dialog = el('div', 'cw');
      dialog.setAttribute('role', 'alertdialog');
      dialog.setAttribute('aria-modal', 'true');
      dialog.setAttribute('aria-labelledby', 'title');
      dialog.setAttribute('aria-describedby', 'destination effect');
      dialog.append(brand, alert, body, foot);

      const scrim = el('div', 'scrim');
      scrim.appendChild(dialog);
      shadow.appendChild(scrim);

      return { host, shadow, scrim, dialog, back, proceed, short, full, toggle };
    }

    // --- Guarding ------------------------------------------------------------------

    function facts(state) {
      const { host, shadow, container, dialog, back, proceed } = state;
      const root = host.getRootNode();
      const style = getComputedStyle(host);
      const box = dialog.getBoundingClientRect();

      // A click on the middle of each button must land on that button: on
      // our element as the page sees it, and on the button inside it.
      const lands = (button) => {
        const rect = button.getBoundingClientRect();
        const x = rect.left + rect.width / 2;
        const y = rect.top + rect.height / 2;
        return (
          typeof root.elementFromPoint === 'function' &&
          root.elementFromPoint(x, y) === host &&
          shadow.elementFromPoint(x, y) === button
        );
      };

      return {
        connected: host.isConnected,
        inPlace: host.parentNode === container,
        onTop: host.matches(':popover-open'),
        display: style.display,
        visibility: style.visibility,
        opacity: Number(style.opacity),
        box: { left: box.left, top: box.top, right: box.right, bottom: box.bottom },
        viewport: { width: window.innerWidth, height: window.innerHeight },
        hit: lands(back) && lands(proceed),
        visible: state.visible,
      };
    }

    function problemNow(state) {
      try {
        return clickguard.integrityProblem(facts(state));
      } catch {
        return 'removed'; // Couldn't even look: treat as tampering.
      }
    }

    function teardown(state) {
      clearInterval(state.timer);
      for (const observer of state.observers) observer.disconnect();
      document.removeEventListener('visibilitychange', state.recheck);
      try {
        if (state.host.matches(':popover-open')) state.host.hidePopover();
      } catch {
        // Already closed or removed.
      }
      state.host.remove();
    }

    // Closes the warning. `outcome` is 'back' or 'continue'.
    function finish(outcome) {
      const state = current;
      if (!state) return;
      current = null;
      teardown(state);
      if (outcome === 'continue') state.onContinue();
      else state.onBack();
    }

    function watch(state) {
      // Closes the warning if the page has interfered with it.
      const recheck = () => {
        if (current !== state) return;
        // A background tab isn't drawn, so there is nothing to look at, and
        // nobody to press "Continue anyway" either.
        if (document.visibilityState !== 'visible') return;
        if (clickguard.isTampering(problemNow(state))) finish('back');
      };
      state.recheck = recheck;
      state.timer = setInterval(recheck, CHECK_INTERVAL_MS);
      document.addEventListener('visibilitychange', recheck);

      // Any change to our element's attributes, and any change to what its
      // parent contains, is looked at straight away.
      const mutations = new MutationObserver(recheck);
      mutations.observe(state.host, { attributes: true });
      mutations.observe(state.container, { childList: true });
      state.observers.push(mutations);
      state.host.addEventListener('toggle', recheck);

      if (canTrackVisibility) {
        // Reports whether the button is really on show: fully drawn, nothing
        // over it, no opacity, filter or distortion applied by anything.
        const visibility = new IntersectionObserver(
          (entries) => {
            const latest = entries[entries.length - 1];
            state.visible = latest.isIntersecting && latest.isVisible;
            recheck();
          },
          { threshold: 1, trackVisibility: true, delay: 100 },
        );
        visibility.observe(state.proceed);
        state.observers.push(visibility);
      } else {
        state.visible = true;
      }
    }

    // --- Controls ------------------------------------------------------------------

    function press(control, event) {
      const state = current;
      if (!state) return;
      const action = clickguard.controlAction({
        control,
        isTrusted: event.isTrusted,
        sinceShownMs: performance.now() - state.shownAt,
        problem: control === 'continue' ? problemNow(state) : null,
      });
      if (action === 'back') finish('back');
      else if (action === 'continue') finish('continue');
      else if (action === 'toggle-address') toggleAddress(state);
    }

    function toggleAddress({ short, full, toggle }) {
      const showFull = full.hidden;
      full.hidden = !showFull;
      short.hidden = showFull;
      toggle.setAttribute('aria-expanded', String(showFull));
      toggle.textContent = showFull ? 'Show less' : 'Show full address';
    }

    // Tab stays inside the warning.
    function trapTab(state, event) {
      if (event.key !== 'Tab' || !event.isTrusted) return;
      const stops = [state.full, state.toggle, state.back, state.proceed].filter((node) => node && !node.hidden);
      const at = stops.indexOf(state.shadow.activeElement);
      const next = event.shiftKey ? at - 1 : at + 1;
      event.preventDefault();
      stops[(next + stops.length) % stops.length].focus();
    }

    function wire(state) {
      state.back.addEventListener('click', (event) => press('back', event));
      state.proceed.addEventListener('click', (event) => press('continue', event));
      if (state.toggle) state.toggle.addEventListener('click', (event) => press('toggle-address', event));
      // A click on the dimmed page around the box.
      state.scrim.addEventListener('click', (event) => {
        if (event.target === state.scrim) press('outside', event);
      });
      state.dialog.addEventListener('keydown', (event) => trapTab(state, event));
    }

    // --- Public ----------------------------------------------------------------------

    /**
     * Shows the warning. Returns false, having changed nothing, if it can't
     * be shown here; the caller then lets the click through.
     *
     * @param {object} request
     * @param {Element} request.container  where the warning's element goes:
     *   <html>, or the page's own modal dialog if the link is inside one
     *   (everything outside a modal dialog can't be clicked)
     * @param {string} request.heading
     * @param {string} request.url  the address that will be followed
     * @param {string[]} request.reasons
     * @param {string} request.effect  what "Continue anyway" will do
     * @param {() => void} request.onBack
     * @param {() => void} request.onContinue
     */
    function show({ container, heading, url, reasons, effect, onBack, onContinue }) {
      if (current) return false;
      let state = null;
      try {
        state = {
          ...build({ heading, url, reasons, effect }),
          container,
          onBack,
          onContinue,
          shownAt: performance.now(),
          visible: null, // Not known until the browser reports.
          observers: [],
          timer: 0,
          recheck: null,
        };
        container.appendChild(state.host);
        state.host.showPopover();

        // If it isn't properly up right now, don't pretend: no warning, and
        // the click goes ahead as it would without Tripwire.
        if (clickguard.isTampering(problemNow(state))) throw new Error('warning could not be shown');

        wire(state);
        watch(state);
        current = state;
        state.back.focus({ preventScroll: true });
        return true;
      } catch {
        if (state) {
          try {
            teardown(state);
          } catch {
            // Nothing more to undo.
          }
        }
        current = null;
        return false;
      }
    }

    // Escape, from content.js's early listener (the page can't swallow it there).
    function escape(event) {
      press('escape', event);
    }

    const supported = typeof HTMLElement.prototype.showPopover === 'function';

    return {
      supported,
      show,
      escape,
      isOpen: () => current !== null,
      // Whether an event happened on the open warning itself.
      owns: (event) => current !== null && event.target === current.host,
    };
  }

  Tripwire.WARNING_ATTR = WARNING_ATTR;
  Tripwire.createWarning = createWarning;
})();
