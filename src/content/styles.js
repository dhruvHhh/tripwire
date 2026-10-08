// Overlay, badge and tooltip styles.
//
// Everything Tripwire draws lives in one overlay element with a closed Shadow
// DOM, so page CSS can't reach the badges and our CSS can't leak out. The
// overlay host itself still sits in the page's DOM, so the properties that
// decide its layout are applied inline with !important to beat page rules
// like `* { position: relative }`.
//
// Everything else on the host is reset by `:host { all: initial }` in the
// shadow sheet. Don't put `all` in the inline list: the browser expands it
// into every longhand, which adds about 11 KB to the style attribute.
//
// Nothing in the overlay takes pointer events, so it can never be what a
// click lands on. Tooltips are driven by the pointer's position instead (see
// overlay.js).

globalThis.Tripwire = globalThis.Tripwire || {};

Tripwire.styles = (() => {
  const { theme } = Tripwire;

  // Must match the size geometry.placeBadge() is called with.
  const BADGE_SIZE = 9;

  // A zero-size box at the page's origin. Badges are positioned from it and
  // overflow it; it never takes clicks or space itself.
  const OVERLAY_INLINE_STYLE = [
    'display: block !important',
    'position: absolute !important',
    'top: 0 !important',
    'left: 0 !important',
    'width: 0 !important',
    'height: 0 !important',
    'margin: 0 !important',
    'padding: 0 !important',
    'border: 0 !important',
    'overflow: visible !important',
    'opacity: 1 !important',
    'visibility: visible !important',
    'transform: none !important',
    'filter: none !important',
    'z-index: 2147483647 !important',
    'pointer-events: none !important',
  ].join('; ');

  const SHADOW_CSS = `
    :host {
      all: initial;
    }

    /* Page-anchored by default: positioned in page coordinates, so the browser
       scrolls it with the document. */
    .tripwire-badge {
      position: absolute;
      top: 0;
      left: 0;
      box-sizing: border-box;
      width: ${BADGE_SIZE}px;
      height: ${BADGE_SIZE}px;
      border-radius: 50%;
      background: #9aa0a6;
      /* Light ring plus a faint shadow keeps the dot visible on any background. */
      box-shadow: 0 0 0 1.5px rgba(255, 255, 255, 0.92), 0 0 3px 1.5px rgba(0, 0, 0, 0.28);
      pointer-events: none;
    }

    /* For links that hold still while the page scrolls (fixed, or sticky while
       stuck): positioned in viewport coordinates instead. */
    .tripwire-badge.tripwire-fixed {
      position: fixed;
    }

    .tripwire-badge[hidden],
    .tripwire-tooltip[hidden],
    .tripwire-ring[hidden] {
      display: none;
    }

    .tripwire-badge[data-level="ok"] {
      background: #1e8e3e;
    }

    .tripwire-badge[data-level="suspicious"] {
      background: #f9ab00;
    }

    .tripwire-badge[data-level="dangerous"] {
      background: #d93025;
    }

    /* Zero-size marker for measuring where viewport coordinates start. */
    .tripwire-probe {
      position: fixed;
      top: 0;
      left: 0;
      width: 0;
      height: 0;
    }

    /* The tooltip uses the popup's colours (src/lib/theme.js), light or dark
       to match the browser, not the page. They are set on the tooltip itself,
       so a page's own custom properties can't leak into them. */
    .tripwire-tooltip {
      ${theme.declarations('light')}
      position: fixed;
      top: 0;
      left: 0;
      /* Above the badges of the links it happens to cover. */
      z-index: 1;
      box-sizing: border-box;
      max-width: min(340px, calc(100vw - 8px));
      padding: 9px 11px 10px;
      border: 1px solid var(--control-border);
      border-left: 4px solid var(--control-border);
      border-radius: 8px;
      background: var(--bg);
      box-shadow: 0 6px 22px rgba(0, 0, 0, 0.28);
      color: var(--text);
      font: 12.5px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      text-align: left;
      overflow-wrap: anywhere;
      pointer-events: none;
    }

    @media (prefers-color-scheme: dark) {
      .tripwire-tooltip {
        ${theme.declarations('dark')}
      }
    }

    .tripwire-tooltip[data-level="ok"] {
      border-left-color: var(--ok-mark);
    }

    .tripwire-tooltip[data-level="suspicious"] {
      border-left-color: var(--warn-mark);
    }

    .tripwire-tooltip[data-level="dangerous"] {
      border-left-color: var(--danger-mark);
    }

    .tripwire-headline {
      display: block;
      font-size: 13px;
      font-weight: 650;
    }

    .tripwire-tooltip[data-level="ok"] .tripwire-headline {
      color: var(--ok-text);
    }

    .tripwire-tooltip[data-level="suspicious"] .tripwire-headline {
      color: var(--warn-text);
    }

    .tripwire-tooltip[data-level="dangerous"] .tripwire-headline {
      color: var(--danger-text);
    }

    .tripwire-label {
      display: block;
      margin-top: 8px;
      color: var(--muted);
      font-size: 10.5px;
      font-weight: 650;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }

    .tripwire-tooltip ul {
      margin: 3px 0 0;
      padding: 0;
      list-style: none;
    }

    .tripwire-tooltip li {
      position: relative;
      margin: 2px 0 0;
      padding-left: 12px;
    }

    .tripwire-tooltip li::before {
      content: "";
      position: absolute;
      top: 0.62em;
      left: 1px;
      width: 4px;
      height: 4px;
      border-radius: 50%;
      background: var(--muted);
    }

    /* Where the link really goes: the whole host, registrable domain in bold. */
    .tripwire-destination {
      display: block;
      margin-top: 2px;
      color: var(--muted);
      font: 12px/1.45 ui-monospace, "Cascadia Mono", Consolas, monospace;
    }

    .tripwire-destination strong {
      color: var(--text);
      font-weight: 700;
    }

    /* Outline drawn around a link picked in the popup. */
    .tripwire-ring {
      position: fixed;
      top: 0;
      left: 0;
      box-sizing: border-box;
      border: 3px solid #1a73e8;
      border-radius: 6px;
      box-shadow: 0 0 0 4px rgba(26, 115, 232, 0.3);
      pointer-events: none;
      animation: tripwire-pulse 0.8s ease-in-out 3;
    }

    @keyframes tripwire-pulse {
      50% {
        box-shadow: 0 0 0 10px rgba(26, 115, 232, 0.12);
      }
    }

    @media (prefers-reduced-motion: reduce) {
      .tripwire-ring {
        animation: none;
      }
    }

    @media print {
      .tripwire-badge,
      .tripwire-tooltip,
      .tripwire-ring {
        display: none;
      }
    }
  `;

  // --- The click-time warning ---------------------------------------------------
  //
  // The warning has its own element and its own closed shadow root. Unlike the
  // overlay it does take clicks, and it is shown in the browser's top layer
  // (as a popover), above everything the page can stack with z-index.
  //
  // Its element is a plain <div>, not a custom element: a page can define a
  // custom element name and run code the moment such an element is added.
  // Every property a page rule could use to hide, move or distort it is set
  // inline with !important, which no page stylesheet can override.
  const WARNING_INLINE_STYLE = [
    'display: block !important',
    'position: fixed !important',
    'inset: 0 !important',
    'width: auto !important',
    'height: auto !important',
    'max-width: none !important',
    'max-height: none !important',
    'margin: 0 !important',
    'padding: 0 !important',
    'border: 0 !important',
    'background: transparent !important',
    'overflow: visible !important',
    'opacity: 1 !important',
    'visibility: visible !important',
    'transform: none !important',
    'translate: none !important',
    'rotate: none !important',
    'scale: none !important',
    'filter: none !important',
    'backdrop-filter: none !important',
    'clip-path: none !important',
    'mask: none !important',
    'mix-blend-mode: normal !important',
    'zoom: 1 !important',
    'contain: none !important',
    'content-visibility: visible !important',
    'animation: none !important',
    'transition: none !important',
    'z-index: 2147483647 !important',
    'pointer-events: auto !important',
  ].join('; ');

  const WARNING_CSS = `
    :host {
      all: initial;
    }

    .scrim {
      position: fixed;
      inset: 0;
      display: grid;
      place-items: center;
      box-sizing: border-box;
      padding: 16px;
      background: rgba(11, 12, 14, 0.62);
    }

    .cw {
      ${theme.declarations('light')}
      display: flex;
      flex-direction: column;
      box-sizing: border-box;
      width: 100%;
      max-width: 440px;
      max-height: 100%;
      overflow: hidden;
      border: 1px solid var(--control-border);
      border-radius: 12px;
      background: var(--bg);
      box-shadow: 0 18px 50px rgba(0, 0, 0, 0.45);
      color: var(--text);
      color-scheme: light;
      font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      text-align: left;
    }

    @media (prefers-color-scheme: dark) {
      .cw {
        ${theme.declarations('dark')}
        color-scheme: dark;
      }
    }

    .cw * {
      box-sizing: border-box;
    }

    /* :where() keeps these resets at zero specificity, so any class wins. */
    :where(.cw p, .cw h2, .cw ul) {
      margin: 0;
      padding: 0;
    }

    .cw ul {
      list-style: none;
    }

    :where(.cw button) {
      font: inherit;
      color: inherit;
    }

    /* :focus, not :focus-visible: "Go back" is focused by script when the
       warning opens, and the ring has to show however the link was activated. */
    .cw :focus {
      outline: 2px solid var(--focus);
      outline-offset: 2px;
      border-radius: 4px;
    }

    .cw-brand {
      display: flex;
      flex: none;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      background: var(--header-bg);
      color: var(--header-text);
      font-size: 13px;
      font-weight: 650;
    }

    .cw-brand canvas {
      display: block;
      width: 20px;
      height: 20px;
    }

    .cw-brand .where {
      margin-left: auto;
      color: var(--header-muted);
      font-size: 12px;
      font-weight: 500;
    }

    .cw-alert {
      display: flex;
      flex: none;
      align-items: center;
      gap: 10px;
      padding: 13px 16px;
      background: var(--danger-fill);
      color: var(--on-danger);
    }

    .cw-alert svg {
      flex: none;
      width: 26px;
      height: 26px;
    }

    .cw-title {
      font-size: 17px;
      font-weight: 650;
      line-height: 1.25;
    }

    /* The middle scrolls if the window is too short; the buttons stay put. */
    .cw-body {
      flex: 1 1 auto;
      min-height: 0;
      overflow-y: auto;
      padding: 4px 16px 14px;
    }

    .cw-label {
      margin-top: 12px;
      color: var(--muted);
      font-size: 11px;
      font-weight: 650;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }

    /* Monospace on purpose: it keeps 1 and l, 0 and O, rn and m apart. */
    .cw-domain {
      margin-top: 2px;
      font: 700 20px/1.25 ui-monospace, "Cascadia Mono", Consolas, monospace;
      overflow-wrap: anywhere;
    }

    .cw-address {
      margin-top: 6px;
      padding: 7px 10px;
      border-radius: 6px;
      background: var(--surface);
    }

    .cw-dest {
      color: var(--muted);
      font: 12px/1.45 ui-monospace, "Cascadia Mono", Consolas, monospace;
      overflow-wrap: anywhere;
    }

    .cw-dest b {
      color: var(--text);
      font-weight: 700;
    }

    .cw-dest--full {
      max-height: 112px;
      overflow-y: auto;
    }

    .cw-dest[hidden] {
      display: none;
    }

    .cw-show {
      margin-top: 4px;
      padding: 1px 2px;
      border: 0;
      background: none;
      font-size: 12.5px;
      font-weight: 650;
      text-decoration: underline;
      text-underline-offset: 2px;
      cursor: pointer;
    }

    .cw-reasons {
      margin-top: 3px;
    }

    .cw-reasons li {
      position: relative;
      padding-left: 12px;
      font-size: 13.5px;
      overflow-wrap: anywhere;
    }

    .cw-reasons li + li {
      margin-top: 3px;
    }

    .cw-reasons li::before {
      content: "";
      position: absolute;
      top: 0.62em;
      left: 1px;
      width: 4px;
      height: 4px;
      border-radius: 50%;
      background: var(--muted);
    }

    .cw-foot {
      flex: none;
      padding: 12px 16px 13px;
      border-top: 1px solid var(--line);
    }

    .cw-effect {
      margin-bottom: 10px;
      font-size: 13px;
    }

    .cw-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }

    .cw-btn {
      flex: 1 1 150px;
      padding: 9px 14px;
      border: 1px solid var(--control-border);
      border-radius: 6px;
      background: var(--bg);
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
    }

    .cw-btn:hover {
      background: var(--surface);
    }

    .cw .cw-btn--primary {
      border-color: var(--text);
      background: var(--text);
      color: var(--bg);
    }

    .cw-note {
      margin-top: 10px;
      color: var(--muted);
      font-size: 12px;
    }

    @media print {
      .scrim {
        display: none;
      }
    }
  `;

  // Puts a stylesheet in a shadow root. A constructed sheet is not subject to
  // the page's content security policy; the <style> fallback is for browsers
  // without one.
  function attach(root, css) {
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(css);
      root.adoptedStyleSheets = [sheet];
    } catch {
      const style = document.createElement('style');
      style.textContent = css;
      root.appendChild(style);
    }
  }

  return { BADGE_SIZE, OVERLAY_INLINE_STYLE, SHADOW_CSS, WARNING_INLINE_STYLE, WARNING_CSS, attach };
})();
