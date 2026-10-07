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

    .tripwire-tooltip {
      position: fixed;
      top: 0;
      left: 0;
      box-sizing: border-box;
      max-width: min(340px, calc(100vw - 8px));
      padding: 8px 10px;
      border-left: 4px solid #9aa0a6;
      border-radius: 6px;
      background: #202124;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.35);
      color: #f1f3f4;
      font: 12px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif;
      text-align: left;
      overflow-wrap: anywhere;
      pointer-events: none;
    }

    .tripwire-tooltip[data-level="ok"] {
      border-left-color: #34a853;
    }

    .tripwire-tooltip[data-level="suspicious"] {
      border-left-color: #f9ab00;
    }

    .tripwire-tooltip[data-level="dangerous"] {
      border-left-color: #ea4335;
    }

    .tripwire-tooltip strong {
      display: block;
      font-weight: 600;
    }

    .tripwire-notes-label {
      display: block;
      margin-top: 6px;
      color: #bdc1c6;
    }

    .tripwire-tooltip ul {
      margin: 4px 0 0;
      padding: 0 0 0 16px;
    }

    .tripwire-tooltip li {
      margin: 2px 0 0;
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

  return { BADGE_SIZE, OVERLAY_INLINE_STYLE, SHADOW_CSS };
})();
