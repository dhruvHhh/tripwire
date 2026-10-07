// Badge styles.
//
// The badge renders inside a closed Shadow DOM, so page CSS can't reach its
// internals and our CSS can't leak out. The host element itself still lives in
// the page's DOM, so the properties that decide its layout are applied inline
// with !important to beat page rules like `* { margin: 10px }` or
// `a + * { display: block }`.
//
// Everything else is reset by `:host { all: initial }` in the shadow sheet.
// Don't put `all` in the inline list: the browser expands it into every
// longhand, which adds about 11 KB of style attribute to each badge.

globalThis.Tripwire = globalThis.Tripwire || {};

Tripwire.styles = {
  HOST_INLINE_STYLE: [
    'display: inline-block !important',
    'position: static !important',
    'float: none !important',
    'width: auto !important',
    'height: auto !important',
    'vertical-align: middle !important',
    'margin: 0 0 0 4px !important',
    'padding: 0 !important',
    'border: 0 !important',
    'background: none !important',
    'line-height: 0 !important',
    'opacity: 1 !important',
    'visibility: visible !important',
    'transform: none !important',
    // The badge takes hover so its tooltip works. It sits after the link, not
    // inside it, so it never receives or changes the link's own clicks.
    'pointer-events: auto !important',
    'cursor: help !important',
    'user-select: none !important',
  ].join('; '),

  SHADOW_CSS: `
    :host {
      all: initial;
    }

    .tripwire-badge {
      display: inline-block;
      box-sizing: border-box;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      /* Grey until a verdict is set. */
      background: #9aa0a6;
      /* Light ring keeps the dot visible on dark backgrounds. */
      box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.85);
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
  `,
};
