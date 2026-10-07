// Badge styles.
//
// The badge renders inside a closed Shadow DOM, so page CSS can't reach its
// internals and our CSS can't leak out. The host element itself still lives in
// the page's DOM, so HOST_INLINE_STYLE is applied inline with !important to
// beat page rules like `* { margin: 10px }` or `a + * { display: block }`.

globalThis.Tripwire = globalThis.Tripwire || {};

Tripwire.styles = {
  HOST_INLINE_STYLE: [
    'all: initial !important',
    'display: inline-block !important',
    'vertical-align: middle !important',
    'margin: 0 0 0 4px !important',
    'padding: 0 !important',
    'line-height: 0 !important',
    'pointer-events: none !important',
    'user-select: none !important',
  ].join('; '),

  SHADOW_CSS: `
    .tripwire-badge {
      display: inline-block;
      box-sizing: border-box;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: #9aa0a6;
      /* Light ring keeps the dot visible on dark backgrounds. */
      box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.85);
    }

    .tripwire-badge[data-level="unknown"] {
      background: #9aa0a6;
    }
  `,
};
