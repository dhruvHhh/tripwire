// Tripwire badge: the small dot shown after a link.
//
// Each badge has a closed shadow root, so nothing outside this file can reach
// its internals. Callers get a handle with setVerdict() instead.

(() => {
  'use strict';

  const BADGE_TAG = 'tripwire-badge';

  const HEADLINES = {
    ok: 'No red flags found (not a guarantee)',
    suspicious: 'Suspicious link',
    dangerous: 'Likely dangerous link',
  };

  let sharedSheet = null;

  function getSharedSheet() {
    if (!sharedSheet) {
      sharedSheet = new CSSStyleSheet();
      sharedSheet.replaceSync(Tripwire.styles.SHADOW_CSS);
    }
    return sharedSheet;
  }

  function applyShadowStyles(root) {
    try {
      root.adoptedStyleSheets = [getSharedSheet()];
    } catch {
      const style = document.createElement('style');
      style.textContent = Tripwire.styles.SHADOW_CSS;
      root.appendChild(style);
    }
  }

  function formatTooltip(level, reasons) {
    const headline = HEADLINES[level];
    if (reasons.length === 0) return headline;

    const lines = reasons.map((reason) => `• ${reason}`);
    // An "ok" link can still carry low-weight observations; keep them clearly
    // separate from the headline so they don't read as red flags.
    if (level === 'ok') return [headline, '', 'Minor notes:', ...lines].join('\n');
    return [headline, ...lines].join('\n');
  }

  function createBadge() {
    const host = document.createElement(BADGE_TAG);
    host.style.cssText = Tripwire.styles.HOST_INLINE_STYLE;
    host.setAttribute('aria-hidden', 'true');

    const root = host.attachShadow({ mode: 'closed' });
    applyShadowStyles(root);

    const dot = document.createElement('span');
    dot.className = 'tripwire-badge';
    dot.dataset.level = 'unknown';
    root.appendChild(dot);

    function setVerdict(level, reasons = []) {
      dot.dataset.level = level;
      dot.title = formatTooltip(level, reasons);

      // Colour alone is invisible to screen readers, so warnings are announced.
      // "ok" badges stay hidden: announcing one after every link is just noise.
      if (level === 'ok') {
        host.setAttribute('aria-hidden', 'true');
        host.removeAttribute('role');
        host.removeAttribute('aria-label');
      } else {
        host.removeAttribute('aria-hidden');
        host.setAttribute('role', 'img');
        host.setAttribute('aria-label', `${HEADLINES[level]}: ${reasons.join('; ')}`);
      }
    }

    return { element: host, setVerdict };
  }

  Tripwire.createBadge = createBadge;
})();
