// Tripwire content script.
// Step 1: put a neutral badge after every usable link on the page, once.

(() => {
  'use strict';

  const BADGE_TAG = 'tripwire-badge';
  const PROCESSED_ATTR = 'data-tripwire-processed';
  const SKIPPED_PROTOCOLS = new Set(['javascript:', 'mailto:', 'tel:']);

  // Link -> inner badge element, so later steps can update a badge's state
  // without reopening its closed shadow root.
  const badgeByLink = new WeakMap();

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

  function isUsableLink(link) {
    // SVG <a> elements match a[href] too, but an HTML badge can't render
    // inside an <svg>.
    if (!(link instanceof HTMLAnchorElement)) return false;

    // Never write into editable regions (email composers, rich-text editors),
    // or the badge would become part of the user's content.
    if (link.isContentEditable) return false;

    const raw = (link.getAttribute('href') || '').trim();
    if (raw === '' || raw.startsWith('#')) return false;

    let url;
    try {
      url = new URL(raw, document.baseURI);
    } catch {
      return false;
    }
    return !SKIPPED_PROTOCOLS.has(url.protocol);
  }

  function createBadge() {
    const host = document.createElement(BADGE_TAG);
    host.style.cssText = Tripwire.styles.HOST_INLINE_STYLE;
    host.setAttribute('aria-hidden', 'true');

    const root = host.attachShadow({ mode: 'closed' });
    applyShadowStyles(root);

    const badge = document.createElement('span');
    badge.className = 'tripwire-badge';
    badge.dataset.level = 'unknown';
    root.appendChild(badge);

    return { host, badge };
  }

  function badgeLink(link) {
    if (link.hasAttribute(PROCESSED_ATTR)) return false;
    link.setAttribute(PROCESSED_ATTR, '');

    if (!isUsableLink(link)) return false;

    const { host, badge } = createBadge();
    link.after(host);
    badgeByLink.set(link, badge);
    return true;
  }

  function scan(root = document) {
    const links = root.querySelectorAll(`a[href]:not([${PROCESSED_ATTR}])`);
    let added = 0;
    for (const link of links) {
      if (badgeLink(link)) added++;
    }
    return { checked: links.length, added };
  }

  const { checked, added } = scan();
  console.debug(`[Tripwire] checked ${checked} link(s), added ${added} badge(s)`);
})();
