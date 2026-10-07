// Tripwire geometry helpers: where a badge and its tooltip go, and which
// nearby links share one badge. Pure functions over plain
// { left, top, right, bottom } rects, so they run under Node's test runner as
// well as in the content script.

(() => {
  'use strict';

  // The badge straddles the top-right corner of the link's text: it reaches
  // this far left of the text's right edge, and rises this far above its top.
  const BADGE_INSET = 3;
  const BADGE_RISE = 6;

  const TOOLTIP_GAP = 8; // Between a badge and its tooltip.
  const TOOLTIP_MARGIN = 4; // Between the tooltip and the viewport's edge.

  // Shortest distance between two rects on the wider axis; 0 if they touch or
  // overlap.
  function rectGap(a, b) {
    const dx = Math.max(0, a.left - b.right, b.left - a.right);
    const dy = Math.max(0, a.top - b.bottom, b.top - a.bottom);
    return Math.max(dx, dy);
  }

  // True if two rects sit on the same line of text: they overlap vertically by
  // more than half of the shorter one.
  function onSameLine(a, b) {
    const overlap = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
    return overlap > Math.min(a.bottom - a.top, b.bottom - b.top) / 2;
  }

  /**
   * Top-left position for a badge of `size` px anchored to `rect`, in the same
   * coordinates as `rect`.
   *
   * The badge is kept inside the viewport's width, because a badge past the
   * right edge would give the page a horizontal scrollbar, and below its top.
   */
  function placeBadge(rect, viewportWidth, size) {
    return {
      x: Math.max(0, Math.min(rect.right - BADGE_INSET, viewportWidth - size)),
      y: Math.max(0, rect.top - BADGE_RISE),
    };
  }

  /**
   * Top-left position for a tooltip, in viewport coordinates.
   *
   * `target` is what the tooltip must not cover: `x` is the badge's left
   * edge, and `top`..`bottom` spans the badge and the line of link text it
   * marks. The tooltip goes below that, or above it when there is no room
   * below, and is kept inside the viewport.
   */
  function placeTooltip(target, tooltip, viewport) {
    const maxX = Math.max(TOOLTIP_MARGIN, viewport.width - tooltip.width - TOOLTIP_MARGIN);
    const x = Math.min(Math.max(TOOLTIP_MARGIN, target.x - TOOLTIP_GAP), maxX);

    const below = target.bottom + TOOLTIP_GAP;
    const above = target.top - TOOLTIP_GAP - tooltip.height;
    const fitsBelow = below + tooltip.height + TOOLTIP_MARGIN <= viewport.height;
    const y = fitsBelow || above < TOOLTIP_MARGIN ? below : above;
    return { x, y };
  }

  /**
   * Decides which links carry a badge when several nearby ones are the same
   * link, such as a search result's title and its URL line.
   *
   * @param {{ key: string, rect: object }[]} items  in document order; links
   *   with the same key are interchangeable (same href, same verdict).
   * @param {number} maxGap  links this close to their group share one badge.
   * @returns {boolean[]}  parallel to `items`: true for the link that gets the
   *   badge, which is the first of each group.
   */
  function pickGroupLeaders(items, maxGap) {
    const groupsByKey = new Map();

    return items.map(({ key, rect }) => {
      let groups = groupsByKey.get(key);
      if (!groups) {
        groups = [];
        groupsByKey.set(key, groups);
      }

      const group = groups.find((bounds) => rectGap(bounds, rect) <= maxGap);
      if (!group) {
        groups.push({ left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom });
        return true;
      }

      // Grow the group so a third link is measured against all of it.
      group.left = Math.min(group.left, rect.left);
      group.top = Math.min(group.top, rect.top);
      group.right = Math.max(group.right, rect.right);
      group.bottom = Math.max(group.bottom, rect.bottom);
      return false;
    });
  }

  const api = {
    BADGE_INSET,
    BADGE_RISE,
    rectGap,
    onSameLine,
    placeBadge,
    placeTooltip,
    pickGroupLeaders,
  };

  globalThis.Tripwire = globalThis.Tripwire || {};
  globalThis.Tripwire.geometry = api;

  if (typeof module !== 'undefined') module.exports = api;
})();
