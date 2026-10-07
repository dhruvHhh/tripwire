// Tripwire overlay: draws every badge in one layer above the page.
//
// Nothing is inserted next to the links themselves. One <tripwire-overlay>
// element with a closed shadow root is appended to <html>, and each badge is
// positioned over the top-right corner of its link's text.
//
// Positioning uses two coordinate systems:
//   - "page": absolute, in page coordinates. The browser scrolls these with
//     the document, so they never lag behind a scroll.
//   - "viewport": position: fixed, in viewport coordinates, for links that
//     hold still while the window scrolls (fixed, or sticky while stuck).
// Each pass notices which kind a link currently is by comparing how far it
// moved with how far the window scrolled.
//
// The overlay takes no pointer events anywhere, so it can never swallow a
// click. Tooltips come from watching where the pointer is instead.

(() => {
  'use strict';

  const { styles, createBadge } = Tripwire;
  const { placeBadge, placeTooltip, pickGroupLeaders, onSameLine } = Tripwire.geometry;

  const OVERLAY_TAG = 'tripwire-overlay';
  // Links with the same href and verdict this close together share one badge.
  const GROUP_GAP = 48;
  // Smaller than this in either direction counts as not rendered.
  const MIN_SIZE = 2;
  // How far inside the anchor's top-right corner the "is it really visible"
  // hit test lands.
  const PROBE_INSET = 8;
  // How many of a link's text nodes to look at when finding its first line.
  const MAX_TEXT_NODES = 12;
  // Ignore position changes smaller than this, so rounding noise in page
  // coordinates doesn't make a badge shimmer between two pixels.
  const MOVE_THRESHOLD = 0.75;
  // The pointer counts as "on" a badge within this many pixels of it, and has
  // to rest there this long before the tooltip appears.
  const HOVER_SLOP = 4;
  const HOVER_DELAY_MS = 120;
  const HIGHLIGHT_MS = 2500;
  const HIGHLIGHT_PADDING = 4;
  // Layout can change without any event we listen for (script-driven
  // animation, content swapped in place). A slow re-check catches those.
  const DRIFT_CHECK_MS = 1000;

  const MEDIA_SELECTOR = 'img, picture, svg, video, canvas';
  // Both spellings of each option: the short names are the original ones.
  const VISIBILITY_OPTIONS = {
    checkOpacity: true,
    checkVisibilityCSS: true,
    opacityProperty: true,
    visibilityProperty: true,
  };

  const isRendered = (rect) => rect.width >= MIN_SIZE && rect.height >= MIN_SIZE;

  function createShadowStyles(root) {
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(styles.SHADOW_CSS);
      root.adoptedStyleSheets = [sheet];
    } catch {
      const style = document.createElement('style');
      style.textContent = styles.SHADOW_CSS;
      root.appendChild(style);
    }
  }

  // True if the link, or something it sits in, is position: fixed. Sticky
  // can't be told apart up front; update() catches it when the page scrolls.
  function isInFixedSubtree(link) {
    for (let node = link; node instanceof HTMLElement; node = node.offsetParent) {
      if (getComputedStyle(node).position === 'fixed') return true;
    }
    return false;
  }

  const textRange = document.createRange();

  // The rect the badge hangs off, in viewport coordinates: the first line of
  // the link's text. Many links are far bigger than their text (padded tabs,
  // buttons, whole cards), and a badge on the box's corner floats away from
  // the words it is about. Links with no text use their image, then their box.
  function findContentRect(link) {
    const walker = document.createTreeWalker(link, NodeFilter.SHOW_TEXT);
    let line = null;
    for (let seen = 0; seen < MAX_TEXT_NODES && walker.nextNode(); ) {
      const node = walker.currentNode;
      if (node.nodeValue.trim() === '') continue;
      seen++;

      textRange.selectNodeContents(node);
      for (const rect of textRange.getClientRects()) {
        if (!isRendered(rect)) continue;
        if (!line) {
          line = { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom };
        } else if (onSameLine(line, rect)) {
          line.left = Math.min(line.left, rect.left);
          line.top = Math.min(line.top, rect.top);
          line.right = Math.max(line.right, rect.right);
          line.bottom = Math.max(line.bottom, rect.bottom);
        } else {
          return line; // The text wrapped: the first line is complete.
        }
      }
    }
    if (line) return line;

    for (const media of link.querySelectorAll(MEDIA_SELECTOR)) {
      const rect = media.getBoundingClientRect();
      if (isRendered(rect)) return rect;
    }
    for (const rect of link.getClientRects()) {
      if (isRendered(rect)) return rect;
    }
    return null;
  }

  function createOverlay() {
    const docElement = document.documentElement;

    const host = document.createElement(OVERLAY_TAG);
    host.style.cssText = styles.OVERLAY_INLINE_STYLE;
    // The badges are far from their links in DOM order, so they'd be noise to
    // a screen reader. The popup lists flagged links instead.
    host.setAttribute('aria-hidden', 'true');

    const shadow = host.attachShadow({ mode: 'closed' });
    createShadowStyles(shadow);

    const fixedProbe = document.createElement('div');
    fixedProbe.className = 'tripwire-probe';

    const ring = document.createElement('div');
    ring.className = 'tripwire-ring';
    ring.hidden = true;

    const tooltip = document.createElement('div');
    tooltip.className = 'tripwire-tooltip';
    tooltip.hidden = true;

    shadow.append(fixedProbe, ring, tooltip);
    docElement.appendChild(host);

    const items = []; // Every tracked link, in document order.
    const itemByLink = new WeakMap();
    let displayed = new Set(); // Items whose badge is currently showing.
    let hasCandidates = false; // Any wanted link on screen at the last pass.
    let highlighted = null; // { link, until }
    let lastScroll = { x: window.scrollX, y: window.scrollY };
    let frame = 0;
    let destroyed = false;

    // Bumped whenever links may have reflowed, so cached anchors are redone.
    // A plain scroll moves links without reflowing them, so it doesn't bump.
    let layoutVersion = 0;

    // From the last pass, for placing the tooltip between passes.
    let viewport = { width: 0, height: 0 };
    let viewportOrigin = { left: 0, top: 0 };

    let pointer = null; // { x, y } in viewport coordinates, or null if outside.
    let hoveredItem = null; // Badge under the pointer.
    let tooltipItem = null; // Badge whose tooltip is showing.
    let tooltipSize = { width: 0, height: 0 };
    let hoverTimer = 0;

    function schedule() {
      if (!frame && !destroyed) frame = requestAnimationFrame(update);
    }

    function relayout() {
      layoutVersion++;
      schedule();
    }

    // --- Measuring (reads only) ---------------------------------------------

    // The anchor is found once per layout and remembered as an offset from the
    // link's own box, so a scroll pass costs one getBoundingClientRect per
    // link instead of walking its text again.
    function anchorRect(item) {
      const box = item.link.getBoundingClientRect();
      if (!item.anchorOffset || item.anchorVersion !== layoutVersion) {
        const content = findContentRect(item.link);
        item.anchorOffset = content && {
          dx: content.left - box.left,
          dy: content.top - box.top,
          width: content.right - content.left,
          height: content.bottom - content.top,
        };
        item.anchorVersion = layoutVersion;
      }
      if (!item.anchorOffset) return null;

      const { dx, dy, width, height } = item.anchorOffset;
      const left = box.left + dx;
      const top = box.top + dy;
      return { left, top, right: left + width, bottom: top + height, width, height };
    }

    // Returns the anchor rect if it can really be seen, else null. The hit
    // test is what catches a link scrolled out of a nested scroll box, or
    // covered by a sticky header, menu or dialog.
    function measure(item) {
      const { link } = item;
      if (!link.isConnected) return null;

      const rect = anchorRect(item);
      if (!rect) return null;
      if (link.checkVisibility && !link.checkVisibility(VISIBILITY_OPTIONS)) return null;

      const x = rect.right - Math.min(PROBE_INSET, rect.width / 2);
      const y = rect.top + Math.min(PROBE_INSET, rect.height / 2);
      if (x < 0 || y < 0 || x >= viewport.width || y >= viewport.height) return null;

      const hit = document.elementFromPoint(x, y);
      return hit && link.contains(hit) ? rect : null;
    }

    // --- Drawing (writes only) ----------------------------------------------

    function show(item, x, y) {
      if (!item.badge) {
        item.badge = createBadge();
        item.badge.setVerdict(item.level, item.reasons);
        shadow.appendChild(item.badge.element);
      }
      const { element } = item.badge;
      const fixed = item.anchor === 'viewport';

      if (item.fixed !== fixed) {
        element.classList.toggle('tripwire-fixed', fixed);
        item.fixed = fixed;
        item.x = NaN; // Different coordinate system: force a move.
      }
      if (!(Math.abs(x - item.x) < MOVE_THRESHOLD && Math.abs(y - item.y) < MOVE_THRESHOLD)) {
        element.style.transform = `translate(${Math.round(x)}px, ${Math.round(y)}px)`;
        item.x = x;
        item.y = y;
      }
      if (!item.shown) {
        element.hidden = false;
        item.shown = true;
      }
    }

    function hide(item) {
      if (!item.shown) return;
      item.badge.element.hidden = true;
      item.shown = false;
    }

    // --- Tooltip --------------------------------------------------------------

    function itemUnderPointer() {
      if (!pointer) return null;
      const reach = styles.BADGE_SIZE + HOVER_SLOP;
      for (const item of displayed) {
        const dx = pointer.x - item.viewX;
        const dy = pointer.y - item.viewY;
        if (dx >= -HOVER_SLOP && dx <= reach && dy >= -HOVER_SLOP && dy <= reach) return item;
      }
      return null;
    }

    function positionTooltip() {
      // Clear of both the badge and the line of text it marks.
      const { x, y } = placeTooltip(
        { x: tooltipItem.viewX, top: tooltipItem.viewY, bottom: tooltipItem.viewBottom },
        tooltipSize,
        viewport,
      );
      const left = Math.round(x - viewportOrigin.left);
      const top = Math.round(y - viewportOrigin.top);
      tooltip.style.transform = `translate(${left}px, ${top}px)`;
    }

    function showTooltip(item) {
      item.badge.renderTooltip(tooltip);
      tooltip.hidden = false;
      tooltipSize = { width: tooltip.offsetWidth, height: tooltip.offsetHeight };
      tooltipItem = item;
      positionTooltip();
    }

    function hideTooltip() {
      tooltip.hidden = true;
      tooltipItem = null;
    }

    // Called when the pointer moves and after every pass (badges can move
    // under a pointer that is holding still).
    function updateHover() {
      const item = itemUnderPointer();
      if (item === hoveredItem) {
        if (tooltipItem) positionTooltip();
        return;
      }
      hoveredItem = item;
      clearTimeout(hoverTimer);
      hideTooltip();
      if (item) {
        hoverTimer = setTimeout(() => {
          if (hoveredItem === item && item.shown) showTooltip(item);
        }, HOVER_DELAY_MS);
      }
    }

    function onPointerMove(event) {
      pointer = { x: event.clientX, y: event.clientY };
      if (displayed.size > 0 || hoveredItem) updateHover();
    }

    function onPointerLeave() {
      pointer = null;
      updateHover();
    }

    // --- The pass: measure everything, then draw everything ------------------

    function update() {
      frame = 0;
      if (destroyed) return;
      // Some pages rebuild <html>'s children; put the overlay back if so.
      if (!host.isConnected) docElement.appendChild(host);

      viewport = {
        width: Math.min(window.innerWidth, docElement.clientWidth || window.innerWidth),
        height: window.innerHeight,
      };
      // Measured, not assumed: stays right if the page offsets or transforms <html>.
      const pageOrigin = host.getBoundingClientRect();
      viewportOrigin = fixedProbe.getBoundingClientRect();

      const scroll = { x: window.scrollX, y: window.scrollY };
      const windowScrolled =
        Math.abs(scroll.x - lastScroll.x) + Math.abs(scroll.y - lastScroll.y) >= 1;
      lastScroll = scroll;

      const visible = [];
      hasCandidates = false;
      for (const item of items) {
        if (!item.wanted || !item.onScreen) continue;
        hasCandidates = true;

        const rect = measure(item);
        if (rect) {
          if (item.anchor === undefined) {
            item.anchor = isInFixedSubtree(item.link) ? 'viewport' : 'page';
          } else if (windowScrolled && item.lastRect) {
            // The window scrolled: a link that stayed put is fixed or stuck.
            const stayedPut =
              Math.abs(rect.left - item.lastRect.left) < 0.5 &&
              Math.abs(rect.top - item.lastRect.top) < 0.5;
            item.anchor = stayedPut ? 'viewport' : 'page';
          }
          visible.push({ item, rect, key: item.key });
        }
        item.lastRect = rect;
      }

      const leaders = pickGroupLeaders(visible, GROUP_GAP);

      let ringRect = null;
      if (highlighted) {
        if (performance.now() > highlighted.until || !highlighted.link.isConnected) {
          highlighted = null;
        } else {
          ringRect = highlighted.link.getBoundingClientRect();
        }
      }

      // Writes start here.
      const nowDisplayed = new Set();
      visible.forEach(({ item, rect }, index) => {
        if (!leaders[index]) return;
        const { x, y } = placeBadge(rect, viewport.width, styles.BADGE_SIZE);
        const origin = item.anchor === 'viewport' ? viewportOrigin : pageOrigin;
        item.viewX = x;
        item.viewY = y;
        item.viewBottom = Math.max(rect.bottom, y + styles.BADGE_SIZE);
        show(item, x - origin.left, y - origin.top);
        nowDisplayed.add(item);
      });
      for (const item of displayed) {
        if (!nowDisplayed.has(item)) hide(item);
      }
      displayed = nowDisplayed;

      if (ringRect) {
        const left = ringRect.left - viewportOrigin.left - HIGHLIGHT_PADDING;
        const top = ringRect.top - viewportOrigin.top - HIGHLIGHT_PADDING;
        ring.style.transform = `translate(${Math.round(left)}px, ${Math.round(top)}px)`;
        ring.style.width = `${Math.round(ringRect.width + HIGHLIGHT_PADDING * 2)}px`;
        ring.style.height = `${Math.round(ringRect.height + HIGHLIGHT_PADDING * 2)}px`;
        ring.hidden = false;
      } else {
        ring.hidden = true;
      }

      updateHover();
    }

    // --- Observers and events: everything funnels into schedule() -----------

    // Root is the viewport, and the observer accounts for clipping by scroll
    // containers, so "not intersecting" covers off-screen, display: none,
    // scrolled out of a nested box, and removed from the document.
    const visibilityObserver = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        const item = itemByLink.get(entry.target);
        if (item) item.onScreen = entry.isIntersecting;
      }
      schedule();
    });

    // Fires for block-level links that change size, and for the page itself
    // growing or shrinking (images loading, sections expanding). Inline links
    // have no box of their own to observe; the page-level observation and the
    // drift check cover them.
    const resizeObserver = new ResizeObserver(relayout);
    resizeObserver.observe(docElement);
    if (document.body) resizeObserver.observe(document.body);

    const listenerOptions = { capture: true, passive: true };
    // Capture phase: scroll doesn't bubble, so this is how scrolling inside
    // any nested container reaches us.
    document.addEventListener('scroll', schedule, listenerOptions);
    document.addEventListener('transitionend', relayout, listenerOptions);
    document.addEventListener('animationend', relayout, listenerOptions);
    document.addEventListener('mousemove', onPointerMove, listenerOptions);
    docElement.addEventListener('mouseleave', onPointerLeave);
    window.addEventListener('resize', relayout, listenerOptions);

    const driftTimer = setInterval(() => {
      if (!document.hidden && (hasCandidates || highlighted)) relayout();
    }, DRIFT_CHECK_MS);

    // --- Public API ----------------------------------------------------------

    // Starts tracking a link. Nothing is drawn until setFilter() wants it.
    function add(link, { level, reasons, key }) {
      const item = {
        link,
        level,
        reasons,
        key,
        wanted: false,
        onScreen: false,
        shown: false,
        badge: null, // Created the first time the badge is actually drawn.
        anchor: undefined, // 'page' | 'viewport', decided on first sight.
        anchorOffset: null,
        anchorVersion: -1,
        lastRect: null,
        fixed: false,
        x: NaN, // Where the badge was last drawn, in its own coordinate system.
        y: NaN,
        viewX: 0, // The same position in viewport coordinates, for hover.
        viewY: 0,
        viewBottom: 0, // Bottom of the badge and its line of text.
      };
      items.push(item);
      itemByLink.set(link, item);
    }

    // Chooses which links get a badge. Only those are observed, so a page of
    // green links costs nothing in "risky" mode.
    function setFilter(predicate) {
      for (const item of items) {
        const wanted = Boolean(predicate(item));
        if (wanted === item.wanted) continue;
        item.wanted = wanted;
        if (wanted) {
          visibilityObserver.observe(item.link);
          resizeObserver.observe(item.link);
        } else {
          visibilityObserver.unobserve(item.link);
          resizeObserver.unobserve(item.link);
          item.onScreen = false;
          item.lastRect = null;
          hide(item);
          displayed.delete(item);
        }
      }
      schedule();
    }

    // Draws a pulsing outline around a link for a moment.
    function highlight(link) {
      highlighted = { link, until: performance.now() + HIGHLIGHT_MS };
      // Hide and flush styles so the pulse restarts if one was already running.
      ring.hidden = true;
      void ring.offsetWidth;
      schedule();
      setTimeout(schedule, HIGHLIGHT_MS + 50);
    }

    function destroy() {
      destroyed = true;
      cancelAnimationFrame(frame);
      clearInterval(driftTimer);
      clearTimeout(hoverTimer);
      visibilityObserver.disconnect();
      resizeObserver.disconnect();
      document.removeEventListener('scroll', schedule, listenerOptions);
      document.removeEventListener('transitionend', relayout, listenerOptions);
      document.removeEventListener('animationend', relayout, listenerOptions);
      document.removeEventListener('mousemove', onPointerMove, listenerOptions);
      docElement.removeEventListener('mouseleave', onPointerLeave);
      window.removeEventListener('resize', relayout, listenerOptions);
      host.remove();
    }

    return { add, setFilter, highlight, destroy };
  }

  Tripwire.createOverlay = createOverlay;
})();
