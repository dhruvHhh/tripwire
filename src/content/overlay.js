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
//
// Cost model: nothing here runs unless a link that wants a badge is on
// screen. Observers and the fallback poll are switched on and off to match,
// so a page with no badges to draw costs nothing.

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
  // The hit test is the one expensive step, and on some pages (thousands of
  // siblings in one container) it is very expensive. Each pass spends at most
  // this long on hit tests, always doing at least the minimum number. Links
  // that miss out keep their last answer and go to the front of the queue.
  const HIT_TEST_BUDGET_MS = 3;
  const MIN_HIT_TESTS = 12;
  const HIT_TESTS_PER_CLOCK_CHECK = 6;
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
  // DOM changes can move links. However fast they arrive, they cause at most
  // one repositioning pass per interval.
  const NUDGE_INTERVAL_MS = 100;
  // Attribute changes that commonly move or reveal things.
  const LAYOUT_ATTRIBUTES = ['class', 'style', 'hidden', 'open'];
  // Some layout changes fire no event at all (CSS-only animation, a :hover
  // rule that shifts content). This slow re-check catches them. It only runs
  // while a badge is drawn and the tab is visible.
  const FALLBACK_POLL_MS = 2000;

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

    const items = new Set(); // Every tracked link.
    const itemByLink = new WeakMap();
    // Links that want a badge and are on screen: the only ones a pass looks at.
    const candidates = new Set();
    let displayed = new Set(); // Items whose badge is currently showing.
    let filter = () => false; // Which items want a badge at all.
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

    let nudgeTimer = 0;
    let lastNudge = 0;
    let pollTimer = 0;
    let watchingLayout = false;

    let passNumber = 0;
    // Set by anything that may have moved or covered a link. Hit-test answers
    // older than the pass that picked it up count as stale.
    let stale = true;
    let freshFrom = 0;
    const stats = { passes: 0, positionMs: 0, hitTests: 0 };

    const hasWork = () => candidates.size > 0 || displayed.size > 0 || highlighted !== null;

    function schedule() {
      stale = true;
      if (!frame && !destroyed && hasWork()) frame = requestAnimationFrame(update);
    }

    function relayout() {
      layoutVersion++;
      schedule();
    }

    // For DOM changes, which can arrive in floods: one pass per interval.
    function nudge() {
      if (nudgeTimer || destroyed || !hasWork()) return;
      const wait = Math.max(0, NUDGE_INTERVAL_MS - (performance.now() - lastNudge));
      nudgeTimer = setTimeout(() => {
        nudgeTimer = 0;
        lastNudge = performance.now();
        schedule();
      }, wait);
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
        // The document, or the shadow root the link lives in.
        item.root = item.link.getRootNode();
      }
      if (!item.anchorOffset) return null;

      const { dx, dy, width, height } = item.anchorOffset;
      const left = box.left + dx;
      const top = box.top + dy;
      return { left, top, right: left + width, bottom: top + height, width, height };
    }

    // The cheap checks. Returns the anchor rect if the link is rendered with
    // its corner inside the viewport, else null.
    function locate(item) {
      const { link } = item;
      if (!link.isConnected) return null;

      const rect = anchorRect(item);
      if (!rect) return null;
      if (link.checkVisibility && !link.checkVisibility(VISIBILITY_OPTIONS)) return null;

      const x = rect.right - Math.min(PROBE_INSET, rect.width / 2);
      const y = rect.top + Math.min(PROBE_INSET, rect.height / 2);
      if (x < 0 || y < 0 || x >= viewport.width || y >= viewport.height) return null;
      return rect;
    }

    // The expensive check: is the link really what you'd see at its corner?
    // This is what catches a link scrolled out of a nested scroll box, or
    // covered by a sticky header, menu or dialog.
    function isUnobstructed(item, rect) {
      const x = rect.right - Math.min(PROBE_INSET, rect.width / 2);
      const y = rect.top + Math.min(PROBE_INSET, rect.height / 2);
      // Asked of the link's own root: from the document, everything inside a
      // shadow root looks like its host element.
      const { root } = item;
      const hit = root && root.elementFromPoint ? root.elementFromPoint(x, y) : null;
      return Boolean(hit && item.link.contains(hit));
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

    // --- Watchers that only run while they are needed -------------------------

    // Attribute changes anywhere in the document can move links, but watching
    // them is only worth it while there is a badge that could move.
    const layoutObserver = new MutationObserver(nudge);

    function syncWatchers() {
      const needsLayoutWatch = !destroyed && candidates.size > 0;
      if (needsLayoutWatch !== watchingLayout) {
        watchingLayout = needsLayoutWatch;
        if (needsLayoutWatch) {
          layoutObserver.observe(document, {
            subtree: true,
            attributes: true,
            attributeFilter: LAYOUT_ATTRIBUTES,
          });
        } else {
          layoutObserver.disconnect();
        }
      }

      const needsPoll =
        !destroyed && displayed.size > 0 && document.visibilityState === 'visible';
      if (needsPoll && !pollTimer) {
        pollTimer = setInterval(relayout, FALLBACK_POLL_MS);
      } else if (!needsPoll && pollTimer) {
        clearInterval(pollTimer);
        pollTimer = 0;
      }
    }

    // --- The pass: measure everything, then draw everything ------------------

    function update() {
      frame = 0;
      if (destroyed) return;
      const started = performance.now();
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

      passNumber++;
      if (stale) {
        stale = false;
        freshFrom = passNumber;
      }
      const located = [];
      for (const item of candidates) {
        const rect = locate(item);
        if (rect) {
          located.push({ item, rect, key: item.key });
        } else {
          item.lastRect = null;
          item.unobstructed = false;
          item.testedAt = 0; // Test it first when it comes back.
        }
      }

      // Hit tests, least recently tested first, until the budget runs out.
      located.sort((a, b) => a.item.testedAt - b.item.testedAt);
      const hitTestsStarted = performance.now();
      let tested = 0;
      for (const { item, rect } of located) {
        if (
          tested >= MIN_HIT_TESTS &&
          tested % HIT_TESTS_PER_CLOCK_CHECK === 0 &&
          performance.now() - hitTestsStarted > HIT_TEST_BUDGET_MS
        ) {
          break;
        }
        item.unobstructed = isUnobstructed(item, rect);
        item.testedAt = passNumber;
        tested++;
      }
      stats.hitTests += tested;
      // Links still holding a stale answer: come back for them next frame.
      const moreToTest = located.some(({ item }) => item.testedAt < freshFrom);

      const visible = [];
      for (const entry of located) {
        const { item, rect } = entry;
        if (item.unobstructed) {
          if (item.anchor === undefined) {
            item.anchor = isInFixedSubtree(item.link) ? 'viewport' : 'page';
          } else if (windowScrolled && item.lastRect) {
            // The window scrolled: a link that stayed put is fixed or stuck.
            const stayedPut =
              Math.abs(rect.left - item.lastRect.left) < 0.5 &&
              Math.abs(rect.top - item.lastRect.top) < 0.5;
            item.anchor = stayedPut ? 'viewport' : 'page';
          }
          visible.push(entry);
        }
        item.lastRect = rect;
      }

      // Links arrive in the order the page added them, not page order. Within
      // a group, the badge goes to the topmost (then leftmost) link.
      visible.sort((a, b) => a.rect.top - b.rect.top || a.rect.left - b.rect.left);
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
      syncWatchers();

      stats.passes++;
      stats.positionMs += performance.now() - started;
      // Not schedule(): nothing new happened, this only finishes the round.
      if (moreToTest && !frame && !destroyed) frame = requestAnimationFrame(update);
    }

    // --- Observers and events: everything funnels into schedule() -----------

    // Root is the viewport, and the observer accounts for clipping by scroll
    // containers, so "not intersecting" covers off-screen, display: none,
    // scrolled out of a nested box, and removed from the document.
    const visibilityObserver = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        const item = itemByLink.get(entry.target);
        if (!item || !item.wanted) continue;
        item.onScreen = entry.isIntersecting;
        if (item.onScreen) candidates.add(item);
        else candidates.delete(item);
      }
      syncWatchers();
      schedule();
    });

    // Fires when the page itself grows or shrinks (images loading, sections
    // expanding). Individual links are not observed: most are inline, which
    // never reports a size, and thousands of observations cost time on every
    // frame. DOM nudges and the fallback poll cover a link that resizes alone.
    const resizeObserver = new ResizeObserver(relayout);
    resizeObserver.observe(docElement);
    if (document.body) resizeObserver.observe(document.body);

    function onVisibilityChange() {
      syncWatchers();
      relayout();
    }

    const listenerOptions = { capture: true, passive: true };
    // Capture phase: scroll (like load and toggle) doesn't bubble, so this is
    // how scrolling inside any nested container reaches us.
    document.addEventListener('scroll', schedule, listenerOptions);
    document.addEventListener('transitionend', relayout, listenerOptions);
    document.addEventListener('animationend', relayout, listenerOptions);
    document.addEventListener('load', relayout, listenerOptions); // Images arriving.
    document.addEventListener('toggle', relayout, listenerOptions); // <details>, popovers.
    document.addEventListener('mousemove', onPointerMove, listenerOptions);
    document.addEventListener('visibilitychange', onVisibilityChange);
    docElement.addEventListener('mouseleave', onPointerLeave);
    window.addEventListener('resize', relayout, listenerOptions);
    if (document.fonts) document.fonts.addEventListener('loadingdone', relayout);

    // --- Public API ----------------------------------------------------------

    function setWanted(item, wanted) {
      if (wanted === item.wanted) return;
      item.wanted = wanted;
      if (wanted) {
        // The observer reports straight away whether the link is on screen.
        visibilityObserver.observe(item.link);
      } else {
        visibilityObserver.unobserve(item.link);
        item.onScreen = false;
        item.lastRect = null;
        item.unobstructed = false;
        item.testedAt = 0;
        candidates.delete(item);
        hide(item);
        displayed.delete(item);
      }
    }

    // Starts tracking a link and returns its handle. Whether it gets a badge
    // is up to the current filter.
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
        root: null,
        unobstructed: false, // Answer from the last hit test.
        testedAt: 0, // Pass number of that test; 0 = not tested since it appeared.
        lastRect: null,
        fixed: false,
        x: NaN, // Where the badge was last drawn, in its own coordinate system.
        y: NaN,
        viewX: 0, // The same position in viewport coordinates, for hover.
        viewY: 0,
        viewBottom: 0, // Bottom of the badge and its line of text.
      };
      items.add(item);
      itemByLink.set(link, item);
      setWanted(item, Boolean(filter(item)));
      return item;
    }

    // The link's verdict or contents changed.
    function updateItem(item, { level, reasons, key }) {
      if (!items.has(item)) return;
      item.level = level;
      item.reasons = reasons;
      item.key = key;
      item.anchorOffset = null; // Its text may have changed shape.
      if (item.badge) item.badge.setVerdict(level, reasons);
      if (tooltipItem === item) hideTooltip();
      setWanted(item, Boolean(filter(item)));
      syncWatchers();
      schedule();
    }

    // The link left the page.
    function remove(item) {
      if (!items.delete(item)) return;
      setWanted(item, false);
      itemByLink.delete(item.link);
      if (item.badge) item.badge.element.remove();
      if (hoveredItem === item) hoveredItem = null;
      if (tooltipItem === item) hideTooltip();
      syncWatchers();
    }

    // Chooses which links get a badge. Only those are observed, so a page of
    // green links costs nothing in "risky" mode.
    function setFilter(predicate) {
      filter = predicate;
      for (const item of items) setWanted(item, Boolean(filter(item)));
      syncWatchers();
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

    function getStats() {
      return {
        passes: stats.passes,
        positionMs: Math.round(stats.positionMs * 10) / 10,
        hitTests: stats.hitTests,
        tracked: items.size,
        onScreen: candidates.size,
        drawn: displayed.size,
        pollRunning: pollTimer !== 0,
        watchingLayout,
      };
    }

    function destroy() {
      destroyed = true;
      cancelAnimationFrame(frame);
      clearTimeout(hoverTimer);
      clearTimeout(nudgeTimer);
      syncWatchers(); // Stops the poll and the layout observer.
      visibilityObserver.disconnect();
      resizeObserver.disconnect();
      document.removeEventListener('scroll', schedule, listenerOptions);
      document.removeEventListener('transitionend', relayout, listenerOptions);
      document.removeEventListener('animationend', relayout, listenerOptions);
      document.removeEventListener('load', relayout, listenerOptions);
      document.removeEventListener('toggle', relayout, listenerOptions);
      document.removeEventListener('mousemove', onPointerMove, listenerOptions);
      document.removeEventListener('visibilitychange', onVisibilityChange);
      docElement.removeEventListener('mouseleave', onPointerLeave);
      window.removeEventListener('resize', relayout, listenerOptions);
      if (document.fonts) document.fonts.removeEventListener('loadingdone', relayout);
      host.remove();
    }

    return { add, update: updateItem, remove, setFilter, highlight, nudge, getStats, destroy };
  }

  Tripwire.OVERLAY_TAG = OVERLAY_TAG;
  Tripwire.createOverlay = createOverlay;
})();
