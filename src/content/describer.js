// Tripwire's route for screen readers.
//
// The badges are drawn in an overlay that is hidden from assistive
// technology: they sit far from their links in DOM order, so read aloud they
// would be noise. Instead, a link marked dangerous gets an aria-describedby
// that points at a short description of the warning, so a screen reader says
// it when the link is reached.
//
// What this adds to the page, and nothing more:
//   - one <tripwire-notes> element per document or open shadow root that
//     holds such a link. It is display: none, so it takes no space and is not
//     read by itself; a hidden element can still be the target of
//     aria-describedby.
//   - one id on the link's aria-describedby. Ids the page put there stay, in
//     front of ours, and are left alone when ours is taken away again.
//
// The description has to live in the page's own tree: an id can't be
// referenced across a shadow boundary, so it can't go in Tripwire's closed
// overlay. The link's look, href, text and behaviour are not touched.

(() => {
  'use strict';

  const NOTES_TAG = 'tripwire-notes';
  const ATTRIBUTE = 'aria-describedby';
  const NOTES_INLINE_STYLE = 'display: none !important';

  function tokensOf(link) {
    return (link.getAttribute(ATTRIBUTE) || '').split(/\s+/).filter(Boolean);
  }

  function createDescriber() {
    // Unlikely to collide with an id the page uses, and different on every load.
    const idPrefix = `tripwire-note-${Math.random().toString(36).slice(2, 8)}-`;
    let nextId = 1;

    // Document or shadow root -> { container, notes: Map(text -> { id, element, uses }) }.
    // Weak, so a component the page throws away takes its notes with it.
    const byRoot = new WeakMap();
    // Link -> { root, text, id }.
    const applied = new WeakMap();

    function release(link, current) {
      applied.delete(link);

      const remaining = tokensOf(link).filter((token) => token !== current.id);
      if (remaining.length > 0) link.setAttribute(ATTRIBUTE, remaining.join(' '));
      else link.removeAttribute(ATTRIBUTE);

      const state = byRoot.get(current.root);
      const note = state && state.notes.get(current.text);
      if (!note) return;
      if (--note.uses > 0) return;
      note.element.remove();
      state.notes.delete(current.text);
      if (state.notes.size === 0) {
        state.container.remove();
        byRoot.delete(current.root);
      }
    }

    function noteFor(root, text) {
      let state = byRoot.get(root);
      if (!state) {
        const container = document.createElement(NOTES_TAG);
        container.hidden = true;
        container.style.cssText = NOTES_INLINE_STYLE;
        (root.nodeType === Node.DOCUMENT_NODE ? root.documentElement : root).appendChild(container);
        state = { container, notes: new Map() };
        byRoot.set(root, state);
      }

      let note = state.notes.get(text);
      if (!note) {
        const element = document.createElement('span');
        element.id = idPrefix + nextId++;
        element.textContent = text;
        state.container.appendChild(element);
        note = { id: element.id, element, uses: 0 };
        state.notes.set(text, note);
      }
      return note;
    }

    /**
     * Gives `link` the description `text`, or takes Tripwire's description
     * away if `text` is null. Safe to call again with the same text.
     */
    function describe(link, text) {
      const current = applied.get(link);
      if (current) {
        // Still in place, unless the page has moved the link or rewritten the
        // attribute since.
        const inPlace = link.getRootNode() === current.root && tokensOf(link).includes(current.id);
        if (current.text === text && inPlace) return;
        release(link, current);
      }
      if (!text) return;

      const root = link.getRootNode();
      const scoped = root.nodeType === Node.DOCUMENT_NODE || root.nodeType === Node.DOCUMENT_FRAGMENT_NODE;
      if (!link.isConnected || !scoped) return;

      const note = noteFor(root, text);
      note.uses++;
      link.setAttribute(ATTRIBUTE, [...tokensOf(link), note.id].join(' '));
      applied.set(link, { root, text, id: note.id });
    }

    return { describe };
  }

  Tripwire.NOTES_TAG = NOTES_TAG;
  Tripwire.createDescriber = createDescriber;
})();
