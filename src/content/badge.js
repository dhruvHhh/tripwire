// Tripwire badge: the small dot drawn at a link's corner, and what its
// tooltip says.
//
// Badges live inside the overlay's closed shadow root (see overlay.js), never
// in the page's own DOM. Callers get a handle with setVerdict() rather than
// reaching into the element.

(() => {
  'use strict';

  const HEADLINES = {
    ok: 'No red flags found (not a guarantee)',
    suspicious: 'Suspicious link',
    dangerous: 'Likely dangerous link',
  };

  function createBadge() {
    const element = document.createElement('span');
    element.className = 'tripwire-badge';
    element.dataset.level = 'unknown';
    element.hidden = true;

    let verdict = { level: 'unknown', reasons: [] };

    function setVerdict(level, reasons = []) {
      verdict = { level, reasons };
      element.dataset.level = level;
    }

    // Fills `container` with this badge's tooltip. Reasons quote hostnames and
    // link text from the page, so everything goes in as text, never as HTML.
    function renderTooltip(container) {
      const { level, reasons } = verdict;
      container.dataset.level = level;

      const headline = document.createElement('strong');
      headline.textContent = HEADLINES[level] || '';
      container.replaceChildren(headline);
      if (reasons.length === 0) return;

      // An "ok" link can still carry low-weight observations; label them so
      // they don't read as red flags.
      if (level === 'ok') {
        const label = document.createElement('span');
        label.className = 'tripwire-notes-label';
        label.textContent = 'Minor notes:';
        container.appendChild(label);
      }

      const list = document.createElement('ul');
      for (const reason of reasons) {
        const item = document.createElement('li');
        item.textContent = reason;
        list.appendChild(item);
      }
      container.appendChild(list);
    }

    return { element, setVerdict, renderTooltip };
  }

  Tripwire.createBadge = createBadge;
})();
