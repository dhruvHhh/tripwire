// Tripwire badge: the small dot drawn at a link's corner, and what its
// tooltip says.
//
// Badges live inside the overlay's closed shadow root (see overlay.js), never
// in the page's own DOM. Callers get a handle with setVerdict() rather than
// reaching into the element.

(() => {
  'use strict';

  const { splitDestination } = Tripwire.findings;

  const HEADLINES = {
    ok: 'No red flags found (not a guarantee)',
    suspicious: 'Suspicious link',
    dangerous: 'Likely dangerous link',
  };
  // A link that is "ok" only because the user trusts its domain.
  const TRUSTED_HEADLINE = 'Trusted domain';

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function createBadge() {
    const dot = element('span', 'tripwire-badge');
    dot.dataset.level = 'unknown';
    dot.hidden = true;

    let verdict = { level: 'unknown', reasons: [], url: '', trusted: false };

    function setVerdict({ level, reasons = [], url = '', trusted = false }) {
      verdict = { level, reasons, url, trusted };
      dot.dataset.level = level;
    }

    // Fills `container` with this badge's tooltip: the verdict, the reasons,
    // then where the link really goes. Reasons quote hostnames and link text
    // from the page, so everything goes in as text, never as HTML.
    function renderTooltip(container) {
      const { level, reasons, url, trusted } = verdict;
      container.dataset.level = level;

      const trustedOk = trusted && level === 'ok';
      const parts = [element('strong', 'tripwire-headline', trustedOk ? TRUSTED_HEADLINE : HEADLINES[level] || '')];

      if (reasons.length > 0) {
        // An "ok" link can still carry low-weight observations; label them so
        // they don't read as red flags.
        if (level === 'ok' && !trusted) parts.push(element('span', 'tripwire-label', 'Minor notes'));
        const list = element('ul');
        for (const reason of reasons) list.appendChild(element('li', '', reason));
        parts.push(list);
      }

      // The whole host, with the registrable domain (whose site it is) in bold.
      const { userinfo, subdomains, domain, port } = splitDestination(url);
      if (domain) {
        const destination = element('span', 'tripwire-destination');
        destination.append(userinfo + subdomains, element('strong', '', domain), port);
        parts.push(element('span', 'tripwire-label', 'Goes to'), destination);
      }

      container.replaceChildren(...parts);
    }

    return { element: dot, setVerdict, renderTooltip };
  }

  Tripwire.createBadge = createBadge;
})();
