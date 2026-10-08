// Tripwire options page.
//
// Lists what is stored in chrome.storage.sync: the default display mode, the
// sites with a mode of their own, and the trusted domains. Everything is
// saved as it is changed, and the page redraws when storage changes, whether
// from here, from the popup or from another device.
//
// Site names and domains are set as text, never as HTML.

(() => {
  'use strict';

  const { settings, trust } = Tripwire;
  const { MODES, MODE_DESCRIPTIONS, DEFAULT_MODE_CHOICES } = settings;

  const $ = (id) => document.getElementById(id);

  let stored = {};
  // After a removal: which list to put the keyboard back in, and where.
  let refocus = null;

  function el(tag, attributes = {}, ...children) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attributes)) {
      if (value === false || value === null || value === undefined) continue;
      if (name === 'class') node.className = value;
      else if (name.startsWith('on')) node.addEventListener(name.slice(2), value);
      else node.setAttribute(name, value === true ? '' : value);
    }
    node.append(...children.filter((child) => child !== false && child !== null && child !== undefined));
    return node;
  }

  function announce(text) {
    $('announce').textContent = text;
  }

  // --- Default mode -------------------------------------------------------------

  function renderDefaultMode() {
    const current = settings.resolveDefaultMode(stored[settings.DEFAULT_MODE_KEY]);
    const choices = DEFAULT_MODE_CHOICES.map((mode) =>
      el('label', {},
        el('input', { type: 'radio', name: 'default-mode', value: mode, checked: mode === current }),
        el('span', { class: 'row-main' },
          el('span', { class: 'row-name' }, mode === settings.DEFAULT_MODE ? `${MODES[mode]} (the usual setting)` : MODES[mode]),
          el('span', { class: 'row-note' }, MODE_DESCRIPTIONS[mode]))));

    const fieldset = $('default-mode');
    // Redrawing would take the keyboard off the radio that was just chosen.
    const shown = fieldset.querySelector('input:checked');
    if (shown && shown.value === current && fieldset.querySelectorAll('input').length === choices.length) return;
    fieldset.replaceChildren(fieldset.querySelector('legend'), ...choices);
  }

  $('default-mode').addEventListener('change', async (event) => {
    const mode = settings.resolveDefaultMode(event.target.value);
    await settings.saveDefaultMode(mode);
    announce(`Saved. Badges on pages: ${MODES[mode]}.`);
  });

  // --- Click-time warning ---------------------------------------------------------

  function renderClickWarning() {
    $('click-warning').checked = settings.resolveClickWarning(stored[settings.CLICK_WARNING_KEY]);
  }

  $('click-warning').addEventListener('change', async (event) => {
    const enabled = event.target.checked;
    await settings.saveClickWarning(enabled);
    announce(enabled ? 'Saved. Dangerous links show a warning first.' : 'Saved. Dangerous links open without a warning.');
  });

  // --- Lists with remove buttons --------------------------------------------------

  function renderList({ id, entries, row }) {
    const list = $(id);
    list.replaceChildren(...entries.map(row));
    list.hidden = entries.length === 0;
    $(`${id}-empty`).hidden = entries.length > 0;

    if (!refocus || refocus.id !== id) return;
    // Onto the row that took the removed one's place, or the one before it;
    // with the list now empty, onto the section's heading.
    const buttons = list.querySelectorAll('button');
    const target = buttons[Math.min(refocus.index, buttons.length - 1)] || $(`${id}-heading`);
    refocus = null;
    target.focus();
  }

  function removeButton({ id, index, label, announcement, remove }) {
    return el('button', {
      type: 'button',
      class: 'btn',
      'aria-label': label,
      onclick: async () => {
        refocus = { id, index };
        try {
          await remove();
          announce(announcement);
        } catch {
          refocus = null;
          announce('That could not be removed. Try again.');
        }
      },
    }, 'Remove');
  }

  function renderSites() {
    renderList({
      id: 'sites',
      entries: settings.listSiteModes(stored),
      row: ({ hostname, mode }, index) =>
        el('li', {},
          el('span', { class: 'row-main' },
            el('span', { class: 'row-name' }, hostname),
            el('span', { class: 'row-note' }, MODES[mode])),
          removeButton({
            id: 'sites',
            index,
            label: `Remove the setting for ${hostname}`,
            announcement: `Removed the setting for ${hostname}.`,
            remove: () => settings.saveSiteMode(hostname, ''),
          })),
    });
  }

  function renderTrusted() {
    const date = (addedAt) =>
      addedAt ? `Trusted on ${new Date(addedAt).toLocaleDateString(undefined, { dateStyle: 'medium' })}` : 'Trusted';
    renderList({
      id: 'trusted',
      entries: trust.listTrusted(stored),
      row: ({ domain, addedAt }, index) =>
        el('li', {},
          el('span', { class: 'row-main' },
            el('span', { class: 'row-name' }, domain),
            el('span', { class: 'row-note' }, date(addedAt))),
          removeButton({
            id: 'trusted',
            index,
            label: `Stop trusting ${domain}`,
            announcement: `${domain} is no longer trusted.`,
            remove: () => trust.remove(domain),
          })),
    });
  }

  function render() {
    renderDefaultMode();
    renderClickWarning();
    renderSites();
    renderTrusted();
  }

  async function reload() {
    try {
      stored = await chrome.storage.sync.get(null);
    } catch {
      // Storage unavailable: show what we have.
    }
    render();
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'sync') reload();
  });

  reload();
})();
