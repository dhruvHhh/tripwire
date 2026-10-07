// Tripwire popup.
//
// Shows what the content script found on the active tab and lets the user
// change the display mode. Settings are written straight to
// chrome.storage.sync; the content script is then asked to re-read them and
// reply with its new state, so the popup always shows what the page did.

(async () => {
  'use strict';

  const { settings } = Tripwire;
  const { MESSAGES, MODES, DEFAULT_MODE_CHOICES } = settings;

  const PAGE_ALERT_TITLES = {
    suspicious: 'This page itself looks suspicious',
    dangerous: 'This page itself looks dangerous',
  };

  const $ = (id) => document.getElementById(id);

  let tabId = null;
  // The content script's state, or null where it isn't running (browser
  // pages, the Web Store, tabs opened before the extension was loaded).
  let state = null;
  let defaultMode = settings.DEFAULT_MODE;

  async function ask(message) {
    if (tabId === null) return null;
    try {
      return (await chrome.tabs.sendMessage(tabId, message)) || null;
    } catch {
      return null;
    }
  }

  function fillSelect(select, options, value) {
    select.replaceChildren(
      ...options.map(([optionValue, label]) => {
        const option = document.createElement('option');
        option.value = optionValue;
        option.textContent = label;
        return option;
      }),
    );
    select.value = value;
  }

  // Everything from the page is untrusted text: set it with textContent only.
  function flaggedItem({ id, level, text, destination, reason }) {
    const item = document.createElement('li');
    const button = document.createElement('button');
    button.type = 'button';
    button.className = level;

    const dot = document.createElement('span');
    dot.className = 'dot';

    const linkText = document.createElement('span');
    linkText.className = 'link-text';
    linkText.textContent = text || '(no text)';

    const linkDestination = document.createElement('span');
    linkDestination.className = 'link-destination';
    linkDestination.textContent = destination;

    const linkReason = document.createElement('span');
    linkReason.className = 'link-reason';
    linkReason.textContent = reason;

    button.append(dot, linkText, linkDestination, linkReason);
    button.addEventListener('click', async () => {
      await ask({ type: MESSAGES.FOCUS_LINK, id });
      // Get out of the way so the highlighted link can be seen.
      window.close();
    });

    item.appendChild(button);
    return item;
  }

  function render() {
    if (state) defaultMode = state.defaultMode;
    const running = Boolean(state);
    const scanned = Boolean(state && state.counts);

    $('host').textContent = running ? state.hostname : '';
    $('unavailable').hidden = running;
    $('off-note').hidden = !(running && state.mode === 'off');

    // The page's own verdict
    const pageLevel = scanned ? state.pageVerdict.level : 'ok';
    const alert = $('page-alert');
    alert.hidden = !(pageLevel in PAGE_ALERT_TITLES);
    if (!alert.hidden) {
      alert.className = `alert ${pageLevel}`;
      $('page-alert-title').textContent = PAGE_ALERT_TITLES[pageLevel];
      $('page-alert-reason').textContent = state.pageVerdict.reasons[0] || '';
    }

    // Counts
    $('counts').hidden = !scanned;
    if (scanned) {
      const { scanned: total, dangerous, suspicious } = state.counts;
      $('count-scanned').textContent = total;
      $('count-dangerous').textContent = dangerous;
      $('count-suspicious').textContent = suspicious;
      $('count-dangerous').parentElement.classList.toggle('nonzero', dangerous > 0);
      $('count-suspicious').parentElement.classList.toggle('nonzero', suspicious > 0);
    }

    // Per-site mode and the one-off reveal
    $('site-controls').hidden = !running;
    if (running) {
      fillSelect(
        $('site-mode'),
        [['', `Use default (${MODES[defaultMode]})`], ...Object.entries(MODES)],
        state.siteMode || '',
      );

      // Nothing to reveal when every badge is already showing, or none can be.
      const reveal = $('reveal');
      reveal.hidden = state.mode === 'off' || state.mode === 'all';
      reveal.disabled = state.revealed;
      reveal.textContent = state.revealed
        ? 'Showing all badges until this page reloads'
        : 'Show badges on this page';
    }

    // Flagged links
    const flagged = scanned ? state.flagged : [];
    $('flagged').hidden = flagged.length === 0;
    $('flagged-list').replaceChildren(...flagged.map(flaggedItem));

    // Global default
    fillSelect(
      $('default-mode'),
      DEFAULT_MODE_CHOICES.map((mode) => [mode, MODES[mode]]),
      defaultMode,
    );
  }

  $('site-mode').addEventListener('change', async (event) => {
    await settings.saveSiteMode(state.hostname, event.target.value);
    state = await ask({ type: MESSAGES.SETTINGS_CHANGED });
    render();
  });

  $('default-mode').addEventListener('change', async (event) => {
    defaultMode = settings.resolveDefaultMode(event.target.value);
    await settings.saveDefaultMode(defaultMode);
    if (state) state = await ask({ type: MESSAGES.SETTINGS_CHANGED });
    render();
  });

  $('reveal').addEventListener('click', async () => {
    state = await ask({ type: MESSAGES.REVEAL });
    render();
  });

  // The active tab's id is available without the "tabs" permission; its URL
  // isn't, which is why the hostname comes from the content script.
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabId = tab && typeof tab.id === 'number' ? tab.id : null;

  state = await ask({ type: MESSAGES.GET_STATE });
  if (!state) defaultMode = await settings.loadDefaultMode().catch(() => settings.DEFAULT_MODE);
  render();
})();
