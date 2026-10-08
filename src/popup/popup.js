// Tripwire popup.
//
// Shows what the content script found on the active tab, lets the user change
// the display mode, and is where a domain gets trusted. Settings and trusted
// domains are written straight to chrome.storage.sync; the content script
// watches that storage and pushes its new state back over a connection, so
// the popup always shows what the page did.
//
// Everything that comes from the page (link text, addresses, reasons) is
// untrusted: it is only ever set as text, never as HTML.

(async () => {
  'use strict';

  const { settings, findings, trust, blocklist } = Tripwire;
  const { MESSAGES, MODES, DEFAULT_MODE_CHOICES } = settings;

  // Rows shown before "Show N more", and links shown in a group before "Show all".
  const VISIBLE_ROWS = 3;
  const VISIBLE_MEMBERS = 10;
  const MAX_PATH_LENGTH = 40;

  const LEVEL_WORDS = { dangerous: 'Dangerous', suspicious: 'Suspicious' };
  const STATUS_ICONS = { clean: '#i-check', neutral: '#i-info' };
  const SVG_NS = 'http://www.w3.org/2000/svg';

  const $ = (id) => document.getElementById(id);

  let tabId = null;
  // The content script's state, or null where it isn't running (browser
  // pages, the Web Store, tabs opened before the extension was loaded).
  let state = null;
  let defaultMode = settings.DEFAULT_MODE;

  // What the user has opened in the list. Kept here, not in the DOM, because
  // the list is redrawn whenever the page reports a change.
  const expanded = new Set(); // Row keys.
  const allMembersShown = new Set(); // Group row keys.
  let allRowsShown = false;
  let confirming = null; // Key of the row asking "trust a listed domain?".
  let lastDrawn = '';

  async function ask(message) {
    if (tabId === null) return null;
    try {
      return (await chrome.tabs.sendMessage(tabId, message)) || null;
    } catch {
      return null;
    }
  }

  // --- Small builders -----------------------------------------------------------

  // el('button', { class: 'btn', onclick: fn }, 'Text', child). `false` and
  // null attributes and children are skipped. Strings become text nodes.
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

  function icon(id) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', id);
    svg.appendChild(use);
    return svg;
  }

  function announce(text) {
    $('announce').textContent = text;
  }

  function fillSelect(select, options, value) {
    select.replaceChildren(...options.map(([optionValue, label]) => el('option', { value: optionValue }, label)));
    select.value = value;
  }

  // --- Flagged links --------------------------------------------------------------

  async function showOnPage(id) {
    await ask({ type: MESSAGES.FOCUS_LINK, id });
    // Get out of the way so the highlighted link can be seen.
    window.close();
  }

  function toggle(set, key) {
    if (set.has(key)) set.delete(key);
    else set.add(key);
    renderFindings();
  }

  // A row's key ends in its level, and trusting a listed domain changes the
  // level (red to amber, and back). These find the same row afterwards.
  const LEVEL_IN_KEY = /\n(dangerous|suspicious)(?=$|\|)/;
  const atOtherLevel = (key) =>
    key.replace(LEVEL_IN_KEY, (_, level) => `\n${level === 'dangerous' ? 'suspicious' : 'dangerous'}`);

  async function setTrust(domain, trusted, rowKey) {
    confirming = null;
    // Keep the row open, and in view, wherever the change moves it.
    if (expanded.has(rowKey)) expanded.add(atOtherLevel(rowKey));
    allRowsShown = true;
    try {
      await (trusted ? trust.add(domain) : trust.remove(domain));
      announce(
        trusted
          ? `${domain} is now trusted. You can undo this in Options.`
          : `${domain} is no longer trusted.`,
      );
    } catch {
      announce('That could not be saved. Try again.');
    }
    // The page looks at its links again and sends the result; until then,
    // show what we have.
    renderFindings();
  }

  // "Trust this domain", or the way back, for a row.
  function trustControls(rowKey, domain, trusted) {
    if (!domain) return [];
    if (trusted) {
      return [
        el('button', { type: 'button', class: 'btn', 'data-focus': `${rowKey}|trust`, onclick: () => setTrust(domain, false, rowKey) },
          'Stop trusting this domain'),
      ];
    }
    const start = () => {
      if (trust.needsConfirmation(domain, state.listedDomains)) {
        confirming = rowKey;
        renderFindings();
        focusKey(`${rowKey}|cancel`);
      } else {
        setTrust(domain, true, rowKey);
      }
    };
    return [
      el('button', { type: 'button', class: 'btn', 'data-focus': `${rowKey}|trust`, onclick: start }, 'Trust this domain'),
    ];
  }

  // A blocklist match is never overridden without the user saying so twice.
  function confirmPanel(rowKey, domain) {
    const cancel = () => {
      confirming = null;
      renderFindings();
      focusKey(`${rowKey}|trust`);
    };
    return el('div', { class: 'confirm', role: 'group', 'aria-label': `Trust ${domain}?` },
      el('p', {},
        el('b', {}, domain),
        ' has an address on a blocklist. If you trust it, its listed links are shown as suspicious instead of dangerous, with the blocklist match still stated. Its other links are no longer flagged.'),
      el('div', { class: 'actions' },
        el('button', { type: 'button', class: 'btn', 'data-focus': `${rowKey}|cancel`, onclick: cancel }, 'Cancel'),
        el('button', { type: 'button', class: 'btn', 'data-focus': `${rowKey}|trust`, onclick: () => setTrust(domain, true, rowKey) }, 'Trust anyway')));
  }

  function destination(url) {
    const { scheme, userinfo, subdomains, domain, port, rest } = findings.splitDestination(url);
    const { text, clipped } = findings.clipRest(rest);
    return el('p', { class: 'dest' },
      scheme + userinfo + subdomains,
      domain ? el('b', {}, domain) : null,
      port + text + (clipped ? '…' : ''));
  }

  // What a row calls its destination: the registrable domain, or the kind of
  // link when there is no host (a data: link, for one).
  function shortDestination(url) {
    const { domain } = findings.splitDestination(url);
    return domain || `${String(url).split(':')[0]}: link`;
  }

  function linkRow(row) {
    const open = expanded.has(row.key);
    const text = row.text || '(no text)';
    const panelId = `more-${row.id}`;
    const domain = trust.domainOf(row.url);

    const item = el('li', { class: `entry entry--${row.level}${open ? ' is-open' : ''}` },
      el('button', { type: 'button', class: 'entry-main', 'data-focus': `${row.key}|main`, onclick: () => showOnPage(row.id) },
        el('span', { class: `dot dot--${row.level}`, 'aria-hidden': 'true' }),
        el('span', { class: 'entry-text' }, text),
        el('span', { class: 'entry-meta' }, el('span', { class: 'level' }, LEVEL_WORDS[row.level]), ` · ${shortDestination(row.url)}`),
        el('span', { class: 'entry-reason' }, row.reasons[0] || ''),
        el('span', { class: 'sr-only' }, '. Scroll to it on the page.')),
      el('button', {
        type: 'button',
        class: 'entry-toggle',
        'aria-expanded': String(open),
        'aria-controls': panelId,
        'aria-label': `Details for ${text}`,
        'data-focus': `${row.key}|toggle`,
        onclick: () => toggle(expanded, row.key),
      }, icon('#i-chevron')));

    if (open) {
      item.appendChild(el('div', { class: 'entry-more', id: panelId },
        el('p', { class: 'more-label' }, 'Why it is flagged'),
        el('ul', { class: 'reasons' },
          ...row.reasons.map((reason) => el('li', { class: reason === trust.TRUSTED_REASON ? 'trusted' : false }, reason))),
        el('p', { class: 'more-label' }, 'Really goes to'),
        destination(row.url),
        confirming === row.key
          ? confirmPanel(row.key, domain)
          : el('div', { class: 'actions' },
            el('button', { type: 'button', class: 'btn', 'data-focus': `${row.key}|show`, onclick: () => showOnPage(row.id) }, 'Show on page'),
            ...trustControls(row.key, domain, row.trusted))));
    }
    return item;
  }

  // One row for every link whose only reason is the warning on the page itself.
  function groupRow(row) {
    const open = expanded.has(row.key);
    const panelId = `more-group-${row.level}`;
    const showAll = allMembersShown.has(row.key);
    const members = showAll ? row.members : row.members.slice(0, VISIBLE_MEMBERS);
    const unlisted = row.count - row.members.length; // Beyond what the page sends.

    const item = el('li', { class: `entry entry--${row.level} entry--group${open ? ' is-open' : ''}` },
      el('button', {
        type: 'button',
        class: 'entry-main',
        'aria-expanded': String(open),
        'aria-controls': panelId,
        'data-focus': `${row.key}|main`,
        onclick: () => toggle(expanded, row.key),
      },
        el('span', { class: `dot dot--${row.level}`, 'aria-hidden': 'true' }),
        el('span', { class: 'entry-text' }, `${row.count.toLocaleString('en')} links on this site share the page warning`),
        el('span', { class: 'entry-meta' }, el('span', { class: 'level' }, LEVEL_WORDS[row.level]), row.domain ? ` · ${row.domain}` : ''),
        el('span', { class: 'group-chevron' }, icon('#i-chevron'))));

    if (open) {
      item.appendChild(el('div', { class: 'entry-more', id: panelId },
        el('p', { class: 'more-label' }, 'The links (choose one to scroll to it)'),
        el('ul', { class: 'members' },
          ...members.map((member) => {
            const { rest } = findings.splitDestination(member.url);
            const path = findings.clipRest(rest, MAX_PATH_LENGTH);
            return el('li', {},
              el('button', { type: 'button', class: 'member', 'data-focus': `${row.key}|member-${member.id}`, onclick: () => showOnPage(member.id) },
                el('span', { class: 'member-text' }, member.text || '(no text)'),
                el('span', { class: 'member-path' }, path.text + (path.clipped ? '…' : ''))));
          })),
        !showAll && row.members.length > VISIBLE_MEMBERS
          ? el('div', { class: 'actions' },
            el('button', { type: 'button', class: 'btn', 'data-focus': `${row.key}|all`, onclick: () => toggle(allMembersShown, row.key) },
              `Show all ${row.members.length.toLocaleString('en')}`))
          : null,
        showAll && unlisted > 0 ? el('p', { class: 'members-note' }, `And ${unlisted.toLocaleString('en')} more.`) : null,
        confirming === row.key
          ? confirmPanel(row.key, row.domain)
          : el('div', { class: 'actions' }, ...trustControls(row.key, row.domain, state.pageTrusted))));
    }
    return item;
  }

  function focusKey(key) {
    const target = [...document.querySelectorAll('[data-focus]')].find((node) => node.dataset.focus === key);
    if (target) target.focus();
    return Boolean(target);
  }

  function renderStatus() {
    const { kind, title, detail } = findings.pageStatus(state, Date.now());
    const section = $('status');
    section.className = `status status--${kind}`;
    // A warning about the page itself is announced; counts that tick up while
    // a page loads are not.
    if (kind.startsWith('page-')) section.setAttribute('role', 'alert');
    else section.removeAttribute('role');
    $('status-icon').setAttribute('href', STATUS_ICONS[kind] || '#i-alert');
    if ($('status-title').textContent !== title) $('status-title').textContent = title;
    if ($('status-detail').textContent !== detail) $('status-detail').textContent = detail;
  }

  // What the page found: redrawn every time the content script reports a
  // change, so links scanned after the popup opened show up.
  function renderFindings() {
    renderStatus();

    const scanning = Boolean(state && state.counts && state.mode !== 'off');
    const rows = (scanning && state.rows) || [];
    $('flagged').hidden = rows.length === 0;
    $('flagged-counts').textContent = scanning ? findings.countsLabel(state.counts) : '';

    // Leave the list alone unless something in it changed: a redraw would
    // interrupt a screen reader, and the page reports often while it loads.
    const drawn = JSON.stringify([
      rows, scanning && state.hiddenRows, scanning && state.listedDomains, scanning && state.pageTrusted,
      [...expanded], [...allMembersShown], allRowsShown, confirming,
    ]);
    if (drawn === lastDrawn) return;
    lastDrawn = drawn;

    const focused = document.activeElement && document.activeElement.dataset.focus;
    const visible = allRowsShown ? rows : rows.slice(0, VISIBLE_ROWS);
    $('flagged-list').replaceChildren(...visible.map((row) => (row.kind === 'group' ? groupRow(row) : linkRow(row))));

    const more = rows.length - visible.length;
    $('flagged-more').hidden = more === 0;
    $('flagged-more').textContent = `Show ${more.toLocaleString('en')} more`;
    const rest = allRowsShown && scanning ? state.hiddenRows : 0;
    $('flagged-rest').hidden = rest === 0;
    $('flagged-rest').textContent = `And ${rest.toLocaleString('en')} more not listed here.`;

    // Keep the keyboard where it was, following a row whose level changed. If
    // the control is gone (its link was just trusted, say), go to the top of
    // the list rather than nowhere.
    if (focused && !focusKey(focused) && !focusKey(atOtherLevel(focused))) {
      const first = document.querySelector('#flagged-list [data-focus]');
      (first && !$('flagged').hidden ? first : $('default-mode')).focus();
    }
  }

  $('flagged-more').addEventListener('click', () => {
    allRowsShown = true;
    renderFindings();
    // The button is gone; carry on from the first row it revealed.
    const revealed = document.querySelectorAll('#flagged-list > .entry')[VISIBLE_ROWS];
    const target = revealed && revealed.querySelector('[data-focus]');
    if (target) target.focus();
  });

  // --- Display mode ---------------------------------------------------------------

  // The controls: redrawn only when a setting changes, so a live update never
  // closes a dropdown the user has open.
  function renderControls() {
    if (state) defaultMode = state.defaultMode;
    const running = Boolean(state);

    $('host').textContent = running ? state.hostname : '';
    $('host').title = running ? state.hostname : '';

    // Per-site mode, next to the default it overrides.
    $('site-field').hidden = !running;
    $('fields').classList.toggle('is-single', !running);
    $('default-label').textContent = running ? 'On all other sites' : 'On all sites';
    if (running) {
      fillSelect($('site-mode'), [['', 'Use default'], ...Object.entries(MODES)], state.siteMode || '');
    }
    fillSelect($('default-mode'), DEFAULT_MODE_CHOICES.map((mode) => [mode, MODES[mode]]), defaultMode);

    // The one-off reveal. Nothing to reveal when every badge is already
    // showing, or none can be.
    const reveal = $('reveal');
    reveal.hidden = !running || state.mode === 'off' || state.mode === 'all';
    reveal.disabled = running && state.revealed;
    reveal.textContent = running && state.revealed ? 'Showing all until reload' : 'Show all on this page';
  }

  function render() {
    renderControls();
    renderFindings();
  }

  $('site-mode').addEventListener('change', async (event) => {
    await settings.saveSiteMode(state.hostname, event.target.value);
    state = (await ask({ type: MESSAGES.SETTINGS_CHANGED })) || state;
    render();
    announce(`Badges on this site: ${event.target.selectedOptions[0].textContent}.`);
  });

  $('default-mode').addEventListener('change', async (event) => {
    defaultMode = settings.resolveDefaultMode(event.target.value);
    await settings.saveDefaultMode(defaultMode);
    if (state) state = (await ask({ type: MESSAGES.SETTINGS_CHANGED })) || state;
    render();
    announce(`Badges on other sites: ${MODES[defaultMode]}.`);
  });

  $('reveal').addEventListener('click', async () => {
    state = (await ask({ type: MESSAGES.REVEAL })) || state;
    render();
    announce('Showing all badges until this page reloads.');
  });

  $('open-options').addEventListener('click', () => chrome.runtime.openOptionsPage());

  // --- Blocklist status -----------------------------------------------------------
  // Read straight from storage, where the service worker keeps it, so this
  // part works on any tab, including ones Tripwire can't run on.

  let listStatus = null;
  let checkingLists = false;
  let listsShownOnce = false;

  const outside = (text, href) => el('a', { href, target: '_blank', rel: 'noopener' }, text);

  function sourceItem(source, sourceState, now) {
    const { tone, text, detail } = blocklist.describeSource(sourceState, now);
    const look = tone === 'ok' ? '' : tone === 'pending' ? ' pending' : ' warn';
    return el('li', { class: `source${look}` },
      el('p', { class: 'source-name' },
        source.homepage ? outside(source.name, source.homepage) : source.name, ` (${source.category})`),
      el('p', { class: 'source-state' }, text),
      detail ? el('p', { class: 'source-credit' }, detail) : null,
      // Credit: where the list comes from and the licence it is published under.
      el('p', { class: 'source-credit' },
        `Built from ${source.builtFrom}`,
        ...(source.licence ? ['. Licence: ', outside(source.licence, source.licenceUrl)] : [])));
  }

  function renderLists() {
    const now = Date.now();
    const states = (listStatus && listStatus.sources) || {};
    const { sources, fixture } = blocklist.CONFIG;

    const overall = blocklist.describeAll(sources.map((source) => states[source.id]), now);
    $('lists-summary').textContent = overall.text;
    $('lists-summary').className = `lists-state${overall.tone === 'ok' ? '' : ' warn'}`;
    // Open by itself when something needs attention, but never close it on the user.
    if (!listsShownOnce && overall.tone !== 'ok') $('lists').open = true;
    listsShownOnce = true;

    const shown = states[fixture.id] ? [...sources, fixture] : sources;
    $('lists-sources').replaceChildren(...shown.map((source) => sourceItem(source, states[source.id], now)));

    $('check-now').disabled = checkingLists;
    $('check-now').textContent = checkingLists ? 'Checking…' : 'Check now';
  }

  $('check-now').addEventListener('click', async () => {
    checkingLists = true;
    renderLists();
    let reply = null;
    try {
      reply = await chrome.runtime.sendMessage({ type: MESSAGES.UPDATE_LISTS });
    } catch {
      // The service worker couldn't be reached; the stored status still shows.
    }
    checkingLists = false;
    if (reply && reply.status) listStatus = reply.status;
    renderLists();
    announce(`Blocklists: ${$('lists-summary').textContent}.`);
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local' || !(settings.LIST_STATUS_KEY in changes)) return;
    listStatus = changes[settings.LIST_STATUS_KEY].newValue || null;
    renderLists();
  });

  chrome.storage.local.get(settings.LIST_STATUS_KEY).then((stored) => {
    listStatus = stored[settings.LIST_STATUS_KEY] || null;
    renderLists();
  });

  // --- Start ----------------------------------------------------------------------

  // The active tab's id is available without the "tabs" permission; its URL
  // isn't, which is why the hostname comes from the content script.
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabId = tab && typeof tab.id === 'number' ? tab.id : null;

  state = await ask({ type: MESSAGES.GET_STATE });
  if (!state) defaultMode = await settings.loadDefaultMode().catch(() => settings.DEFAULT_MODE);
  render();

  // Stay connected while open: the content script pushes its state whenever
  // late-loading links, a new setting or a newly trusted domain change it.
  if (state) {
    try {
      const port = chrome.tabs.connect(tabId, { name: settings.POPUP_PORT });
      port.onMessage.addListener((pushed) => {
        const modeChanged = pushed.mode !== state.mode || pushed.revealed !== state.revealed;
        state = pushed;
        if (modeChanged) renderControls();
        renderFindings();
      });
      port.onDisconnect.addListener(() => void chrome.runtime.lastError);
    } catch {
      // No live updates; the popup still shows what it had when it opened.
    }
  }
})();
