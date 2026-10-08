// Run with: node --test

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  CONTINUE_ARM_MS,
  shouldWarn,
  dispositionOf,
  effectText,
  opensElsewhere,
  headingFor,
  controlAction,
  integrityProblem,
  isTampering,
  openPlan,
} = require('../src/lib/clickguard.js');
const { resolveClickWarning } = require('../src/lib/settings.js');

// --- shouldWarn ---------------------------------------------------------------------

const RED_CLICK = { enabled: true, mode: 'risky', level: 'dangerous', type: 'click', button: 0 };

test('shouldWarn: a click on a dangerous link is stopped', () => {
  assert.equal(shouldWarn(RED_CLICK), true);
});

test('shouldWarn: only dangerous links, never an un-analysed one', () => {
  const cases = [
    ['dangerous', true],
    ['suspicious', false],
    ['ok', false],
    [null, false], // No verdict yet.
    [undefined, false],
    ['unknown', false],
  ];
  for (const [level, expected] of cases) {
    assert.equal(shouldWarn({ ...RED_CLICK, level }), expected, String(level));
  }
});

test('shouldWarn: not when the warning is off, or the site is off', () => {
  assert.equal(shouldWarn({ ...RED_CLICK, enabled: false }), false);
  assert.equal(shouldWarn({ ...RED_CLICK, mode: 'off' }), false);
  // The display mode only decides which badges are drawn.
  for (const mode of ['risky', 'all', 'click']) assert.equal(shouldWarn({ ...RED_CLICK, mode }), true, mode);
});

test('shouldWarn: which events follow a link', () => {
  const cases = [
    [{ type: 'click', button: 0 }, true, 'main button (also Ctrl-click and Shift-click)'],
    [{ type: 'auxclick', button: 1 }, true, 'middle button'],
    [{ type: 'auxclick', button: 2 }, false, 'right button opens the menu'],
    [{ type: 'auxclick', button: 3 }, false, 'a side button'],
    [{ type: 'click', button: 1 }, false],
    [{ type: 'keydown', key: 'Enter', isTrusted: true }, true, 'Enter on the link'],
    [{ type: 'keydown', key: ' ', isTrusted: true }, false, 'Space does not follow a link'],
    [{ type: 'keydown', key: 'Tab', isTrusted: true }, false],
    [{ type: 'keydown', key: 'Enter', isTrusted: false }, false, 'a scripted key press follows nothing'],
    [{ type: 'mousedown', button: 0 }, false],
    [{ type: 'contextmenu', button: 2 }, false],
  ];
  for (const [event, expected, why] of cases) {
    assert.equal(shouldWarn({ ...RED_CLICK, button: undefined, ...event }), expected, why || JSON.stringify(event));
  }
});

test('shouldWarn: a click made by a script is stopped too (it would follow the link)', () => {
  assert.equal(shouldWarn({ ...RED_CLICK, isTrusted: false }), true);
});

test('shouldWarn: not when something already cancelled the click', () => {
  assert.equal(shouldWarn({ ...RED_CLICK, defaultPrevented: true }), false);
});

test('shouldWarn: nothing at all means no', () => {
  assert.equal(shouldWarn(), false);
  assert.equal(shouldWarn({}), false);
});

test('the click warning is on unless it was explicitly turned off', () => {
  for (const value of [undefined, null, true, 'false', 0, '', {}]) {
    assert.equal(resolveClickWarning(value), true, JSON.stringify(value));
  }
  assert.equal(resolveClickWarning(false), false);
});

// --- dispositionOf ------------------------------------------------------------------

test('dispositionOf: what the click would have done', () => {
  const cases = [
    [{}, 'same', 'a plain click'],
    [{ target: '_self' }, 'same'],
    [{ target: '_top' }, 'same'],
    [{ target: '_blank' }, 'foreground-tab', 'target=_blank'],
    [{ target: '_BLANK' }, 'foreground-tab'],
    [{ target: 'payment-frame' }, 'named', 'a named tab or frame'],
    [{ ctrlKey: true }, 'background-tab', 'Ctrl-click'],
    [{ metaKey: true }, 'background-tab', 'Cmd-click'],
    [{ ctrlKey: true, shiftKey: true }, 'foreground-tab', 'Ctrl-Shift-click'],
    [{ type: 'auxclick', button: 1 }, 'background-tab', 'middle-click'],
    [{ type: 'auxclick', button: 1, shiftKey: true }, 'foreground-tab'],
    [{ shiftKey: true }, 'new-window', 'Shift-click'],
    [{ altKey: true }, 'download', 'Alt-click'],
    [{ ctrlKey: true, target: '_blank' }, 'background-tab', 'the modifier decides, not the target'],
    [{ type: 'keydown', ctrlKey: true }, 'background-tab', 'Ctrl-Enter'],
    [{ type: 'keydown' }, 'same', 'Enter'],
    // A download link on the page's own site downloads, whatever else is held.
    [{ hasDownload: true, sameOrigin: true }, 'download'],
    [{ hasDownload: true, sameOrigin: true, ctrlKey: true }, 'download'],
    [{ hasDownload: true, sameOrigin: true, target: '_blank' }, 'download'],
    // Chrome ignores `download` on a link to another site: it opens instead.
    [{ hasDownload: true, sameOrigin: false }, 'same'],
    [{ hasDownload: true, sameOrigin: false, target: '_blank' }, 'foreground-tab'],
  ];
  for (const [click, expected, why] of cases) {
    assert.equal(dispositionOf(click), expected, why || JSON.stringify(click));
  }
  assert.equal(dispositionOf(), 'same');
});

test('effectText: the line above the buttons says what Continue will do', () => {
  assert.equal(effectText('same'), 'If you continue, it opens in this tab.');
  assert.equal(effectText('foreground-tab'), 'If you continue, it opens in a new tab.');
  assert.equal(effectText('background-tab'), 'If you continue, it opens in a new tab.');
  assert.equal(effectText('new-window'), 'If you continue, it opens in a new window.');
  assert.equal(effectText('download'), 'If you continue, it downloads a file.');
  assert.match(effectText('named'), /tab or frame/);
  assert.equal(effectText('nonsense'), effectText('same'));
});

test('opensElsewhere: which outcomes need a new tab or window', () => {
  assert.deepEqual(
    ['same', 'named', 'download', 'foreground-tab', 'background-tab', 'new-window'].filter(opensElsewhere),
    ['foreground-tab', 'background-tab', 'new-window'],
  );
});

test('headingFor: names the blocklist category when the link is listed', () => {
  assert.equal(headingFor({ category: 'phishing' }), 'This link is listed as phishing');
  assert.equal(headingFor({ category: 'malware' }), 'This link is listed as malware');
  assert.equal(headingFor(null), 'This link looks dangerous');
  assert.equal(headingFor(undefined), 'This link looks dangerous');
});

// --- controlAction: hardening rule 1 (trusted events only) -----------------------------

const LATER = CONTINUE_ARM_MS + 1;
const CONTROLS = ['back', 'escape', 'outside', 'continue', 'toggle-address'];

test('controlAction: every control ignores an event made by a script', () => {
  for (const control of CONTROLS) {
    for (const isTrusted of [false, undefined, null, 'true', 1]) {
      assert.equal(
        controlAction({ control, isTrusted, sinceShownMs: 60000, problem: null }),
        null,
        `${control}, isTrusted=${JSON.stringify(isTrusted)}`,
      );
    }
  }
});

test('controlAction: what each control does for the user', () => {
  const cases = [
    ['back', 'back'],
    ['escape', 'back'],
    ['outside', 'back'],
    ['continue', 'continue'],
    ['toggle-address', 'toggle-address'],
    ['something-else', null],
  ];
  for (const [control, expected] of cases) {
    assert.equal(controlAction({ control, isTrusted: true, sinceShownMs: LATER, problem: null }), expected, control);
  }
  assert.equal(controlAction(), null);
});

test('controlAction: "Continue anyway" does nothing in the first half second', () => {
  for (const sinceShownMs of [0, 1, 250, CONTINUE_ARM_MS - 1, undefined, NaN]) {
    assert.equal(controlAction({ control: 'continue', isTrusted: true, sinceShownMs }), null, String(sinceShownMs));
  }
  assert.equal(controlAction({ control: 'continue', isTrusted: true, sinceShownMs: CONTINUE_ARM_MS }), 'continue');
  // "Go back" works at once.
  assert.equal(controlAction({ control: 'back', isTrusted: true, sinceShownMs: 0 }), 'back');
});

// --- controlAction + integrityProblem: hardening rule 2 --------------------------------

test('controlAction: on a warning that was tampered with, "Continue anyway" goes back', () => {
  for (const problem of ['removed', 'moved', 'closed', 'hidden', 'offscreen', 'covered']) {
    assert.equal(
      controlAction({ control: 'continue', isTrusted: true, sinceShownMs: LATER, problem }),
      'back',
      problem,
    );
  }
  // Never "continue", whatever else is true.
  for (const problem of ['removed', 'hidden', 'covered']) {
    for (const sinceShownMs of [0, LATER, 1e9]) {
      assert.notEqual(controlAction({ control: 'continue', isTrusted: true, sinceShownMs, problem }), 'continue');
    }
  }
});

test('controlAction: until the browser confirms the button is on show, "Continue anyway" waits', () => {
  assert.equal(controlAction({ control: 'continue', isTrusted: true, sinceShownMs: LATER, problem: 'unconfirmed' }), null);
});

const INTACT = {
  connected: true,
  inPlace: true,
  onTop: true,
  display: 'block',
  visibility: 'visible',
  opacity: 1,
  box: { left: 330, top: 120, right: 770, bottom: 510 },
  viewport: { width: 1100, height: 800 },
  hit: true,
  visible: true,
};

test('integrityProblem: an untouched warning has none', () => {
  assert.equal(integrityProblem(INTACT), null);
  assert.equal(isTampering(null), false);
});

test('integrityProblem: removed, hidden or covered', () => {
  const cases = [
    [{ connected: false }, 'removed', 'taken out of the document'],
    [{ inPlace: false }, 'moved', 'moved somewhere else in the page'],
    [{ onTop: false }, 'closed', 'taken out of the top layer'],
    [{ display: 'none' }, 'hidden'],
    [{ visibility: 'hidden' }, 'hidden'],
    [{ visibility: 'collapse' }, 'hidden'],
    [{ opacity: 0 }, 'hidden'],
    [{ opacity: 0.99 }, 'hidden', 'nearly invisible counts'],
    [{ opacity: NaN }, 'hidden'],
    [{ box: null }, 'hidden'],
    [{ box: { left: 100, top: 100, right: 100, bottom: 100 } }, 'hidden', 'squashed to nothing'],
    [{ box: { left: -5000, top: 120, right: -4560, bottom: 510 } }, 'offscreen'],
    [{ box: { left: 330, top: 700, right: 770, bottom: 1090 } }, 'offscreen', 'pushed below the window'],
    [{ hit: false }, 'covered', 'something else takes the click'],
    [{ visible: false }, 'covered', 'something is drawn over the button'],
    [{ hit: false, visible: null }, 'covered'],
  ];
  for (const [change, expected, why] of cases) {
    const problem = integrityProblem({ ...INTACT, ...change });
    assert.equal(problem, expected, why || JSON.stringify(change));
    assert.equal(isTampering(problem), true, `${expected} closes the warning`);
  }
});

test('integrityProblem: waiting for the browser is not tampering, and not a go-ahead', () => {
  const problem = integrityProblem({ ...INTACT, visible: null });
  assert.equal(problem, 'unconfirmed');
  assert.equal(isTampering(problem), false, 'the warning stays open');
  assert.equal(controlAction({ control: 'continue', isTrusted: true, sinceShownMs: LATER, problem }), null, 'but Continue waits');
});

test('integrityProblem: with no facts at all, the answer is the safe one', () => {
  assert.equal(integrityProblem(), 'removed');
  assert.equal(integrityProblem({}), 'removed');
  assert.equal(integrityProblem({ connected: true }), 'moved');
});

test('no combination of tampering and timing lets "Continue anyway" through', () => {
  const changes = [{ connected: false }, { inPlace: false }, { onTop: false }, { display: 'none' }, { opacity: 0 }, { hit: false }, { visible: false }, { box: null }];
  for (const change of changes) {
    for (const isTrusted of [true, false]) {
      for (const sinceShownMs of [0, LATER]) {
        const problem = integrityProblem({ ...INTACT, ...change });
        assert.notEqual(controlAction({ control: 'continue', isTrusted, sinceShownMs, problem }), 'continue', JSON.stringify(change));
      }
    }
  }
});

// --- openPlan ----------------------------------------------------------------------------

const SENDER = { tab: { id: 7, index: 3, windowId: 2, incognito: false } };

test('openPlan: a new tab next to the page that asked', () => {
  assert.deepEqual(openPlan({ url: 'https://www.paypa1.example/signin', disposition: 'foreground-tab' }, SENDER), {
    tab: { url: 'https://www.paypa1.example/signin', active: true, openerTabId: 7, windowId: 2, index: 4 },
  });
  assert.equal(openPlan({ url: 'https://a.example/', disposition: 'background-tab' }, SENDER).tab.active, false);
});

test('openPlan: a new window, private if the page was', () => {
  assert.deepEqual(openPlan({ url: 'http://a.example/x', disposition: 'new-window' }, SENDER), {
    window: { url: 'http://a.example/x', incognito: false },
  });
  const privateSender = { tab: { ...SENDER.tab, incognito: true } };
  assert.equal(openPlan({ url: 'http://a.example/x', disposition: 'new-window' }, privateSender).window.incognito, true);
});

test('openPlan: refuses anything it should not open', () => {
  const cases = [
    [{ url: 'https://a.example/', disposition: 'same' }, SENDER, 'not a new-tab request'],
    [{ url: 'https://a.example/', disposition: 'download' }, SENDER],
    [{ url: 'https://a.example/' }, SENDER, 'no disposition'],
    [{ url: 'javascript:alert(1)', disposition: 'foreground-tab' }, SENDER, 'not a web address'],
    [{ url: 'data:text/html,<h1>hi</h1>', disposition: 'foreground-tab' }, SENDER],
    [{ url: 'chrome://settings/', disposition: 'foreground-tab' }, SENDER],
    [{ url: 'file:///C:/Windows/', disposition: 'foreground-tab' }, SENDER],
    [{ url: 'not a url', disposition: 'foreground-tab' }, SENDER],
    [{ url: 'https://a.example/', disposition: 'foreground-tab' }, {}, 'not sent from a tab'],
    [{ url: 'https://a.example/', disposition: 'foreground-tab' }, { tab: {} }],
    [null, SENDER],
    [{ url: 'https://a.example/', disposition: 'foreground-tab' }, null],
  ];
  for (const [message, sender, why] of cases) {
    assert.equal(openPlan(message, sender), null, why || JSON.stringify(message));
  }
});

// --- The embedded logo ---------------------------------------------------------------------

test('src/content/logo.js holds the 48px icon, byte for byte', () => {
  const root = path.join(__dirname, '..');
  globalThis.Tripwire = globalThis.Tripwire || {};
  require('../src/content/logo.js');
  const icon = fs.readFileSync(path.join(root, 'icons', 'icon48.png'));
  assert.equal(globalThis.Tripwire.LOGO_PNG_BASE64, icon.toString('base64'), 'run: node tools/make-icons.js');
});

// --- The manifest ------------------------------------------------------------------------------

test('the click listeners load before the page: early.js runs at document_start, alone', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'manifest.json'), 'utf8'));
  const [first, second] = manifest.content_scripts;
  assert.deepEqual(first.js, ['src/content/early.js']);
  assert.equal(first.run_at, 'document_start');
  assert.deepEqual(first.matches, second.matches);
  // Nothing in the warning is loaded by pages, so nothing needs exposing to them.
  assert.equal(manifest.web_accessible_resources, undefined);
  for (const file of [...first.js, ...second.js]) {
    assert.ok(fs.existsSync(path.join(__dirname, '..', file)), `${file} exists`);
  }
});
