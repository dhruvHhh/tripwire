// Tripwire's colours.
//
// One set of names, two sets of values: light and dark. The pages (popup,
// options, welcome) get them from src/ui/theme.css; what Tripwire draws on
// web pages gets them from here, because that lives in a shadow root and
// can't load a stylesheet file. A test keeps the two in step, and checks
// every pair below against WCAG AA.
//
// The logo's red (#fd3833) is 3.6:1 on white: fine for a mark, too light for
// text. So text uses `danger-text`, fills use `danger-fill`, and dots and
// icons use `danger-mark`.

(() => {
  'use strict';

  const TOKENS = {
    light: {
      bg: '#ffffff',
      surface: '#f3f4f6',
      line: '#dfe2e7',
      'control-border': '#858b95',
      text: '#15171a',
      muted: '#59606b',
      'header-bg': '#15171a',
      'header-text': '#ffffff',
      'header-muted': '#b8bec8',
      'danger-fill': '#c8241f',
      'on-danger': '#ffffff',
      'danger-text': '#b3201b',
      'danger-mark': '#e5352f',
      'danger-tint': '#fdecea',
      'warn-text': '#8a4b00',
      'warn-mark': '#b96a00',
      'warn-tint': '#fff4d9',
      'ok-text': '#18722f',
      'ok-mark': '#1f8f3d',
      'ok-tint': '#e8f5ec',
      focus: '#15171a',
    },
    dark: {
      bg: '#15171a',
      surface: '#1e2125',
      line: '#2e3238',
      'control-border': '#6b727d',
      text: '#f2f3f5',
      muted: '#aab1bc',
      'header-bg': '#0b0c0e',
      'header-text': '#ffffff',
      'header-muted': '#b8bec8',
      'danger-fill': '#c8241f',
      'on-danger': '#ffffff',
      'danger-text': '#ff8078',
      'danger-mark': '#f2554e',
      'danger-tint': '#3a1614',
      'warn-text': '#f5c04a',
      'warn-mark': '#f0a91a',
      'warn-tint': '#33270a',
      'ok-text': '#5fd37f',
      'ok-mark': '#3fb963',
      'ok-tint': '#11301b',
      focus: '#ffffff',
    },
  };

  // [foreground, background, minimum ratio, what it is used for].
  // 4.5 for text; 3 for icons, dots, control borders and the focus ring.
  const CONTRAST_PAIRS = [
    ['text', 'bg', 4.5, 'body text'],
    ['text', 'surface', 4.5, 'text on cards and hover'],
    ['muted', 'bg', 4.5, 'secondary text'],
    ['muted', 'surface', 4.5, 'secondary text on cards'],
    ['header-text', 'header-bg', 4.5, 'header title'],
    ['header-muted', 'header-bg', 4.5, 'header hostname'],
    ['on-danger', 'danger-fill', 4.5, 'page warning banner'],
    ['danger-text', 'bg', 4.5, '"Dangerous" label'],
    ['danger-text', 'surface', 4.5, '"Dangerous" label on hover'],
    ['warn-text', 'bg', 4.5, '"Suspicious" label'],
    ['warn-text', 'surface', 4.5, '"Suspicious" label on cards'],
    ['ok-text', 'bg', 4.5, 'tooltip heading for a link with no red flags'],
    ['text', 'danger-tint', 4.5, 'title on the red banner tint'],
    ['muted', 'danger-tint', 4.5, 'detail on the red banner tint'],
    ['text', 'warn-tint', 4.5, 'title on the amber banner tint'],
    ['muted', 'warn-tint', 4.5, 'detail on the amber banner tint'],
    ['text', 'ok-tint', 4.5, 'title on the green banner tint'],
    ['muted', 'ok-tint', 4.5, 'detail on the green banner tint'],
    ['bg', 'text', 4.5, 'primary button label'],
    ['danger-mark', 'bg', 3, 'red dot'],
    ['danger-mark', 'danger-tint', 3, 'red icon on its banner'],
    ['warn-mark', 'bg', 3, 'amber dot'],
    ['warn-mark', 'warn-tint', 3, 'amber icon on its banner'],
    ['ok-mark', 'bg', 3, 'green dot'],
    ['ok-mark', 'ok-tint', 3, 'green icon on its banner'],
    ['ok-mark', 'surface', 3, 'green edge of a healthy list'],
    ['control-border', 'bg', 3, 'button and select borders'],
    ['focus', 'bg', 3, 'focus ring'],
    ['focus', 'surface', 3, 'focus ring on cards'],
    ['on-danger', 'danger-fill', 3, 'focus ring on the red banner'],
  ];

  // Relative luminance and contrast ratio, as WCAG 2 defines them.
  function luminance(hex) {
    const value = parseInt(hex.slice(1), 16);
    const [r, g, b] = [value >> 16, (value >> 8) & 255, value & 255].map((channel) => {
      const c = channel / 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  }

  function contrast(a, b) {
    const [lighter, darker] = [luminance(a), luminance(b)].sort((x, y) => y - x);
    return (lighter + 0.05) / (darker + 0.05);
  }

  // The tokens of one theme as CSS custom-property declarations.
  function declarations(theme) {
    return Object.entries(TOKENS[theme])
      .map(([name, value]) => `--${name}: ${value};`)
      .join(' ');
  }

  const api = { TOKENS, CONTRAST_PAIRS, contrast, declarations };

  globalThis.Tripwire = globalThis.Tripwire || {};
  globalThis.Tripwire.theme = api;

  if (typeof module !== 'undefined') module.exports = api;
})();
