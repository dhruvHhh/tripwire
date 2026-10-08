# Tripwire

Tripwire is a Chrome extension that scans every link on a web page and marks the risky ones with a small badge, so you can spot a bad link before you click it. It runs in the page as you browse, and its goal is to flag suspicious destinations (lookalike domains, odd URL tricks, known-bad sites) while staying out of the way on normal pages.

> **Status:** version 0.4.0. Links are scored by offline checks on the link itself, including links a page adds after it loads, and by default only amber and red links are marked. Tripwire makes no network requests yet.

## Roadmap

1. ✅ **Skeleton:** Manifest V3 extension that puts a neutral badge next to every link.
2. ✅ **Local heuristics:** score links on-device (lookalike domains, IP hosts, punycode, suspicious TLDs, etc.) and color the badges.
   - ✅ Follow-up: lookalike-page detection, display modes, toolbar count and popup, and badges drawn in an overlay instead of inside the page.
3. ✅ **Dynamic pages and performance:** scan links added or changed after load, follow single-page navigation, scan open shadow roots, and do all of it in idle time.
4. **Reputation lookups:** check link destinations against external reputation sources via the service worker, with caching.
5. **UI:** an options page, richer link details, and managing the per-site list.
6. **Publish:** polish, privacy policy, and release on the Chrome Web Store.

## What the badges mean

| Badge | Level | Meaning |
| --- | --- | --- |
| Green | `ok` | No red flags found. This is not a guarantee: heuristics can't prove a link is safe. |
| Amber | `suspicious` | Something about the link is unusual. Check where it really goes. |
| Red | `dangerous` | The link shows a pattern typical of phishing. |

Hover a badge to see the reasons. Each check adds weighted points, and the total decides the level (30 or more is amber, 70 or more is red).

The checks:

- **Text/href mismatch:** the link text is a domain (`paypal.com`) but the link goes to a different registrable domain.
- **IP-address hosts,** including disguised decimal, hex and octal forms.
- **Homographs:** punycode / non-ASCII hostnames and names that mix scripts.
- **Credentials in the URL,** such as `http://google.com@evil.com`.
- **URL shorteners** (mild; ignored on the shortener's own platform, like `t.co` on x.com).
- **Brand lookalikes:** look-alike characters (`paypa1`), near-miss spellings, and `brand.com.evil.com` subdomains.
- **Other signals:** no HTTPS, `data:` URIs, many subdomains, very long URLs, high-abuse TLDs.

**Same-site links and the page's own verdict.** The page's own address is scored once per page load. If it looks fine, a link that stays on the same site has its score cut to a quarter. If the page itself is suspicious or dangerous (for example you are on `paypa1.com`), there is no reduction: its same-site links inherit at least the page's level, with the reason "This page itself looks dangerous: ...".

All weights, thresholds and lists (brands, shorteners, TLDs, domain suffixes) are in the `CONFIG` object at the top of [src/lib/analyzer.js](src/lib/analyzer.js).

Known limits: registrable domains come from a small bundled suffix list, not the full Public Suffix List, and near-miss matching will sometimes flag a real site whose name is one or two letters from a brand (amber, never red on its own).

## Display modes

Tripwire scans every page unless the site is switched off. The mode only decides which badges are drawn.

| Mode | What you see on the page |
| --- | --- |
| **Risky only** (default) | Badges on amber and red links. Green links get nothing. |
| **Show all** | A badge on every link, including green. |
| **Only when I click** | Nothing, until you press "Show badges on this page" in the popup. |
| **Off for this site** | Nothing is scanned or drawn on this site. |

There is one global default (any mode except Off) and an optional override per site, both set from the popup. A site is a hostname, so `en.wikipedia.org` and `de.wikipedia.org` are separate. Changes apply immediately, without reloading the page.

"Show badges on this page" is a one-off: it shows every badge until the page reloads or you pick a different mode.

Settings are stored in `chrome.storage.sync`, so they follow your browser profile if sync is on.

## Toolbar icon and popup

The toolbar icon shows a count for the current tab: the number of red destinations on a red background, or, if there are none, the number of amber destinations on amber. No number means neither was found.

A destination is a distinct address and verdict, so a search result's title and its URL line count once. Hidden links count too, because a menu or dropdown can reveal them later. The count follows the page as links are added, changed and removed.

The popup shows:

- the current site, and a warning if the page's own address looks suspicious or dangerous;
- how many links are being tracked, and how many distinct red and amber destinations there are. These update while the popup is open;
- the mode for this site, the one-off "Show badges on this page" button, and the global default;
- up to 10 flagged links. Clicking one scrolls to it and outlines it for a moment. It does not open the link.

## How badges are drawn

Tripwire adds no elements next to your links, so it can't shift a page's layout. Every badge lives in one overlay (`<tripwire-overlay>`, a closed shadow root attached to `<html>`) and is positioned over the top-right corner of its link's first line of text, or of its image for a picture link.

- Only links that are on screen and actually visible get a badge. Links that are hidden, zero-size, scrolled out of a scroll box, or covered by a sticky header or dialog don't.
- Badges follow their links through page scrolling, scrolling inside nested boxes, resizes, DOM changes, and fixed or sticky headers.
- The overlay takes no pointer events anywhere, so it can never receive a click meant for the page. Tooltips are shown by watching where the pointer is.
- When nearby links go to the same address with the same verdict, such as a search result's title and its URL line, they share one badge.

The only thing Tripwire writes into the page itself is a `data-tripwire-processed` attribute on links it has given a verdict.

## Pages that change

Tripwire keeps scanning after the page has loaded.

- **New and changed links.** Links added later (search panels, feeds, infinite scroll) are scanned, and a link whose `href` or contents change is scanned again. Links removed from the page lose their badge and drop out of the counts.
- **Single-page navigation.** When a site changes its address without loading a new page, the page's own address is judged again. If that verdict changed, every link is re-checked, since same-site links depend on it.
- **Shadow roots.** Links inside open shadow roots are scanned and watched like the rest of the page. A shadow root is found when its host element is scanned; one attached later is picked up only for custom elements whose definition had not loaded yet. Closed shadow roots are not scanned.
- **Editable areas** (email composers, rich-text editors) are left alone.

### Performance

- Nothing is analysed where it is noticed. The first scan and every later change go into a queue that is worked through in idle time, a few milliseconds at a time.
- Positioning is driven by events: scrolling, resizing, DOM changes, images and fonts loading. A two-second fallback check covers layout changes that fire no event; it runs only while a badge is drawn and the tab is visible.
- A page where no badge is drawn costs nothing beyond scanning its links once.
- Memory stays bounded on long-lived pages: removed links are forgotten, and the verdict cache holds at most 2,000 entries.

To see what Tripwire is doing on a page, set `debug: true` in `CONFIG` at the top of [src/lib/analyzer.js](src/lib/analyzer.js), reload the extension, and open the page's DevTools console with the "Verbose" level on. It logs links tracked and analysed, time spent analysing and positioning, and the number of mutation batches.

## Load it in Chrome (unpacked)

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (toggle in the top-right).
3. Click **Load unpacked** and select this project folder (the one containing `manifest.json`).
4. Pin Tripwire to the toolbar (puzzle-piece icon, then the pin) so its count is visible.
5. Open (or reload) any `http://` or `https://` page.

After editing code, click the reload icon on Tripwire's card in `chrome://extensions`, then reload the page you're testing on.

## Testing

Automated tests use Node's built-in test runner and need no dependencies (Node 20 or newer):

```
node --test
```

To see the badges, modes and placement in the browser, serve the demo page and open it with the extension loaded:

```
node demo/serve.js
```

- <http://localhost:8080/> has a mix of green, amber and red links, plus placement tests (a sticky flex nav bar, a scrollable box, an image link, a wrapped link, hidden links, a fixed corner) and dynamic tests (inject 500 links, change a link's address, infinite scroll, single-page navigation, shadow roots).
- <http://paypa1.localhost:8080/> is the same page on a hostname that looks like a paypal lookalike (Chrome resolves any `.localhost` name to your own machine). Use it to see the page-verdict behavior.
- <http://one.two.three.four.tripwire.localhost:8080/> is the same page on a hostname with many subdomains. Its single-page navigation buttons make the page's own verdict change without a reload.

The page has to be served because content scripts don't run on `file://` pages. Clicking is disabled on it.

## Icons

The icons in `icons/` are generated from `logo.png`:

```
node tools/make-icons.js
```

Add `--preview` to also write `icon-preview.png`, a contact sheet of every size at actual size and enlarged, on light and dark backgrounds. The script needs only Node, and is not part of the extension.

The icons are not plain downscales. The logo's chain links are white with a hairline outline, which would vanish on a light toolbar, so each size redraws the outline at a visible width. The 16 and 32 px icons go further for legibility: the warning triangle is enlarged, the spark marks are dropped, the "!" is placed on whole pixels, and at 16 px the links are solid grey. The 128 px icon keeps its artwork inside the middle 96x96, as the Chrome Web Store asks.

## Project structure

```
manifest.json              Extension manifest (MV3)
icons/                     Toolbar and store icons, generated from logo.png
logo.png                   Source artwork for the icons
tools/make-icons.js        Regenerates icons/ from logo.png (development only)
src/lib/analyzer.js        analyzeLink() and analyzePage(): pure, offline scoring and its config
src/lib/settings.js        Display modes, storage keys, message names, toolbar count
src/lib/bookkeeping.js     Pure helpers: distinct-destination counts, bounded verdict cache
src/lib/geometry.js        Pure helpers: badge and tooltip placement, grouping nearby links
src/content/styles.js      CSS for the overlay, badges and tooltip
src/content/badge.js       Creates a badge; exposes setVerdict() and its tooltip
src/content/overlay.js     The overlay: tracks links, positions badges, shows tooltips
src/content/scanner.js     Finds links, watches the page for changes, works through them in idle time
src/content/content.js     Applies the mode, reports counts, answers the popup
src/popup/                 Toolbar popup
src/background/            Service worker: sets the toolbar count for each tab
test/                      Tests for the analyzer, settings, bookkeeping, geometry and the demo page
demo/                      Demo page and a tiny server for it
```

Content scripts can't use ES module imports, so the files load in order through the manifest's `js` array and share one global, `Tripwire`. The files in `src/lib/` also set `module.exports` so Node can test them directly.

## Permissions

| Permission | Why |
| --- | --- |
| `storage` | Saves the default display mode and per-site overrides in `chrome.storage.sync`. |

That is the only permission requested. Tripwire does not ask for `tabs` or `activeTab`: the popup only needs the active tab's id, which is available without a permission, and it gets the site's hostname from the content script.

The content script runs on all `http`/`https` pages, so Chrome will say Tripwire can "read and change your data on all websites"; that's needed to scan links and draw badges.
