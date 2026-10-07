# Tripwire

Tripwire is a Chrome extension that scans every link on a web page and puts a small badge next to each one showing how risky it looks, so you can spot a bad link before you click it. It runs in the page as you browse, and its goal is to flag suspicious destinations (lookalike domains, odd URL tricks, known-bad sites) while staying out of the way on normal pages.

> **Status:** Step 2 (local heuristics). Every link gets a green, amber or red badge from offline checks on the link itself. Tripwire makes no network requests yet.

## Roadmap

1. ✅ **Skeleton:** Manifest V3 extension that puts a neutral badge next to every link.
2. ✅ **Local heuristics:** score links on-device (lookalike domains, IP hosts, punycode, suspicious TLDs, etc.) and color the badges.
3. **Dynamic pages and performance:** handle links added after load (MutationObserver) and only process links near the viewport.
4. **Reputation lookups:** check link destinations against external reputation sources via the service worker, with caching.
5. **UI:** badge tooltips/details, a toolbar popup, and an options page.
6. **Publish:** polish, privacy policy, and release on the Chrome Web Store.

## What the badges mean

| Badge | Level | Meaning |
| --- | --- | --- |
| Green | `ok` | No red flags found. This is not a guarantee: heuristics can't prove a link is safe. |
| Amber | `suspicious` | Something about the link is unusual. Check where it really goes. |
| Red | `dangerous` | The link shows a pattern typical of phishing. |

Hover a badge to see the reasons. Each check adds weighted points, and the total decides the level (30 or more is amber, 70 or more is red). A link that stays on the current page's own site has its score cut to a quarter.

The checks:

- **Text/href mismatch:** the link text is a domain (`paypal.com`) but the link goes to a different registrable domain.
- **IP-address hosts,** including disguised decimal, hex and octal forms.
- **Homographs:** punycode / non-ASCII hostnames and names that mix scripts.
- **Credentials in the URL,** such as `http://google.com@evil.com`.
- **URL shorteners** (mild; ignored on the shortener's own platform, like `t.co` on x.com).
- **Brand lookalikes:** look-alike characters (`paypa1`), near-miss spellings, and `brand.com.evil.com` subdomains.
- **Other signals:** no HTTPS, `data:` URIs, many subdomains, very long URLs, high-abuse TLDs.

All weights, thresholds and lists (brands, shorteners, TLDs, domain suffixes) are in the `CONFIG` object at the top of [src/lib/analyzer.js](src/lib/analyzer.js).

Known limits: registrable domains come from a small bundled suffix list, not the full Public Suffix List, and near-miss matching will sometimes flag a real site whose name is one or two letters from a brand (amber, never red on its own).

## Load it in Chrome (unpacked)

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (toggle in the top-right).
3. Click **Load unpacked** and select this project folder (the one containing `manifest.json`).
4. Open (or reload) any `http://` or `https://` page. A small colored dot should appear after each link.

After editing code, click the reload icon on Tripwire's card in `chrome://extensions`, then reload the page you're testing on.

## Testing

Automated tests use Node's built-in test runner and need no dependencies (Node 20 or newer):

```
node --test
```

To see all three badge colors in the browser, serve the demo page and open it with the extension loaded:

```
node demo/serve.js
```

Then open <http://localhost:8080/>. The page has to be served because content scripts don't run on `file://` pages. Its links are grouped by the badge each should get, and clicking is disabled on the page.

## Project structure

```
manifest.json              Extension manifest (MV3)
icons/                     Toolbar / store icons (placeholders)
src/background/            Service worker
src/lib/analyzer.js        analyzeLink(): pure, offline link scoring and its config
src/content/styles.js      Badge CSS (applied inside each badge's Shadow DOM)
src/content/badge.js       Creates a badge and exposes setVerdict()
src/content/content.js     Finds links, scores them, inserts badges
test/                      Tests for the analyzer and the demo page
demo/                      Demo page with good and bad links, plus a tiny server for it
```

Content scripts can't use ES module imports, so the files load in order through the manifest's `js` array and share one global, `Tripwire`. `analyzer.js` also sets `module.exports` so Node can test the same file.

## Permissions

Tripwire currently requests no permissions. Its content script runs on all `http`/`https` pages, so Chrome will say it can "read and change your data on all websites"; that's needed to place badges next to links.
