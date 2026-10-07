# Tripwire

Tripwire is a Chrome extension that scans every link on a web page and puts a small badge next to each one showing how safe it looks, so you can spot a risky link before you click it. It runs in the page as you browse, and its goal is to flag suspicious destinations (lookalike domains, odd URL tricks, known-bad sites) while staying out of the way on normal pages.

> **Status:** Step 1 (skeleton). Every link gets a neutral grey badge. No safety checks yet.

## Roadmap

1. **Skeleton:** Manifest V3 extension that puts a neutral badge next to every link.
2. **Local heuristics:** score links on-device (lookalike domains, IP hosts, punycode, suspicious TLDs, etc.) and color the badges.
3. **Dynamic pages and performance:** handle links added after load (MutationObserver) and only process links near the viewport.
4. **Reputation lookups:** check link destinations against external reputation sources via the service worker, with caching.
5. **UI:** badge tooltips/details, a toolbar popup, and an options page.
6. **Publish:** polish, privacy policy, and release on the Chrome Web Store.

## Load it in Chrome (unpacked)

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (toggle in the top-right).
3. Click **Load unpacked** and select this project folder (the one containing `manifest.json`).
4. Open (or reload) any `http://` or `https://` page. A small grey dot should appear after each link.

After editing code, click the reload icon on Tripwire's card in `chrome://extensions`, then reload the page you're testing on.

## Project structure

```
manifest.json              Extension manifest (MV3)
icons/                     Toolbar / store icons (placeholders)
src/background/            Service worker
src/content/styles.js      Badge CSS (applied inside each badge's Shadow DOM)
src/content/content.js     Finds links and inserts badges
```

## Permissions

Tripwire currently requests no permissions. Its content script runs on all `http`/`https` pages, so Chrome will say it can "read and change your data on all websites"; that's needed to place badges next to links.
