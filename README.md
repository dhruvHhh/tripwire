# <img src="icons/icon128.png" alt="" width="40" height="40" align="center"> Tripwire

A Chrome extension that marks risky links on the pages you visit, and warns you before a dangerous one opens, without any link ever leaving your browser.

![Tripwire's popup listing the flagged links on a page, next to the page with its red and amber badges](docs/screenshots/popup.png)

## What it does

- Puts a red or amber dot on risky links. Hover it to see why, and where the link really goes.
- Spots lookalike domains, link text that names one site while the link goes to another, disguised addresses, and known phishing and malware sites.
- Asks before a dangerous link opens, with **Go back** and **Continue anyway**.
- Lists a page's flagged links in its popup, and lets you trust domains you know.
- Works with the keyboard and screen readers, in light and dark mode.

## Install

1. Download `tripwire-<version>.zip` from the latest release on the [Releases page](../../releases). Don't use **Code** > **Download ZIP**: that's the source, with test files in it.
2. Unzip it into a folder you'll keep. Chrome runs Tripwire from there.
3. Open `chrome://extensions` and turn on **Developer mode** (top right).
4. Click **Load unpacked** and choose the unzipped folder.

There are no automatic updates yet: to update, unzip the new release into the same folder and click reload on Tripwire's card ([details](docs/DETAILS.md#updating)).

## Privacy

Every check runs on your device, and the only thing Tripwire downloads is two public blocklists. It collects, sends and sells nothing; see [PRIVACY.md](PRIVACY.md).

## Limitations

- A second opinion, not a guarantee: no badge doesn't mean a link is safe.
- The blocklists lag new attacks by hours, so very new phishing sites may not be on them.
- The warning covers links you click, not pages that redirect you by themselves.

More in [the full list](docs/DETAILS.md#limitations).

## Development

```
node --test               # run the tests
node demo/serve.js        # demo page at http://localhost:8080/
node tools/package.js     # build dist/tripwire-<version>.zip
```

How it works, every feature, and the project's layout: [docs/DETAILS.md](docs/DETAILS.md).

## Credits and licence

Tripwire's code is [MIT](LICENSE). The blocklists come from the [malware-filter](https://gitlab.com/malware-filter) project and are downloaded at runtime, not included here: the [Phishing URL Blocklist](https://gitlab.com/malware-filter/phishing-filter) (CC BY-SA 4.0) and the [Online Malicious URL Blocklist](https://gitlab.com/malware-filter/urlhaus-filter) (CC0).
