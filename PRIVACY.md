# Tripwire privacy policy

Effective 9 October 2026. This policy covers the Tripwire extension for Chrome, version 1.0.0 and later.

## In short

Tripwire checks the links on the pages you visit, and it does all of that on your device. It does not collect, send, sell or share any information about you or about what you browse. It has no server, no account, no analytics and no ads.

## What Tripwire reads

On every `http` and `https` page you open (except on sites where you have switched Tripwire off), Tripwire reads:

- the address of the page;
- the links on the page: where each one goes, and its visible text (or, for a link without text, its image description or label).

It uses these only to decide, on your device, whether a link looks risky, and to show you the result. To find the links it looks through the structure of the page, but it does not keep or use anything else from it. It never reads what you type into forms.

Nothing Tripwire reads is sent anywhere, and nothing it reads is kept after you leave the page.

## What Tripwire stores

**Your settings**, in Chrome's extension storage (`chrome.storage.sync`):

- how badges are shown by default, and on any site you gave its own setting (stored by the site's name, for example `example.com`);
- the domains you have told Tripwire to trust, and the date you trusted each one;
- whether the warning before dangerous links is switched on.

If you have turned on sync in Chrome, Chrome copies these settings to your other devices through your own Google account, as it does for any extension's settings. Tripwire itself sends them nowhere. You can see and remove them on Tripwire's options page.

**The blocklists**, on your device only: the two downloaded lists of known phishing and malware addresses, in the browser's own storage (IndexedDB), and a short record of when each was last updated (`chrome.storage.local`).

Tripwire keeps no browsing history, no list of the pages you visit or the links on them, and no logs.

## Network requests

The only requests Tripwire makes are downloads of the two blocklists, which are public text files. It downloads them when it is installed, checks for newer copies about every 6 hours, and again when you press "Check now". It asks these addresses, in this order, moving to the next only if one can't be reached:

- `https://malware-filter.gitlab.io/malware-filter/`
- `https://curbengh.github.io/malware-filter/`
- `https://malware-filter.pages.dev/`

These are the servers of the [malware-filter](https://gitlab.com/malware-filter) project, hosted by GitLab, GitHub and Cloudflare. Like any server you download a file from, they can see your IP address and the ordinary details every browser request carries, such as the browser's version. The requests carry no cookies, no referrer, and nothing about you, the pages you visit or the links on them.

No page address and no link is ever sent to these servers or to anyone else. When you choose "Continue anyway" on Tripwire's warning, the link you chose opens, exactly as if Tripwire weren't installed.

## What Tripwire does not do

- It does not collect, transmit, sell or share personal data or browsing data.
- It does not use analytics, telemetry or crash reporting.
- It does not show ads.
- It does not load or run code from anywhere outside the extension itself.
- It does not need, or offer, an account.

## Your choices

- Switch Tripwire off for any site from its popup. On that site nothing is read at all.
- Remove trusted domains and site settings on the options page.
- Removing Tripwire from Chrome deletes what it stored on that device.

## Changes to this policy

If Tripwire ever changes what it reads, stores or sends, this policy will be updated before the change is released, and the effective date above will change. The history of this file is public in Tripwire's source repository.

## Contact

Questions about this policy can be asked by opening an issue on Tripwire's GitHub repository.
