# Salient Hook  Plugin Lockdown

**Author:** Hamad K - Lead Developer
**Website:** https://hamadhere.de
**Version:** 1.0.0
**Requires PHP:** 7.4 – 8.4
**Requires WordPress:** 5.9+

---

## Why I built this

Over the past week I spent a significant amount of time going through the codebases of several WordPress sites that had been compromised. Line by line. Multiple sites, multiple themes, multiple plugin folders  checking everything manually to figure out what was actually going on.

Visitors were seeing a fake Cloudflare verification popup. It looked legitimate enough that people were clicking through. What it was actually doing was tricking Windows users into opening PowerShell and running a command that downloaded malware in the background  stealing credentials, browser sessions, and crypto wallets. The campaign is documented over on the Sucuri blog if you want the full breakdown of how it works at a technical level — https://blog.sucuri.net/2025/05/another-fake-cloudflare-verification-targets-wordpress-sites.html

After going through everything I kept finding the same plugin sitting there doing nothing obvious  **WP Performance Analytics** by "Developer Tools Team", version 1.2.95. Disabled it on one of the sites and the popup disappeared immediately. That was it.

The frustrating part is it could have been caught much earlier if there was something in place that simply didn't allow unknown plugins to be installed in the first place. So I built Salient Hook  to lock things down, detect this specific plugin if it ever comes back, and give a clear view of what's sitting on the site.

---

## What it does

**Locks down plugin updates**
No more update checks going out to wordpress.org, no auto-updates, no cron jobs quietly pulling changes in the background. Updates are fully frozen until you decide otherwise.

**Blocks new plugin installs**
The Add New Plugin screen is gone. Direct URLs to it get redirected. Upload MIME types are stripped so you can't sneak a ZIP through the media uploader either. Every blocked attempt gets logged with the user and IP.

**Auto-detects and kills the malware plugin**
The moment an admin logs in, Salient Hook checks if WP Performance Analytics (or anything matching its code fingerprint) is sitting in the plugins folder. If it finds it, it deactivates it instantly and puts a red notice on screen telling you to delete it. It also runs this check every hour in the background.

**Scans your themes for leftover infection**
The malware drops a file called `verification.html` into your theme folders and injects code into `header.php`. The theme scanner checks all your installed themes for this file, for references to the known malware domains and IPs, and for other red flags like obfuscated code. You get a full report with exactly which file and which line was flagged.

**Dashboard under Settings → Salient Hook**
A single page showing you the status of every protection layer, the last scan results, and buttons to run a fresh scan on demand. Green means locked, red means something needs your attention.

---

## PHP Compatibility

| PHP | Tested |
|-----|--------|
| 7.4 | Yes |
| 8.1 | Yes |
| 8.2 | Yes |
| 8.3 | Yes |
| 8.4 | Yes |

---

## Install

1. Drop the `salienthook` folder into `/wp-content/plugins/`
2. Activate it from the Plugins screen
3. Go to **Settings → Salient Hook** and run both scans to get a baseline
