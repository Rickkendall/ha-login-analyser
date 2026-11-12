# Login Analyser for Home Assistant

A custom integration that logs every failed login and unauthorised request to Home Assistant, works out where each one came from and what it was after, and blocks attackers the way fail2ban does.

## What you get

**For every failed attempt**
- Time, IP, reverse DNS, and whether that reverse DNS checks out going the other way
- Method, full URL, host, scheme, HTTP version, referer, `X-Forwarded-For`, user agent, and all request headers (auth tokens and cookies are redacted)
- **Username tried** (from the login form or HTTP Basic auth)
- **Password tried**, but *only* when the username does not exist in your HA. An attacker trying `admin / 123456` gets recorded. If you mistype your own password, it is never stored.
- An alert when an attacker uses one of your **real** usernames
- What the attempt was: HA login brute force, token abuse, REST API probe, WordPress/Joomla/phpMyAdmin scanner, `.env`/git secrets hunt, router/IoT botnet exploit, Log4Shell, path traversal, command injection, known scanner tools, and so on. Each comes with a severity score.
- A flag when the request came from a **Home Assistant app**. That is usually your own phone with an expired token, so it is not banned straight away.

**For every attacking IP**
- Country, region, city, coordinates, timezone, ISP, organisation, ASN ([ip-api.com](https://ip-api.com), free, no key)
- Datacenter/VPS, proxy/VPN/Tor and mobile-network flags
- [Shodan InternetDB](https://internetdb.shodan.io): the attacker's own open ports, software, known CVEs, and tags like `compromised` or `scanner` (free, no key)
- Optional [AbuseIPDB](https://www.abuseipdb.com) abuse score and report count (needs a free API key)
- Every username, password, URL and user agent it tried, plus first seen, last seen, hit count and ban history
- One-click links to AbuseIPDB, Shodan, GreyNoise, VirusTotal, ipinfo and BGP lookup

**Blocking (works like fail2ban)**
- Bans an IP after *N* failures within *T* minutes (default: 3 in 60 min). Default ban length is 24 h.
- Bans requests that are never legitimate for HA straight away (WordPress, `.env`, router exploits and similar)
- Repeat offenders get longer bans (the time doubles each time), and the 3rd ban is permanent (you can change both)
- Bans expire on their own. HA's built-in bans never expire.
- Never bans LAN/private IPs, IPs you have whitelisted (IP or CIDR), or IPs that logged in successfully in the last 30 days
- Ban or unban from the panel, or with the `login_analyser.ban_ip` / `unban_ip` actions. Unbanning also removes the IP from `ip_bans.yaml`.

**In Home Assistant**
- **Login Analyser** sidebar panel (admin only) with tiles, a 48-hour chart, and tabs for Attackers, Live feed, Credentials & stats, Bans and Successful logins
- Sensors: failed attempts (24h), attacking IPs (24h), active bans, last attacker (with location and ISP as attributes), last attempt time, top country
- Events `login_analyser_attempt`, `login_analyser_ban` and `login_analyser_unban` to use in your own automations
- Replaces HA's vague "Login attempt failed" notification with a detailed one
- Optional push notification to your phone, at most one per IP per hour (bans always notify)

## Install

### One click (Marketplace / HACS)

[![Open your Home Assistant and add this repository to the Marketplace.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=Rickkendall&repository=ha-login-analyser&category=integration)

1. Click the button above. Home Assistant opens and offers to add this repository. Then press **Download**.
   (Without the button: **Settings → Marketplace** (HACS on older versions) → ⋮ → **Custom repositories** → add `https://github.com/Rickkendall/ha-login-analyser` with category **Integration**, then download **Login Analyser**.)
2. Restart Home Assistant.
3. [![Add the Login Analyser integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=login_analyser)
   or go to **Settings → Devices & services → Add integration → Login Analyser**. Check the options (the defaults are sensible) and submit.
4. Open **Login Analyser** in the sidebar.
   - If it shows **Blocking is not active**, press **Enable blocking**. This sets `ip_ban_enabled: true` and `login_attempts_threshold: -1` in HA's HTTP server settings (since HA 2026.11 these live in **Settings → System → Network**, not `configuration.yaml`) and restarts HA. Afterwards, press **Keep these HTTP settings** within 5 minutes. If you don't, HA undoes the change by itself.
   - `-1` turns off HA's own "ban forever after N tries" rule, so Login Analyser decides who gets banned, for how long, and who is whitelisted.
5. Before you rely on the blocking, check the panel's **Successful logins** tab. If you sometimes log in from a fixed IP outside your home network (work, Tailscale `100.64.0.0/10`, etc.), add it to the whitelist in the integration's options.

Updates show up in Home Assistant like any other Marketplace integration.

### Manual install

Copy `custom_components/login_analyser` into `/config/custom_components/` (for example with the Studio Code Server app), restart, then carry on from step 3.

### If you lock yourself out

Unban yourself from any device that still works, either from the panel or by running the action `login_analyser.unban_ip`. Or, from the Terminal & SSH app:
```bash
ha core restart   # clears in-memory bans that are not permanent
```
To clear permanent bans, delete the IP's line from `/config/ip_bans.yaml` and restart.

## Notes

- **Most of what you see is automated scanners, not a person.** Bots crawl the whole IPv4 internet looking for WordPress, Joomla and router exploits. Your HA answers them with 401, and HA counts each 401 as a failed login. That is where those notifications come from.
- The only real fix is to stop exposing port 8123 to the internet. Use Nabu Casa, Tailscale/WireGuard, or a reverse proxy with an allow-list. Also turn on **multi-factor authentication** for every user (Profile → Security).
- HA's own security filter rejects some exploit requests (path traversal, SQL injection, `<script>` in the URL) with a 400 before any login check runs. Those are already blocked, so they never show up as failed logins or in this panel.
- Only the IP is sent to ip-api.com, Shodan and AbuseIPDB. ip-api.com's free tier is plain HTTP and limited to 45 lookups a minute. Results are cached for 7 days.
- Captured passwords are stored in plain text in `/config/.storage/login_analyser.data`, together with the rest of the history. Turn off **Record passwords tried** if you don't want that.
- The integration hooks into HA's internal auth functions (`process_wrong_login` and the login form step). A future HA update could break the hook. If it does, the integration logs an error and HA's own login keeps working as normal.
