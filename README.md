# Hestia De-Noise

Request filtering in Nginx, before Varnish, Apache and PHP. **Preview 0.1.0.**
Targets Ubuntu with HestiaCP's Nginx proxy and accounts under `/home`.

## Quick start

Run these two commands in the server's root SSH session:

1. Clone:

   ```bash
   git clone https://github.com/orloxgr/hestia-de-noise.git /usr/local/src/hestia-de-noise
   ```

2. Install:

   ```bash
   python3 /usr/local/src/hestia-de-noise/tools/install.py
   ```

3. Refresh Hestia and open **Plugins → De-Noise** as administrator.

4. Click **Add suggested agents**, select **Observe** or **Enforce**, then
   **Save & Apply**. Endpoint and private-file presets are separate switches.

Installation starts in **Observe with an empty blocklist**; it blocks nothing.
Observe records matching requests while allowing them. Enforce returns **403**
for agent/private-file matches and **429** for exceeded endpoint limits.
There is no mandatory observation period.

## Included

- One literal, case-insensitive User-Agent substring per line.
- Optional POST login and XML-RPC rate limits, with editable rate and burst.
- Optional narrow private-file preset: `.env`, `.git`, WordPress config backups.
- All accounts and domains in the administrator's view; bulk mode changes and
  per-domain Off / Observe / Enforce / Inherit. Users can view their own domains.
- Existing proxy templates stay selected, including Varnish templates. Aliases
  share their domain's settings and rate budget.
- New domains are picked up by one minute-based maintenance job.
- Candidate Nginx validation, confirmed reload, recovery journal and visible errors.
- **Disable everywhere** in the panel; no extra resident service.

## Updates

```bash
git -C /usr/local/src/hestia-de-noise pull --ff-only
python3 /usr/local/src/hestia-de-noise/tools/install.py
```

Updates preserve the saved policy and domain exceptions.

## Disable or uninstall

Use **Disable everywhere** in Hestia. If panel access is unavailable:

```bash
/usr/local/hestia/bin/v-denoise-hestia disable
```

To remove its active Nginx includes, menu, route and maintenance job:

```bash
python3 /usr/local/src/hestia-de-noise/tools/install.py --uninstall
```

The saved policy, logs and installed code generations remain on disk.

## Operational notes

UA names are declarations, not verified identities. Presets do not automatically
block search crawlers or sharing fetchers; an administrator's custom entries do
apply literally. Endpoint limits may affect shared connections and legitimate
integrations: use the domain exceptions where needed. Client budgets use Nginx's
remote address, never arbitrary forwarded headers; any upstream proxy must have
its real-client-IP handling configured separately.

Normal requests run entirely in Nginx, without Python, PHP or external API calls.
Enabled endpoint modules reserve 10 MiB of shared rate-limit state each. Existing
templates with conflicting limits or missing native include points are reported
as unsupported and kept unchanged. Other inherited Nginx rules can still apply.

Logs are in `/var/log/hestia-de-noise/`: `matches.log` stores timestamp, domain,
rule, rate-limit outcome and status only; `maintenance.log` stores job results.
No request URL, query value, IP, cookie or credential is added to the match log.
The addon installs a daily logrotate policy retaining seven rotations, with a
10 MiB size trigger when logrotate runs. Existing server logs remain separate.

The installer adds only addon-owned code, domain includes, one HTTP-context
Nginx include, a panel route/menu asset, a cron entry and log rotation. It does not
install packages or change existing templates, Hestia core, WordPress, Varnish,
SSH, firewall or DNS settings. It relies on Hestia's existing panel sudo bridge.

Local verification covers live requests against Nginx, authorization boundaries,
candidate rollback, interrupted recovery and uninstall file ownership. A full
Ubuntu/Hestia installer run is still pending for this first preview.
