# Hestia De-Noise

Request filtering in Nginx, before Varnish, Apache and PHP. **Preview 0.3.0.**
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

4. In **General**, select **Enforce** and enable **Private-file protection**.
   In **User-Agents**, click **Add scanner tools**, then **Save & Apply**.
   **Add bulk / AI crawlers** is optional.

Installation starts in **Observe with an empty blocklist**; it blocks nothing.
Observe records matching requests while allowing them. Enforce returns **403**
for agent/private-file matches and **429** for exceeded rate limits.
There is no mandatory observation period.

## Included

- Separate Scanner tools and Crawlers blocklists, each with its own switch.
  One literal, case-insensitive User-Agent substring per line.
- Optional POST login and XML-RPC rate limits, with editable rate and burst.
- Private-file preset: environment files, source control, configuration backups,
  cloud credentials, Kubernetes tokens and operating-system secret paths.
- Separate editable suggestions for scanner tools and bulk / AI crawlers.
- **Filtered URL crawling:** match a path, parameter names and crawler names;
  limit or block them on selected domains. The rate budget is per crawler and
  domain across all IPs, aliases and matching URL combinations.
- **Missing static files:** select a directory and file extensions; return 404
  before PHP for missing files. Existing files keep their current routing.
- **Activity:** last 15 minutes of matched, observed and blocked requests by
  domain and rule, from bounded addon logs.
- **IP bans:** optional first-probe native Hestia firewall bans, permanent or
  timed, with editable trigger count/window, domain scope, never-ban networks
  and selected/all unban controls.
- Hestia's native tabs: General, User-Agents, Endpoints, Filtered URLs, Static
  files, IP bans, Domains and Activity. Save & Apply retains all tabs' settings.
- All accounts and domains in the administrator's view; bulk mode changes and
  per-domain Off / Observe / Enforce / Inherit. Users can view their own domains.
- Existing proxy templates stay selected, including Varnish templates. Aliases
  share their domain's settings and rate budget.
- New domains are picked up by one minute-based maintenance job.
- Candidate Nginx validation, confirmed reload, recovery journal and visible errors.
- **Disable everywhere** in the panel; no extra resident service.

Filtering does not require Cloudflare. Browser challenges, Turnstile and general
custom endpoint rules remain planned. This is a request filter, not a full WAF.
See [PRESETS.md](PRESETS.md) for the lists and rule examples.
See [ROADMAP.md](ROADMAP.md) for completed and remaining work.

## Updates

```bash
git -C /usr/local/src/hestia-de-noise pull --ff-only
python3 /usr/local/src/hestia-de-noise/tools/install.py
```

Updates preserve the saved policy and domain exceptions. Version 0.2.0 expands
the existing private-file preset if it was already enabled. It does not insert
new agent names or enable filtered-URL/static rules: use the panel buttons and
**Save & Apply** to select them.

Version 0.3.0 separates recognized scanner-tool entries from the previous mixed
list without changing its effective blocks. Unknown/custom entries stay under
Crawlers / other agents. The two lists can then be edited or disabled separately.
Automatic IP bans remain off until enabled in the panel.

## Enable automatic IP bans

1. Open **IP bans** and check **Enable automatic firewall bans**.
2. Select secret/config-file probes, source-control probes, or both.
3. Keep **Matching requests before ban = 1**. Set **Ban duration = 0** for
   permanent bans, or enter the number of days.
4. Select trigger domains, or leave empty for all. Optionally enter never-ban
   IPs/CIDR networks, one per line.
5. **Save & Apply**. Use **Synchronize now** to run the pending synchronization
   immediately; otherwise it runs within about one minute.

The selected probe receives HTTP 403 immediately, even with the separate
private-file switch off. The existing maintenance job reads its dedicated log
and uses Hestia's native firewall commands to add the IP to its **DENOISE**
chain, covering TCP **80/443 across all sites**. The domain selection controls
which sites trigger a ban. No extra daemon or firewall is installed.

Use **Unban selected**, **Unban all De-Noise IPs**, or the linked **Hestia IP
bans** screen. Native panel unbans are respected at synchronization. The counting
window is editable; increasing it does not delay a ban when the request count is
one. Duration changes apply to existing and future bans. Disabled/Observe source
domains stop triggering bans and their existing addon bans are released at sync.
**Disable everywhere** releases all addon bans at sync. Uninstall removes them
before removing its maintenance job and integration.

## Add a filtered-URL rule

1. Open **Filtered URLs → Filtered URL crawling**.
2. Click **Product listing filters** or **VLM directory filters**.
3. Select the domains. An empty selection means all domains.
4. Review the prefilled rate and parameter names, then **Save & Apply**.

For another URL pattern use **Add rule**. All presets remain editable. Ordinary
URLs without the selected parameter names and visitors without the selected
crawler names do not match the rule.

## Enable missing-static-file protection

1. Open **Static files → Missing static files**.
2. Click **WordPress source maps** or **WordPress JS / CSS**. The paths and
   extensions are shown below each button.
3. Leave **Enabled** checked and select the domains, or leave the selection
   empty for all domains.
4. **Save & Apply** with server/domain mode **Enforce**.

Preset buttons fill the form; they do not save or reload Nginx. Repeated clicks
keep matching existing rules and their edited rates, switches and domain scope.

## Exclude files from static-file protection

1. Open **Static files → File exceptions by domain**.
2. Choose the domain and enter one exact URL path per line:

   ```text
   /wp-content/plugins/example/assets/app.js.map
   /wp-content/themes/example/assets/theme.css.map
   ```

3. **Save & Apply**. You can edit multiple domains before saving.

Exceptions keep normal site routing even if the file is missing. They cover all
static rules for the selected domain and its aliases, for any query string.
They are case-sensitive exact paths, not full URLs, filesystem paths or wildcards.
Encoded URL paths are accepted. Clearing the list removes the exceptions. Other
De-Noise rules, including agent and private-file blocks, still apply.

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

Normal requests run entirely in Nginx, without Python, PHP or external API calls;
rate limits use `nodelay`, rejecting excess requests rather than queuing them.
Each endpoint or filtered-URL rate rule reserves 10 MiB of shared state. Selected
static rules add an Nginx file-existence check on their domains; use only literal
document roots and directories where missing files should really be 404, not
dynamic image generators or protected download routes. The bundled static presets
cover source maps and plugin/theme/core JS/CSS; they do not select upload images
or generated-cache directories. Existing
templates with conflicting limits or missing native include points are reported
as unsupported and kept unchanged. Other inherited Nginx rules can still apply.

Logs are in `/var/log/hestia-de-noise/`: `matches.log` stores timestamp, domain,
rule, rate-limit outcome, status and mode only; `maintenance.log` stores job results.
No request URL, query value, IP, cookie or credential is added to the match log.
When automatic bans are enabled, `ban-events.log` separately stores timestamp,
client IP, domain and a fixed reason, with no raw URL or query. A root-private
`/var/lib/hestia-de-noise/bans.sqlite` stores counters, rotation cursors, expiry
and the addon ban queue. Maintenance output contains counts and errors rather
than repeatedly dumping the IP table.
Activity reads at most 2 MiB each from the current and previous uncompressed
match log when opening the panel; it is a bounded sample, not a traffic total or
CPU measurement. The addon installs a daily logrotate policy retaining seven rotations, with a
10 MiB size trigger when logrotate runs. Existing server logs remain separate.

The native ban backend supports **IPv4**. IPv6 probes still receive HTTP 403,
but are counted as unsupported for firewall bans. There is no automatic change
to SSH, panel, mail ports, the existing Fail2ban jails or recidive policy. Ordinary
404s, missing static files, denied User-Agents and crawler rate limits do not
trigger bans. Loopback, local server addresses and the explicit never-ban list
are excluded from automatic bans, along with native Hestia IP exclusions; no administrator public IP is inserted
automatically. Bans use Nginx's configured client address, not arbitrary
forwarded headers. Never-ban entries do not bypass request filtering.

Firewall additions/removals are processed in resumable batches, up to 100
operations and approximately ten seconds of work per synchronization. Pending
work and native failures are visible in IP bans; large queues can take more than
one sync. The table displays the latest 100 active/pending entries; this is a
display limit, not a total ban cap. Hestia stores individual IPv4 rules in this
backend; IPset scaling and native IPv6 enforcement remain planned.

The installer adds only addon-owned code, domain includes, one HTTP-context
Nginx include, a panel route/menu asset, a cron entry and log rotation. It does not
install packages or change existing templates, Hestia core, WordPress, Varnish,
SSH or DNS settings. Firewall changes occur only through the optional ban
module. The addon uses Hestia's native commands and records; cleanup also handles
the empty multiport-chain removal left behind by some native versions, touching
only its verified owned jump and chain. It relies on Hestia's existing panel sudo bridge.

Verification covers real requests against isolated Nginx, origin bypass for
rejected paths, crawler budgets across IPs and aliases, domain scope, static
file handling, authorization, upgrade policy retention, candidate rollback,
interrupted recovery and uninstall ownership. Native firewall verification uses
actual Hestia commands and TCP traffic in isolated network/mount namespaces,
with no changes to the running VM's native firewall files or rules. Native Hestia
tabs and cross-tab form submission are checked in a browser. Full Hestia installer integration
is separate from these isolated tests.
