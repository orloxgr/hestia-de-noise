# Hestia De-Noise

Request filtering in Nginx, before Varnish, Apache and PHP. **Preview 0.13.1.**
Targets Ubuntu with HestiaCP's Nginx proxy and accounts under `/home`.

## Quick start

Run the following steps in the server's root SSH session:

1. **Get the code. Choose one command:**

   For a **new installation**, clone the repository:

   ```bash
   git clone https://github.com/orloxgr/hestia-de-noise.git /usr/local/src/hestia-de-noise
   ```

   To **update an existing checkout**, pull instead:

   ```bash
   git -C /usr/local/src/hestia-de-noise pull --ff-only
   ```

   Wait for Git to finish successfully before continuing.

2. **Install or apply the update:**

   ```bash
   python3 /usr/local/src/hestia-de-noise/tools/install.py
   ```

   Pulling the code alone does not apply the update; run the installer too.

3. Refresh Hestia and open **Plugins → De-Noise** as administrator.

4. For a **new installation**, in **General**, select **Enforce** and enable **Private-file protection**.
   In **User-Agents**, click **Add scanner tools**, then **Save & Apply**.
   **Add bulk / AI crawlers** is optional.

New installations start in **Observe with an empty blocklist**; they block nothing.
Updates preserve the existing settings.
Observe records matching requests while allowing them. Enforce returns **403**
for agent/private-file matches and **429** for exceeded rate limits.
There is no mandatory observation period.

## Included

- Separate Scanner tools and Crawlers blocklists, each with its own switch.
  One literal, case-insensitive User-Agent substring per line.
- Optional POST login and XML-RPC rate limits, with editable rate and burst.
- **User enumeration:** optional protection for public WordPress REST user
  lists/numeric profiles, the `rest_route` variant, and author-ID discovery.
  A separate optional switch covers public author archives. Authenticated
  requests retain WordPress's normal permissions; other REST routes remain available.
- **WordPress logins:** administrator controls for the existing Fail2ban
  service: enable, failed-attempt threshold/window, three-stage ban durations,
  on-demand status and selected/all WordPress unban.
- Private-file preset: environment files, source control, configuration backups,
  cloud credentials, Kubernetes tokens and operating-system secret paths.
- Separate editable suggestions for scanner tools and bulk / AI crawlers.
- **Filtered URL crawling:** match a path, parameter names and crawler names;
  limit or block them on selected domains. The rate budget is per crawler and
  domain across all IPs, aliases and matching URL combinations.
  Add optional search-crawler names to an individual rule without a global
  block. Preview/copy robots.txt directives when those filtered URLs should
  stay out of search; the addon does not write robots.txt files.
- **Analyze logs:** administrator-triggered review of one/all web domains over
  30 minutes, 6 hours or 24 hours. Suggestions distinguish site faults, possible
  crawl spaces, known probes and traffic requiring investigation. They do not
  create rules or bans. Ordinary image/icon requests are excluded from findings;
  traffic totals still include them. Concrete next steps and domain-specific
  filter candidates help review each finding. Read coverage is shown explicitly.
- **Missing static files:** select a directory and file extensions; return 404
  before PHP for missing files. Existing files keep their current routing.
- **Activity:** last 15 minutes of matched, observed and blocked requests by
  domain, rule and full declared User-Agent, from complete on-demand reviews of
  available retained addon logs. Older records show Not recorded for the agent.
- **IP bans:** optional first-probe native Hestia firewall bans, permanent or
  timed, with editable trigger count/window, domain scope, never-ban networks
  and selected/all unban controls.
- **Why was this IP banned?** Request paths, methods and times, plus the actual
  threshold/window and duration at trigger time, for global and domain bans.
- Independent selected-PHP and suspicious-query 404 counters: 2 strikes in
  60 seconds and a 3-day ban by default, editable lists and domain exceptions.
- Optional general 404 bans: 10 final 404 responses within 5 minutes, for 3 days.
  By default, exclude missing images, CSS, JS, maps, fonts, media and PDFs, and
  require at least 3 different URL paths. All controls are editable; existing
  thresholds, durations and active bans are preserved during upgrade.
- **General → Protect webmail HTTP hosts:** optional User-Agent and private-file
  protection through native mail includes. Does not change SMTP/IMAP or webmail login.
- **General → Detailed rate-limit messages in error logs:** off by default;
  expected rejections use notice level while Activity keeps recording them.
- Log readers and upgrades support Nginx worker-owned logs after rotation.
  Activity reports unavailable data without displaying a misleading zero.
- Last successful maintenance and failures are shown without an extra service
  or background status polling.
- **Cron:** preview, apply and restore spread schedules for existing WordPress
  jobs through native Hestia cron management, with readable intervals and
  expandable exact schedule details.
- **Domain bans:** owners can switch on additional automatic bans for their own
  domains. These use Nginx, support IPv4/IPv6 and do not block other domains.
- Hestia's native tabs: General, User-Agents, Endpoints, Filtered URLs, Static
  files, IP bans, Domain bans, User enumeration, WordPress logins, Cron, Domains
  and Activity. Administrator tabs occupy two full-width rows of six, without
  horizontal scrolling. Small screens use three columns to keep labels readable.
  Domain bans and Cron have separate
  save/apply controls.
- All accounts and domains in the administrator's view; bulk mode changes and
  per-domain Off / Observe / Enforce / Inherit. Users see only their own Domain
  bans, Domains and Activity tabs.
- Existing proxy templates stay selected, including Varnish templates. Aliases
  share their domain's settings and rate budget.
- New domains are picked up by one minute-based maintenance job.
- Candidate Nginx validation, confirmed reload, recovery journal and visible errors.
- **Disable everywhere** in the panel; no extra resident service.

Filtering does not require Cloudflare. Browser challenges, Turnstile and general
custom endpoint rules remain planned. This is a request filter, not a full WAF.
See [PRESETS.md](PRESETS.md) for the lists and rule examples.
See [ROADMAP.md](ROADMAP.md) for completed and remaining work.

## User-enumeration protection

Open **Plugins → De-Noise → User enumeration**, enable the feature, choose its
switches and domain scope, then **Save & Apply**. Empty domain selection means all
supported WordPress sites and their aliases. The feature starts **off**, including
after an upgrade. Domain Off / Observe / Enforce modes still apply.

Nginx rejects matching requests without WordPress credentials before PHP. In
Enforce, the addon also installs one owned file,
`wp-content/mu-plugins/hestia-de-noise-user-enumeration.php`, as the site's Hestia
owner. That small companion uses WordPress's authentication result: a fabricated
cookie or Authorization header cannot unlock the user list. Login, password reset,
`/users/me`, editor operations and unrelated REST routes keep their normal behavior.
No account/domain quotas or automatic bans are introduced by this feature.

Disable, Off, Observe and uninstall remove the owned companion when it is no
longer required. Existing plugins and `wp-config.php` are not modified. WordPress
is never bootstrapped as root. The existing journal covers website-file and Nginx
changes together; unchanged maintenance does not launch website helper processes.
Enabling or changing this protection also purges the selected native Nginx cache
when the domain uses a `caching`/`caching-*` proxy template.

Only standard WordPress installations at the configured document root with the
standard `wp-content/mu-plugins` directory are supported. Non-WordPress HTML/PHP
sites are skipped; custom content directories report an error. Shared document
roots are scoped by domain and aliases. Custom authentication and cache templates
need their own compatibility checks. The archive switch is off by default because
blocking author pages can affect author-page SEO. Article bylines, feeds and old
indexed names are not rewritten.

## Updates

Run these commands separately. First, download the latest code:

```bash
git -C /usr/local/src/hestia-de-noise pull --ff-only
```

After Git finishes successfully, apply the update:

```bash
python3 /usr/local/src/hestia-de-noise/tools/install.py
```

Version 0.12.0 adds **Filtered URLs → Analyze logs** and removes the generic
insertion buttons for application-specific listing/filter presets. Saved rules
are not removed, disabled or retuned. Review them explicitly if they were only
temporary overload protection. New manual rules start disabled and require
parameter names, crawler names and a chosen rate. Analysis runs only on request
and changes no protection settings, bans, robots.txt or website files.

Version 0.11.0 expands the selected missing-PHP preset from 219 to 265 paths.
An exact previous bundled list is upgraded automatically; edited lists are
retained. To merge suggestions into an edited list, use **IP bans → Add suggested
PHP files**, then review and **Save & Apply**. Existing exceptions, limits and
ban state are retained. Optional crawler additions and webmail protection remain
operator choices; the update does not enable them. In **Filtered URLs**, use
**Add optional search crawlers to this rule** for scoped limits, or **Preview
robots.txt suggestions** for text to review and merge into existing crawler
groups. There are no automatic robots.txt or website-content changes.

Version 0.10.0 added the User enumeration tab and a two-row tab layout. Existing
settings, ban history and thresholds are retained; enumeration protection stays
off until enabled in the panel. Refresh Hestia with **Ctrl+F5** after updating.

Updates preserve the saved policy and domain exceptions. Version 0.2.0 expands
the existing private-file preset if it was already enabled. It does not insert
new agent names or enable filtered-URL/static rules: use the panel buttons and
**Save & Apply** to select them.

Version 0.3.0 separates recognized scanner-tool entries from the previous mixed
list without changing its effective blocks. Unknown/custom entries stay under
Crawlers / other agents. The two lists can then be edited or disabled separately.
Automatic IP bans remain off until enabled in the panel.

Version 0.4.0 keeps existing ban settings and adds two disabled trigger groups.
Enable them explicitly below. Existing schedules and saved crawler lists are not
changed by an update. `YisouSpider` is available in the editable crawler preset.

Version 0.5.0 preserves existing schedules and protection settings. Additional
domain protection starts off for every domain. Owners may edit its switches
unless the administrator disables that permission in **General**.

Version 0.6.0 adds the optional general 404 counter, initially off globally and
per domain. The bundled PHP preset grows from 138 to 193 paths. An unchanged
bundled list is expanded automatically; custom lists are preserved. To merge
suggestions into a custom list, use **Add suggested list** and **Save & Apply**.
Filtered URLs and Static files now show their controls directly inside the tab.

Version 0.7.0 adds WordPress login protection. New installations leave it off.
The supported existing standalone `wordpress-login` jail is adopted with its
current settings, stable jail/action identity and ban history. Its original
configuration is retained privately and restored on addon uninstall. Unrelated
Fail2ban configurations are kept unchanged.

Version 0.7.1 adds request evidence without changing saved protection settings.
In **IP bans** or **Domain bans**, expand **Why was this IP banned?** to see up
all retained matching requests and the policy that triggered the ban. Evidence stays
with the ban after its strike counter is cleared. Existing bans keep working;
paths cannot be reconstructed for records written before this update.

Addon evidence stores URL paths only: no query strings, cookies, authorization
headers or request bodies. Native access-log queries are stripped before storage.
Paths are retained without an addon length cutoff; the existing log rotation is reused. No additional service, polling or per-request script is added.

Version 0.8.0 adds **Active bans / History** and **Previous / Next** navigation
to IP bans and Domain bans, with 50 records selected per page in SQLite.
WordPress login IPs are also shown 50 per page, from the existing on-demand
Fail2ban status command; its history and escalation remain separate.
Completed bans keep their reason and available request evidence for **30 days**.
The administrator can change **History retention (days)** in IP bans. Existing
maintenance performs retention cleanup once a day; saving retention applies it
immediately. **Empty history** clears only completed records in the selected
global/domain scope. Domain owners can view and clear only their own domain
history. Active/permanent bans, pending removals, strike counters, log cursors and
the separate Fail2ban repeat-offender database are preserved. Legacy completed
rows use their last recorded timestamp when an original start time is unavailable.
No Hestia core files or native firewall rule formats are changed.
The native Hestia ban command has no reason/comment argument; the reason is
shown in De-Noise rather than inserted into native firewall records.

## WordPress login protection

**Requirement:** install and activate the official **WP fail2ban** WordPress
plugin in each site you want to protect. De-Noise does not scan for that plugin,
run WP-CLI presence checks or install it automatically.

1. Open **WordPress logins** as administrator.
2. Enable protection. Keep **3 failures within 5 minutes** for the first ban.
3. Set the durations: **5 minutes → 3 days → 0 days (permanent)**.
4. Click **Save & Apply WordPress protection**.

Real failed logins are read by Fail2ban from its authentication log. IP counters
cover all sites; bans cover TCP 80/443 for IPv4 and IPv6. Successful logins,
password-reset requests, comments, pingbacks and simply opening the login page
do not count. Native Fail2ban escalation reduces the default failure threshold
from 3 to 2 after the first ban and 1 after the second. Ban history is retained
for at least 30 days; permanent bans last until an administrator removes them.

Status and banned IPs are queried only when opening/refreshing this tab or
applying its settings. The existing Fail2ban service performs detection and
enforcement. The addon's periodic Nginx maintenance does not poll it. The
WordPress switch is independent of Nginx Off/Observe/Enforce; **Disable
everywhere** also disables addon-managed WordPress protection.

Configuration uses addon-owned filters/actions and local Fail2ban jail files.
Before reload, changes are syntax-checked; failed/interrupted changes restore
the previous configuration. The history-retention setting affects the shared
Fail2ban database, while thresholds/durations apply only to the WordPress jail.

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

## Enable the two 404 ban rules

1. Open **IP bans** and enable **Enable automatic firewall bans**.
2. Enable **Ban IPs that 404 any of these files X times**.
3. Enable **Ban IPs that 404 suspicious queries X times**.
4. Keep **X = 2**, **Counting window = 60 seconds**, **Ban duration = 3 days**
   in each box. The suggested lists are already filled and remain editable.
5. **Save & Apply**.

The PHP rule returns 404 only for a selected nonexistent file. It counts distinct
selected file paths per IP across domains; repeating one file does not create
two distinct strikes. Existing files retain normal routing. The full bundled
list is [src/php-probes.txt](src/php-probes.txt), one exact URL path per line.

The query rule matches selected parameter names plus complete secret-file
arguments, traversal to those targets or PHP filter resources. It recognizes
literal, percent-encoded and supported double-encoded forms. Matching requests
receive 404 before the origin; two matching requests can trigger a ban. A name
such as `file` alone, ordinary relative paths and search terms do not match the
suggested rules. This module examines URL query arguments, not POST bodies.

For a legitimate file manager use **Probe exceptions by domain → Allowed query
endpoints** and enter its exact URL path. Selected-file exceptions have their
own box. Exceptions bypass only that category. Never-ban IPs bypass bans only.
The two counters and durations are independent of direct secret/repository bans.

## Enable 10×404 bans for 3 days

1. Open **IP bans** and enable **Enable automatic firewall bans**.
2. Check **Enable general 404 bans**.
3. Keep **404 responses before ban = 10**, **Counting window = 300 seconds**
   and **Ban duration = 3 days**.
4. **Save & Apply**.

Every final 404 counts, including repeated requests for the same URL, missing
assets and application 404s. Counts combine selected domains per IP. The PHP
probe counter still bans after two distinct selected files independently.
Other responses, such as 200, 403, 409 and 429, do not count toward this threshold.
Owners can select the corresponding additional protection in **Domain bans**;
their counts and blocks apply only to that domain and its aliases.

General 404 bans also count genuine broken links/assets and search crawlers;
visitors sharing an IP share its counter. Use the threshold/window and the
administrator's never-ban list accordingly. A page saying “not found” with HTTP
200 does not count. Probe-path exceptions do not exempt a final 404 from this
independent general counter.

## Enable additional domain-only automatic bans

1. Open **Domain bans**, as administrator or as the domain's Hestia owner.
2. Enable **Automatic bans for selected file probes**, **Automatic bans for
   suspicious queries**, or **Automatic bans for repeated 404 responses** for
   the selected domain.
3. Click **Save domain protection**. The domain must be in **Enforce** mode.

These bans affect only that domain and its aliases. They are enforced in Nginx
and support IPv4 and IPv6; they add no firewall rules. Counters and expiry are
processed by the existing maintenance job, within about one minute.

Trigger lists, exceptions, thresholds, duration and never-ban addresses come
from the administrator's **IP bans** settings. Owners cannot edit those settings,
add exceptions, create manual bans or unblock IPs. They can switch their
additional protections off; existing administrator rules always apply.
The administrator sees all domains and can revoke owner editing in **General**.
Revoking editing retains the saved protections. Off/Observe mode, disabling a
category or **Disable everywhere** stops the corresponding domain bans.

**IP bans** remains the separate administrator control for server-wide native
firewall bans. Its enable switch is not required for domain-only protection.

## Spread WordPress cron jobs

1. Open **Cron**; keep minimum **5** and maximum **15** minutes.
2. Click **Generate preview**.
3. Review the selected jobs and click **Apply selected schedules**.

The generated minute lists have cyclic gaps within the selected interval range,
including the hour boundary. They remain stable and visible in native Hestia
CRON. Commands and other jobs are preserved. Scheduled WordPress work may wait
up to the selected maximum interval. Use **Restore selected original schedules**
to restore jobs from the current preview. The apply operation checks for
intervening edits in Hestia before changing each job. Generating another
preview replaces the current preview.

The preview shows intervals such as **Every 6–7 minutes**. Open **Schedule
details** to see exact clock minutes and the WordPress path. Long paths wrap
inside the panel; narrow screens scroll only the table.

## Add a filtered-URL rule

1. Open **Filtered URLs** and choose a domain and time window under **Analyze logs**.
2. Review the evidence and coverage. A suggestion is not a legitimacy verdict.
3. Fix application links, missing assets or expensive work in the site when that
   is the appropriate remedy. Manage unwanted filter crawling separately from
   security probes; do not convert valid pages into 404s.
4. If a protection rule is still appropriate, click **Add rule**, select domains,
   parameter names, declared crawler names and an explicitly chosen rate/action.
   New rules start disabled. An empty domain selection means all web domains.
5. Enable only the reviewed rule and **Save & Apply**.

Existing rules remain editable. Ordinary
URLs without the selected parameter names and visitors without the selected
crawler names do not match the rule.

### Complete reviews, progress and privacy

An administrator may select one known web domain or all web domains, and any
positive time window in minutes. Presets are conveniences, not exclusive choices.
The worker reads current and all available numbered rotations, including gzip,
bzip2 and xz, using trusted-owner/no-follow checks and shared-inode deduplication.
There is no addon quota for bytes, elapsed work, domains, groups or distinct counts.
A snapshot boundary leaves newly appended active-log data for the next review.
Logs already removed by retention cannot be reconstructed; coverage and genuine
read errors are reported instead of claiming an incomplete review succeeded.

Reviews run on demand in a low-priority background process, separate from
protection/recovery transactions. Progress, cancellation and resumption survive
a panel reload or lost HTTP response. Requests wait in a serialized queue rather
than being rejected when another review is running. No periodic collector or
public request-time script is installed. Reviews never modify protection rules,
ban counters, firewall rules or website files.

Exact aggregates and complete findings are stored in root-private SQLite files
under `/var/lib/hestia-de-noise/analysis-jobs/`. Display pages contain 20 findings;
all pages are available. Activity uses the same background workflow and exposes
every retained event in the chosen window, limited to the viewer's domains.
Opening the panel fetches job metadata rather than rescanning logs. Completed,
failed and cancelled reports older than the selected history retention are
removed when a new review starts; active work is never removed by that cleanup.

Filtered-URL review reports do not return or retain query values, raw client IPs
or raw User-Agents. Distinct client/combination counts use one-way digests in private
aggregation. Sensitive path segments remain redacted with distinct hash labels.
Unsaved protection-rule edits survive report updates and page navigation.
Resuming a report restores its time window/domain/verification selection unless
the operator has already edited the review controls. Ordinary image/icon paths
are omitted from findings, including missing images; total record counts retain
them. Explicit secret-probe evidence is kept even when its path ends in an image
extension. Script, stylesheet and other non-image faults remain diagnostic.
Recommendations favor site repairs before a crawler rule. Optional filter
candidates contain only the finding's own domain, path, parameter names and
observed crawler names; they never create a rule, choose a rate or ban visitors.

Activity's existing conditional native Nginx log now also stores the full declared
User-Agent with JSON escaping. Both grouped counts and individual events show it.
Legacy records have no agent and display Not recorded; an empty header displays
Not sent. Activity records still omit client IPs, URLs, query strings, cookies and
request bodies. Agents are untrusted client claims and are escaped in the panel.
The same trusted-log access, owner scope, rotation and report retention apply;
no extra collector, periodic scan or per-request script is installed.
Native access-log records are not total incoming traffic or proof of PHP work:
early blocks/cache HITs may be absent and layered logs may duplicate records.
Timing/cache information is shown only when already recorded; no logging
configuration is added to collect it.

Optional Googlebot verification downloads only Google's public common-crawler
CIDRs, without a separate addon work deadline, and uses a root-private 24-hour cache
at `/var/lib/hestia-de-noise/google-common-crawlers.json`. No visitor data is sent
to Google and no per-request DNS lookup occurs. A source-range match is not a
verdict that the requested URL is useful or harmless. Missing/failed verification
stays unconfirmed. Verification depends on the address already recorded in logs;
incorrect proxy/client-IP configuration affects its usefulness.

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
client IP, domain, a fixed reason, a non-secret rule digest, path and method,
without query strings, headers, cookies or request bodies. A root-private
`/var/lib/hestia-de-noise/bans.sqlite` stores counters, rotation cursors, expiry
and native/domain ban state and completed history, with independent log cursors.
The state directory is root-owned `0700`; the SQLite database and separate
`history-settings.json` are root-owned `0600`. Logs are root-owned `0640`.
General 404 counting
also reads the existing Hestia combined logs in `/var/log/apache2/domains/`,
incrementally, at most 2 MiB per scope per sync and 256 KiB per file. Domains
rotate through the read budget. Native static responses and Apache origin
responses use that shared native log; local Nginx 404s inheriting server logging
use a query-free ban event instead. Only the method and stripped path are copied
into addon storage. This targets the standard Hestia Apache2 combined-log layout.
A root-private
`domain-ban-applied.json` records the last successfully applied domain rules and
participates in configuration recovery. Maintenance output contains counts and errors rather
than repeatedly dumping the IP table.
Activity reads all retained rotations for the selected interval when explicitly requested. It is not a total-traffic or CPU measurement. The addon installs a daily logrotate policy retaining seven rotations, with a
10 MiB size trigger when logrotate runs. Existing server logs remain separate.

Global bans support **IPv4 and IPv6**. IPv4 uses native Hestia commands; IPv6 uses an addon-owned `ip6tables` chain restricted to TCP 80/443, with a root-private ownership journal. Reconciliation restores owned IPv6 rules after a native firewall reload. Domain-only Nginx bans also support both families. There is no automatic change
to SSH, panel, mail ports, the existing Fail2ban jails or recidive policy. Ordinary
unselected 404s trigger bans only when general 404 counting is enabled. Missing
static assets are excluded by default. Denied User-Agents and crawler rate limits do not count as
404s. Loopback, local server addresses and the explicit never-ban list
are excluded from automatic bans, along with native Hestia IP exclusions; no administrator public IP is inserted
automatically. Bans use Nginx's configured client address, not arbitrary
forwarded headers. Never-ban entries do not bypass request filtering.

Firewall additions/removals are processed in resumable batches, up to 100
operations and approximately ten seconds of work per synchronization. Pending
work and native failures are visible in IP bans; large queues can take more than
one sync. Active and completed IP lists are paginated, 50 rows per page; this is
a display limit, not a total ban cap. Hestia stores individual IPv4 rules in this
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

The panel JavaScript regression tests require Node.js on a development machine
only; Node.js is not a server runtime dependency:

```bash
node --test tests/panel-settings.test.cjs
```
