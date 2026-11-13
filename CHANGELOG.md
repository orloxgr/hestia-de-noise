# Changelog

## 0.18.0 · 2026-11-13

- Adapt the reusable Webuzo De-Noise 0.4.3 analysis/panel features to native Hestia discovery, logs and CLI. Keep delegated domain bans, administrator/account ownership, native IPv4/IPv6 enforcement, existing Fail2ban integration and CAPTCHA fixes. No Webuzo dependencies or replacement firewall backend.
- Split agent controls into five independent purpose-based lists. Migrate existing literal entries and enabled/disabled choices without adding blocks. Recognize declared crawler products across versions; explain operator, purpose, usefulness and sources without treating a name as authenticated identity.
- Add complete on-demand agent and PHP-404 inventories, resumable background workers, exact per-domain counts, repeated-directory grouping and pseudonymous client-pattern evidence. Append exact selected paths/names or recognized category members to unsaved lists without saving or enabling rules.
- Add full-report finding filters, exact domain/path review notes, separate evidence priorities/tags, rejected-probe grouping and known application endpoint descriptions. Ignore technical cron/cache tokens as content-filter dimensions; retain genuine errors and probe evidence.
- Add shared 20/50/100/500/All pagination and complete CSV exports, including scoped domain-ban exports and grouped exact-path expansion. Preserve unsaved settings across remote list navigation; escape spreadsheet formulas and reject incomplete transfers.
- Parse Activity records with an empty Nginx limit status correctly. Resolve the CAPTCHA socket group using native Nginx directive/build semantics. Keep Hestia session/CSRF and trusted-storage checks, without arbitrary report/search length caps.
- Validate in the Hestia VM with the Python/native-Nginx suite, JavaScript regressions, authenticated admin/owner workflows and browser append/pagination tests.

## 0.17.2 · 2026-11-13

- Complete successful CAPTCHA submissions with a local confirmation document before navigating back to the requested URL. Avoid Chromium applying the form's CSP restriction to the application's subsequent canonical-host/SSO redirects; retain same-origin form submission, signed host-specific cookies and existing CSP protections.
- Use immediate native HTML navigation with a plain Continue fallback, without JavaScript or external services. Keep Activity's verified event distinct from displayed/retried questions.
- Extend browser verification through correct answers and the actual WordPress login, including configured alias-to-canonical redirects. Read the visible question image in test code, without introducing an answer endpoint or bypass in the product.

## 0.17.1 · 2026-11-13

- Restore saved IPv4 bans after reboot/firewall reload removes the live De-Noise chain or rules. Queue reconciliation instead of aborting all maintenance on the first saved-record/firewall disagreement.
- Handle Hestia's early exit for an already recorded IP by restoring only the missing DROP rule. Reattach detached, validated web-only chains without rebuilding other firewall rules.
- Preserve original ban times and expiry, finish partial native panel unbans, and avoid restoring expired/disabled/exempt bans. Keep per-IP restoration failures pending while continuing independent work; retain ownership and unmanaged-rule checks.
- Verify reboot loss, detached jumps, individual missing rules, expiry, partial unban and unrelated SSH preservation through regression tests and real iptables in an isolated network namespace.

## 0.17.0 · 2026-11-13

- Add a local image math CAPTCHA as an alternative to HTTP username/password in WP access, with the existing central → account → domain inheritance. Keep saved HTTP/Off profiles unchanged during upgrade.
- Add a responsive challenge card, new-image control and configurable browser verification lifetime (six hours by default). Verify signed host/protocol-specific clearance cookies natively in Nginx, with no service call on ordinary or cleared requests.
- Render and verify questions in a socket-activated, restricted local Python service without WordPress, external scripts, API keys or image dependencies. Keep single-use expiring question state, root-private signing/derived keys and same-host return targets; never retain/replay original login POST data.
- Preserve frontend AJAX/admin-post/customer exceptions, internal-request bypass, Observe/Off and existing explicit denials. Wrong CAPTCHA answers do not create IP/account bans. Add clear Activity events without tokens, credentials or cookies.
- Install/update/remove the managed service units with the addon, stop the service when the last CAPTCHA is disabled, and retain transactional Nginx/settings rollback.

## 0.16.0 · 2026-11-10

- Add central → account → domain profiles for the WordPress HTTP gate and country policy. Accounts and domains can inherit, override, or disable protection independently; future domains inherit automatically.
- Add explicit inheritance controls and show the effective profile source. Allow custom profiles to inherit the parent password so central/account rotations propagate without replacing other controls or exposing password hashes.
- Preserve all 0.15 domain settings as explicit overrides, including disabled profiles. Keep access settings separate from the General form and enforce administrator/account/domain ownership for each operation.
- Resolve inherited settings consistently for native Nginx maps, private password publication, country database refresh and transactional rollback. Verify central defaults, account Off, domain overrides and country rules through real Nginx requests in the VM.

## 0.15.0 · 2026-11-10

- Add optional per-domain WordPress HTTP access gates for administrators and domain owners, with exact same-origin/Referer bypass, frontend handler exceptions, salted hashes and worker-readable private password files. Direct login GET/POST requests are challenged in Nginx before the backend; Observe/Off do not challenge. Existing protection remains unchanged until explicitly enabled.
- Add independent domain country allow/deny policies, administration/entire-site scope and an explicit unknown-country choice. Native Nginx IPv4/IPv6 geo tables use one locally compiled GeoLite2 Country database; no per-visitor scripts, API calls or extra Nginx module. Preserve ACME certificate validation.
- Add administrator database download/update controls, root-private central MaxMind credentials, weekly optional refresh and last-working-data retention on failure. Strip credentials from download redirects.
- Keep access settings separate from the global policy, enforce domain ownership and CSRF, and journal settings and published password files together for rollback. Report existing independently managed authentication conflicts.
- Record actual HTTP challenges/country denials and Observe candidates in Activity, without creating IP bans or logging authentication secrets.

## 0.14.0 · 2026-11-10

- Add an Activity site filter for both grouped counts and all event pages. Filter the saved private report instead of rescanning logs or filtering only the visible page; preserve admin/owner job scope and parameterized SQL.
- Show the exact saved review time range, including reports created before this version. Resumed reports no longer appear to represent a rolling last-N-minutes window; timestamps use the viewer's local browser formatting.
- Separate blocked, no-recorded-block and observe-only totals. Combine outcomes into one summary row per site/rule/full User-Agent, retain full escaped agents in expandable details, and explain that a match is not proof of abuse, a block or an IP ban.
- Preserve all protection settings, thresholds, bans and native request-time logging. This update adds no collector, periodic scan or per-request script.

## 0.13.2 · 2026-11-04

- Treat the four known UltraCache revalidation/bucket transport parameters as technical query arguments, avoiding misleading crawl-filter candidates from changing cache tokens.
- Preserve real content-filter dimensions, all traffic totals and error/slow-route/secret-probe diagnostics. Parameter names do not authenticate a caller or exempt any request from protection; arbitrary UltraCache-prefixed names remain analyzable.

## 0.13.1 · 2026-11-04

- Exclude ordinary image/icon requests from log-review findings, including 404s and slow/error responses. Retain honest traffic totals and explicit secret-probe evidence; existing ban settings are unchanged.
- Recognize SVGZ, JPEG XL and HEIC/HEIF images in the existing optional static-file exclusion for general 404 bans.
- Give each finding concrete next steps. Crawl-space candidates show the original domain, path, parameter names and observed crawler names for an optional domain-specific rule, without inventing a rate or applying protection.
- Restore a resumed review's actual time window, domain and Google verification choice without overwriting edits made for the next review.
- Record the full declared User-Agent in the existing conditional native Activity log using JSON escaping. Show it in grouped counts and event pages; older records remain readable and say Not recorded. No extra collector or request-time script is added.
- Align the installer/panel version with the release metadata.

## 0.13.0 · 2026-11-04

- Complete log and Activity reviews run as root-private, low-priority background jobs with progress, cancellation and resumption. New reviews queue without discarding work; panel sessions are released while work continues.
- Read all available numbered/compressed rotations, with no addon byte/time/domain/group/distinct-count quota. Exact disk-backed aggregates and paginated results expose every retained finding and activity record.
- Preserve authenticated admin/owner scopes, CSRF, trusted file/log access, privacy, managed-file ownership and configuration rollback. Reviews never apply protection rules or bans.
- Remove addon limits on settings/list counts, managed files, transport output, cron range, ban evidence, maintenance operations and WordPress Unban all. Native format checks, chosen thresholds and history retention still apply.
- Complete firewall synchronization until finished, leaving genuine failed operations pending while attempting unrelated operations. Support owned IPv6 web-only bans alongside Hestia's IPv4 backend.
- Remove addon administrative deadlines and Referer interstitials. Complete both child output streams without pipe deadlocks; report actual native failures.
- Keep exact native Fail2ban escalation durations, including permanent bans, for arbitrary valid administrator-selected first durations.

## 0.12.1

- Fix Analyze logs submitting to an invalid URL because Hestia's hidden action
  input shadows the form's action property. Preserve the intended form URL,
  CSRF token, selected scope and unsaved protection settings.
- Report HTTP failures and unexpected panel responses accurately; only identify
  an expired session when the response redirects to Hestia's login page.
- Add JavaScript regression coverage for named form controls, response errors
  and report-only updates; verify submission against a strict browser fixture.

## 0.12.0

- Add an administrator-triggered native-log review in Filtered URLs, scoped to
  one domain or all web domains, with 30-minute, 6-hour and 24-hour windows.
  Report actual patterns, HTTP statuses, declared agents, burst/diversity counts
  and explicit read coverage; never apply a rule, return a new 404 or ban an IP.
- Separate site faults, crawl-space candidates, known probe signatures and
  diagnostic traffic. Missing assets, virtual PHP routes, REST/AJAX and ordinary
  high activity are not classified as malicious solely from frequency or 404s.
- Bound each scan to 64 MiB and an 8-second processing budget with limited route
  groups/distinct counters. Use a separate nonblocking scan lock, lower process
  priority, no maintenance hook and no protection/recovery transaction lock.
- Add optional Googlebot source-range verification from Google's public CIDRs,
  with a bounded download and private 24-hour cache. No client IPs or logs are
  sent out; unavailable verification leaves claims unconfirmed and does not fail
  the review. Do not infer timing/cache measurements absent from native logs.
- Remove application-specific filtered-URL insertion presets. Preserve saved
  rules unchanged. New manual rules start disabled with empty parameters,
  crawler names and rate, requiring an explicit operator choice.

## 0.11.0

- Expand the literal missing-PHP preset from 219 to 265 paths. Upgrade an exact
  previous bundled list, including schema-9 policies; retain edited lists,
  exceptions, thresholds, enabled states, existing bans and all other choices.
  Existing files continue through their normal routing.
- Add ibou-search to the separate optional search-crawler suggestion. Add a
  per-filter-rule button to merge those crawler names without changing global
  blocklists, the rule's domains, action, rate or existing names.
- Add on-demand robots.txt directive previews for individual filtered-URL rules,
  scoped domain labels, validation and copy controls. These are suggestions for
  URLs that should not be indexed; existing robots.txt files are never rewritten.
- Retain webmail's explicit enable control and general-404 static exclusions.
  No new runtime scripts, collectors, scheduled tasks or shared user quotas.

## 0.10.0

- Add an administrator User enumeration tab with independent REST user-list,
  author-ID discovery and optional author-archive switches, selected/all-domain
  scope, and hover help. Preserve existing modes and keep new protection off.
- Reject credential-free enumeration at Nginx before PHP. Install a small owned
  WordPress MU guard only for selected standard WordPress sites in Enforce, using
  the hosting user's privileges. WordPress verifies authentication; spoofed
  cookies/headers cannot bypass the guard. Preserve authenticated API/editor
  operations, ordinary REST routes and password reset flows.
- Journal companion/Nginx changes together, refuse unmanaged files/custom content
  directories, preserve host scope for shared roots, and remove owned guards on
  disable/uninstall. Avoid recurring helper processes for unchanged sites.
- Record native enumeration rejections in existing Activity without adding ban
  counters, shared quotas, log collectors or resident services. Clear the site's
  native Nginx cache when enabling/changing protection on caching templates.
- Arrange twelve administrator tabs in two equal full-width rows, six per row,
  without a horizontal scrollbar. Keep native tab behavior and keyboard navigation.

## 0.9.0

- Fix Activity, automatic-ban event reading and installer upgrades after Nginx
  reopens logs under its configured worker user. Keep root-controlled directories,
  regular-file checks, no-follow opens and protection against writable logs.
- Show unavailable Activity without a zero request count. Record the last
  successful maintenance and failures from the complete synchronization pipeline.
- Add missing-static-asset exclusion and minimum different-path controls for
  general 404 bans, shared by global/domain scopes and early/native log sources.
  Enable these guardrails on upgrade while retaining thresholds and active bans.
- Add a detailed rate-limit error-log switch; expected rejections use notice
  level by default, retaining Activity and genuine error reporting.
- Add 26 literal PHP probe suggestions, training crawlers and a separate optional
  search-crawler preset. Preserve custom lists and enabled states.
- Add an optional VLM place/route filter preset and webmail HTTP protection using
  existing native includes, without modifying templates or SMTP/IMAP settings.

## 0.8.0

- Page global and domain IP lists in SQLite, 50 records at a time, with stable
  ordering, total counts and separate Active bans / History views.
- Page WordPress login IPs from the existing on-demand Fail2ban command without
  changing that jail's history or adding periodic status reads.
- Retain completed bans and their reason/evidence for 30 days by default. Add
  administrator retention controls and scope-aware Empty history buttons.
- Keep active/permanent bans, pending removals, counters, cursors and native
  Fail2ban repeat history independent of history cleanup.
- Preserve original ban timestamps/evidence through native unban and repeated
  bans; archive domain removals only as completed after their rules are unapplied.
- Keep the existing core database table layouts and native firewall formats.

## 0.7.1

- Record escaped, query-free request paths and methods for native Nginx ban
  events, including early 404s, and extract the same fields from native access logs.
- Show “Why was this IP banned?” for global and owner-scoped bans, with up to
  ten matching requests and the threshold/window/duration captured at trigger time.
- Preserve existing bans, counters, cursors and legacy log compatibility during
  the additive database upgrade. Older bans show that evidence is unavailable.
- Keep saved policy, counting behavior, exclusions and ban durations unchanged;
  no query strings, cookies, headers or request bodies are added to addon evidence.

## 0.7.0

- Add an administrator WordPress logins tab with enable, threshold/window,
  three-stage ban durations, native Fail2ban status and scoped IP unban.
- Document WP fail2ban as an installed-and-active WordPress prerequisite.
  Do not discover WordPress installations, test plugin presence or install it.
- Adopt the supported standalone WordPress jail using stable jail/action names,
  preserving settings and ban history; keep fresh installations disabled.
- Keep configuration in owned filters/actions and local Fail2ban files; validate
  candidates and journal rollback/recovery. Restore adopted setup on uninstall.
- Query Fail2ban only on explicit panel use; use its existing service for
  IPv4/IPv6 web bans and leave periodic HTTP maintenance independent.

## 0.6.0

- Add optional general 404 bans: 10 responses in 300 seconds, for 3 days by
  default, with independent enable/count/window/duration controls.
- Count repeated URLs, missing assets and origin 404s through incremental native
  log reads plus metadata-only local Nginx events; retain the stricter distinct
  PHP probe counter. Add the same optional switch to owner-scoped Domain bans.
- Expand the PHP probe preset from 138 to 193 exact paths. Update unchanged
  bundled lists automatically, preserve custom lists and keep new bans off.
- Migrate saved policies and preserve new controls when an older panel saves.
- Show Filtered URLs and Missing static files directly inside their tabs,
  removing their redundant outer collapsible sections.

## 0.5.0

- Keep all panel tabs on one row, with horizontal scrolling on narrow screens.
- Show readable Cron intervals and expandable exact schedule/path details;
  contain long paths and tables within the panel without changing saved jobs.
- Add Domain bans for selected-file and suspicious-query protection, editable
  by domain owners for their own supported domains, with an administrator grant.
- Enforce these additional bans in Nginx per domain and aliases for IPv4/IPv6,
  without changing firewall rules or affecting neighbouring domains.
- Reuse administrator lists, thresholds, exclusions and durations; prevent owner
  changes to global policy, exceptions, manual bans and other accounts.
- Process separate counters and log cursors in existing maintenance; journal
  applied domain rules and report active, pending and removing states.
- Preserve existing settings on schema upgrade; leave new per-domain switches
  off until selected. Keep Cron and domain-save forms separate from global settings.

## 0.4.0

- Add separate controls for selected-PHP and suspicious-query 404 bans, each
  defaulting to 2 strikes within 60 seconds and a 3-day duration when enabled.
- Bundle 138 editable exact PHP paths; reject only selected nonexistent files,
  preserve existing files and count distinct paths across domains per IP.
- Match selected query parameters with literal secret targets, traversal and PHP
  filter resource arguments, including supported encoded forms; reject with 404.
- Add independent domain exceptions for file probes and query endpoints, plus
  distinct activity/ban reasons and privacy-preserving event digests.
- Preserve existing ban settings on schema upgrade and stale-panel saves; keep
  the new categories off until selected, with independent expiry and disable.
- Add native Hestia Cron preview/apply/restore controls for existing WordPress
  jobs, preserving commands and rejecting stale previews after native edits.
- Add `YisouSpider` to optional crawler suggestions without changing saved lists.

## 0.3.0

- Add optional native Hestia IPv4 bans for selected secret/repository probes,
  defaulting to one request and permanent duration when enabled.
- Add controls for duration, request count/window, trigger domains, never-ban
  networks, native ban status and selected/all unban actions.
- Process logs incrementally and bans in bounded resumable batches through the
  existing sync job; preserve other firewall chains, ports and Fail2ban policies.
- Add expiry, native-panel unban reconciliation and owned-ban uninstall cleanup.
- Organize the panel with Hestia's native tabs and keep one shared settings form
  across tabs, including validation that opens the affected tab.
- Split scanner tools and crawler entries into independent editable lists with
  separate switches, migrating the previous mixed list without losing entries.

## 0.2.2

- Add per-domain, one-file-per-line exceptions for static-file protection,
  editable inside Missing static files with a domain selector.
- Match normalized exact URL paths, including encoded filenames, across all
  static rules and aliases while retaining ordinary application routing.
- Preserve other filtering modules, existing policy and exceptions when saving
  from an older panel page; migrate previous policy formats on upgrade.

## 0.2.1

- Add visible one-click presets for WordPress source maps, plugin/theme/core
  JS/CSS, product listing filters and VLM directory filters.
- Show paths, extensions or parameter names before insertion; keep the inserted
  rules editable and apply only after Save & Apply.
- Preserve matching existing rules and their settings when a preset is clicked
  again; leave saved policies unchanged during installation/update.

## 0.2.0

- Separate scanner-tool and optional bulk/AI crawler suggestions, including
  TLM-Audit-Scanner; preserve the operator's saved list on upgrade.
- Expand the private-file preset to selected cloud, container, source-control
  and operating-system secret paths, independent of the declared crawler name.
- Add scoped filtered-URL rules with literal path/parameter/agent matching and
  native per-crawler/domain budgets shared across IPs and aliases.
- Add optional early 404 rules for selected missing static files without new
  locations or changes to existing routing/templates.
- Add bounded, owner-scoped activity summaries with separate observed and
  blocked outcomes; migrate existing policies without enabling new modules.

## 0.1.1

- Recognize Hestia's root-owned SSL ACME include symlink to its HTTP counterpart.
- Inspect the target read-only for conflicting rules; retain strict no-follow
  handling for addon-owned files and unrelated symlinks.

## 0.1.0

- First installable preview for Ubuntu and Hestia's Nginx proxy.
- Native panel page and shared Plugins menu entry.
- Literal User-Agent list, suggestions, optional login/XML-RPC limits and private-file rules.
- Server mode, domain mode overrides, bulk selection and read-only account view.
- Addon-owned HTTP/HTTPS includes without switching proxy templates.
- Minute-based discovery of domains and retained policies on update.
- Nginx validation, confirmed reload, transaction recovery and uninstall.
