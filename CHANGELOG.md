# Changelog

## 0.26.1 · 2026-11-23

- Put Analyze current agents in a native accordion; retain its form, report and background-job behavior when collapsed.
- Rename the existing general category to Data Collection / Monitoring / Various. Split optional collection and monitoring append buttons in both editors, retaining the same saved category, switches and shared group budget.
- Add a separate Various picker with unchecked individual choices, descriptions, source links where confirmed, and destination-specific append. Preserve current edits and manual append; no save, enable or stored-list insertion occurs automatically.
- Add optional RiverBot/PostHog training, Keenable/Seznam/Sofya/Qwant/Sogou search, l9scan/Modat scanning and webXtrend/KStand collection suggestions. Recognize generic automation and uncertain declarations for review without bulk suggestions; do not attribute Bravebot to Brave Search or treat HeadlessChrome as a security scanner.
- Prefer specific bot declarations over generic renderer/library tokens in new analysis. Preserve distinct search/image/news and user-triggered products, all stored rules and schema 17. Keep native request matching, budgets and Nginx transactions unchanged.

## 0.26.0 · 2026-11-23

- Give all five User-Agent categories a full-width accordion, with independent block and group-rate lists side by side and a full-width editable individual-rule table below. Keep presets/analyzed append destination-specific, preserve unsaved edits, and show effective-action previews, validation and button tooltips.
- Add native server-wide group budgets shared by all listed bots across every protected website/IP, plus individual budgets that override all groups and blocklists. Match individual first, then group, then block; use longest literals within a rate level. Require resolution of conflicting duplicate settings. Keep independent protection rules active.
- Support requests per minute/second and burst without queuing; reject excess requests with 429 and do not create IP bans. Count all matching paths/methods, including static assets. Separate Observe and Enforce counters; Off does not count.
- Migrate schema 16 to 17 with empty inactive rate settings and preserve every existing choice. Older open panels retain saved new settings. Keep administrator backend permissions and existing Nginx validation/reload/rollback transactions.
- Identify group/individual matches in Activity and retain the overall native rate result in individual records and complete CSV, with honest attribution when other independent limiters apply.
- Add Parallel's ShapBot to optional additional Search Indexers suggestions and purpose information. Do not add it to saved lists on upgrade.

## 0.25.1 · 2026-11-16

- Classify Bytespider, ElevenlabsCrawler, CCBot and VelenPublicWebCrawler under AI Training, with descriptions noting the mixed research/business uses of Common Crawl and Velen. Put YisouSpider and ZoominfoBot in Additional search, including specialized business search.
- Rename Other Crawlers / Data Collection to Data Collection / Monitoring. Keep GoogleOther, AwarioBot, ImagesiftBot, Magpie-Crawler and RecordedFuture there; keep the existing five categories and editor keys.
- Update purpose information and sources. Change suggestions and new analysis classification only; preserve every saved list, enable switch and effective blocking choice without a schema migration.

## 0.25.0 · 2026-11-16

- Split the Search editor's append presets into Add additional search bots (alternative/regional engines) and Add major search & AI bots (including Google, Bing, Meta and AI search). Both append to the same blocklist, with visibility warnings and button tooltips; neither saves, enables or replaces existing entries.
- Recognize all 50 distinct names in the community list. Add 10 SEO, six search and six other data crawlers, with purpose information and sources. Recognize six unconfirmed names and three generic client declarations for individual review without adding them to bulk suggestions.
- Keep the existing five purpose categories, independent switches, saved lists and policy schema. Keep training, search, user-triggered fetches, advertising and link-preview clients distinct. No blocking policy changes on upgrade.

## 0.24.0 · 2026-11-16

- Add a Global exceptions box to Disable XML-RPC with a general IPv4/IPv6/CIDR field and its own Allow Jetpack button, using the same append workflow as each site's box. Keep global and site lists independently editable; neither button changes switches, site selections or other lists.
- Combine global and per-site exceptions for XML-RPC on protected sites and their aliases, including sites selected later. Continue enforcing other De-Noise rules, firewall bans and XML-RPC rate limits.
- Migrate schema 15 to 16 with an empty global list while retaining existing policy. Preserve saved global exceptions when older panels submit and allow the current form to clear them explicitly.

## 0.23.1 · 2026-11-16

- Add Allow Jetpack beside each site's XML-RPC exceptions. Download the current official IP list on demand and append missing ranges without replacing manual entries, concurrent edits, switches or domain selections. Keep Save & Apply explicit; do not automatically save or enable protection.
- Use an authenticated, CSRF-protected administrator lookup with a fixed official source. Validate the entire download before returning ranges; failed or malformed replies leave the editor untouched. Keep lookup outside protection locks and mutation recovery.
- Simplify the XML-RPC instructions and retain manual IPv4/IPv6/CIDR exceptions. IP refresh is on demand and additive; obsolete entries can be removed manually.

## 0.23.0 · 2026-11-16

- Add per-site IPv4/IPv6 and CIDR exceptions to Disable XML-RPC in Endpoints. Allowed sources reach XML-RPC on that site and its aliases; unlisted sources remain blocked. Keep all other De-Noise rules, firewall bans and XML-RPC rate limits in force.
- Compile native Nginx geo checks against the actual client address, without trusting arbitrary forwarded headers or User-Agent names. Link the editor to Jetpack's official current IP list and instructions.
- Migrate policy schema 14 to 15 while retaining switches, site selections and existing settings. Preserve exceptions when an older already-open panel saves; retain saved entries for unavailable sites and across paginated rows.

## 0.22.0 · 2026-11-16

- Port Webuzo De-Noise's per-site Disable XML-RPC feature into the native Hestia Endpoints panel. Select sites with checkboxes and Select all / Clear selection across pages; an empty selection protects no sites. Start disabled and empty on upgrade.
- Reject XML-RPC requests in Nginx before WordPress in Enforce, including aliases, subfolder installations, path-info and decoded URI forms. Observe logs without blocking and Off keeps routing. Keep the feature separate from XML-RPC POST rate limiting and automatic IP bans; identify XML-RPC disabled in Activity.
- Migrate schema 13 to 14 while retaining existing policy. Preserve saved XML-RPC choices when an older already-open settings panel submits, using a dedicated presence marker in the current form.

## 0.21.0 · 2026-11-15

- Add configurable attempts and counting window to selected-path final-404 bans. Count repeated requests per IP across selected paths/domains, preserve real-status routing, self/exclusion checks and expiry. Reconcile overlapping native/structured log source counts without summing duplicate layers; retain genuine same-second repeats within each source. Capture the actual threshold/window in ban details.
- Migrate policy schema 12 to 13 with threshold 1 and a 300-second window. Preserve existing paths/scopes/durations and saved attempt controls when an older open panel submits. Reset counting activation when threshold/window changes.
- Replace grouped finding previews with native multiple-selection lists. Append only selected paths, with Select all / Clear selection, independent manual 403 and observed-404 actions, and no action for an empty selection. Keep per-row/page append and existing settings.
- Display Press CTRL to select/deselect beside every native multiple-select list, including domains, findings and cloned rule templates.

## 0.20.3 · 2026-11-15

- Restore manual append for every exact endpoint finding, independent of classification and recommendation: per-row and grouped disabled domain-scoped 403 rules, and per-row/group/page append to the exact 404 list for any recorded 404, including JS, CSS, PHP and mixed-status paths. Keep advice separate from manual capabilities; retain observed successes and real-final-404 ban behavior.
- Include all finding categories in grouped results and export every available exact 404-list path. Keep exact-path deduplication, existing switches/durations/scopes, and individual rules instead of giant generated regexes.

## 0.20.2 · 2026-11-15

- Organize Endpoints into native Hestia accordions: exact-path 404 bans, custom rules, log analysis/suggestions, WordPress login limits and XML-RPC limits. Show persistent chevrons on section and suggestion headers in both open and closed states, with keyboard focus and responsive spacing.
- Open the custom rules section when appending a suggestion or adding a rule. Keep form associations, submitted settings, rule behavior and background review IDs intact.

## 0.20.1 · 2026-11-15

- Remove suggested block/ban actions for ordinary PHP/core/plugin/theme paths, JS, CSS and application routes. Keep their evidence and investigation/repair advice. Offer 404-list candidates only for sensitive/backup paths with exclusively 404 responses; restrict disabled 403 suggestions to configuration backups and secret/repository paths. Reassess saved reports and CSV with the same criteria.
- Prepare individual domain-scoped exact 403 rules instead of a large generated alternation regex, preserving disabled state, IP banning off and deduplication.
- Lay out suggestions as responsive cards with full-width exact-path previews, separate wrapping actions and explicit mouse-over descriptions for 403, 404-list and selection controls. Explain the effect of appending to an already enabled 404 list.

## 0.20.0 · 2026-11-15

- Review all retained non-image URL paths, including JS, CSS, PHP and application routes. Remove the previous backup/secret-only discovery filter. Keep every response status and identify the same missing path across domains, without assuming every asset 404 is a broken site reference.
- Add concrete grouped rules/fixes, exact observed-filename regex proposals scoped to the source domain, saved-report filters and review notes. Include proposed action, rule, scope and exact 404-list candidate in CSV. Normal delivery remains normal; missing assets, application errors and filename probes receive different recommendations. Existing saved reports gain suggestions; a new scan collects the broader path coverage.
- Add a bulk exact-path 404 instaban list in Endpoints, with any file extension, domain selection and exact duration. Ban on the first real final 404 in Enforce; do not change routing or manufacture a rejection. Read native access logs and structured final-404 events, deduplicate through the existing ban lifecycle, preserve exclusions/self-IP protection, and count from activation rather than retroactively banning retained history.
- Append selected 404 paths or complete proposal path sets in bulk, preserving enable switches, durations and existing selections. Keep the new list disabled/empty on upgrade and preserve it when an older open settings panel saves. Remove the old browser-only path-search length reset; control-character validation remains.

## 0.19.0 · 2026-11-15

- Add named custom endpoint rules in Endpoints: exact paths or native PCRE regex, per-domain/all-web scope, 403 in Enforce and match logging in Observe. The first matching rule determines the action; existing files are included. No query/header/cookie matching or new automatic block defaults.
- Add optional first-match native Hestia firewall IP bans with exact seconds/minutes/hours/days duration (0 = permanent), independent of the existing global probe-ban switch. Preserve exclusions, self-IP protection, manual unban, expiry and reboot reconciliation; retain rule name and path in ban evidence and identify the rule in Activity.
- Add read-only Analyze endpoint logs for backup/database and secret/repository path suggestions from retained native logs, including compressed rotations and every response status. Show domain/path counts, successful responses, methods, declared agents, distinct clients, coverage, pagination and complete CSV. Appending prepares a disabled domain-scoped exact rule with banning off; analysis never enables protection.
- Preserve existing policy on upgrade and custom rules when an older open settings panel saves. Validate PCRE with native Nginx and the existing apply/rollback transaction; escape config syntax without imposing arbitrary regex/list limits.

## 0.18.3 · 2026-11-15

- Show timestamped installer stages, actual work counts where available and a current-stage heartbeat during slow work or lock waits. Reporting adds no work deadline and stays silent outside the administrator installer.
- Replace the default final JSON dump with a readable success/failure summary, installed version, full result details and elapsed time. Retain explicit `--json` mode with progress/diagnostics on stderr and one JSON document on stdout; preserve native failure details and nonzero exit status.
- Keep panel, background and internal JSON interfaces unchanged. Respect `NO_COLOR` and plain redirected logs; a closed reporting stream cannot cancel completed installation work.

## 0.18.2 · 2026-11-13

- Explain Back, Synchronize now and Disable everywhere with mouse-over descriptions, including saved versus unsaved settings and the scope of global deactivation.
- Give direct secret/repository probes, general repeated-404 bans, per-domain probe exceptions, ban status and domain automatic bans the same collapsible sections as selected PHP/query probes. Keep their controls, values and save behavior intact.

## 0.18.1 · 2026-11-13

- Place Analyze PHP 404s inside IP bans → selected missing PHP files, next to the list it enriches, matching the Webuzo workflow. Keep the analyzer outside the remotely replaced ban-history fragment and available independently of the ban enable switch.
- Align the administrator navigation with the twelve-section Webuzo layout: show Domains in General and preserve domain-specific ban controls in IP bans. Keep the owner's four scoped tabs and existing permissions. Use bordered full-width tab cells, readable mixed-case labels and a clear selected state; retain old tab links as aliases.
- Verify the rendered form placement, absence of nested forms and browser analysis/append flow in the Hestia VM.

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
