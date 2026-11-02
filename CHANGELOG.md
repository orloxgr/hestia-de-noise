# Changelog

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
