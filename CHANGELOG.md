# Changelog

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
