# Hestia De-Noise

Central request filtering for HestiaCP, before requests reach Varnish, Apache or PHP.

**Status: project definition. The installer and panel are not implemented yet.**

## Planned controls

- **User-Agent blocklist:** one literal, case-insensitive substring per line.
- **Endpoint rules:** allow, rate-limit or block selected paths and HTTP methods.
- **Scanner rules:** reject explicitly selected probes for private files and backups.
- **Filtered URL rules:** optionally restrict crawling of selected query parameters.
- **Static file rules:** optionally return a direct 404 for missing files in explicitly
  selected static directories, rather than invoking the application.
- **Activity:** request counts, matched rules and response status, without recording
  passwords, cookies, authentication headers or query parameter values.

The administrator manages server defaults, domain exceptions and bulk changes.
The panel will provide an enable switch, Save & Apply and Disable & Restore.
Endpoint, scanner, filtered URL and static file rules are opt-in. Existing domains
retain their application routing until an applicable rule is explicitly enabled.

## Hestia and Varnish integration

- Keep each domain's selected proxy template, including Varnish templates.
- Use Hestia's native `nginx.conf_*` and `nginx.ssl.conf_*` include points.
- Install only addon-owned files; retain existing Hestia code and templates.
- Maintain one central policy and generate the required includes automatically.
- Cover existing and newly created domains without manual per-domain files.
- Support an explicit exception for any domain; report unsupported templates.
- Validate the candidate Nginx configuration before reload. If validation fails,
  retain the active policy and show the actual command error in the panel.
- Remove only addon-owned files during uninstall.

## Search and sharing

Unmatched requests remain allowed. Search crawlers, social preview fetchers,
ordinary visitors, existing `robots.txt` responses and sitemaps are unchanged by
default. A bot's declared User-Agent is not identity verification: endpoint and
scanner rules must not be bypassed merely by claiming a search-engine name.

XML-RPC, login and application APIs may serve legitimate integrations. Rules for
these endpoints require explicit configuration, with domain exceptions available.
Filtered URL rules must preserve the site's intended indexable URLs and visitor
functionality. Missing-file rules apply only to declared static paths and must
not replace application image-generation or download handlers accidentally.

Request counts identify traffic volume, not CPU time per request. Application
profiling remains separate from the request filter.

## Installation

No server installation is available yet. Install commands will be added when a
tested installer exists.

Repository: https://github.com/orloxgr/hestia-de-noise
