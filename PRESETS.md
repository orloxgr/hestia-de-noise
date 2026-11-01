# Proposed presets

These are editable suggestions for the planned panel, not deployed rules.
They cover repeat endpoint traffic, excessive filtered-URL crawling, private-file
probes and missing static files. Applying a preset is an explicit admin action.
Presets are bundled and versioned; the addon does not import changing third-party
deny lists or enable new restrictions automatically during an update.

## Endpoint suggestions

| Preset | Path and method | Suggested initial setting |
| --- | --- | --- |
| WordPress login forms | POST `/wp-login.php`, including normalized slash variants | 5 requests/minute/client/site, burst 3; editable |
| WordPress XML-RPC | POST `/xmlrpc.php`, including normalized slash variants | 10 requests/minute/client/site, burst 3; editable; optional block when unused |
| WordPress AJAX | `/wp-admin/admin-ajax.php` | Observe only; no general rate limit |
| WordPress REST | `/wp-json/` | Observe only; restrict only explicitly selected routes |
| Private environment files | Selected `.env` and `.env.*` file paths | Reject when this preset is enabled |
| Source-control metadata | `/.git` and `/.git/` descendants | Reject when this preset is enabled |
| WordPress configuration backups | Selected `wp-config.php.bak`, `.backup` and `.old` paths | Reject when this preset is enabled |
| Filtered listing pages | Admin-selected listing paths and query parameter names | Observe initially; offer an explicit crawler restriction or rate limit |
| Missing generated static files | An admin-selected static directory, optionally a generated-image cache directory | Direct 404 only after explicit selection; retain dynamic-generator exceptions |

Login and XML-RPC rates are starting suggestions, not universal safe capacities.
Show the rate and scope before applying them. Existing integrations can receive
specific exceptions. Login protection covers POST-body actions too, rather than
depending only on the query-string action. Do not disable password recovery,
customer login, XML-RPC integrations, AJAX or REST silently.

Parameter names for filtered listings are site-specific. Suggestions can be
derived from bounded local traffic summaries, but no site-specific parameter or
rule is inserted into a global preset automatically. Preserve indexable landing
pages and working visitor filters. The private-file preset must not match broad
prefixes such as `/api/` or `/config` and must preserve `/.well-known/` behavior.

## User-Agent suggestions

| Group | Entries | Panel behavior |
| --- | --- | --- |
| Initial candidates | `meta-externalagent`, `GoogleOther`, `MJ12bot` | Offer one-click insertion into the editable blocklist |
| Additional candidates for review | `Bytespider`, `ClaudeBot`, `Reflectionbot`, `ElevenlabsCrawler`, `Amazonbot` | Show separately; operator decides whether the associated service is wanted |
| Search and user-requested retrieval | Googlebot, Bingbot, Applebot and other search/retrieval agents | No automatic block or challenge |
| Sharing and previews | `facebookexternalhit`, `meta-externalfetcher`, `Twitterbot`, `LinkedInBot`, Slack, WhatsApp, Telegram and Discord fetchers | No automatic block or challenge |

The group labels are recommendations, not identity verification. Do not use
browser strings such as `Chrome`, `Mozilla` or an old browser-version token as a
general deny rule. Scanners can claim browser or search-bot names. Endpoint and
private-file rules work independently of those claims.

Keep `GoogleOther` distinct from Googlebot, `ClaudeBot` from search-oriented
Claude agents, and bulk collection from user-requested retrieval. Operators may
still enter their own literal entries; the addon does not secretly ignore them.

## Operator workflow

1. Open a module and choose a preset.
2. Review its explicit scope, action and suggested rate or entries.
3. Edit or remove entries and choose applicable domains/exceptions.
4. Save & Apply in Observe or Enforce mode.

There is no mandatory observation period, automatic application inspection,
WordPress installation prerequisite or hidden scanner-approval step.
