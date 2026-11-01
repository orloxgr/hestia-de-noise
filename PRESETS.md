# Presets — 0.2.0

## Scanner tools

**Add scanner tools** inserts these literal names into the editable blocklist:

```text
TLM-Audit-Scanner
sqlmap
Nikto
Nuclei
zgrab
masscan
ZmEu
DirBuster
gobuster
ffuf
WPScan
```

These are scanning tools; authorized scans can use them too. The list matches
declared names and is not identity verification.

## Optional bulk / AI crawlers

**Add bulk / AI crawlers** inserts:

```text
meta-externalagent
GoogleOther
MJ12bot
Bytespider
ClaudeBot
Amazonbot
Reflectionbot
GPTBot
AhrefsBot
SemrushBot
DotBot
BLEXBot
```

These are collection, training or SEO-analysis crawlers, not inherently malicious
services. Use the group only when that traffic is unwanted. Googlebot, Bingbot,
Applebot, social-preview and user-requested retrieval agents are not in either
blocklist. Custom entries still apply literally.

## Paths and request budgets

| Module | Match | Action in Enforce |
| --- | --- | --- |
| WordPress login | POST `/wp-login.php`, including normalized trailing slash | 5/minute/client/domain, burst 3 by default; editable |
| XML-RPC | POST `/xmlrpc.php`, including normalized trailing slash | 10/minute/client/domain, burst 3 by default; editable |
| Private files | `.env`, `.git`, `.svn`, `.hg`, selected `wp-config.php` backup extensions, `.htpasswd`, `.DS_Store` | 403 |
| Credentials | Selected `.aws`, `.docker`, `.kube`, `.terraform`, `/var/run/secrets/kubernetes.io/serviceaccount/` paths | 403 |
| Operating-system probes | `/proc/self/environ`, numeric-process equivalents, `cmdline`, `/etc/passwd`, `/etc/shadow`, `/etc/gshadow` | 403 |
| Filtered URL crawling | Selected path + any selected parameter name + selected crawler name + domain scope | Editable limit per crawler/domain across IPs, or explicit 403 |
| Missing static files | Selected directory + extension, GET/HEAD, file does not exist | 404; existing files retain their routing |

Private paths are matched against Nginx's normalized URI, independently of the
declared User-Agent. Ordinary `/api`, `/config`, `/.well-known`, AJAX, REST and
public pages are not generally blocked. There is no blanket browser/bot rule.

## Filtered URL examples

| Listing type | Path | Parameter names |
| --- | --- | --- |
| Product listing | `/shop/` | `min_price`, `max_price`, `orderby`, `filter_color`, `filter_size` |
| Directory listing | `/directory/` | `listing_tag`, `listing_category`, `listing_distance` |
| Localized listings using the same parameters | `/` on selected domains | The exact parameter names used by that application |

The add-rule form starts at 30 requests/minute/crawler/domain, burst 5, with
Applebot, Amazonbot, Reflectionbot, Googlebot and Bingbot as editable candidates.
This limits only the configured filter combinations; ordinary indexable pages
remain outside that rule. No query values or URLs are rewritten, and no
`robots.txt`, sitemap or canonical setting is changed.

Aliases use the canonical domain's budget. Different crawlers and domains have
independent budgets. Multiple rules can apply; all applicable limits must pass.

## Missing static files

The add-rule form suggests `/wp-content/` with extension `map`. Add directories
and extensions explicitly. No directory is selected automatically. Do not select
an on-demand generator directory where a missing file is normally produced by
the application. Observe records candidates and allows them; Off disables them.

All rules are bundled and editable. There is no automatic external deny-list
import or application/plugin detection.
