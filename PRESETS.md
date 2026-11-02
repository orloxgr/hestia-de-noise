# Presets — 0.4.0

## Scanner tools

**User-Agents → Add scanner tools** inserts these literal names into the
Scanner tools box, which has its own enable switch:

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

**User-Agents → Add bulk / AI crawlers** inserts these into the separate
Crawlers / other agents box, with its own enable switch:

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
YisouSpider
```

These are collection, search, training or SEO-analysis crawlers, not inherently malicious
services. Use the group only when that traffic is unwanted. Googlebot, Bingbot,
Applebot, social-preview and user-requested retrieval agents are not in either
blocklist. Custom entries still apply literally.

## Paths and request budgets

The optional **IP bans** module has separate switches for secret/config-file
and repository probes. It defaults to one matching request and permanent duration
when enabled. Its two separate 404 groups default to 2 strikes in 60 seconds
and a 3-day ban. PHP strikes require distinct selected nonexistent paths;
query strikes require selected parameters and explicit secret-target matches.
The complete editable PHP list is [src/php-probes.txt](src/php-probes.txt).
It does not ban IPs for unselected 404s, ordinary missing static files, User-Agent
matches or exceeded crawler/login budgets. The counting window, duration,
trigger domains and never-ban networks are editable in the panel.

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

The panel provides **Product listing filters** for `min_price`, `max_price` and
`orderby`, and **VLM directory filters** for `vlm_listing_tag`,
`vlm_listing_category` and `vlm_listing_distance`. Both use path `/` to cover
localized listing routes and an editable 30/minute/crawler/domain limit, burst 5.
Choose the applicable domains before saving; an empty selection means all.

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

| Panel preset | Directories | Extensions |
| --- | --- | --- |
| WordPress source maps | `/wp-content/` | `map` |
| WordPress JS / CSS | `/wp-content/plugins/`, `/wp-content/themes/`, `/wp-includes/` | `js css map` |

The JS/CSS button inserts three editable rules. **Add rule** creates a custom
rule, initially `/wp-content/` with extension `map`. Nothing is saved until
**Save & Apply**. Repeated preset clicks preserve matching existing rules,
including their switches and domain selection. Observe records candidates and
allows them; Off disables them.

**File exceptions by domain** accepts one exact URL path per line. A listed
file follows normal routing on that domain and its aliases, regardless of query
string, across every static rule. It does not bypass other De-Noise modules.

All rules are bundled and editable. There is no automatic external deny-list
import or application/plugin detection.
