# Delivery status

## Available in 0.9.0

| Area | Delivered |
| --- | --- |
| Agents | Independent scanner-tool and crawler lists, enable switches and insertion presets |
| Request filtering | Login/XML-RPC limits, private paths, scoped filtered-URL budgets and missing-static-file rules |
| Exceptions | Per-domain modes and exact static-file exceptions, one path per line |
| Firewall bans | Optional native Hestia IPv4 bans, first-request trigger, editable duration/count/window/scope, exclusions, expiry and unban |
| PHP probes | 219 editable exact paths, nonexistent-file 404s and distinct-path counters across domains |
| General 404s | Optional 10 responses / 5 minutes / 3-day bans; missing-static exclusion and minimum distinct paths, globally or per domain |
| Ban evidence | Query-free paths/methods/times and the trigger-time threshold/window, in global and scoped ban details |
| WordPress logins | Native Fail2ban controls, three-stage durations, on-demand status and scoped unban; requires WP fail2ban |
| Query probes | Selected parameters, literal secret targets and encoded traversal/filter resources, independent counter and 3-day default duration |
| Probe exceptions | Separate exact-path exceptions by domain for selected PHP files and legitimate query endpoints |
| Cron | Explicit preview/apply/restore of native WordPress jobs with readable intervals and expandable exact schedules |
| Domain bans | Owner-editable additional file/query bans for own domains, IPv4/IPv6 in Nginx; administrator controls delegation and shared rules |
| Panel | Compact native Hestia tabs, responsive tables, all-domain administrator view, bulk mode changes and scoped owner controls |
| Activity | Bounded matched/observed/blocked summaries, rotation-safe reads, explicit unavailable state and paged ban history |
| Maintenance | Last success/failure, domain discovery, native includes, policy migration, validation/recovery and owned integration removal |
| Webmail | Optional HTTP-only User-Agent/private-file protection using native mail includes |
