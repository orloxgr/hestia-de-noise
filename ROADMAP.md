# Delivery status

## Available in 0.7.1

| Area | Delivered |
| --- | --- |
| Agents | Independent scanner-tool and crawler lists, enable switches and insertion presets |
| Request filtering | Login/XML-RPC limits, private paths, scoped filtered-URL budgets and missing-static-file rules |
| Exceptions | Per-domain modes and exact static-file exceptions, one path per line |
| Firewall bans | Optional native Hestia IPv4 bans, first-request trigger, editable duration/count/window/scope, exclusions, expiry and unban |
| PHP probes | 193 editable exact paths, nonexistent-file 404s and distinct-path counters across domains |
| General 404s | Optional 10 responses / 5 minutes / 3-day bans, including repeated URLs and assets, globally or per domain |
| Ban evidence | Query-free paths/methods/times and the trigger-time threshold/window, in global and scoped ban details |
| WordPress logins | Native Fail2ban controls, three-stage durations, on-demand status and scoped unban; requires WP fail2ban |
| Query probes | Selected parameters, literal secret targets and encoded traversal/filter resources, independent counter and 3-day default duration |
| Probe exceptions | Separate exact-path exceptions by domain for selected PHP files and legitimate query endpoints |
| Cron | Explicit preview/apply/restore of native WordPress jobs with readable intervals and expandable exact schedules |
| Domain bans | Owner-editable additional file/query bans for own domains, IPv4/IPv6 in Nginx; administrator controls delegation and shared rules |
| Panel | Compact native Hestia tabs, responsive tables, all-domain administrator view, bulk mode changes and scoped owner controls |
| Activity | Bounded matched/observed/blocked summaries plus administrator ban state and errors |
| Maintenance | Domain discovery, native includes, saved policy migration, validation/recovery and owned integration removal |
