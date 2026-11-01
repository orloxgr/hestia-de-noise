# Changelog

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
