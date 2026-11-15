# Login appearance and OIDC auto sign-in

Project branding settings now include `login_theme` (`default` or `glass`), `login_title`, `login_subtitle`, `login_kicker`, `font_preset` (`default` or `classic-serif`), and `auto_sso` (default false). Administrators edit them under Settings / General / Project branding. The login button uses the configured OAuth provider display name. Glass login uses the existing project logo.

These values are stored in `system_settings`, alongside existing branding settings. They are exposed through the existing public branding API so the unauthenticated page can render them. Credentials are not included. The default installation uses the glass login card. The classic two-column screen remains selectable as `login_theme=default`. Automatic sign-in remains disabled unless explicitly enabled.

Automatic sign-in uses OIDC `prompt=none`, with a short per-tab retry cooldown. An identity provider must support prompt=none. Interactive errors leave the manual login controls available. The authorization server must return login_required when no session exists, rather than displaying a login page for a silent request.

The classic serif preset uses locally installed Times New Roman for Latin and STKaiti for Chinese. Font binaries are not shipped. Clients lacking those fonts use their local serif fallback.

For upgrades, preserve the configured data directory (database and uploaded assets) and service configuration. Replace the program and deploy a frontend built from the matching source revision; do not replace the data directory with repository defaults. Do not edit generated CSS or bundle personal assets into releases. Branding may use validated data-image URLs saved in the database or durable URLs outside the release directory. Back up the data directory before upgrades and verify appearance and OIDC bindings afterward. No database reset is required.

## Random backgrounds

`login_background_mode` accepts `gradient`, `fixed` (compatibility default), or `random`. The existing login wallpaper setting supplies fixed mode. `login_background_urls` is a list of up to 30 HTTPS image URLs or same-origin paths, editable in General / Appearance. Random mode selects one URL per login-page mount and adds a cache-busting `_bg` parameter; a URL may itself be a random-image endpoint. Typing credentials does not rotate the background. Failed images and empty random lists fall back to the built-in gradient. The browser fetches images without a Referer; remote image providers can still observe visitor IP addresses. Background URLs are public branding data and must not contain credentials. A bundled source list is deliberately not provided.

Successful login and OIDC callbacks land on #/dashboard. During authorization-code exchange, the UI shows a connection state and suppresses the public probe, including when an old probe=1 preview parameter is present. Anonymous visits to the site root retain the public probe behavior.

The bundled frontend corresponds to relaydock-frontend revision 247184bd66e9c03e30d3f76775ca9be277ac9005.
