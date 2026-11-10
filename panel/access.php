<h2 class="u-mb20">WordPress administration access</h2>
<p class="u-mb20">An additional HTTP password for direct login/admin requests. It is a simple bot filter; clients can imitate the origin headers. WordPress authentication remains required. Customer account and checkout pages are outside this gate.</p>
<p class="u-mb20">Domain mode applies: <strong>Enforce</strong> activates protection, <strong>Observe</strong> records candidates without a prompt, and <strong>Off</strong> bypasses protection. AJAX, form handlers and the password-strength scripts are exempt.</p>
<?php foreach ($data['sites'] ?? [] as $site): if (($site['kind'] ?? 'web') === 'mail') continue;
    $entry = $data['access'][$site['key']] ?? ['enabled' => false, 'bypass_internal' => true, 'username' => 'wp', 'password_set' => false,
        'country' => ['enabled' => false, 'scope' => 'admin', 'mode' => 'deny', 'countries' => [], 'allow_unknown' => true]];
    $country = $entry['country']; ?>
<details class="box-collapse u-mb20">
    <summary class="box-collapse-header"><?= $escape($site['domain']) ?> · <?= $escape(ucfirst($site['mode'])) ?> · HTTP gate <?= $entry['enabled'] ? 'enabled' : 'disabled' ?> · Countries <?= $country['enabled'] ? 'enabled' : 'disabled' ?></summary>
    <div class="box-collapse-content">
    <form method="post" autocomplete="off" class="hdn-access-form"><?php $fields('access_save'); ?>
        <input type="hidden" name="access_target" value="<?= $escape($site['key']) ?>">
        <fieldset <?= !$site['supported'] || $site['suspended'] ? 'disabled' : '' ?>>
        <label class="form-label u-block u-mb10" title="Ask for an extra HTTP username/password before forwarding protected administration requests to WordPress. Applies only to this domain and its aliases in Enforce mode."><input type="checkbox" name="access_enabled" <?= $entry['enabled'] ? 'checked' : '' ?>> Enable administration HTTP password</label>
        <label class="form-label u-block u-mb10" title="Bypass the extra password for Sec-Fetch-Site: same-origin. Only when that header is absent, accept a Referer with the exact same scheme, hostname and default port. Direct, cross-site, same-site-only and headerless requests still need the HTTP password."><input type="checkbox" name="access_bypass_internal" <?= $entry['bypass_internal'] ? 'checked' : '' ?>> Bypass for internal requests</label>
        <div class="hdn-access-grid">
        <label class="form-label">HTTP username <input class="form-control u-mb10" name="access_username" value="<?= $escape($entry['username']) ?>" autocomplete="off" required title="The extra HTTP username. This is separate from the WordPress account."></label>
        <label class="form-label">New HTTP password <input class="form-control u-mb10" type="password" name="access_password" autocomplete="new-password" title="Leave empty to keep the saved password. Only a salted password hash is retained; the current password is never displayed."></label>
        </div>
        <p class="u-mb20"><?= $entry['password_set'] ? 'A password is saved. Leave the field empty to keep it.' : 'No password saved. Set one before enabling the HTTP gate.' ?></p>
        <h3 class="u-mb10">Country filter</h3>
        <p class="u-mb10">Requires the server country database<?= empty($data['geography']['available']) ? ' (not downloaded yet; ask the administrator)' : '' ?>. Country rules also apply to requests that bypass the HTTP password.</p>
        <label class="form-label u-block u-mb10" title="Enable a separate geographic access policy for this domain. A rejection returns HTTP 403; it does not create a firewall ban."><input type="checkbox" name="country_enabled" <?= $country['enabled'] ? 'checked' : '' ?>> Enable country filter</label>
        <div class="hdn-access-grid">
        <label class="form-label">Apply to <select name="country_scope" class="form-select u-mb10" title="Administration protects the WordPress login/admin paths with frontend handler exceptions. Entire site includes shop customers, APIs and payment/webhook services; select it only intentionally. ACME certificate validation remains accessible.">
            <option value="admin" <?= $country['scope'] === 'admin' ? 'selected' : '' ?>>WordPress administration only</option>
            <option value="site" <?= $country['scope'] === 'site' ? 'selected' : '' ?>>Entire site</option>
        </select></label>
        <label class="form-label">Policy <select name="country_mode" class="form-select u-mb10" title="Block selected countries, or allow only selected countries. The unknown-country choice is applied separately.">
            <option value="deny" <?= $country['mode'] === 'deny' ? 'selected' : '' ?>>Block selected countries</option>
            <option value="allow" <?= $country['mode'] === 'allow' ? 'selected' : '' ?>>Allow only selected countries</option>
        </select></label>
        </div>
        <label class="form-label">Country codes <textarea class="form-control u-mb10" name="country_codes" rows="3" placeholder="GR&#10;CY" title="Two-letter country codes, one per line or separated by commas. For example GR for Greece and CY for Cyprus."><?= $escape(implode("\n", $country['countries'])) ?></textarea></label>
        <label class="form-label u-block u-mb20" title="Allow IPs with no known location, including local/private addresses. When unchecked, unknown locations are rejected within the selected scope."><input type="checkbox" name="country_allow_unknown" <?= $country['allow_unknown'] ? 'checked' : '' ?>> Allow unknown country</label>
        <button class="button" type="submit" title="Save and apply only this domain. Other domains and global settings are preserved.">Save domain protection</button>
        </fieldset>
    </form>
    </div>
</details>
<?php endforeach; ?>
