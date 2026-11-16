<?php
if (!isset($data, $escape)) { http_response_code(403); exit; }
$xmlrpcBlock = $policy['xmlrpc_block'] ?? ['enabled' => false, 'targets' => [], 'exceptions' => []];
$xmlrpcExceptions = (array)($xmlrpcBlock['exceptions'] ?? []);
$xmlrpcSites = array_values(array_filter($data['sites'] ?? [], static fn($site) => ($site['kind'] ?? 'web') === 'web'));
$xmlrpcKnown = array_column($xmlrpcSites, 'key');
foreach (array_diff(array_unique(array_merge($xmlrpcBlock['targets'], array_keys($xmlrpcExceptions))), $xmlrpcKnown) as $xmlrpcOld) {
    $xmlrpcSites[] = ['key'=>$xmlrpcOld, 'domain'=>$xmlrpcOld.' (unavailable)', 'owner'=>''];
}
?>
<details class="box-collapse hdn-endpoint-section u-mb20" id="hdn-xmlrpc-block-box">
<summary class="box-collapse-header">Disable XML-RPC</summary>
<div class="box-collapse-content">
<input form="hdn-settings" type="hidden" name="xmlrpc_block_present" value="1">
<input form="hdn-settings" type="hidden" name="xmlrpc_exceptions_present" value="1">
<input form="hdn-settings" type="hidden" name="xmlrpc_global_present" value="1">
<label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="xmlrpc_block_enabled" <?= $xmlrpcBlock['enabled'] ? 'checked' : '' ?>> Disable XML-RPC for the checked sites</label>
<p>In Enforce, Nginx returns 403 for XML-RPC requests before they reach WordPress, including installations in subfolders. Observe records matches without blocking; Off allows normal routing. This does not ban IP addresses.</p>
<p>Need Jetpack on all sites? Use <strong>Allow Jetpack</strong> in Global exceptions, then <strong>Save &amp; Apply</strong>. For a single site, use its own button below. Buttons add the current official IP ranges and keep your existing entries; they do not update automatically.</p>
<p>No checked sites means no XML-RPC blocking. Exceptions cover only XML-RPC on that site and its aliases; other rules, firewall bans and the XML-RPC rate limit still apply. Normal wp-admin access is unchanged.</p>
<details class="hdn-xmlrpc-help u-mb10"><summary>Other services and manual IP exceptions</summary>
<p>For other XML-RPC clients, open Allowed IPs / CIDRs beside the site and enter IPv4/IPv6 addresses or CIDRs, one per line. Behind a proxy, Nginx must already obtain the real client IP from that trusted proxy.</p>
<p>Jetpack's <a href="https://jetpack.com/ips-v4.txt" target="_blank" rel="noopener noreferrer">official IP list</a> can change. See the <a href="https://jetpack.com/support/how-to-add-jetpack-ips-allowlist/" target="_blank" rel="noopener noreferrer">Jetpack instructions</a>.</p>
</details>
<div class="hdn-xmlrpc-exceptions hdn-xmlrpc-global u-mb20" id="hdn-xmlrpc-global">
<h3>Global exceptions</h3>
<p>These IPs may use XML-RPC on every site where this block is enabled, including aliases and sites selected later. Per-site exceptions still apply to their own site.</p>
<button type="button" class="button button-secondary u-mb10" data-hdn-allow-jetpack title="Download Jetpack's current official IP ranges and append them to the global XML-RPC exceptions. Site lists and switches are kept. Save &amp; Apply is required.">Allow Jetpack</button>
<small class="hdn-jetpack-status" data-hdn-jetpack-status role="status"></small>
<details class="hdn-xmlrpc-help" open><summary>Allowed IPs / CIDRs — all sites</summary>
<textarea form="hdn-settings" class="form-control u-mt10" name="xmlrpc_global_exceptions" rows="4" spellcheck="false" aria-label="Global XML-RPC allowed IPs / CIDRs" placeholder="192.0.2.10&#10;2001:db8::/32"><?= $escape(implode("\n", $xmlrpcBlock['global_exceptions'] ?? [])) ?></textarea>
</details>
</div>
<div class="hdn-list-controls u-mt10 u-mb10">
<button type="button" class="button button-secondary" data-hdn-xmlrpc-select="all" title="Check every listed site across all pages. Save &amp; Apply is required.">Select all sites</button>
<button type="button" class="button button-secondary" data-hdn-xmlrpc-select="none" title="Uncheck every listed site across all pages. Save &amp; Apply is required.">Clear selection</button>
</div>
<table class="table" data-hdn-list="Disable XML-RPC sites" id="hdn-xmlrpc-block-sites">
<thead><tr><th>Select</th><th>Domain</th><th>Account</th><th>IP exceptions</th></tr></thead><tbody>
<?php foreach ($xmlrpcSites as $site): ?>
<tr><td><input form="hdn-settings" type="checkbox" name="xmlrpc_block_targets[]" value="<?= $escape($site['key']) ?>" <?= in_array($site['key'], $xmlrpcBlock['targets'], true) ? 'checked' : '' ?> aria-label="Disable XML-RPC on <?= $escape($site['domain']) ?>"></td><td><?= $escape($site['domain']) ?></td><td><?= $escape($site['owner']) ?></td><td class="hdn-xmlrpc-exceptions">
<button type="button" class="button button-secondary u-mb10" data-hdn-allow-jetpack title="Download Jetpack's current official IP ranges and append them for this site. Existing IPs and switches are kept. Save &amp; Apply is required.">Allow Jetpack</button>
<small class="hdn-jetpack-status" data-hdn-jetpack-status role="status"></small>
<details <?= !empty($xmlrpcExceptions[$site['key']]) ? 'open' : '' ?>><summary title="Allow these source IPs to use XML-RPC on this site only. Save &amp; Apply is required.">Allowed IPs / CIDRs</summary>
<textarea form="hdn-settings" class="form-control u-mt10" name="xmlrpc_block_exceptions[<?= $escape($site['key']) ?>]" rows="4" spellcheck="false" aria-label="XML-RPC allowed IPs / CIDRs for <?= $escape($site['domain']) ?>" placeholder="192.0.2.10&#10;2001:db8::/32"><?= $escape(implode("\n", $xmlrpcExceptions[$site['key']] ?? [])) ?></textarea>
</details></td></tr>
<?php endforeach; ?>
</tbody></table>
</div></details>
