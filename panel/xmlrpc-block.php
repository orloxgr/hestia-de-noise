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
<label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="xmlrpc_block_enabled" <?= $xmlrpcBlock['enabled'] ? 'checked' : '' ?>> Disable XML-RPC for the checked sites</label>
<p>In Enforce, Nginx returns 403 for XML-RPC requests before they reach WordPress, including installations in subfolders. Observe records matches without blocking; Off allows normal routing. This does not ban IP addresses.</p>
<p>Jetpack connections, external XML-RPC publishing and pingbacks are blocked unless their source IP is listed in that site's IP exceptions. Normal wp-admin access is unchanged.</p>
<p>IP exceptions allow XML-RPC only on that site and its aliases. Other De-Noise rules, firewall bans and the XML-RPC rate limit still apply. Enter IPv4/IPv6 addresses or CIDRs, one per line. Behind a proxy, Nginx must already be configured to obtain the real client IP from that trusted proxy.</p>
<p>For Jetpack, copy the current ranges from the <a href="https://jetpack.com/ips-v4.txt" target="_blank" rel="noopener noreferrer">official IP list</a> into the site's IP exceptions. Ranges can change; see the <a href="https://jetpack.com/support/how-to-add-jetpack-ips-allowlist/" target="_blank" rel="noopener noreferrer">Jetpack instructions</a>.</p>
<p>Check the sites to protect, then Save &amp; Apply. No checked sites means no XML-RPC blocking. Aliases of each checked site are included.</p>
<div class="hdn-list-controls u-mt10 u-mb10">
<button type="button" class="button button-secondary" data-hdn-xmlrpc-select="all" title="Check every listed site across all pages. Save &amp; Apply is required.">Select all sites</button>
<button type="button" class="button button-secondary" data-hdn-xmlrpc-select="none" title="Uncheck every listed site across all pages. Save &amp; Apply is required.">Clear selection</button>
</div>
<table class="table" data-hdn-list="Disable XML-RPC sites" id="hdn-xmlrpc-block-sites">
<thead><tr><th>Select</th><th>Domain</th><th>Account</th><th>IP exceptions</th></tr></thead><tbody>
<?php foreach ($xmlrpcSites as $site): ?>
<tr><td><input form="hdn-settings" type="checkbox" name="xmlrpc_block_targets[]" value="<?= $escape($site['key']) ?>" <?= in_array($site['key'], $xmlrpcBlock['targets'], true) ? 'checked' : '' ?> aria-label="Disable XML-RPC on <?= $escape($site['domain']) ?>"></td><td><?= $escape($site['domain']) ?></td><td><?= $escape($site['owner']) ?></td><td class="hdn-xmlrpc-exceptions">
<details <?= !empty($xmlrpcExceptions[$site['key']]) ? 'open' : '' ?>><summary title="Allow these source IPs to use XML-RPC on this site only. Save &amp; Apply is required.">Allowed IPs / CIDRs</summary>
<textarea form="hdn-settings" class="form-control u-mt10" name="xmlrpc_block_exceptions[<?= $escape($site['key']) ?>]" rows="4" spellcheck="false" aria-label="XML-RPC allowed IPs / CIDRs for <?= $escape($site['domain']) ?>" placeholder="192.0.2.10&#10;2001:db8::/32"><?= $escape(implode("\n", $xmlrpcExceptions[$site['key']] ?? [])) ?></textarea>
</details></td></tr>
<?php endforeach; ?>
</tbody></table>
</div></details>
