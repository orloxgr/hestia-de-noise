<?php $ban = $policy['bans'] ?? []; $banState = $data['bans'] ?? []; ?>
<h2 class="u-mb20">Automatic IP bans</h2>
<label class="form-label u-block u-mb20"><input form="hdn-settings" type="checkbox" name="bans_enabled" <?= !empty($ban['enabled']) ? 'checked' : '' ?>> Enable automatic firewall bans</label>
<p class="u-mb20">Selected probes are rejected immediately. Firewall bans synchronize within about one minute and cover all sites on TCP 80/443. Backend: Hestia native IPv4 firewall.</p>
<label class="form-label u-block u-mb10"><input form="hdn-settings" type="checkbox" name="bans_private_files" <?= !empty($ban['private_files']) ? 'checked' : '' ?>> Secret and configuration-file probes, including traversal to secret paths</label>
<label class="form-label u-block u-mb20"><input form="hdn-settings" type="checkbox" name="bans_repositories" <?= !empty($ban['repositories']) ? 'checked' : '' ?>> Source-control metadata probes (.git, .svn, .hg)</label>
<?php foreach (['maxretry' => ['Matching requests before ban', 1, 1000, 1],
               'findtime' => ['Counting window (seconds)', 30, 86400, 300],
               'duration_days' => ['Ban duration (days; 0 = permanent), for existing and new bans', 0, 3650, 0]] as $key => [$label, $minimum, $maximum, $default]): ?>
<div class="u-mb20"><label class="form-label" for="bans-<?= $key ?>"><?= $escape($label) ?></label>
<input form="hdn-settings" class="form-control" type="number" id="bans-<?= $key ?>" name="bans_<?= $key ?>" min="<?= $minimum ?>" max="<?= $maximum ?>" value="<?= $escape($ban[$key] ?? $default) ?>" required></div>
<?php endforeach; ?>
<label class="form-label" for="bans-targets">Domains that can trigger a ban (empty selection means all)</label>
<select form="hdn-settings" class="form-select u-mb20" id="bans-targets" name="bans_targets[]" multiple size="4">
<?php foreach ($data['sites'] ?? [] as $site): ?>
<option value="<?= $escape($site['key']) ?>" <?= in_array($site['key'], $ban['targets'] ?? [], true) ? 'selected' : '' ?>><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option>
<?php endforeach; ?></select>
<label class="form-label" for="bans-ignore">Never ban — one IP address or CIDR network per line</label>
<textarea form="hdn-settings" class="form-control u-mb20" id="bans-ignore" name="bans_ignore_ips" rows="4" spellcheck="false"><?= $escape(implode("\n", $ban['ignore_ips'] ?? [])) ?></textarea>
<p class="u-mb20">Never-ban entries bypass automatic IP bans only. Ordinary 404s, missing static files, crawler limits and User-Agent blocks do not trigger bans. Observe/Off domains do not trigger bans. IPv6 probes still receive the HTTP block; native IPv6 firewall bans are unavailable in this backend.</p>
<h3 class="u-mb10">Ban status</h3>
<?php if (!empty($banState['error'])): ?><div class="alert alert-danger u-mb20" role="alert"><pre style="white-space:pre-wrap;overflow-wrap:anywhere"><?= $escape($banState['error']) ?></pre></div><?php endif; ?>
<p class="u-mb10">Active: <?= $escape($banState['active'] ?? 0) ?> · Pending: <?= $escape($banState['pending'] ?? 0) ?> · Last sync: <?= !empty($banState['last_sync']) ? $escape(gmdate('Y-m-d H:i:s', (int)$banState['last_sync']) . ' UTC') : 'Not synchronized yet' ?></p>
<?php if (!empty($banState['unsupported_ipv6'])): ?><p class="u-mb10">IPv6 probes without a native firewall ban: <?= $escape($banState['unsupported_ipv6']) ?></p><?php endif; ?>
<form method="post"><?php $fields('unban'); ?>
<div class="u-mb10"><button class="button button-secondary" type="submit">Unban selected</button>
<button class="button button-secondary" type="submit" name="unban_all" value="1">Unban all De-Noise IPs</button>
<a class="button button-secondary" href="/list/firewall/banlist/">Hestia IP bans</a></div>
<table class="table"><thead><tr><th>Select</th><th>IP</th><th>Source domain</th><th>Reason</th><th>Expiry</th><th>Status</th></tr></thead><tbody>
<?php foreach ($banState['rows'] ?? [] as $row): ?><tr>
<td><input type="checkbox" name="ips[]" value="<?= $escape($row['ip']) ?>" aria-label="Unban <?= $escape($row['ip']) ?>"></td>
<td><?= $escape($row['ip']) ?></td><td><?= $escape($row['domain']) ?></td><td><?= $escape($row['reason']) ?></td>
<td><?= $row['expires'] ? $escape(gmdate('Y-m-d H:i:s', (int)$row['expires']) . ' UTC') : 'Permanent' ?></td>
<td><?= $escape($row['status']) ?><?php if ($row['error']): ?><br><?= $escape($row['error']) ?><?php endif; ?></td></tr><?php endforeach; ?>
</tbody></table>
<?php if (empty($banState['rows'])): ?><p>No active or pending De-Noise bans.</p><?php endif; ?>
</form>
