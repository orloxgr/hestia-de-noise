<?php if (!isset($data, $escape)) { http_response_code(403); exit; }
$endpointAnalysis = $data['analysis'] ?? null;
?>
<div id="hdn-endpoints-output">
<?php if (is_array($endpointAnalysis) && ($endpointAnalysis['inventory_kind'] ?? '') === 'endpoints'): $analysis = $endpointAnalysis; ?>
<h4 class="u-mt20">Endpoint suggestions Β· <?= $escape($analysis['minutes']) ?> minutes</h4>
<p><?= $escape($analysis['totals']['requests'] ?? 0) ?> native log records Β· <?= $escape($analysis['findings_total']) ?> domain/path findings Β· <?= $escape(round($analysis['bytes_read']/1048576, 2)) ?> MiB read.</p>
<p><?= !empty($analysis['partial']) ? 'Incomplete coverage; see coverage below.' : 'All available retained logs processed.' ?> <?= $escape($analysis['note']) ?></p>
<?php if (($analysis['endpoint_scope'] ?? '') !== 'all-non-image-paths'): ?><p>This older saved review covered backup/secret paths only. Run Analyze endpoint logs again to include JavaScript, CSS, PHP and other routes.</p><?php endif; ?>
<?php require __DIR__ . '/review-filters.php'; ?>
<?php if (!empty($analysis['suggestions'])): ?>
<h4 class="u-mt20">Suggested rules and fixes</h4>
<div data-hdn-list="Endpoint suggestions">
<?php foreach ($analysis['suggestions'] as $proposal): ?>
<details class="u-mt10" data-hdn-list-row><summary><strong><?= $escape($proposal['domain']) ?></strong> · <?= $escape($proposal['category'].' — '.$proposal['title']) ?> · <?= $escape($proposal['count']) ?> hits</summary>
<p><?= $escape($proposal['detail']) ?></p>
<p>Scope: <?= $escape($proposal['domain']) ?>. Observed paths: <?= count($proposal['paths']) ?>. HTTP statuses: <?= $escape(json_encode($proposal['statuses'])) ?>.</p>
<?php if ($proposal['pattern'] !== null && in_array($proposal['action'],['block','review_block'],true)): ?>
<label class="form-label">Suggested <?= $escape($proposal['type']) ?> rule (only the observed paths)<textarea class="form-control" rows="3" readonly spellcheck="false"><?= $escape($proposal['pattern']) ?></textarea></label>
<button type="button" class="button button-secondary u-mt10" data-hdn-append-endpoint="<?= $escape($proposal['pattern']) ?>" data-hdn-endpoint-site="<?= $escape($proposal['site']) ?>" data-hdn-endpoint-type="<?= $escape($proposal['type']) ?>" data-hdn-endpoint-name="<?= $escape($proposal['category']) ?>">Append disabled 403 rule</button>
<?php endif; ?>
<?php if (!empty($proposal['missing_paths'])): ?><button type="button" class="button button-secondary u-mt10" data-hdn-endpoint404-group="<?= $escape(json_encode($proposal['missing_paths'])) ?>" data-hdn-endpoint-site="<?= $escape($proposal['site']) ?>">Append these <?= count($proposal['missing_paths']) ?> exact paths to the 404 list</button><?php endif; ?>
<details><summary>Exact observed paths</summary><ul><?php foreach ($proposal['paths'] as $proposedPath): ?><li><code><?= $escape($proposedPath) ?></code></li><?php endforeach; ?></ul></details>
</details>
<?php endforeach; ?>
</div>
<?php endif; ?>
<?php $reviewPage = $analysis; require __DIR__ . '/review-pagination.php'; ?>
<div class="u-mt10"><label><input type="checkbox" data-hdn-select-endpoint404> Select all 404 paths on this page</label>
<button type="button" class="button button-secondary" data-hdn-append-endpoint404>Append selected paths to the 404 list</button></div>

<p>Append prepares a disabled exact-path rule scoped to that domain, with Also ban IP off. Review the path, enable it if appropriate, then Save &amp; Apply. Repeated scans preserve existing rules.</p>
<p id="hdn-endpoint-append-status" role="status"></p>
<?php foreach ($analysis['findings'] ?? [] as $row): ?>
<details class="u-mt10"><summary><?php if (!empty($row['missing']) && $row['candidate'] !== null): ?><input type="checkbox" data-hdn-endpoint404-path="<?= $escape($row['candidate']) ?>" data-hdn-endpoint-site="<?= $escape($row['site']) ?>" aria-label="Select exact 404 path <?= $escape($row['path']) ?>"> <?php endif; ?><strong><?= $escape($row['domain']) ?></strong> Β· <code><?= $escape($row['path']) ?></code> Β· <?= $escape($row['count']) ?> hits<?= $row['successful'] ? ' Β· successful/redirected responses present' : '' ?></summary>
<p><?= $escape($row['category'] . ' β€” ' . $row['advice']) ?></p>
<p>HTTP statuses: <?= $escape(json_encode($row['statuses'])) ?> Β· Methods: <?= $escape(json_encode($row['methods'])) ?> Β· Distinct clients: <?= $escape($row['clients']) ?></p>
<p><?= $escape(gmdate('Y-m-d H:i:s',(int)$row['first'])) ?> β€“ <?= $escape(gmdate('Y-m-d H:i:s',(int)$row['last'])) ?> UTC</p>
<table class="table" data-hdn-list="Endpoint agents"><thead><tr><th>Declared agent (unverified)</th><th>Hits</th></tr></thead><tbody><?php foreach ($row['agents'] as $agent => $hits): ?><tr><td><?= $escape($agent) ?></td><td><?= $escape($hits) ?></td></tr><?php endforeach; ?></tbody></table>
<?php if ($row['candidate'] !== null): ?><button type="button" class="button button-secondary u-mt10" data-hdn-append-endpoint="<?= $escape($row['candidate']) ?>" data-hdn-endpoint-site="<?= $escape($row['site']) ?>">Append disabled endpoint rule</button><?php endif; ?>
<?php $reviewRow=$row; require __DIR__ . '/review-note-controls.php'; ?>
</details>
<?php endforeach; if (empty($analysis['findings'])): ?><p>No matching backup, database or secret-path candidates in these logs and time window.</p><?php endif; ?>
<details class="u-mt20"><summary>Log coverage</summary>
<?php foreach ($analysis['unavailable_domains'] ?? [] as $host): ?><p>No readable log: <?= $escape($host) ?></p><?php endforeach; ?>
<?php foreach ($analysis['errors'] ?? [] as $errorRow): ?><p><?= $escape($errorRow['domain'] . ' Β· ' . $errorRow['file'] . ': ' . $errorRow['message']) ?></p><?php endforeach; ?>
<table class="table" data-hdn-list="Endpoint log coverage"><thead><tr><th>Domain / source / log</th><th>Records</th><th>Coverage</th></tr></thead><tbody><?php foreach ($analysis['coverage'] ?? [] as $coverage): ?><tr><td><?= $escape($coverage['domain'] . ' Β· ' . $coverage['source'] . '/' . $coverage['file']) ?></td><td><?= $escape($coverage['records']) ?></td><td><?= $escape($coverage['note']) ?></td></tr><?php endforeach; ?></tbody></table>
</details>
<?php endif; ?>
</div>
