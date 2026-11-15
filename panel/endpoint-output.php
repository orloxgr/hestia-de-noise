<?php if (!isset($data, $escape)) { http_response_code(403); exit; }
$endpointAnalysis = $data['analysis'] ?? null;
?>
<div id="hdn-endpoints-output">
<?php if (is_array($endpointAnalysis) && ($endpointAnalysis['inventory_kind'] ?? '') === 'endpoints'): $analysis = $endpointAnalysis; ?>
<h4 class="u-mt20">Endpoint suggestions · <?= $escape($analysis['minutes']) ?> minutes</h4>
<p><?= $escape($analysis['totals']['requests'] ?? 0) ?> native log records · <?= $escape($analysis['findings_total']) ?> domain/path findings · <?= $escape(round($analysis['bytes_read']/1048576, 2)) ?> MiB read.</p>
<p><?= !empty($analysis['partial']) ? 'Incomplete coverage; see coverage below.' : 'All available retained logs processed.' ?> <?= $escape($analysis['note']) ?></p>
<?php $reviewPage = $analysis; require __DIR__ . '/review-pagination.php'; ?>
<p>Append prepares a disabled exact-path rule scoped to that domain, with Also ban IP off. Review the path, enable it if appropriate, then Save &amp; Apply. Repeated scans preserve existing rules.</p>
<p id="hdn-endpoint-append-status" role="status"></p>
<?php foreach ($analysis['findings'] ?? [] as $row): ?>
<details class="u-mt10"><summary><strong><?= $escape($row['domain']) ?></strong> · <code><?= $escape($row['path']) ?></code> · <?= $escape($row['count']) ?> hits<?= $row['successful'] ? ' · successful/redirected responses present' : '' ?></summary>
<p><?= $escape($row['category'] . ' — ' . $row['advice']) ?></p>
<p>HTTP statuses: <?= $escape(json_encode($row['statuses'])) ?> · Methods: <?= $escape(json_encode($row['methods'])) ?> · Distinct clients: <?= $escape($row['clients']) ?></p>
<p><?= $escape(gmdate('Y-m-d H:i:s',(int)$row['first'])) ?> – <?= $escape(gmdate('Y-m-d H:i:s',(int)$row['last'])) ?> UTC</p>
<table class="table" data-hdn-list="Endpoint agents"><thead><tr><th>Declared agent (unverified)</th><th>Hits</th></tr></thead><tbody><?php foreach ($row['agents'] as $agent => $hits): ?><tr><td><?= $escape($agent) ?></td><td><?= $escape($hits) ?></td></tr><?php endforeach; ?></tbody></table>
<?php if ($row['candidate'] !== null): ?><button type="button" class="button button-secondary u-mt10" data-hdn-append-endpoint="<?= $escape($row['candidate']) ?>" data-hdn-endpoint-site="<?= $escape($row['site']) ?>">Append disabled endpoint rule</button><?php endif; ?>
</details>
<?php endforeach; if (empty($analysis['findings'])): ?><p>No matching backup, database or secret-path candidates in these logs and time window.</p><?php endif; ?>
<details class="u-mt20"><summary>Log coverage</summary>
<?php foreach ($analysis['unavailable_domains'] ?? [] as $host): ?><p>No readable log: <?= $escape($host) ?></p><?php endforeach; ?>
<?php foreach ($analysis['errors'] ?? [] as $errorRow): ?><p><?= $escape($errorRow['domain'] . ' · ' . $errorRow['file'] . ': ' . $errorRow['message']) ?></p><?php endforeach; ?>
<table class="table" data-hdn-list="Endpoint log coverage"><thead><tr><th>Domain / source / log</th><th>Records</th><th>Coverage</th></tr></thead><tbody><?php foreach ($analysis['coverage'] ?? [] as $coverage): ?><tr><td><?= $escape($coverage['domain'] . ' · ' . $coverage['source'] . '/' . $coverage['file']) ?></td><td><?= $escape($coverage['records']) ?></td><td><?= $escape($coverage['note']) ?></td></tr><?php endforeach; ?></tbody></table>
</details>
<?php endif; ?>
</div>
