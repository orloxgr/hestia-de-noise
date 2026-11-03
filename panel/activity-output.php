<div id="hdn-activity-output">
<?php $activity = $data['analysis'] ?? null; if (is_array($activity)): ?>
<p class="u-mb10">Matched requests · last <?= $escape($activity['window_minutes']) ?> minutes · <?= $escape($activity['total']) ?> in available retained logs</p>
<div class="hdn-table-scroll"><table class="table"><thead><tr><th>Domain</th><th>Rule</th><th>Outcome</th><th>Requests</th></tr></thead><tbody>
<?php foreach ($activity['rows'] ?? [] as $row): ?><tr>
<td><?= $escape($row['domain']) ?></td><td><?= $escape($row['rule']) ?></td>
<td><?= $escape($row['outcome']) ?></td><td><?= $escape($row['count']) ?></td></tr><?php endforeach; ?>
</tbody></table></div>
<?php if (empty($activity['rows'])): ?><p>No matching requests in this time window.</p><?php endif; ?>
<div class="hdn-table-scroll"><table class="table"><thead><tr><th>Time</th><th>Domain</th><th>Rule</th><th>Outcome</th><th>Status</th></tr></thead><tbody>
<?php foreach ($activity['findings'] ?? [] as $row): ?><tr>
<td><?= $escape($row['time']) ?></td><td><?= $escape($row['domain']) ?></td><td><?= $escape($row['rule']) ?></td><td><?= $escape($row['outcome']) ?></td><td><?= $escape($row['status']) ?></td>
</tr><?php endforeach; ?>
</tbody></table></div>
<p>Page <?= $escape($activity['page'] ?? 1) ?> of <?= $escape($activity['pages'] ?? 1) ?></p>
<?php if (($activity['page'] ?? 1) > 1): ?><button type="button" class="button button-secondary" title="Read this result page without restarting the review or changing protection settings." data-hdn-analysis-page="<?= $escape($activity['page'] - 1) ?>">Previous</button><?php endif; ?>
<?php if (($activity['page'] ?? 1) < ($activity['pages'] ?? 1)): ?><button type="button" class="button button-secondary" title="Read this result page without restarting the review or changing protection settings." data-hdn-analysis-page="<?= $escape($activity['page'] + 1) ?>">Next</button><?php endif; ?>
<?php endif; ?>
</div>
