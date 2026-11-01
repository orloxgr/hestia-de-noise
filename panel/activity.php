<h2 class="u-mb20">Activity</h2>
<?php $activity = $data['activity'] ?? []; ?>
<p class="u-mb10">Matched requests · last 15 minutes · <?= $escape($activity['total'] ?? 0) ?> in the bounded log sample</p>
<?php if (!empty($activity['available'])): ?>
<table class="table"><thead><tr><th>Domain</th><th>Rule</th><th>Outcome</th><th>Requests</th></tr></thead><tbody>
<?php foreach ($activity['rows'] ?? [] as $row): ?><tr>
<td><?= $escape($row['domain']) ?></td><td><?= $escape($row['rule']) ?></td>
<td><?= $escape($row['outcome']) ?></td><td><?= $escape($row['count']) ?></td></tr><?php endforeach; ?>
</tbody></table>
<?php if (empty($activity['rows'])): ?><p>No matching requests in this sample.</p><?php endif; ?>
<?php else: ?><p>Activity is unavailable.<?= $isAdmin && !empty($activity['error']) ? ' ' . $escape($activity['error']) : '' ?></p><?php endif; ?>
