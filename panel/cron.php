<h2 class="u-mb20">Spread WordPress cron jobs</h2>
<p class="u-mb20">Preview different minute offsets for existing active WordPress jobs. Selected jobs remain visible and editable in Hestia CRON. A 5–15 minute interval may delay scheduled WordPress work by up to 15 minutes. Installing or updating De-Noise never reschedules jobs.</p>
<form method="post" class="u-mb20"><?php $fields('cron_preview'); ?>
<label class="form-label u-block u-mb10">Minimum interval (minutes)<input class="form-control" type="number" name="cron_min" min="1" max="30" value="<?= $escape($data['cron']['minimum'] ?? 5) ?>" required></label>
<label class="form-label u-block u-mb10">Maximum interval (minutes)<input class="form-control" type="number" name="cron_max" min="1" max="30" value="<?= $escape($data['cron']['maximum'] ?? 15) ?>" required></label>
<button class="button button-secondary" type="submit">Generate preview</button></form>
<?php if (!empty($data['cron']['error'])): ?><div class="alert alert-danger" role="alert"><?= $escape($data['cron']['error']) ?></div>
<?php elseif (!empty($data['cron']['id'])): ?>
<form method="post"><?php $fields('cron_apply'); ?>
<input type="hidden" name="plan_id" value="<?= $escape($data['cron']['id']) ?>">
<table class="table"><thead><tr><th>Select</th><th>Account / job</th><th>WordPress path</th><th>Previous minutes</th><th>New minutes</th><th>Status</th></tr></thead><tbody>
<?php foreach ($data['cron']['rows'] as $row): ?><tr>
<td><input type="checkbox" name="cron_jobs[]" value="<?= $escape($row['key']) ?>" checked></td>
<td><?= $escape($row['key']) ?></td><td><?= $escape($row['label']) ?></td><td><?= $escape($row['before']) ?></td><td><?= $escape($row['after']) ?></td><td><?= $escape($row['state']) ?></td>
</tr><?php endforeach; ?></tbody></table>
<button class="button u-mt20" type="submit">Apply selected schedules</button>
<button class="button button-secondary u-mt20" type="submit" name="restore_cron" value="1">Restore selected original schedules</button>
</form>
<?php if (empty($data['cron']['rows'])): ?><p>No eligible active WordPress cron jobs were found.</p><?php endif; ?>
<?php endif; ?>
