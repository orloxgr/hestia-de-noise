<?php
require $root . '/web/templates/header.php';
$panel = top_panel($headerOwner, $TAB);
?>
<script>document.title = 'De-Noise';</script>
<div class="toolbar"><div class="toolbar-inner"><div class="toolbar-buttons">
    <a class="button button-secondary" href="/list/web/"><i class="fas fa-arrow-left icon-blue"></i>Back</a>
    <?php if ($isAdmin): ?>
    <form method="post"><?php $fields('sync'); ?><button class="button button-secondary" type="submit">Refresh domains</button></form>
    <form method="post"><?php $fields('disable'); ?><button class="button button-secondary" type="submit">Disable everywhere</button></form>
    <?php endif; ?>
</div></div></div>
<div class="container"><div class="form-container form-container-wide">
<h1 class="u-mb20">De-Noise</h1>
<?php if ($error !== ''): ?><div class="alert alert-danger u-mb20" role="alert"><pre style="white-space:pre-wrap;overflow-wrap:anywhere"><?= $escape($isAdmin ? $error : 'De-Noise is temporarily unavailable. Contact the administrator.') ?></pre></div>
<?php elseif ($message !== ''): ?><div class="alert alert-success u-mb20" role="status"><p><?= $escape($message) ?></p></div><?php endif; ?>
<?php if ($isAdmin && isset($policy['mode'])): ?>
<form method="post" class="u-mb20">
    <?php $fields('save'); ?>
    <div class="u-mb20"><label class="form-label" for="mode">Server default</label>
        <select class="form-select" name="mode" id="mode">
            <?php foreach (['off' => 'Off', 'observe' => 'Observe — record matches, allow requests', 'enforce' => 'Enforce — block and rate-limit'] as $value => $label): ?>
            <option value="<?= $value ?>" <?= $policy['mode'] === $value ? 'selected' : '' ?>><?= $escape($label) ?></option>
            <?php endforeach; ?>
        </select>
    </div>
    <details class="box-collapse u-mb20" open>
        <summary class="box-collapse-header"><i class="fas fa-filter u-mr10"></i>User-Agents</summary>
        <div class="box-collapse-content">
            <p class="u-mb10">One literal substring per line. Case-insensitive.</p>
            <label class="form-label" for="agents">Blocklist</label>
            <textarea class="form-control u-mb10" rows="7" id="agents" name="agents" maxlength="32500" spellcheck="false"><?= $escape(implode("\n", $policy['agents'] ?? [])) ?></textarea>
            <button type="button" class="button button-secondary" id="hdn-preset">Add suggested agents</button>
            <p class="u-mt10">meta-externalagent · GoogleOther · MJ12bot</p>
        </div>
    </details>
    <details class="box-collapse u-mb20">
        <summary class="box-collapse-header"><i class="fas fa-sliders u-mr10"></i>Endpoint presets</summary>
        <div class="box-collapse-content">
            <?php foreach (['login' => 'WordPress login — POST /wp-login.php', 'xmlrpc' => 'WordPress XML-RPC — POST /xmlrpc.php'] as $key => $label): ?>
            <div class="u-mb20">
                <label class="form-label"><input type="checkbox" name="<?= $key ?>_enabled" <?= !empty($policy[$key]['enabled']) ? 'checked' : '' ?>> <?= $escape($label) ?></label>
                <label class="form-label" for="<?= $key ?>-rate">Requests per minute, per client and domain</label>
                <input class="form-control u-mb10" id="<?= $key ?>-rate" type="number" min="1" max="600" name="<?= $key ?>_rate" value="<?= $escape($policy[$key]['rate'] ?? 5) ?>" required>
                <label class="form-label" for="<?= $key ?>-burst">Burst allowance (Nginx burst)</label>
                <input class="form-control" id="<?= $key ?>-burst" type="number" min="0" max="100" name="<?= $key ?>_burst" value="<?= $escape($policy[$key]['burst'] ?? 3) ?>" required>
            </div>
            <?php endforeach; ?>
        </div>
    </details>
    <div class="u-mb20"><label class="form-label"><input type="checkbox" name="scanners" <?= !empty($policy['scanners']) ? 'checked' : '' ?>> Private-file preset</label>
        <p>/.env and /.env.* · /.git/ · /wp-config.php.bak, .backup, .old</p></div>
    <button class="button" type="submit"><i class="fas fa-floppy-disk icon-purple"></i>Save &amp; Apply</button>
</form>
<?php endif; ?>
<h2 class="u-mb20">Domains</h2>
<?php if ($isAdmin): ?>
<form method="post"><?php $fields('bulk'); ?>
<div class="toolbar-buttons u-mb20">
    <button class="button button-secondary" id="hdn-select" type="button">Select all</button>
    <select class="form-select" name="bulk_mode" aria-label="Mode for selected domains">
        <option value="inherit">Inherit server default</option><option value="off">Off</option><option value="observe">Observe</option><option value="enforce">Enforce</option>
    </select><button class="button" type="submit">Apply to selected</button>
</div>
<?php endif; ?>
<?php foreach ($data['sites'] ?? [] as $site): ?>
<details class="box-collapse u-mb10">
    <summary class="box-collapse-header">
        <?php if ($isAdmin): ?><input class="hdn-target" type="checkbox" name="targets[]" value="<?= $escape($site['key']) ?>" aria-label="Select <?= $escape($site['domain']) ?>"><?php endif; ?>
        <?= $escape($site['domain']) ?> · <?= $escape($site['owner']) ?> · <?= $escape(!$site['supported'] ? 'Unsupported' : ($site['suspended'] ? 'Suspended' : ucfirst($site['mode']))) ?>
    </summary>
    <div class="box-collapse-content">
        <p class="u-mb10">Proxy template: <?= $escape($site['template']) ?></p>
        <p class="u-mb10">Domain setting: <?= $escape($site['override']) ?></p>
        <?php if ($site['aliases'] !== ''): ?><p class="u-mb10">Aliases: <?= $escape($site['aliases']) ?></p><?php endif; ?>
        <?php if ($site['reason'] !== ''): ?><p><?= $escape($isAdmin ? $site['reason'] : 'This template is not currently supported.') ?></p><?php endif; ?>
    </div>
</details>
<?php endforeach; ?>
<?php if ($isAdmin): ?></form><?php endif; ?>
<?php if (empty($data['sites'])): ?><p>No domains to display.</p><?php endif; ?>
<p class="u-mt20"><small>Version <?= $escape($meta['version']) ?></small></p>
</div></div>
<script>
document.getElementById('hdn-preset')?.addEventListener('click', () => {
    const field = document.getElementById('agents');
    const lines = field.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    ['meta-externalagent', 'GoogleOther', 'MJ12bot'].forEach(agent => {
        if (!lines.some(line => line.toLowerCase() === agent.toLowerCase())) lines.push(agent);
    });
    field.value = lines.join('\n');
});
document.getElementById('hdn-select')?.addEventListener('click', () => {
    const boxes = [...document.querySelectorAll('.hdn-target')];
    const next = boxes.some(box => !box.checked);
    boxes.forEach(box => { box.checked = next; });
});
</script>
<?php require $root . '/web/templates/footer.php'; ?>
