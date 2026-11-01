<?php
$renderRule = static function (string $module, $index, array $rule) use ($escape, $data): void {
    $name = $module . '[' . $index . ']';
    $field = static fn($key) => $escape($name . '[' . $key . ']');
    $filter = $module === 'filters';
    $targets = $rule['targets'] ?? [];
    ?>
    <div class="hdn-rule u-mb20" data-module="<?= $module ?>">
        <label class="form-label u-block">Name <input class="form-control" name="<?= $field('id') ?>" value="<?= $escape($rule['id']) ?>" pattern="[a-z][a-z0-9_]{0,31}" maxlength="32" required></label>
        <label class="form-label u-block u-mt10"><input type="checkbox" name="<?= $field('enabled') ?>" <?= !empty($rule['enabled']) ? 'checked' : '' ?>> Enabled</label>
        <label class="form-label u-block">URL <?= $filter ? 'path prefix' : 'directory' ?>
            <input class="form-control" name="<?= $field('path') ?>" value="<?= $escape($rule['path']) ?>" maxlength="250" required></label>
        <?php if ($filter): ?>
        <label class="form-label u-block u-mt10">Query parameter names (one per line)
            <textarea class="form-control" name="<?= $field('parameters') ?>" rows="3" required><?= $escape(implode("\n", $rule['parameters'])) ?></textarea></label>
        <label class="form-label u-block u-mt10">Crawler names (one literal substring per line)
            <textarea class="form-control" name="<?= $field('agents') ?>" rows="4" required><?= $escape(implode("\n", $rule['agents'])) ?></textarea></label>
        <label class="form-label u-block u-mt10">Action <select class="form-select" name="<?= $field('rule_action') ?>">
            <option value="limit" <?= $rule['action'] === 'limit' ? 'selected' : '' ?>>Rate limit</option>
            <option value="block" <?= $rule['action'] === 'block' ? 'selected' : '' ?>>Block matching crawlers on these URLs</option>
        </select></label>
        <label class="form-label u-block u-mt10">Requests per minute, per crawler and domain, across all client IPs
            <input class="form-control" name="<?= $field('rate') ?>" type="number" min="1" max="600" value="<?= $escape($rule['rate']) ?>" required></label>
        <label class="form-label u-block u-mt10">Burst allowance
            <input class="form-control" name="<?= $field('burst') ?>" type="number" min="0" max="100" value="<?= $escape($rule['burst']) ?>" required></label>
        <?php else: ?>
        <label class="form-label u-block u-mt10">File extensions (without dots)
            <input class="form-control" name="<?= $field('extensions') ?>" value="<?= $escape(implode(' ', $rule['extensions'])) ?>" required></label>
        <?php endif; ?>
        <label class="form-label u-block u-mt10">Domains (empty selection means all domains)
        <select class="form-select" name="<?= $field('targets') ?>[]" multiple size="4">
            <?php $known = []; foreach ($data['sites'] ?? [] as $site): $known[] = $site['key']; ?>
            <option value="<?= $escape($site['key']) ?>" <?= in_array($site['key'], $targets, true) ? 'selected' : '' ?>><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option>
            <?php endforeach; foreach (array_diff($targets, $known) as $old): ?>
            <option value="<?= $escape($old) ?>" selected><?= $escape($old) ?> (unavailable)</option>
            <?php endforeach; ?>
        </select></label>
        <button type="button" class="button button-secondary u-mt10" data-hdn-remove>Remove rule</button>
    </div>
    <?php
};
foreach (['filters' => 'Filtered URL crawling', 'static' => 'Missing static files'] as $module => $title): ?>
<details class="box-collapse u-mb20">
    <summary class="box-collapse-header"><i class="fas fa-filter u-mr10"></i><?= $escape($title) ?></summary>
    <div class="box-collapse-content">
        <p class="u-mb10"><?= $module === 'filters'
            ? 'Match selected crawler names, a URL path and query parameter names. Ordinary visitors and unmatched URLs keep their current routing.'
            : 'Return 404 for missing files in selected directories. Existing files keep their current routing.' ?></p>
        <div id="hdn-<?= $module ?>-rows">
        <?php foreach (is_array($policy[$module] ?? null) ? $policy[$module] : [] as $index => $rule) { $renderRule($module, $index, $rule); } ?>
        </div>
        <button type="button" class="button button-secondary" data-hdn-add="<?= $module ?>">Add rule</button>
    </div>
</details>
<template id="hdn-<?= $module ?>-template">
<?php $renderRule($module, '__INDEX__', $module === 'filters'
    ? ['id' => '__ID__', 'enabled' => true, 'path' => '/shop/', 'parameters' => ['min_price', 'max_price', 'orderby'], 'agents' => $data['presets']['filter_agents'] ?? [], 'action' => 'limit', 'rate' => 30, 'burst' => 5, 'targets' => []]
    : ['id' => '__ID__', 'enabled' => true, 'path' => '/wp-content/', 'extensions' => ['map'], 'targets' => []]); ?>
</template>
<?php endforeach; ?>
