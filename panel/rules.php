<?php
$renderRule = static function (string $module, $index, array $rule) use ($escape, $data): void {
    $name = $module . '[' . $index . ']';
    $field = static fn($key) => $escape($name . '[' . $key . ']');
    $filter = $module === 'filters';
    $targets = $rule['targets'] ?? [];
    ?>
    <div class="hdn-rule u-mb20" data-module="<?= $module ?>">
        <label class="form-label u-block">Name <input form="hdn-settings" class="form-control" name="<?= $field('id') ?>" value="<?= $escape($rule['id']) ?>" pattern="[a-z][a-z0-9_]{0,31}" maxlength="32" required></label>
        <label class="form-label u-block u-mt10"><input form="hdn-settings" type="checkbox" name="<?= $field('enabled') ?>" <?= !empty($rule['enabled']) ? 'checked' : '' ?>> Enabled</label>
        <label class="form-label u-block">URL <?= $filter ? 'path prefix' : 'directory' ?>
            <input form="hdn-settings" class="form-control" name="<?= $field('path') ?>" value="<?= $escape($rule['path']) ?>" maxlength="250" required></label>
        <?php if ($filter): ?>
        <label class="form-label u-block u-mt10">Query parameter names (one per line)
            <textarea form="hdn-settings" class="form-control" name="<?= $field('parameters') ?>" rows="3" required><?= $escape(implode("\n", $rule['parameters'])) ?></textarea></label>
        <label class="form-label u-block u-mt10">Crawler names (one literal substring per line)
            <textarea form="hdn-settings" class="form-control" name="<?= $field('agents') ?>" rows="4" required><?= $escape(implode("\n", $rule['agents'])) ?></textarea></label>
        <label class="form-label u-block u-mt10">Action <select form="hdn-settings" class="form-select" name="<?= $field('rule_action') ?>">
            <option value="limit" <?= $rule['action'] === 'limit' ? 'selected' : '' ?>>Rate limit</option>
            <option value="block" <?= $rule['action'] === 'block' ? 'selected' : '' ?>>Block matching crawlers on these URLs</option>
        </select></label>
        <label class="form-label u-block u-mt10">Requests per minute, per crawler and domain, across all client IPs
            <input form="hdn-settings" class="form-control" name="<?= $field('rate') ?>" type="number" min="1" max="600" value="<?= $escape($rule['rate']) ?>" required></label>
        <label class="form-label u-block u-mt10">Burst allowance
            <input form="hdn-settings" class="form-control" name="<?= $field('burst') ?>" type="number" min="0" max="100" value="<?= $escape($rule['burst']) ?>" required></label>
        <?php else: ?>
        <label class="form-label u-block u-mt10">File extensions (without dots)
            <input form="hdn-settings" class="form-control" name="<?= $field('extensions') ?>" value="<?= $escape(implode(' ', $rule['extensions'])) ?>" required></label>
        <?php endif; ?>
        <label class="form-label u-block u-mt10">Domains (empty selection means all domains)
        <select form="hdn-settings" class="form-select" name="<?= $field('targets') ?>[]" multiple size="4">
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
foreach (isset($ruleModule) ? [$ruleModule => $ruleModule === 'filters' ? 'Filtered URL crawling' : 'Missing static files'] : ['filters' => 'Filtered URL crawling', 'static' => 'Missing static files'] as $module => $title): ?>
<details class="box-collapse u-mb20">
    <summary class="box-collapse-header"><i class="fas fa-filter u-mr10"></i><?= $escape($title) ?></summary>
    <div class="box-collapse-content">
        <p class="u-mb10"><?= $module === 'filters'
            ? 'Match selected crawler names, a URL path and query parameter names. Ordinary visitors and unmatched URLs keep their current routing.'
            : 'Return 404 for missing files in selected directories. Existing files keep their current routing.' ?></p>
        <?php foreach ($data['presets']['rules'][$module] ?? [] as $preset): ?>
        <div class="u-mb10">
            <button type="button" class="button button-secondary" data-hdn-add="<?= $module ?>" data-hdn-rule-preset="<?= $escape($preset['key']) ?>"><?= $escape($preset['title']) ?></button>
            <p class="u-mt10"><?= $escape($preset['description']) ?></p>
        </div>
        <?php endforeach; ?>
        <p class="u-mb10" role="status" id="hdn-<?= $module ?>-message"></p>
        <div id="hdn-<?= $module ?>-rows">
        <?php foreach (is_array($policy[$module] ?? null) ? $policy[$module] : [] as $index => $rule) { $renderRule($module, $index, $rule); } ?>
        </div>
        <button type="button" class="button button-secondary" data-hdn-add="<?= $module ?>">Add rule</button>
        <?php if ($module === 'static' && !empty($data['sites'])): ?>
        <h3 class="u-mt20 u-mb10">File exceptions by domain</h3>
        <label class="form-label" for="hdn-exception-domain">Domain</label>
        <select form="hdn-settings" class="form-select u-mb10" id="hdn-exception-domain">
            <?php foreach ($data['sites'] as $site): ?>
            <option value="<?= $escape($site['key']) ?>"><?= $escape($site['domain'] . ' · ' . $site['owner']) ?></option>
            <?php endforeach; ?>
        </select>
        <?php foreach ($data['sites'] as $index => $site):
            $exceptions = $policy['static_exceptions'][$site['key']] ?? []; ?>
        <div data-hdn-exception-domain="<?= $escape($site['key']) ?>" <?= $index !== 0 ? 'hidden' : '' ?>>
            <label class="form-label u-block" for="hdn-exceptions-<?= $index ?>">Allowed file paths — one per line</label>
            <textarea form="hdn-settings" class="form-control" rows="4" maxlength="65536" spellcheck="false" id="hdn-exceptions-<?= $index ?>" name="static_exceptions[<?= $escape($site['key']) ?>]" placeholder="/wp-content/plugins/example/assets/app.js.map"><?= $escape(implode("\n", is_array($exceptions) ? $exceptions : [])) ?></textarea>
        </div>
        <?php endforeach; ?>
        <p class="u-mt10">Exact URL paths, starting with /. Exceptions use the domain's normal routing for every query string and apply to its aliases too. Save &amp; Apply to save all domains.</p>
        <?php endif; ?>
    </div>
</details>
<template id="hdn-<?= $module ?>-template">
<?php $renderRule($module, '__INDEX__', $module === 'filters'
    ? ['id' => '__ID__', 'enabled' => true, 'path' => '/shop/', 'parameters' => ['min_price', 'max_price', 'orderby'], 'agents' => $data['presets']['filter_agents'] ?? [], 'action' => 'limit', 'rate' => 30, 'burst' => 5, 'targets' => []]
    : ['id' => '__ID__', 'enabled' => true, 'path' => '/wp-content/', 'extensions' => ['map'], 'targets' => []]); ?>
</template>
<?php endforeach; ?>
<?php if (!isset($ruleModule) || $ruleModule === 'static'): ?>
<script type="application/json" id="hdn-rule-presets"><?= json_encode($data['presets']['rules'] ?? [], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
<?php endif; ?>
