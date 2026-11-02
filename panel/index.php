<?php
// Managed by hestia-de-noise
declare(strict_types=1);
$install = '__INSTALL_ROOT__';
$meta = json_decode(file_get_contents($install . '/addon.json'), true, 16, JSON_THROW_ON_ERROR);
if ($_SERVER['REQUEST_METHOD'] === 'GET' && empty($_SERVER['HTTP_REFERER'])) {
    header('Cache-Control: no-store');
    echo '<!doctype html><meta charset="utf-8"><title>De-Noise</title><p><a href="./">Open De-Noise</a></p>';
    exit;
}
$root = '/usr/local/hestia';
chdir($root . '/web');
$TAB = 'WEB';
$panel = new class implements ArrayAccess {
    public function offsetExists(mixed $offset): bool { return true; }
    public function offsetGet(mixed $offset): mixed {
        $name = trim((string)$offset, "'");
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/D', $name)) return ['SUSPENDED' => 'yes'];
        return get_user_data($name)[$name] ?? ['SUSPENDED' => 'yes'];
    }
    public function offsetSet(mixed $offset, mixed $value): void { throw new LogicException('Read only'); }
    public function offsetUnset(mixed $offset): void { throw new LogicException('Read only'); }
};
require $root . '/web/inc/main.php';
header('Cache-Control: no-store, private');
header('X-Robots-Tag: noindex, nofollow');
header('Content-Type: text/html; charset=utf-8');
$actor = $_SESSION['user'] ?? '';
$owner = ($_SESSION['userContext'] ?? '') === 'admin' && !empty($_SESSION['look']) ? $_SESSION['look'] : $actor;
$headerOwner = $owner;
$actorData = get_user_data($actor)[$actor] ?? [];
$isAdmin = ($actorData['ROLE'] ?? '') === 'admin' && empty($_SESSION['look']);
$escape = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$bridge = static function (array $request) use ($root): array {
    $pipes = [];
    $process = proc_open(['/usr/bin/sudo', '-n', $root . '/bin/v-denoise-hestia'],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) return ['ok' => false, 'error' => 'Could not start the De-Noise command.'];
    fwrite($pipes[0], json_encode($request, JSON_THROW_ON_ERROR)); fclose($pipes[0]);
    $output = stream_get_contents($pipes[1], 2097152); fclose($pipes[1]);
    $error = stream_get_contents($pipes[2], 8192); fclose($pipes[2]);
    $code = proc_close($process);
    $result = json_decode($output, true);
    return is_array($result) ? $result : ['ok' => false, 'error' => "De-Noise failed (exit $code): " . $error];
};
$listing = [];
foreach (['bans', 'domain'] as $scope) {
    $pageValue = $_POST[$scope . '_page'] ?? $_GET[$scope . '_page'] ?? 1;
    $viewValue = $_POST[$scope . '_view'] ?? $_GET[$scope . '_view'] ?? 'active';
    $listing[$scope . '_page'] = filter_var($pageValue, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 1000000]]) ?: 1;
    $listing[$scope . '_view'] = in_array($viewValue, ['active', 'history'], true) ? $viewValue : 'active';
}
$statusRequest = ['actor' => $actor, 'owner' => $owner, 'action' => 'status', 'listing' => $listing];
$listing['wordpress_page'] = filter_var($_POST['wordpress_target_page'] ?? $_POST['wordpress_page'] ?? $_GET['wordpress_page'] ?? 1,
    FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 1000000]]) ?: 1;
$statusRequest['listing'] = $listing;
$error = '';
$message = '';
$submitted = null;
$wordpressResult = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ((!$isAdmin && !in_array($_POST['action'] ?? '', ['domain_bans_save', 'history_clear'], true)) || !empty($read_only) || !is_string($_POST['token'] ?? null) ||
        !hash_equals($_SESSION['token'] ?? '', $_POST['token'])) {
        $error = 'Write access and a valid request token are required.';
    } else {
        $request = [...$statusRequest, 'action' => $_POST['action'] ?? ''];
        if ($request['action'] === 'save') {
            $agents = is_string($_POST['agents'] ?? null) ? preg_split('/\r\n|\r|\n/', trim($_POST['agents'])) : [];
            $tools = is_string($_POST['tool_agents'] ?? null) ? preg_split('/\r\n|\r|\n/', trim($_POST['tool_agents'])) : [];
            $submitted = ['schema' => 7, 'mode' => $_POST['mode'] ?? '', 'agents' => array_values(array_filter($agents, static fn($line) => trim($line) !== '')),
                'tool_agents' => array_values(array_filter($tools, static fn($line) => trim($line) !== '')),
                'agents_enabled' => isset($_POST['agents_enabled']), 'tool_agents_enabled' => isset($_POST['tool_agents_enabled']),
                'scanners' => isset($_POST['scanners'])];
            $submitted['domain_bans'] = ['allow_users' => isset($_POST['allow_domain_bans']), 'sites' => (object)[]];
            foreach (['login', 'xmlrpc'] as $key) {
                $submitted[$key] = ['enabled' => isset($_POST[$key . '_enabled']),
                    'rate' => filter_var($_POST[$key . '_rate'] ?? '', FILTER_VALIDATE_INT),
                    'burst' => filter_var($_POST[$key . '_burst'] ?? '', FILTER_VALIDATE_INT)];
            }
            $list = static function ($value, bool $lines = false): array {
                if (!is_string($value)) return [];
                return array_values(array_filter(array_map('trim', preg_split($lines ? '/\r\n|\r|\n/' : '/[\s,]+/', $value)), static fn($x) => $x !== ''));
            };
            $submitted['bans'] = ['enabled' => isset($_POST['bans_enabled']),
                'private_files' => isset($_POST['bans_private_files']), 'repositories' => isset($_POST['bans_repositories']),
                'maxretry' => filter_var($_POST['bans_maxretry'] ?? '', FILTER_VALIDATE_INT),
                'findtime' => filter_var($_POST['bans_findtime'] ?? '', FILTER_VALIDATE_INT),
                'duration_days' => filter_var($_POST['bans_duration_days'] ?? '', FILTER_VALIDATE_INT),
                'ignore_ips' => $list($_POST['bans_ignore_ips'] ?? '', true), 'targets' => $_POST['bans_targets'] ?? []];
            foreach (['missing_files' => 'paths', 'suspicious_queries' => 'targets'] as $key => $field) {
                $submitted['bans'][$key] = ['enabled' => isset($_POST['bans_' . $key . '_enabled']),
                    'maxretry' => filter_var($_POST['bans_' . $key . '_maxretry'] ?? '', FILTER_VALIDATE_INT),
                    'findtime' => filter_var($_POST['bans_' . $key . '_findtime'] ?? '', FILTER_VALIDATE_INT),
                    'duration_days' => filter_var($_POST['bans_' . $key . '_duration_days'] ?? '', FILTER_VALIDATE_INT),
                    $field => $list($_POST['bans_' . $key . '_list'] ?? '', true)];
            }
            $submitted['bans']['suspicious_queries']['parameters'] = $list($_POST['bans_suspicious_queries_parameters'] ?? '', true);
            $submitted['bans']['any_404'] = ['enabled' => isset($_POST['bans_any_404_enabled']),
                'maxretry' => filter_var($_POST['bans_any_404_maxretry'] ?? '', FILTER_VALIDATE_INT),
                'findtime' => filter_var($_POST['bans_any_404_findtime'] ?? '', FILTER_VALIDATE_INT),
                'duration_days' => filter_var($_POST['bans_any_404_duration_days'] ?? '', FILTER_VALIDATE_INT)];
            $submitted['probe_exceptions'] = [];
            foreach (['files', 'queries'] as $kind) {
                $submitted['probe_exceptions'][$kind] = [];
                $values = $_POST['probe_exceptions_' . $kind] ?? [];
                if (!is_array($values)) { $submitted['probe_exceptions'][$kind] = false; continue; }
                foreach ($values as $site => $paths) {
                    if (!is_string($paths)) { $submitted['probe_exceptions'][$kind] = false; break; }
                    $paths = $list($paths, true);
                    if ($paths) $submitted['probe_exceptions'][$kind][$site] = $paths;
                }
            }
            $submitted['static_exceptions'] = [];
            if (!is_array($_POST['static_exceptions'] ?? [])) { $submitted['static_exceptions'] = false; }
            else {
                foreach ($_POST['static_exceptions'] ?? [] as $site => $paths) {
                    if (!is_string($paths)) { $submitted['static_exceptions'] = false; break; }
                    $paths = $list($paths, true);
                    if ($paths) $submitted['static_exceptions'][$site] = $paths;
                }
            }
            foreach (['filters', 'static'] as $module) {
                $submitted[$module] = [];
                if (!is_array($_POST[$module] ?? [])) { $submitted[$module] = false; continue; }
                foreach ($_POST[$module] ?? [] as $row) {
                    $row = is_array($row) ? $row : [];
                    $rule = ['id' => $row['id'] ?? '', 'enabled' => isset($row['enabled']),
                        'path' => $row['path'] ?? '', 'targets' => $row['targets'] ?? []];
                    if ($module === 'filters') {
                        $rule += ['parameters' => $list($row['parameters'] ?? ''),
                            'agents' => $list($row['agents'] ?? '', true), 'action' => $row['rule_action'] ?? '',
                            'rate' => filter_var($row['rate'] ?? '', FILTER_VALIDATE_INT),
                            'burst' => filter_var($row['burst'] ?? '', FILTER_VALIDATE_INT)];
                    } else { $rule['extensions'] = $list(strtolower((string)($row['extensions'] ?? ''))); }
                    $submitted[$module][] = $rule;
                }
            }
            $request['policy'] = $submitted;
            if (is_array($submitted['static_exceptions'])) $request['policy']['static_exceptions'] = (object)$submitted['static_exceptions'];
            foreach (['files', 'queries'] as $kind) {
                if (is_array($submitted['probe_exceptions'][$kind])) $request['policy']['probe_exceptions'][$kind] = (object)$submitted['probe_exceptions'][$kind];
            }
        } elseif ($request['action'] === 'history_clear') {
            $request['scope'] = $_POST['history_scope'] ?? '';
        } elseif ($request['action'] === 'history_settings_save') {
            $request['days'] = filter_var($_POST['history_days'] ?? '', FILTER_VALIDATE_INT);
        } elseif ($request['action'] === 'wordpress_save') {
            $integer = static fn($key) => filter_var($_POST[$key] ?? '', FILTER_VALIDATE_INT);
            $third = $integer('wordpress_third_days');
            $request['settings'] = ['enabled' => isset($_POST['wordpress_enabled']),
                'maxretry' => $integer('wordpress_maxretry'),
                'findtime' => $integer('wordpress_window_minutes') * 60,
                'durations' => [$integer('wordpress_first_minutes') * 60,
                    $integer('wordpress_second_days') * 86400, $third === 0 ? -1 : $third * 86400]];
        } elseif ($request['action'] === 'wordpress_unban') {
            $request['ips'] = isset($_POST['wordpress_unban_all']) ? 'all' : ($_POST['wordpress_ips'] ?? []);
        } elseif ($request['action'] === 'bulk') {
            $request['targets'] = $_POST['targets'] ?? [];
            $request['mode'] = $_POST['bulk_mode'] ?? '';
        } elseif ($request['action'] === 'unban') {
            $request['ips'] = isset($_POST['unban_all']) ? 'all' : ($_POST['ips'] ?? []);
        } elseif ($request['action'] === 'cron_preview') {
            $request['minimum'] = filter_var($_POST['cron_min'] ?? '', FILTER_VALIDATE_INT);
            $request['maximum'] = filter_var($_POST['cron_max'] ?? '', FILTER_VALIDATE_INT);
        } elseif ($request['action'] === 'cron_apply') {
            $request['plan_id'] = $_POST['plan_id'] ?? '';
            $request['jobs'] = $_POST['cron_jobs'] ?? [];
            $request['restore'] = isset($_POST['restore_cron']);
        } elseif ($request['action'] === 'domain_bans_save') {
            $request['preferences'] = [];
            if (!is_array($_POST['domain_preferences'] ?? null)) { $request['preferences'] = false; }
            else foreach ($_POST['domain_preferences'] as $site => $flags) {
                if (!is_array($flags) || array_diff(array_keys($flags), ['present', 'missing_files', 'suspicious_queries', 'any_404'])) {
                    $request['preferences'] = false; break;
                }
                $request['preferences'][$site] = ['missing_files' => isset($flags['missing_files']), 'suspicious_queries' => isset($flags['suspicious_queries']), 'any_404' => isset($flags['any_404'])];
            }
            if (is_array($request['preferences'])) $request['preferences'] = (object)$request['preferences'];
        }
        if (!in_array($request['action'], ['save', 'bulk', 'disable', 'sync', 'unban', 'cron_preview', 'cron_apply', 'domain_bans_save', 'wordpress_status', 'wordpress_save', 'wordpress_unban', 'history_clear', 'history_settings_save'], true)) {
            $error = 'Unsupported operation.';
        } else {
            $result = $bridge($request);
            if (isset($result['wordpress'])) $wordpressResult = $result['wordpress'];
            if (empty($result['ok'])) $error = $result['error'] ?? 'The operation failed.';
            elseif ($request['action'] === 'history_clear') $message = 'Completed ban history cleared. Active bans and strike counters are unchanged.';
            elseif ($request['action'] === 'history_settings_save') $message = 'History retention saved.';
            elseif (str_starts_with($request['action'], 'wordpress_')) $message = match ($request['action']) {
                'wordpress_save' => 'WordPress login protection applied through Fail2ban.',
                'wordpress_unban' => 'Selected WordPress IP bans removed.',
                default => 'WordPress login protection status refreshed.'
            };
            else $message = $request['action'] === 'domain_bans_save' ? 'Domain protection saved. Automatic bans synchronize within about one minute.' :
                ($request['action'] === 'cron_preview' ? 'Cron preview generated. No schedule has changed.' :
                ($request['action'] === 'cron_apply' ? 'Selected cron schedules updated through Hestia.' :
                ($request['action'] === 'disable' ? 'De-Noise is off for every domain. Its firewall bans will be released by synchronization.' :
                ($request['action'] === 'unban' ? 'Unban requested. Check the active and pending counts.' : 'Settings applied. Firewall changes synchronize within about one minute.'))));
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405); exit;
}
$data = $bridge($statusRequest);
if ($wordpressResult !== null) $data['wordpress'] = $wordpressResult;
if (empty($data['ok'])) $error = $error ?: ($data['error'] ?? 'Could not load De-Noise.');
// When impersonating a user, render the user's scope even for an admin session.
if (!$isAdmin) $data['sites'] = array_values(array_filter($data['sites'] ?? [], static fn($site) => $site['owner'] === $owner));
$policy = $error !== '' && $submitted !== null ? $submitted : ($data['policy'] ?? []);
$selectedTab = $_POST['tab'] ?? $_GET['tab'] ?? 'general';
$activeTab = is_string($selectedTab) ? $selectedTab : 'general';
$fields = static function (string $action) use ($escape, $activeTab, $listing): void {
    echo '<input type="hidden" name="token" value="' . $escape($_SESSION['token']) . '">';
    echo '<input type="hidden" name="action" value="' . $escape($action) . '">';
    echo '<input type="hidden" name="tab" value="' . $escape($activeTab) . '">';
    foreach ($listing as $key => $value) echo '<input type="hidden" name="' . $escape($key) . '" value="' . $escape($value) . '">';
};
require $install . '/panel/view.php';
