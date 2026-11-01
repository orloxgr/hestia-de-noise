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
$statusRequest = ['actor' => $actor, 'owner' => $owner, 'action' => 'status'];
$error = '';
$message = '';
$submitted = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$isAdmin || !empty($read_only) || !is_string($_POST['token'] ?? null) ||
        !hash_equals($_SESSION['token'] ?? '', $_POST['token'])) {
        $error = 'Administrator access and a valid request token are required.';
    } else {
        $request = [...$statusRequest, 'action' => $_POST['action'] ?? ''];
        if ($request['action'] === 'save') {
            $agents = is_string($_POST['agents'] ?? null) ? preg_split('/\r\n|\r|\n/', trim($_POST['agents'])) : [];
            $submitted = ['schema' => 1, 'mode' => $_POST['mode'] ?? '', 'agents' => array_values(array_filter($agents, static fn($line) => trim($line) !== '')),
                'scanners' => isset($_POST['scanners'])];
            foreach (['login', 'xmlrpc'] as $key) {
                $submitted[$key] = ['enabled' => isset($_POST[$key . '_enabled']),
                    'rate' => filter_var($_POST[$key . '_rate'] ?? '', FILTER_VALIDATE_INT),
                    'burst' => filter_var($_POST[$key . '_burst'] ?? '', FILTER_VALIDATE_INT)];
            }
            $request['policy'] = $submitted;
        } elseif ($request['action'] === 'bulk') {
            $request['targets'] = $_POST['targets'] ?? [];
            $request['mode'] = $_POST['bulk_mode'] ?? '';
        }
        if (!in_array($request['action'], ['save', 'bulk', 'disable', 'sync'], true)) {
            $error = 'Unsupported operation.';
        } else {
            $result = $bridge($request);
            if (empty($result['ok'])) $error = $result['error'] ?? 'The operation failed.';
            else $message = $request['action'] === 'disable' ? 'De-Noise is off for every domain.' : 'Settings applied.';
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405); exit;
}
$data = $bridge($statusRequest);
if (empty($data['ok'])) $error = $error ?: ($data['error'] ?? 'Could not load De-Noise.');
// When impersonating a user, render the user's scope even for an admin session.
if (!$isAdmin) $data['sites'] = array_values(array_filter($data['sites'] ?? [], static fn($site) => $site['owner'] === $owner));
$policy = $error !== '' && $submitted !== null ? $submitted : ($data['policy'] ?? []);
$fields = static function (string $action) use ($escape): void {
    echo '<input type="hidden" name="token" value="' . $escape($_SESSION['token']) . '">';
    echo '<input type="hidden" name="action" value="' . $escape($action) . '">';
};
require $install . '/panel/view.php';
