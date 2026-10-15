<?php
/* Package-aware Capstone rule deployment. Run on pfSense, never on Ubuntu. */
require_once('/etc/inc/config.inc');
require_once('/etc/inc/interfaces.inc');
require_once('/usr/local/pkg/snort/snort.inc');

function output_result($result, $status = 0) {
    echo json_encode($result, JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit($status);
}

function rebuild_instance($instance) {
    global $rebuild_rules;
    $rebuild_rules = true;
    try { snort_generate_conf($instance); }
    finally { $rebuild_rules = false; }
}

function validate_instance($conf) {
    $lines = [];
    $status = 0;
    exec('/usr/local/bin/snort -T -c ' . escapeshellarg($conf) . ' 2>&1', $lines, $status);
    if ($status !== 0) {
        throw new RuntimeException('Snort validation failed: ' . implode("\n", array_slice($lines, -12)));
    }
}

$lock = fopen('/var/run/capstone-snort.lock', 'c');
if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
    output_result(['ok' => false, 'error' => 'Another deployment is running'], 1);
}
$old = null;
$changed = false;
$persisted = false;
try {
    $request = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
    $interface = $request['interface'] ?? 'wan';
    $instances = config_get_path('installedpackages/snortglobal/rule', []);
    $matches = [];
    foreach ($instances as $index => $instance) {
        if (($instance['interface'] ?? '') === $interface) { $matches[] = $index; }
    }
    if (count($matches) !== 1) { throw new RuntimeException('Need exactly one matching Snort interface'); }
    $index = $matches[0];
    $old = $instances[$index];
    $real = get_real_interface($interface);
    $uuid = (string)$old['uuid'];
    if (!preg_match('/^[0-9]+$/', $uuid) || !preg_match('/^[a-zA-Z0-9_]+$/', $real)) {
        throw new RuntimeException('Invalid Snort instance identifiers');
    }
    $conf = SNORTDIR . '/snort_' . $uuid . '_' . $real . '/snort.conf';
    $mode = ($old['ips_mode'] ?? '') === 'ips_mode_inline' ? 'inline' : 'legacy';
    $info = ['interface' => $interface, 'device' => $real, 'uuid' => $uuid,
        'mode' => $mode, 'blocking' => ($old['blockoffenders7'] ?? '') === 'on',
        'running' => (bool)snort_is_running($uuid), 'config_path' => $conf];
    if (($request['operation'] ?? '') === 'inspect') { output_result(['ok' => true] + $info); }
    if (($request['operation'] ?? '') !== 'apply') { throw new RuntimeException('Unknown operation'); }
    if (($request['mode'] ?? '') !== $mode || !$info['blocking'] || !$info['running']) {
        throw new RuntimeException('Expected mode, running service and blocking enabled are required');
    }
    $rules = $request['rules'] ?? [];
    if (!is_array($rules) || count($rules) > 1000) { throw new RuntimeException('Invalid rule set'); }
    $sids = [];
    $action = $mode === 'inline' ? 'drop' : 'alert';
    foreach ($rules as $rule) {
        $pattern = '/^' . $action . ' tcp any any -> any 5020 \(msg:"Capstone Modbus write register [0-9]+ value [0-9]+"; flow:to_server,established; content:"\|06 [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2}\|"; offset:7; depth:5; sid:([0-9]+); rev:1;\)$/D';
        if (!is_string($rule) || !preg_match($pattern, $rule, $match)) {
            throw new RuntimeException('Only generated command-specific rules are accepted');
        }
        if (isset($sids[$match[1]])) { throw new RuntimeException('Duplicate SID'); }
        $sids[$match[1]] = true;
    }
    $existing = base64_decode($old['customrules'] ?? '', true);
    if ($existing === false) { throw new RuntimeException('Invalid existing custom rules'); }
    $begin = '# BEGIN CAPSTONE MANAGED';
    $end = '# END CAPSTONE MANAGED';
    if (substr_count($existing, $begin) !== substr_count($existing, $end) || substr_count($existing, $begin) > 1) {
        throw new RuntimeException('Invalid managed rule markers');
    }
    $outside = preg_replace('/^# BEGIN CAPSTONE MANAGED\R.*?^# END CAPSTONE MANAGED\R?/ms', '', $existing);
    $preserved = [];
    foreach (preg_split('/\R/', $outside) as $line) {
        if (preg_match('/\bsid:\s*([0-9]+)\s*;/', $line, $match) && isset($sids[$match[1]])) {
            // Migrate the same manually installed Capstone signature only.
            if (strpos($line, 'msg:"Capstone Modbus write register ') === false) {
                throw new RuntimeException('SID conflicts with an unrelated existing rule');
            }
            continue;
        }
        $preserved[] = $line;
    }
    $merged = rtrim(implode("\n", $preserved)) . "\n" . $begin . "\n" . implode("\n", $rules) . "\n" . $end . "\n";
    if ($merged === $existing) { output_result(['ok' => true, 'changed' => false] + $info); }
    $backup_dir = '/conf/capstone-backups';
    if (!is_dir($backup_dir) && !mkdir($backup_dir, 0700)) { throw new RuntimeException('Cannot create backup directory'); }
    $backup = $backup_dir . '/snort-' . $uuid . '-' . bin2hex(random_bytes(8)) . '.json';
    if (file_put_contents($backup, json_encode(['interface' => $interface, 'uuid' => $uuid, 'customrules' => $old['customrules'] ?? null])) === false) {
        throw new RuntimeException('Cannot back up custom rules');
    }
    chmod($backup, 0600);
    $instances[$index]['customrules'] = base64_encode($merged);
    config_set_path('installedpackages/snortglobal/rule', $instances);
    $changed = true;
    rebuild_instance($instances[$index]);
    validate_instance($conf);
    write_config('Capstone: validated custom rule deployment for ' . $interface);
    $persisted = true;
    snort_reload_config($instances[$index]);
    if (!snort_is_running($uuid)) { throw new RuntimeException('Snort is not running after reload'); }
    output_result(['ok' => true, 'changed' => true, 'rules' => count($rules), 'backup' => $backup] + $info);
} catch (Throwable $error) {
    $rollback_error = null;
    if ($changed && $old !== null) {
        try {
            $instances[$index] = $old;
            config_set_path('installedpackages/snortglobal/rule', $instances);
            rebuild_instance($old);
            if ($persisted) {
                write_config('Capstone: rollback failed custom rule deployment');
                snort_reload_config($old);
            }
        } catch (Throwable $rollback) { $rollback_error = $rollback->getMessage(); }
    }
    output_result(['ok' => false, 'error' => $error->getMessage(), 'rollback_error' => $rollback_error], 1);
}
