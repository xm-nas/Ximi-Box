<?php
error_reporting(E_ALL);
ini_set('display_errors', '0');
date_default_timezone_set('Asia/Shanghai');

/*
 * Ximi Disk security-hardened backend.
 * Requires PHP 7.4+ (8.x recommended), 64-bit PHP for large uploads.
 */

$is_https = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off')
    || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
if ($is_https) {
    ini_set('session.cookie_secure', '1');
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: SAMEORIGIN');

$base_dir = __DIR__;
$data_dir = $base_dir . '/data';
$upload_dir = $base_dir . '/uploads';
$chunks_dir = $data_dir . '/chunks';
$json_file = $data_dir . '/metadata.json';

define('XIMI_CHUNK_SIZE', 3 * 1024 * 1024);
define('XIMI_MAX_UPLOAD_BYTES', 2 * 1024 * 1024 * 1024); // 全局硬上限：2 GiB
define('XIMI_MAX_CHUNKS', (int)ceil(XIMI_MAX_UPLOAD_BYTES / XIMI_CHUNK_SIZE));
define('XIMI_MAX_FILENAME_BYTES', 240);
define('XIMI_MAX_TEXT_BYTES', 20000);

function jsonResp($status, $msg, $extra = [], $http_code = 200) {
    if (!headers_sent()) {
        http_response_code((int)$http_code);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, max-age=0');
    }
    $payload = array_merge(["status" => $status, "message" => $msg], is_array($extra) ? $extra : []);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function inputString($value, $max_length = 4096) {
    if (!is_string($value) && !is_numeric($value)) {
        return '';
    }
    $value = (string)$value;
    if (strlen($value) > $max_length) {
        return '';
    }
    return $value;
}

function isValidDirKey($dir_key) {
    return is_string($dir_key)
        && strlen($dir_key) <= 90
        && preg_match('/\A(?:dir_default|dir_[A-Za-z0-9_-]{1,80})\z/D', $dir_key) === 1;
}

function isSafeFilename($filename) {
    if (!is_string($filename) || $filename === '' || strlen($filename) > XIMI_MAX_FILENAME_BYTES) {
        return false;
    }
    if ($filename === '.' || $filename === '..' || $filename[0] === '.') {
        return false;
    }
    if (preg_match('/[\x00-\x1F\x7F\/\\\\<>:"|?*]/u', $filename)) {
        return false;
    }
    if (preg_match('/[. ]\z/u', $filename)) {
        return false;
    }
    if (preg_match('//u', $filename) !== 1) {
        return false;
    }
    return true;
}

function normalizeClientFilename($filename) {
    $filename = inputString($filename, 4096);
    if ($filename === '') return '';
    // 不做 basename() 静默截断；发现任何路径分隔符都拒绝。
    if (!isSafeFilename($filename)) return '';
    return $filename;
}

function isSafeHttpUrl($url) {
    if (!is_string($url) || $url === '' || strlen($url) > 2048) return false;
    if (preg_match('/[\x00-\x20\x7F]/', $url)) return false;
    if (!filter_var($url, FILTER_VALIDATE_URL)) return false;
    $parts = parse_url($url);
    if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) return false;
    $scheme = strtolower($parts['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') return false;
    if (isset($parts['user']) || isset($parts['pass'])) return false;
    return true;
}

function normalizeExtCsv($raw_str) {
    $clean_exts = [];
    if (trim((string)$raw_str) !== '') {
        foreach (explode(',', strtolower((string)$raw_str)) as $part) {
            $ext = ltrim(trim($part), '.');
            if ($ext !== '' && preg_match('/^[a-z0-9]{1,16}$/', $ext)) {
                $clean_exts[] = $ext;
            }
        }
        $clean_exts = array_values(array_unique($clean_exts));
    }
    return implode(',', $clean_exts);
}

function hardForbiddenExtensions() {
    // 禁止可执行脚本、服务器配置、浏览器可执行内容，避免同源上传 XSS/RCE。
    return [
        'php','php3','php4','php5','php7','php8','phtml','pht','phar',
        'asp','aspx','ashx','asmx','jsp','jspx','cgi','pl','py','rb',
        'sh','bash','zsh','fish','ps1','bat','cmd','com','exe','dll',
        'so','dylib','msi','msp','vbs','vbe','js','mjs','cjs','jsx',
        'ts','tsx','html','htm','xhtml','shtml','svg','xml','xsl',
        'css','wasm','htaccess','ini'
    ];
}

function getAllExtensions($filename) {
    $name = strtolower((string)$filename);
    $parts = explode('.', $name);
    if (count($parts) < 2) return [];
    array_shift($parts);
    return array_values(array_filter($parts, function($part) {
        return $part !== '';
    }));
}

function checkSystemForbiddenExt($filename, $data) {
    $configured = normalizeExtCsv($data['settings']['forbidden_exts'] ?? '');
    $forbidden = $configured === '' ? [] : explode(',', $configured);
    $forbidden = array_values(array_unique(array_merge($forbidden, hardForbiddenExtensions())));

    foreach (getAllExtensions($filename) as $ext) {
        if (in_array($ext, $forbidden, true)) {
            return $ext;
        }
    }
    return null;
}

function normalizeLimitsFromPost() {
    $readMb = function($key) {
        $raw = $_POST[$key] ?? '0';
        if (!is_scalar($raw) || !is_numeric($raw)) return 0;
        $number = (float)$raw;
        if (!is_finite($number) || $number < 0) return 0;
        return min(2048, round($number, 2));
    };

    return [
        "max_total_mb" => $readMb('max_total_mb'),
        "max_file_mb" => $readMb('max_file_mb'),
        "allowed_exts" => normalizeExtCsv(inputString($_POST['allowed_exts'] ?? '', 2048))
    ];
}

function safeUploadDirectory($dir_key, $upload_dir, $create = false) {
    if (!isValidDirKey($dir_key)) return false;
    $base = realpath($upload_dir);
    if ($base === false) {
        if (!$create || !@mkdir($upload_dir, 0750, true)) return false;
        $base = realpath($upload_dir);
    }
    if ($base === false) return false;

    $candidate = $upload_dir . DIRECTORY_SEPARATOR . $dir_key;
    if (is_link($candidate)) return false;
    if (!is_dir($candidate)) {
        if (!$create || !@mkdir($candidate, 0750, true)) return false;
    }
    $real = realpath($candidate);
    if ($real === false || strpos($real, $base . DIRECTORY_SEPARATOR) !== 0) return false;
    return $real;
}

function safeStoredFilePath($dir_key, $filename, $upload_dir) {
    if (!isValidDirKey($dir_key) || !isSafeFilename($filename)) return false;
    $folder = safeUploadDirectory($dir_key, $upload_dir, false);
    if ($folder === false) return false;
    $path = $folder . DIRECTORY_SEPARATOR . $filename;
    if (is_link($path)) return false;
    $parent = realpath(dirname($path));
    if ($parent === false || $parent !== $folder) return false;
    return $path;
}

function getDirUsedBytes($dir_key, $upload_dir) {
    $total = 0;
    $folder = safeUploadDirectory($dir_key, $upload_dir, false);
    if ($folder === false) return 0;

    $items = @scandir($folder);
    if ($items) {
        foreach ($items as $it) {
            if ($it === '.' || $it === '..' || $it === '@eaDir' || $it === '.DS_Store') continue;
            $path = $folder . DIRECTORY_SEPARATOR . $it;
            if (is_file($path) && !is_link($path)) {
                $size = @filesize($path);
                if ($size !== false) $total += $size;
            }
        }
    }
    return $total;
}

function validateUploadRules($target_dir, $filename, $file_size_bytes, $data, $upload_dir, $default_limits) {
    if (!isValidDirKey($target_dir) || !isSafeFilename($filename)) {
        return "文件名或目录参数不合法";
    }
    if (!is_numeric($file_size_bytes) || $file_size_bytes < 0 || $file_size_bytes > XIMI_MAX_UPLOAD_BYTES) {
        return "文件大小超出系统允许范围（最大 2 GiB）";
    }

    $blocked_ext = checkSystemForbiddenExt($filename, $data);
    if ($blocked_ext !== null) {
        return "系统禁止上传 ." . $blocked_ext . " 类型文件";
    }

    $limits = $data['directories'][$target_dir]['limits'] ?? $default_limits;
    $allowed_str = normalizeExtCsv($limits['allowed_exts'] ?? '');
    if ($allowed_str !== '') {
        $allowed_arr = explode(',', $allowed_str);
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if ($ext === '' || !in_array($ext, $allowed_arr, true)) {
            return "类型受限：仅允许 " . implode(', ', $allowed_arr);
        }
    }

    $max_file_mb = max(0, (float)($limits['max_file_mb'] ?? 0));
    if ($max_file_mb > 0 && $file_size_bytes > ($max_file_mb * 1024 * 1024)) {
        return "单文件超出大小限制（上限 {$max_file_mb} MB）";
    }

    $max_total_mb = max(0, (float)($limits['max_total_mb'] ?? 0));
    if ($max_total_mb > 0) {
        $used_bytes = getDirUsedBytes($target_dir, $upload_dir);
        $limit_bytes = $max_total_mb * 1024 * 1024;
        if (($used_bytes + $file_size_bytes) > $limit_bytes) {
            $used_mb = round($used_bytes / 1048576, 2);
            return "目录容量不足（上限 {$max_total_mb} MB，已用 {$used_mb} MB）";
        }
    }
    return null;
}

function removeDirRecursive($dir) {
    if (!is_dir($dir) || is_link($dir)) return;
    $items = @scandir($dir);
    if ($items) {
        foreach ($items as $it) {
            if ($it === '.' || $it === '..') continue;
            $p = $dir . DIRECTORY_SEPARATOR . $it;
            if (is_link($p) || is_file($p)) {
                @unlink($p);
            } elseif (is_dir($p)) {
                removeDirRecursive($p);
            }
        }
    }
    @rmdir($dir);
}

function saveJson($file, $data) {
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($json === false) return false;

    $tmp = $file . '.tmp.' . bin2hex(random_bytes(6));
    $fp = @fopen($tmp, 'xb');
    if (!$fp) return false;

    $written = 0;
    $length = strlen($json);
    while ($written < $length) {
        $n = fwrite($fp, substr($json, $written));
        if ($n === false || $n === 0) {
            fclose($fp);
            @unlink($tmp);
            return false;
        }
        $written += $n;
    }
    fflush($fp);
    if (function_exists('fsync')) @fsync($fp);
    fclose($fp);

    @chmod($tmp, 0640);
    if (!@rename($tmp, $file)) {
        @unlink($tmp);
        return false;
    }
    return true;
}

function generatePickupCode($data) {
    $existing = [];
    foreach (($data['directories'] ?? []) as $dir) {
        foreach (($dir['files'] ?? []) as $f) {
            if (!empty($f['pickup_code'])) $existing[] = strtoupper((string)$f['pickup_code']);
        }
    }

    for ($i = 0; $i < 5000; $i++) {
        $code = chr(random_int(65, 90)) . str_pad((string)random_int(0, 9999), 4, '0', STR_PAD_LEFT);
        if (!in_array($code, $existing, true)) return $code;
    }
    return '';
}

function isDirUnlocked($dir_key) {
    return isset($_SESSION['unlocked_dirs'][$dir_key]) && $_SESSION['unlocked_dirs'][$dir_key] === true;
}

function hasDirManagePermission($dir_key, $data, $is_admin) {
    if ($is_admin) return true;
    if (!isValidDirKey($dir_key) || !isset($data['directories'][$dir_key])) return false;
    return isDirUnlocked($dir_key) && !empty($data['directories'][$dir_key]['pwd_perm']['manage']);
}

function checkDirPermission($dir_key, $action, $data, $is_admin) {
    if ($is_admin) return true;
    if (!isValidDirKey($dir_key) || !isset($data['directories'][$dir_key])) return false;

    $dir = $data['directories'][$dir_key];
    $unlocked = isDirUnlocked($dir_key);
    $has_pwd = !empty(trim((string)($dir['password'] ?? '')));
    $direct_perm = $dir['direct_perm'] ?? ["view" => true, "download" => false, "upload" => false];
    $prohibit_visitor = empty($direct_perm['view']);

    if ($unlocked) {
        $pwd_perm = $dir['pwd_perm'] ?? ["download" => true, "upload" => true, "manage" => false];
        if ($action === 'view') return true;
        if ($action === 'download' && !empty($pwd_perm['download'])) return true;
        if ($action === 'upload' && !empty($pwd_perm['upload'])) return true;
        if ($action === 'manage' && !empty($pwd_perm['manage'])) return true;
        return false;
    }

    if ($has_pwd || $prohibit_visitor) return false;
    if ($action === 'view' && !empty($direct_perm['view'])) return true;
    if ($action === 'download' && !empty($direct_perm['download'])) return true;
    if ($action === 'upload' && !empty($direct_perm['upload'])) return true;
    return false;
}

function findFileIndexById($files, $file_id) {
    if (!is_array($files) || $file_id === '') return -1;
    foreach ($files as $idx => $item) {
        if (isset($item['file_id']) && hash_equals((string)$item['file_id'], (string)$file_id)) return $idx;
    }
    return -1;
}

function filenameExistsInDirectory($dir_key, $filename, $data, $upload_dir, $except_file_id = '') {
    $except_name = '';
    if ($except_file_id !== '') {
        foreach (($data['directories'][$dir_key]['files'] ?? []) as $item) {
            if ((string)($item['file_id'] ?? '') === (string)$except_file_id
                && ($item['type'] ?? 'file') === 'file') {
                $except_name = (string)($item['name'] ?? '');
                break;
            }
        }
    }

    $path = safeStoredFilePath($dir_key, $filename, $upload_dir);
    if ($path !== false && file_exists($path) && strcasecmp($except_name, $filename) !== 0) {
        return true;
    }
    foreach (($data['directories'][$dir_key]['files'] ?? []) as $item) {
        if (($item['type'] ?? 'file') === 'file'
            && strcasecmp((string)($item['name'] ?? ''), $filename) === 0
            && (string)($item['file_id'] ?? '') !== (string)$except_file_id) {
            return true;
        }
    }
    return false;
}

function validUploadId($upload_id) {
    return is_string($upload_id) && preg_match('/\A[a-f0-9]{32}\z/D', $upload_id) === 1;
}

function getUploadSessionDir($upload_id, $chunks_dir) {
    if (!validUploadId($upload_id)) return false;
    $base = realpath($chunks_dir);
    if ($base === false) return false;
    $path = $chunks_dir . DIRECTORY_SEPARATOR . $upload_id;
    if (is_link($path)) return false;
    if (is_dir($path)) {
        $real = realpath($path);
        if ($real === false || strpos($real, $base . DIRECTORY_SEPARATOR) !== 0) return false;
    }
    return $path;
}

function loadUploadState($upload_id, $chunks_dir) {
    $dir = getUploadSessionDir($upload_id, $chunks_dir);
    if ($dir === false || !is_dir($dir)) return [false, null, null];
    $meta = $dir . DIRECTORY_SEPARATOR . 'meta.json';
    if (!is_file($meta) || is_link($meta)) return [$dir, null, null];
    $state = json_decode((string)@file_get_contents($meta), true);
    return [$dir, is_array($state) ? $state : null, $meta];
}

function saveUploadState($meta_path, $state) {
    return saveJson($meta_path, $state);
}

function verifyUploadState($state, $target_dir, $filename, $total_chunks, $total_size) {
    if (!is_array($state)) return false;
    $owner = hash('sha256', session_id());
    return isset($state['owner'], $state['dir_key'], $state['filename'], $state['total_chunks'], $state['total_size'])
        && hash_equals((string)$state['owner'], $owner)
        && hash_equals((string)$state['dir_key'], (string)$target_dir)
        && hash_equals((string)$state['filename'], (string)$filename)
        && (int)$state['total_chunks'] === (int)$total_chunks
        && (int)$state['total_size'] === (int)$total_size;
}

function sendFileDownload($filepath, $filename) {
    if (!is_file($filepath) || is_link($filepath) || !is_readable($filepath)) {
        http_response_code(404);
        exit('文件不存在或已被删除');
    }
    $size = filesize($filepath);
    if ($size === false) {
        http_response_code(404);
        exit('无法读取文件');
    }

    while (ob_get_level()) ob_end_clean();
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('X-Content-Type-Options: nosniff');
    header('Content-Disposition: attachment; filename="download"; filename*=UTF-8\'\'' . rawurlencode($filename));
    header('Content-Length: ' . $size);
    header('Cache-Control: private, no-store, no-cache, must-revalidate');
    readfile($filepath);
    exit;
}

function sendInlinePreview($filepath, $filename, $extension) {
    if (!is_file($filepath) || is_link($filepath) || !is_readable($filepath)) {
        http_response_code(404);
        exit('文件不存在或已被删除');
    }

    $types = [
        'png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg',
        'gif' => 'image/gif', 'webp' => 'image/webp', 'bmp' => 'image/bmp',
        'mp4' => 'video/mp4', 'm4v' => 'video/mp4', 'webm' => 'video/webm',
        'ogg' => 'video/ogg', 'mov' => 'video/quicktime', 'mkv' => 'video/x-matroska',
        'mp3' => 'audio/mpeg', 'wav' => 'audio/wav', 'm4a' => 'audio/mp4',
        'aac' => 'audio/aac', 'flac' => 'audio/flac',
        'txt' => 'text/plain; charset=utf-8', 'ini' => 'text/plain; charset=utf-8',
        'log' => 'text/plain; charset=utf-8', 'json' => 'text/plain; charset=utf-8',
        'md' => 'text/plain; charset=utf-8', 'csv' => 'text/plain; charset=utf-8',
        'xml' => 'text/plain; charset=utf-8'
    ];

    $extension = strtolower((string)$extension);
    if (!isset($types[$extension])) {
        http_response_code(415);
        exit('该文件类型不允许在线预览');
    }

    $size = filesize($filepath);
    if ($size === false) {
        http_response_code(404);
        exit('无法读取文件');
    }

    while (ob_get_level()) ob_end_clean();
    header('Content-Type: ' . $types[$extension]);
    header('X-Content-Type-Options: nosniff');
    header("Content-Disposition: inline; filename=\"preview\"; filename*=UTF-8''" . rawurlencode($filename));
    header('Cache-Control: private, no-store, no-cache, must-revalidate');
    header("Content-Security-Policy: default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox");

    $start = 0;
    $end = max(0, $size - 1);
    $range = (string)($_SERVER['HTTP_RANGE'] ?? '');

    if ($range !== '') {
        if (strpos($range, ',') !== false || !preg_match('/\Abytes=(\d*)-(\d*)\z/D', trim($range), $matches)
            || ($matches[1] === '' && $matches[2] === '')) {
            http_response_code(416);
            header('Content-Range: bytes */' . $size);
            exit;
        }

        if ($matches[1] === '') {
            $suffix = (int)$matches[2];
            if ($suffix <= 0) {
                http_response_code(416);
                header('Content-Range: bytes */' . $size);
                exit;
            }
            $start = max(0, $size - $suffix);
        } else {
            $start = (int)$matches[1];
        }
        if ($matches[1] !== '' && $matches[2] !== '') $end = (int)$matches[2];

        if ($size === 0 || $start > $end || $start >= $size) {
            http_response_code(416);
            header('Content-Range: bytes */' . $size);
            exit;
        }
        $end = min($end, $size - 1);
        http_response_code(206);
        header('Content-Range: bytes ' . $start . '-' . $end . '/' . $size);
    }
    header('Accept-Ranges: bytes');

    $length = $size > 0 ? ($end - $start + 1) : 0;
    header('Content-Length: ' . $length);
    $fp = @fopen($filepath, 'rb');
    if (!$fp) {
        http_response_code(404);
        exit('无法打开文件');
    }
    if ($start > 0) fseek($fp, $start);

    $remaining = $length;
    while ($remaining > 0 && !feof($fp)) {
        $chunk = fread($fp, min(1024 * 1024, $remaining));
        if ($chunk === false || $chunk === '') break;
        echo $chunk;
        $remaining -= strlen($chunk);
        if (function_exists('flush')) flush();
    }
    fclose($fp);
    exit;
}

/* Create protected storage roots. */
if (!is_dir($data_dir) && !@mkdir($data_dir, 0750, true)) {
    jsonResp('error', '数据目录不可用', [], 500);
}
if (!is_dir($upload_dir) && !@mkdir($upload_dir, 0750, true)) {
    jsonResp('error', '上传目录不可用', [], 500);
}
if (!is_dir($chunks_dir) && !@mkdir($chunks_dir, 0700, true)) {
    jsonResp('error', '分片目录不可用', [], 500);
}
@chmod($data_dir, 0750);
@chmod($upload_dir, 0750);
@chmod($chunks_dir, 0700);

/*
 * Apache protection. Nginx users must also install the location rules
 * supplied with the final security notes; .htaccess is ignored by Nginx.
 */
$data_htaccess = $data_dir . '/.htaccess';
$data_rules = "Require all denied\n";
if (!is_link($data_htaccess) && (!is_file($data_htaccess) || @file_get_contents($data_htaccess) !== $data_rules)) {
    @file_put_contents($data_htaccess, $data_rules, LOCK_EX);
    @chmod($data_htaccess, 0640);
}
$upload_htaccess = $upload_dir . '/.htaccess';
$upload_rules = "Options -Indexes -ExecCGI\nRequire all denied\n";
if (!is_link($upload_htaccess) && (!is_file($upload_htaccess) || @file_get_contents($upload_htaccess) !== $upload_rules)) {
    @file_put_contents($upload_htaccess, $upload_rules, LOCK_EX);
    @chmod($upload_htaccess, 0640);
}

$default_limits = [
    "max_total_mb" => 0,
    "max_file_mb" => 0,
    "allowed_exts" => ""
];

$initial_admin_password = getenv('XIMI_ADMIN_PASSWORD');
$generated_initial_password = false;
if (!is_string($initial_admin_password) || strlen($initial_admin_password) < 12) {
    $initial_admin_password = bin2hex(random_bytes(16));
    $generated_initial_password = true;
}

$default_data = [
    "settings" => [
        "space_total" => 9999,
        "admin_password" => password_hash($initial_admin_password, PASSWORD_DEFAULT),
        "forbidden_exts" => "php,phtml,php3,php4,php5,phar,exe,bat,cmd,sh,ps1,vbs,jsp,asp,aspx,cgi,pl,html,htm,svg,js,mjs,css"
    ],
    "guestbook" => [],
    "directories" => [
        "dir_default" => [
            "name" => "默认公共目录",
            "remark" => "系统默认公共资源目录",
            "open_mode" => "direct",
            "password" => "",
            "direct_perm" => ["view" => true, "download" => true, "upload" => false],
            "pwd_perm" => ["download" => true, "upload" => true, "manage" => false],
            "limits" => $default_limits,
            "files" => []
        ]
    ]
];

if (!file_exists($json_file) || filesize($json_file) === 0) {
    if (!saveJson($json_file, $default_data)) {
        jsonResp('error', '无法初始化数据文件', [], 500);
    }
    @chmod($json_file, 0640);

    // Fresh install: keep the generated password outside the public web path.
    if ($generated_initial_password) {
        $initial_password_file = $data_dir . '/initial-admin-password.txt';
        if (!is_link($initial_password_file)) {
            @file_put_contents($initial_password_file, $initial_admin_password . PHP_EOL, LOCK_EX);
            @chmod($initial_password_file, 0600);
        }
        error_log('Ximi Disk first-run administrator password was written to data/initial-admin-password.txt');
    }
}

/*
 * Serialize all POST mutations so concurrent PHP requests do not load the
 * same old JSON and overwrite each other's updates. The lock is released on exit.
 */
$request_lock = null;
$action = inputString($_GET['action'] ?? '', 64);
$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$needs_mutation_lock = ($method === 'POST') || in_array($action, ['download', 'pickup_download'], true);
if ($needs_mutation_lock) {
    $request_lock = @fopen($data_dir . '/metadata.mutex', 'c');
    if (!$request_lock || !flock($request_lock, LOCK_EX)) {
        jsonResp('error', '系统繁忙，请稍后重试', [], 503);
    }
}

$data_raw = @file_get_contents($json_file);
$data = is_string($data_raw) ? json_decode($data_raw, true) : null;
if (!is_array($data) || !isset($data['settings'], $data['directories'])
    || !is_array($data['settings']) || !is_array($data['directories'])) {
    jsonResp('error', '数据文件损坏，请先备份并修复 data/metadata.json', [], 500);
}
if (!isset($data['guestbook']) || !is_array($data['guestbook'])) $data['guestbook'] = [];

if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$is_admin = isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;

if ($method === 'POST') {
    $posted_token = inputString($_POST['csrf_token'] ?? '', 128);
    $session_token = (string)($_SESSION['csrf_token'] ?? '');
    if ($session_token === '' || $posted_token === '' || !hash_equals($session_token, $posted_token)) {
        jsonResp('error', '请求验证失败，请刷新页面后重试', [], 403);
    }
}

/* Authentication and system settings */
if ($action === 'login') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);

    $attempts = $_SESSION['admin_login_attempts'] ?? [];
    if (!is_array($attempts)) $attempts = [];
    $now = time();
    $attempts = array_values(array_filter($attempts, function($timestamp) use ($now) {
        return is_numeric($timestamp) && (int)$timestamp > ($now - 900);
    }));
    if (count($attempts) >= 8) {
        jsonResp('error', '登录尝试过于频繁，请 15 分钟后重试', [], 429);
    }

    $pwd = inputString($_POST['password'] ?? '', 1024);
    $saved_pwd = (string)($data['settings']['admin_password'] ?? 'admin');
    $is_hash = (strpos($saved_pwd, '$2y$') === 0 || strpos($saved_pwd, '$argon2') === 0);
    $valid = $is_hash ? password_verify($pwd, $saved_pwd) : hash_equals($saved_pwd, $pwd);

    if ($valid) {
        session_regenerate_id(true);
        $_SESSION['is_admin'] = true;
        $_SESSION['admin_login_attempts'] = [];
        if (!$is_hash) {
            $data['settings']['admin_password'] = password_hash($pwd, PASSWORD_DEFAULT);
            if (!saveJson($json_file, $data)) {
                unset($_SESSION['is_admin']);
                jsonResp('error', '密码安全升级失败，请稍后重试', [], 500);
            }
        }
        $initial_password_file = $data_dir . '/initial-admin-password.txt';
        if (is_file($initial_password_file) && !is_link($initial_password_file)) {
            @unlink($initial_password_file);
        }
        jsonResp("success", "管理员模式已开启！");
    }

    $attempts[] = $now;
    $_SESSION['admin_login_attempts'] = $attempts;
    jsonResp("error", "管理密码错误！");
}

if ($action === 'logout') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    unset($_SESSION['is_admin'], $_SESSION['unlocked_dirs'], $_SESSION['admin_login_attempts']);
    session_regenerate_id(true);
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    jsonResp("success", "已退出管理员模式并清理权限缓存");
}

if ($action === 'change_admin_pwd') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    if (!$is_admin) jsonResp("error", "无权限操作", [], 403);
    $new_pwd = inputString($_POST['new_pwd'] ?? '', 1024);
    if (strlen($new_pwd) < 12) jsonResp("error", "新密码至少需要 12 个字符");
    if (strlen($new_pwd) > 200) jsonResp("error", "密码长度不能超过 200 个字符");
    $data['settings']['admin_password'] = password_hash($new_pwd, PASSWORD_DEFAULT);
    if (!saveJson($json_file, $data)) jsonResp('error', '密码保存失败', [], 500);
    jsonResp("success", "管理密码已更新！");
}

if ($action === 'save_security_settings') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    if (!$is_admin) jsonResp("error", "仅管理员可修改系统安全设置", [], 403);
    $forbidden_csv = normalizeExtCsv($_POST['forbidden_exts'] ?? '');
    $data['settings']['forbidden_exts'] = $forbidden_csv;
    if (!saveJson($json_file, $data)) jsonResp('error', '安全设置保存失败', [], 500);
    jsonResp("success", "系统强制禁止文件类型已保存！");
}

if ($action === 'unlock_dir') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    $dir_key = inputString($_POST['dir_key'] ?? '', 90);
    $pwd = inputString($_POST['password'] ?? '', 1024);
    if (!isValidDirKey($dir_key) || !isset($data['directories'][$dir_key])) jsonResp("error", "目录不存在");

    $dir = $data['directories'][$dir_key];
    $saved_dir_pwd = (string)($dir['password'] ?? '');
    if ($saved_dir_pwd === '') jsonResp("error", "该目录未设置访问密码，无法解锁！");
    $is_hash = (strpos($saved_dir_pwd, '$2y$') === 0 || strpos($saved_dir_pwd, '$argon2') === 0);
    $valid = $is_hash ? password_verify($pwd, $saved_dir_pwd) : hash_equals($saved_dir_pwd, $pwd);

    $attempts = $_SESSION['dir_login_attempts'][$dir_key] ?? [];
    if (!is_array($attempts)) $attempts = [];
    $now = time();
    $attempts = array_values(array_filter($attempts, function($timestamp) use ($now) {
        return is_numeric($timestamp) && (int)$timestamp > ($now - 900);
    }));
    if (count($attempts) >= 10) {
        jsonResp('error', '密码尝试过于频繁，请 15 分钟后重试', [], 429);
    }

    if ($valid) {
        unset($_SESSION['dir_login_attempts'][$dir_key]);
        // Upgrade legacy plaintext directory passwords after successful verification.
        if (!$is_hash) {
            $data['directories'][$dir_key]['password'] = password_hash($pwd, PASSWORD_DEFAULT);
            if (!saveJson($json_file, $data)) {
                jsonResp('error', '目录密码安全升级失败，请稍后重试', [], 500);
            }
        }
        session_regenerate_id(true);
        $_SESSION['unlocked_dirs'][$dir_key] = true;
        jsonResp("success", "目录解锁成功！");
    }
    $attempts[] = $now;
    $_SESSION['dir_login_attempts'][$dir_key] = $attempts;
    jsonResp("error", "目录访问密码错误！");
}

/* Directory management */
if ($action === 'add_dir') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    if (!$is_admin) jsonResp("error", "仅管理员可新增目录", [], 403);

    $name = trim(inputString($_POST['name'] ?? '', 300));
    $remark = trim(inputString($_POST['remark'] ?? '', 1000));
    $open_mode = inputString($_POST['open_mode'] ?? 'direct', 16);
    $password = inputString($_POST['password'] ?? '', 1024);

    if ($name === '') jsonResp("error", "目录标题不能为空");
    if (!in_array($open_mode, ['direct', 'pwd'], true)) jsonResp("error", "目录开启方式无效");
    if ($open_mode === 'pwd' && $password === '') jsonResp("error", "密码访问模式下密码不能为空");

    $dir_key = 'dir_' . time() . '_' . bin2hex(random_bytes(5));
    $folder = safeUploadDirectory($dir_key, $upload_dir, true);
    if ($folder === false) jsonResp('error', '无法创建目录存储位置', [], 500);

    $data['directories'][$dir_key] = [
        "name" => $name,
        "remark" => $remark,
        "open_mode" => $open_mode,
        "password" => ($password !== '' ? password_hash($password, PASSWORD_DEFAULT) : ''),
        "direct_perm" => [
            "view" => !empty($_POST['d_view']),
            "download" => !empty($_POST['d_download']),
            "upload" => !empty($_POST['d_upload'])
        ],
        "pwd_perm" => [
            "download" => !empty($_POST['p_download']),
            "upload" => !empty($_POST['p_upload']),
            "manage" => !empty($_POST['p_manage'])
        ],
        "limits" => normalizeLimitsFromPost(),
        "files" => []
    ];
    if (!saveJson($json_file, $data)) jsonResp('error', '目录数据保存失败', [], 500);
    jsonResp("success", "目录创建成功！");
}

if ($action === 'edit_dir') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    $dir_key = inputString($_POST['dir_key'] ?? '', 90);
    if (!isValidDirKey($dir_key) || !isset($data['directories'][$dir_key])) jsonResp("error", "目录不存在");
    if (!hasDirManagePermission($dir_key, $data, $is_admin)) {
        jsonResp("error", "权限不足：无权修改此目录的权限与设置", [], 403);
    }

    $name = trim(inputString($_POST['name'] ?? '', 300));
    if ($name === '') jsonResp("error", "目录标题不能为空");

    $open_mode = inputString($_POST['open_mode'] ?? 'direct', 16);
    if (!in_array($open_mode, ['direct', 'pwd'], true)) jsonResp("error", "目录开启方式无效");
    $password = inputString($_POST['password'] ?? '', 1024);
    $clear_password = !empty($_POST['clear_password']);
    $stored_password = (string)($data['directories'][$dir_key]['password'] ?? '');
    if ($clear_password) {
        $stored_password = '';
    } elseif ($password !== '') {
        $stored_password = password_hash($password, PASSWORD_DEFAULT);
    }
    if ($open_mode === 'pwd' && $stored_password === '') jsonResp("error", "密码访问模式下密码不能为空");

    $data['directories'][$dir_key]['name'] = $name;
    $data['directories'][$dir_key]['remark'] = trim(inputString($_POST['remark'] ?? '', 1000));
    $data['directories'][$dir_key]['open_mode'] = $open_mode;
    $data['directories'][$dir_key]['password'] = $stored_password;
    $data['directories'][$dir_key]['direct_perm'] = [
        "view" => !empty($_POST['d_view']),
        "download" => !empty($_POST['d_download']),
        "upload" => !empty($_POST['d_upload'])
    ];
    $data['directories'][$dir_key]['pwd_perm'] = [
        "download" => !empty($_POST['p_download']),
        "upload" => !empty($_POST['p_upload']),
        "manage" => !empty($_POST['p_manage'])
    ];
    $data['directories'][$dir_key]['limits'] = normalizeLimitsFromPost();

    if (!saveJson($json_file, $data)) jsonResp('error', '目录设置保存失败', [], 500);
    jsonResp("success", "目录设置已更新！");
}

if ($action === 'delete_dir') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    if (!$is_admin) jsonResp("error", "仅管理员可删除目录", [], 403);
    $dir_key = inputString($_POST['dir_key'] ?? '', 90);
    if (!isValidDirKey($dir_key) || !isset($data['directories'][$dir_key])) jsonResp("error", "目录不存在");

    $folder = safeUploadDirectory($dir_key, $upload_dir, false);
    if ($folder !== false) removeDirRecursive($folder);
    unset($data['directories'][$dir_key], $_SESSION['unlocked_dirs'][$dir_key]);
    if (!saveJson($json_file, $data)) jsonResp('error', '目录数据保存失败', [], 500);
    jsonResp("success", "目录及内部文件已删除");
}

/* Chunk upload */
if ($action === 'upload_chunk') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);

    $target_dir = inputString($_POST['dir_key'] ?? '', 90);
    $upload_id = inputString($_POST['upload_id'] ?? '', 32);
    $filename = normalizeClientFilename($_POST['filename'] ?? '');
    $chunk_index = filter_var($_POST['chunk_index'] ?? null, FILTER_VALIDATE_INT);
    $total_chunks = filter_var($_POST['total_chunks'] ?? null, FILTER_VALIDATE_INT);
    $total_size = filter_var($_POST['total_size'] ?? null, FILTER_VALIDATE_INT);

    if (!isValidDirKey($target_dir) || !isset($data['directories'][$target_dir])) jsonResp("error", "目标目录不存在");
    if (!checkDirPermission($target_dir, 'upload', $data, $is_admin)) jsonResp("error", "权限不足：当前目录不允许上传", [], 403);
    if (!validUploadId($upload_id) || $filename === '' || $chunk_index === false || $total_chunks === false || $total_size === false) {
        jsonResp("error", "分片参数不完整或格式错误");
    }
    if ($total_size < 0 || $total_size > XIMI_MAX_UPLOAD_BYTES
        || $total_chunks < 1 || $total_chunks > XIMI_MAX_CHUNKS
        || $chunk_index < 0 || $chunk_index >= $total_chunks) {
        jsonResp("error", "分片数量或文件大小超出限制");
    }
    $expected_chunks = max(1, (int)ceil($total_size / XIMI_CHUNK_SIZE));
    if ($expected_chunks !== $total_chunks) jsonResp('error', '分片总数与文件大小不匹配');

    if (!isset($_FILES['chunk']) || !is_array($_FILES['chunk']) || (int)($_FILES['chunk']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        jsonResp("error", "分片数据接收失败");
    }
    $tmp_name = (string)($_FILES['chunk']['tmp_name'] ?? '');
    $chunk_size = (int)($_FILES['chunk']['size'] ?? -1);
    $expected_chunk_size = ($chunk_index === $total_chunks - 1)
        ? ($total_size - ($chunk_index * XIMI_CHUNK_SIZE))
        : XIMI_CHUNK_SIZE;
    if ($expected_chunk_size < 0 || $chunk_size !== $expected_chunk_size
        || $chunk_size > XIMI_CHUNK_SIZE || !is_uploaded_file($tmp_name)) {
        jsonResp('error', '分片大小不正确');
    }

    $rule_err = validateUploadRules($target_dir, $filename, $total_size, $data, $upload_dir, $default_limits);
    if ($rule_err !== null) jsonResp("error", $rule_err);

    $session_chunk_dir = getUploadSessionDir($upload_id, $chunks_dir);
    if ($session_chunk_dir === false) jsonResp('error', '分片会话 ID 无效');

    if ($chunk_index === 0) {
        if (is_dir($session_chunk_dir)) {
            list($existing_dir, $existing_state) = loadUploadState($upload_id, $chunks_dir);
            if (!verifyUploadState($existing_state, $target_dir, $filename, $total_chunks, $total_size)) {
                jsonResp('error', '分片会话已存在或不属于当前会话');
            }
        } else {
            if (!@mkdir($session_chunk_dir, 0700, true)) jsonResp("error", "无法创建临时分片目录");
            @chmod($session_chunk_dir, 0700);
            $meta_path = $session_chunk_dir . '/meta.json';
            $state = [
                'owner' => hash('sha256', session_id()),
                'dir_key' => $target_dir,
                'filename' => $filename,
                'total_chunks' => $total_chunks,
                'total_size' => $total_size,
                'created_at' => time()
            ];
            if (!saveUploadState($meta_path, $state)) {
                removeDirRecursive($session_chunk_dir);
                jsonResp('error', '无法初始化分片会话', [], 500);
            }
        }
    }

    list($session_chunk_dir, $state) = loadUploadState($upload_id, $chunks_dir);
    if (!verifyUploadState($state, $target_dir, $filename, $total_chunks, $total_size)) {
        jsonResp('error', '分片会话无效、已过期或不属于当前用户', [], 403);
    }

    $chunk_path = $session_chunk_dir . '/part_' . str_pad((string)$chunk_index, 6, '0', STR_PAD_LEFT);
    if (is_link($chunk_path)) jsonResp('error', '分片目标无效');
    if (!move_uploaded_file($tmp_name, $chunk_path)) jsonResp("error", "保存分片失败");
    @chmod($chunk_path, 0600);

    jsonResp("success", "分片已接收", ["chunk_index" => $chunk_index]);
}

if ($action === 'merge_chunks') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);

    $target_dir = inputString($_POST['dir_key'] ?? '', 90);
    $upload_id = inputString($_POST['upload_id'] ?? '', 32);
    $filename = normalizeClientFilename($_POST['filename'] ?? '');
    $total_chunks = filter_var($_POST['total_chunks'] ?? null, FILTER_VALIDATE_INT);
    $total_size = filter_var($_POST['total_size'] ?? null, FILTER_VALIDATE_INT);

    if (!isValidDirKey($target_dir) || !isset($data['directories'][$target_dir])) jsonResp("error", "目标目录不存在");
    if (!checkDirPermission($target_dir, 'upload', $data, $is_admin)) jsonResp("error", "权限不足：当前目录不允许上传", [], 403);
    if (!validUploadId($upload_id) || $filename === '' || $total_chunks === false || $total_size === false) {
        jsonResp("error", "合并参数不完整或格式错误");
    }
    if ($total_size < 0 || $total_size > XIMI_MAX_UPLOAD_BYTES || $total_chunks < 1 || $total_chunks > XIMI_MAX_CHUNKS
        || max(1, (int)ceil($total_size / XIMI_CHUNK_SIZE)) !== $total_chunks) {
        jsonResp('error', '合并参数超出限制');
    }

    list($session_chunk_dir, $state) = loadUploadState($upload_id, $chunks_dir);
    if (!verifyUploadState($state, $target_dir, $filename, $total_chunks, $total_size)) {
        jsonResp("error", "临时分片会话不存在或无权访问", [], 403);
    }

    $rule_err = validateUploadRules($target_dir, $filename, $total_size, $data, $upload_dir, $default_limits);
    if ($rule_err !== null) {
        removeDirRecursive($session_chunk_dir);
        jsonResp("error", $rule_err);
    }

    $save_dir = safeUploadDirectory($target_dir, $upload_dir, true);
    if ($save_dir === false) {
        removeDirRecursive($session_chunk_dir);
        jsonResp('error', '目标目录不可用', [], 500);
    }
    if (filenameExistsInDirectory($target_dir, $filename, $data, $upload_dir)) {
        removeDirRecursive($session_chunk_dir);
        jsonResp('error', '同名文件已存在，请先重命名现有文件');
    }

    $final_path = safeStoredFilePath($target_dir, $filename, $upload_dir);
    if ($final_path === false) {
        removeDirRecursive($session_chunk_dir);
        jsonResp('error', '目标文件路径无效');
    }

    $out = @fopen($final_path, 'xb');
    if (!$out) {
        removeDirRecursive($session_chunk_dir);
        jsonResp("error", "无法创建目标文件，可能存在同名文件");
    }

    $copied_total = 0;
    for ($i = 0; $i < $total_chunks; $i++) {
        $part_file = $session_chunk_dir . '/part_' . str_pad((string)$i, 6, '0', STR_PAD_LEFT);
        if (!is_file($part_file) || is_link($part_file)) {
            fclose($out);
            @unlink($final_path);
            removeDirRecursive($session_chunk_dir);
            jsonResp("error", "分片缺失或无效（第 " . ($i + 1) . " 片），合并中止");
        }

        $expected = ($i === $total_chunks - 1) ? ($total_size - ($i * XIMI_CHUNK_SIZE)) : XIMI_CHUNK_SIZE;
        $actual = @filesize($part_file);
        if ($actual === false || $actual !== $expected) {
            fclose($out);
            @unlink($final_path);
            removeDirRecursive($session_chunk_dir);
            jsonResp('error', '分片大小校验失败');
        }

        $in = @fopen($part_file, 'rb');
        if (!$in) {
            fclose($out);
            @unlink($final_path);
            removeDirRecursive($session_chunk_dir);
            jsonResp("error", "读取分片失败");
        }
        while (!feof($in)) {
            $buf = fread($in, 1024 * 1024);
            if ($buf === false) {
                fclose($in);
                fclose($out);
                @unlink($final_path);
                removeDirRecursive($session_chunk_dir);
                jsonResp('error', '读取分片数据失败');
            }
            if ($buf !== '') {
                $n = fwrite($out, $buf);
                if ($n === false || $n !== strlen($buf)) {
                    fclose($in);
                    fclose($out);
                    @unlink($final_path);
                    removeDirRecursive($session_chunk_dir);
                    jsonResp('error', '写入目标文件失败');
                }
                $copied_total += $n;
            }
        }
        fclose($in);
    }
    fflush($out);
    fclose($out);

    if ($copied_total !== $total_size || @filesize($final_path) !== $total_size) {
        @unlink($final_path);
        removeDirRecursive($session_chunk_dir);
        jsonResp('error', '合并后的文件大小校验失败');
    }
    @chmod($final_path, 0640);
    removeDirRecursive($session_chunk_dir);

    $size_kb = $total_size > 1048576
        ? round($total_size / 1048576, 2) . " MB"
        : round($total_size / 1024, 2) . " KB";
    $pickup_code = generatePickupCode($data);
    if ($pickup_code === '') {
        @unlink($final_path);
        jsonResp('error', '无法生成唯一取件码，请稍后重试', [], 500);
    }

    $data['directories'][$target_dir]['files'][] = [
        "file_id" => 'f_' . bin2hex(random_bytes(8)),
        "type" => "file",
        "name" => $filename,
        "size" => $size_kb,
        "pickup_code" => $pickup_code,
        "upload_date" => date('Y-m-d H:i:s'),
        "downloads" => 0,
        "download_logs" => [],
        "modifications" => [["time" => date('Y-m-d H:i:s'), "action" => "分片上传合并完成，生成取件码: {$pickup_code}"]]
    ];
    if (!saveJson($json_file, $data)) {
        @unlink($final_path);
        jsonResp('error', '文件已保存但元数据写入失败，请联系管理员处理', [], 500);
    }
    jsonResp("success", "文件上传并合并成功！取件码: {$pickup_code}", ["pickup_code" => $pickup_code]);
}

/* Legacy single-request upload endpoint */
if ($action === 'upload') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    $target_dir = inputString($_POST['dir_key'] ?? '', 90);
    if (!isValidDirKey($target_dir) || !isset($data['directories'][$target_dir])) jsonResp("error", "目标目录不存在");
    if (!checkDirPermission($target_dir, 'upload', $data, $is_admin)) jsonResp("error", "权限不足：当前目录不允许上传", [], 403);
    if (!isset($_FILES['file']) || !is_array($_FILES['file']) || (int)($_FILES['file']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        jsonResp("error", "文件上传出错");
    }

    $file = $_FILES['file'];
    $filename = normalizeClientFilename($file['name'] ?? '');
    $size = (int)($file['size'] ?? -1);
    $tmp = (string)($file['tmp_name'] ?? '');
    if ($filename === '' || $size < 0 || $size > XIMI_MAX_UPLOAD_BYTES || !is_uploaded_file($tmp)) {
        jsonResp('error', '文件名、大小或上传来源不合法');
    }

    $rule_err = validateUploadRules($target_dir, $filename, $size, $data, $upload_dir, $default_limits);
    if ($rule_err !== null) jsonResp("error", $rule_err);
    if (filenameExistsInDirectory($target_dir, $filename, $data, $upload_dir)) {
        jsonResp('error', '同名文件已存在，请先重命名现有文件');
    }

    $save_dir = safeUploadDirectory($target_dir, $upload_dir, true);
    $final_path = safeStoredFilePath($target_dir, $filename, $upload_dir);
    if ($save_dir === false || $final_path === false || !move_uploaded_file($tmp, $final_path)) {
        jsonResp("error", "服务器保存文件失败");
    }
    @chmod($final_path, 0640);

    $size_kb = $size > 1048576
        ? round($size / 1048576, 2) . " MB"
        : round($size / 1024, 2) . " KB";
    $pickup_code = generatePickupCode($data);
    if ($pickup_code === '') {
        @unlink($final_path);
        jsonResp('error', '无法生成唯一取件码', [], 500);
    }
    $data['directories'][$target_dir]['files'][] = [
        "file_id" => 'f_' . bin2hex(random_bytes(8)),
        "type" => "file",
        "name" => $filename,
        "size" => $size_kb,
        "pickup_code" => $pickup_code,
        "upload_date" => date('Y-m-d H:i:s'),
        "downloads" => 0,
        "download_logs" => [],
        "modifications" => [["time" => date('Y-m-d H:i:s'), "action" => "初始上传，生成取件码: {$pickup_code}"]]
    ];
    if (!saveJson($json_file, $data)) {
        @unlink($final_path);
        jsonResp('error', '元数据保存失败', [], 500);
    }
    jsonResp("success", "文件上传成功！取件码: {$pickup_code}", ["pickup_code" => $pickup_code]);
}

/* External links */
if ($action === 'add_link') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    $target_dir = inputString($_POST['dir_key'] ?? '', 90);
    if (!isValidDirKey($target_dir) || !isset($data['directories'][$target_dir])) jsonResp("error", "目标目录不存在");
    if (!checkDirPermission($target_dir, 'upload', $data, $is_admin)) jsonResp("error", "权限不足：当前目录不允许添加链接", [], 403);

    $link_title = trim(inputString($_POST['link_title'] ?? '', 300));
    $link_url = trim(inputString($_POST['link_url'] ?? '', 2048));
    if ($link_title === '' || $link_url === '') jsonResp("error", "链接名称和地址不能为空");
    if (!preg_match('~^https?://~i', $link_url)) $link_url = 'https://' . $link_url;
    if (!isSafeHttpUrl($link_url)) jsonResp('error', '链接地址必须是有效的 HTTP/HTTPS 地址');

    $pickup_code = generatePickupCode($data);
    if ($pickup_code === '') jsonResp('error', '无法生成唯一取件码', [], 500);

    $data['directories'][$target_dir]['files'][] = [
        "file_id" => 'l_' . bin2hex(random_bytes(8)),
        "type" => "link",
        "name" => $link_title,
        "url" => $link_url,
        "size" => "外部链接",
        "pickup_code" => $pickup_code,
        "upload_date" => date('Y-m-d H:i:s'),
        "downloads" => 0,
        "download_logs" => [],
        "modifications" => [["time" => date('Y-m-d H:i:s'), "action" => "添加链接，生成取件码: {$pickup_code}"]]
    ];
    if (!saveJson($json_file, $data)) jsonResp('error', '链接保存失败', [], 500);
if (!saveJson($json_file, $data)) jsonResp('error', '链接保存失败', [], 500);
    jsonResp("success", "外部链接添加成功！取件码为: {$pickup_code}");
}

if ($action === 'edit_link') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    $dir_key = inputString($_POST['dir_key'] ?? '', 90);
    $file_id = inputString($_POST['file_id'] ?? '', 100);
    if (!isValidDirKey($dir_key) || !isset($data['directories'][$dir_key])) jsonResp("error", "目录不存在");
    if (!hasDirManagePermission($dir_key, $data, $is_admin)) {
        jsonResp("error", "权限不足：无权编辑此目录的链接", [], 403);
    }

    $idx = findFileIndexById($data['directories'][$dir_key]['files'] ?? [], $file_id);
    if ($idx < 0) jsonResp("error", "未找到目标项目", [], 404);
    $item = $data['directories'][$dir_key]['files'][$idx];
    if (($item['type'] ?? 'file') !== 'link') {
        jsonResp("error", "目标项目不是外部链接");
    }

    $link_title = trim(inputString($_POST['link_title'] ?? '', 300));
    $link_url = trim(inputString($_POST['link_url'] ?? '', 2048));
    if ($link_title === '' || $link_url === '') jsonResp("error", "链接名称和地址不能为空");
    if (!preg_match('~^https?://~i', $link_url)) $link_url = 'https://' . $link_url;
    if (!isSafeHttpUrl($link_url)) jsonResp('error', '链接地址必须是有效的 HTTP/HTTPS 地址');

    $data['directories'][$dir_key]['files'][$idx]['name'] = $link_title;
    $data['directories'][$dir_key]['files'][$idx]['url'] = $link_url;
    $data['directories'][$dir_key]['files'][$idx]['modifications'][] = [
        "time" => date('Y-m-d H:i:s'),
        "action" => "编辑链接: {$link_title} ({$link_url})"
    ];
    if (!saveJson($json_file, $data)) jsonResp('error', '链接修改保存失败', [], 500);
    jsonResp("success", "外部链接已更新！");
}

/* File metadata operations */

/* File metadata operations */
if ($action === 'update_pickup_code') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    $dir_key = inputString($_POST['dir_key'] ?? '', 90);
    $file_id = inputString($_POST['file_id'] ?? '', 100);
    $new_code = strtoupper(trim(inputString($_POST['pickup_code'] ?? '', 16)));

    if (!isValidDirKey($dir_key) || !isset($data['directories'][$dir_key])) jsonResp("error", "目录不存在");
    if (!hasDirManagePermission($dir_key, $data, $is_admin)) jsonResp("error", "权限不足：无权修改此目录的取件码", [], 403);
    if (!preg_match('/\A[A-Z][0-9]{4}\z/D', $new_code)) jsonResp("error", "取件码格式错误，必须为1个大写字母+4位数字（如A8888）");

    foreach ($data['directories'] as $dv) {
        foreach (($dv['files'] ?? []) as $fv) {
            if (strcasecmp((string)($fv['pickup_code'] ?? ''), $new_code) === 0 && (string)($fv['file_id'] ?? '') !== $file_id) {
                jsonResp("error", "该取件码已被占用，请更换其他取件码");
            }
        }
    }

    $idx = findFileIndexById($data['directories'][$dir_key]['files'] ?? [], $file_id);
    if ($idx < 0) jsonResp("error", "未找到目标项目");
    $old_code = $data['directories'][$dir_key]['files'][$idx]['pickup_code'] ?? '';
    $data['directories'][$dir_key]['files'][$idx]['pickup_code'] = $new_code;
    $data['directories'][$dir_key]['files'][$idx]['modifications'][] = [
        "time" => date('Y-m-d H:i:s'),
        "action" => "修改取件码: {$old_code} -> {$new_code}"
    ];
    if (!saveJson($json_file, $data)) jsonResp('error', '取件码保存失败', [], 500);
    jsonResp("success", "取件码修改成功！");
}

if ($action === 'rename_item') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    $dir_key = inputString($_POST['dir_key'] ?? '', 90);
    $file_id = inputString($_POST['file_id'] ?? '', 100);
    $new_name = normalizeClientFilename($_POST['new_name'] ?? '');

    if (!isValidDirKey($dir_key) || !isset($data['directories'][$dir_key])) jsonResp("error", "目录不存在");
    if (!hasDirManagePermission($dir_key, $data, $is_admin)) jsonResp("error", "无管理权限", [], 403);
    if ($new_name === '') jsonResp("error", "新名称不合法：不能包含路径分隔符、控制字符或系统保留字符");

    $idx = findFileIndexById($data['directories'][$dir_key]['files'] ?? [], $file_id);
    if ($idx < 0) jsonResp("error", "未找到目标项目");
    $item = $data['directories'][$dir_key]['files'][$idx];

    if (($item['type'] ?? 'file') === 'file') {
        $blocked_ext = checkSystemForbiddenExt($new_name, $data);
        if ($blocked_ext !== null) jsonResp("error", "系统禁止使用 ." . $blocked_ext . " 后缀，重命名已拦截");
        if (filenameExistsInDirectory($dir_key, $new_name, $data, $upload_dir, $file_id)) jsonResp('error', '目标名称已存在');

        $old_name = (string)($item['name'] ?? '');
        $old_path = safeStoredFilePath($dir_key, $old_name, $upload_dir);
        $new_path = safeStoredFilePath($dir_key, $new_name, $upload_dir);
        if ($old_path === false || $new_path === false || !is_file($old_path) || is_link($old_path)) {
            jsonResp('error', '原文件路径无效或文件不存在');
        }
        if (!@rename($old_path, $new_path)) jsonResp('error', '文件重命名失败');
    }

    $old_name = (string)($item['name'] ?? '');
    $data['directories'][$dir_key]['files'][$idx]['name'] = $new_name;
    $data['directories'][$dir_key]['files'][$idx]['modifications'][] = [
        "time" => date('Y-m-d H:i:s'),
        "action" => "重命名为: {$new_name}"
    ];
    if (!saveJson($json_file, $data)) jsonResp('error', '名称已修改但元数据保存失败，请联系管理员', [], 500);
    jsonResp("success", "名称已更新");
}

if ($action === 'delete_item') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    $dir_key = inputString($_POST['dir_key'] ?? '', 90);
    $file_id = inputString($_POST['file_id'] ?? '', 100);
    if (!isValidDirKey($dir_key) || !isset($data['directories'][$dir_key])) jsonResp("error", "目录不存在");
    if (!hasDirManagePermission($dir_key, $data, $is_admin)) jsonResp("error", "无管理权限", [], 403);

    $idx = findFileIndexById($data['directories'][$dir_key]['files'] ?? [], $file_id);
    if ($idx < 0) jsonResp("error", "删除失败");
    $item = $data['directories'][$dir_key]['files'][$idx];

    if (($item['type'] ?? 'file') === 'file') {
        $path = safeStoredFilePath($dir_key, (string)($item['name'] ?? ''), $upload_dir);
        if ($path === false) jsonResp('error', '文件路径无效，已停止删除');
        if (is_file($path) && !@unlink($path)) jsonResp('error', '物理文件删除失败');
    }

    array_splice($data['directories'][$dir_key]['files'], $idx, 1);
    if (!saveJson($json_file, $data)) jsonResp('error', '元数据保存失败', [], 500);
    jsonResp("success", "项目已成功删除");
}

if ($action === 'move_file') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    $from_dir = inputString($_POST['from_dir'] ?? '', 90);
    $to_dir = inputString($_POST['to_dir'] ?? '', 90);
    $file_id = inputString($_POST['file_id'] ?? '', 100);

    if (!isValidDirKey($from_dir) || !isValidDirKey($to_dir)
        || !isset($data['directories'][$from_dir], $data['directories'][$to_dir])) {
        jsonResp("error", "目标目录不存在");
    }
    if (!hasDirManagePermission($from_dir, $data, $is_admin)
        || !hasDirManagePermission($to_dir, $data, $is_admin)) {
        jsonResp("error", "无管理权限：需要同时拥有源目录和目标目录的管理权限", [], 403);
    }
    if ($from_dir === $to_dir) jsonResp('error', '不能迁移到当前目录');

    $idx = findFileIndexById($data['directories'][$from_dir]['files'] ?? [], $file_id);
    if ($idx < 0) jsonResp("error", "迁移失败");
    $item = $data['directories'][$from_dir]['files'][$idx];

    if (($item['type'] ?? 'file') === 'file') {
        $filename = (string)($item['name'] ?? '');
        $old_path = safeStoredFilePath($from_dir, $filename, $upload_dir);
        $to_folder = safeUploadDirectory($to_dir, $upload_dir, true);
        $new_path = safeStoredFilePath($to_dir, $filename, $upload_dir);
        if ($old_path === false || $new_path === false || !is_file($old_path) || is_link($old_path)) {
            jsonResp('error', '源文件路径无效或文件不存在');
        }
        if (filenameExistsInDirectory($to_dir, $filename, $data, $upload_dir)) jsonResp('error', '目标目录存在同名文件');
        if ($to_folder === false || !@rename($old_path, $new_path)) jsonResp('error', '文件迁移失败');
    }

    array_splice($data['directories'][$from_dir]['files'], $idx, 1);
    $to_name = (string)($data['directories'][$to_dir]['name'] ?? '');
    $item['modifications'][] = [
        "time" => date('Y-m-d H:i:s'),
        "action" => "迁移至目录: {$to_name}"
    ];
    $data['directories'][$to_dir]['files'][] = $item;
    if (!saveJson($json_file, $data)) jsonResp('error', '迁移已执行但元数据保存失败，请联系管理员', [], 500);
    jsonResp("success", "迁移成功");
}

/* Permission-checked inline preview: uploaded files are not directly web-accessible. */
if ($action === 'preview') {
    if ($method !== 'GET') jsonResp('error', '请求方法不允许', [], 405);
    $dir_key = inputString($_GET['dir'] ?? '', 90);
    $file_id = inputString($_GET['id'] ?? '', 100);

    if (!isValidDirKey($dir_key) || !isset($data['directories'][$dir_key])) {
        http_response_code(404);
        exit('文件不存在');
    }
    if (!checkDirPermission($dir_key, 'view', $data, $is_admin)) {
        http_response_code(403);
        exit('拒绝访问：当前目录不可查看');
    }

    $idx = findFileIndexById($data['directories'][$dir_key]['files'] ?? [], $file_id);
    if ($idx < 0) {
        http_response_code(404);
        exit('文件不存在');
    }
    $item = $data['directories'][$dir_key]['files'][$idx];
    if (($item['type'] ?? 'file') !== 'file') {
        http_response_code(415);
        exit('外部链接不支持文件预览');
    }

    $filename = (string)($item['name'] ?? '');
    if (!isSafeFilename($filename)) {
        http_response_code(404);
        exit('文件名无效');
    }
    $filepath = safeStoredFilePath($dir_key, $filename, $upload_dir);
    if ($filepath === false) {
        http_response_code(404);
        exit('文件路径无效');
    }
    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    sendInlinePreview($filepath, $filename, $extension);
}

/* Downloads */
if ($action === 'download') {
    if ($method !== 'GET') jsonResp('error', '请求方法不允许', [], 405);
    $dir_key = inputString($_GET['dir'] ?? '', 90);
    $file_id = inputString($_GET['id'] ?? '', 100);
    if (!isValidDirKey($dir_key) || !isset($data['directories'][$dir_key])) {
        http_response_code(404);
        exit('文件不存在');
    }
    if (!checkDirPermission($dir_key, 'download', $data, $is_admin)) {
        http_response_code(403);
        exit('拒绝访问：当前目录或访客权限未开启下载功能！');
    }

    $idx = findFileIndexById($data['directories'][$dir_key]['files'] ?? [], $file_id);
    if ($idx < 0) {
        http_response_code(404);
        exit('文件不存在或已被删除');
    }
    $item = $data['directories'][$dir_key]['files'][$idx];
    $data['directories'][$dir_key]['files'][$idx]['downloads'] = (int)($item['downloads'] ?? 0) + 1;
    $logs = $data['directories'][$dir_key]['files'][$idx]['download_logs'] ?? [];
    if (!is_array($logs)) $logs = [];
    $logs[] = ["time" => date('Y-m-d H:i:s'), "ip" => substr((string)($_SERVER['REMOTE_ADDR'] ?? '未知'), 0, 64)];
    $data['directories'][$dir_key]['files'][$idx]['download_logs'] = array_slice($logs, -100);
    if (!saveJson($json_file, $data)) jsonResp('error', '下载日志写入失败', [], 500);
    if ($request_lock) { flock($request_lock, LOCK_UN); fclose($request_lock); $request_lock = null; }

    if (($item['type'] ?? 'file') === 'link') {
        $url = (string)($item['url'] ?? '');
        if (!isSafeHttpUrl($url)) {
            http_response_code(400);
            exit('外部链接地址无效');
        }
        header('Cache-Control: no-store');
        header('Location: ' . $url, true, 302);
        exit;
    }

    $filepath = safeStoredFilePath($dir_key, (string)($item['name'] ?? ''), $upload_dir);
    if ($filepath === false) {
        http_response_code(404);
        exit('文件路径无效');
    }
    sendFileDownload($filepath, (string)$item['name']);
}

if ($action === 'pickup_download') {
    if ($method !== 'GET') jsonResp('error', '请求方法不允许', [], 405);
    $code = strtoupper(inputString($_GET['code'] ?? '', 8));
    if (!preg_match('/\A[A-Z][0-9]{4}\z/D', $code)) {
        http_response_code(404);
        exit('取件码不存在或文件已被删除！');
    }

    $found_file = null;
    $found_dir = '';
    foreach ($data['directories'] as $dk => $dv) {
        foreach (($dv['files'] ?? []) as $fv) {
            if (strcasecmp((string)($fv['pickup_code'] ?? ''), $code) === 0) {
                $found_file = $fv;
                $found_dir = (string)$dk;
                break 2;
            }
        }
    }
    if (!$found_file || !isValidDirKey($found_dir)) {
        http_response_code(404);
        exit('取件码不存在或文件已被删除！');
    }

    $idx = findFileIndexById($data['directories'][$found_dir]['files'] ?? [], (string)($found_file['file_id'] ?? ''));
    if ($idx < 0) {
        http_response_code(404);
        exit('文件不存在');
    }
    $item = $data['directories'][$found_dir]['files'][$idx];
    $data['directories'][$found_dir]['files'][$idx]['downloads'] = (int)($item['downloads'] ?? 0) + 1;
    $logs = $data['directories'][$found_dir]['files'][$idx]['download_logs'] ?? [];
    if (!is_array($logs)) $logs = [];
    $logs[] = ["time" => date('Y-m-d H:i:s'), "ip" => substr((string)($_SERVER['REMOTE_ADDR'] ?? '未知'), 0, 64)];
    $data['directories'][$found_dir]['files'][$idx]['download_logs'] = array_slice($logs, -100);
    if (!saveJson($json_file, $data)) jsonResp('error', '下载日志写入失败', [], 500);
    if ($request_lock) { flock($request_lock, LOCK_UN); fclose($request_lock); $request_lock = null; }

    if (($item['type'] ?? 'file') === 'link') {
        $url = (string)($item['url'] ?? '');
        if (!isSafeHttpUrl($url)) {
            http_response_code(400);
            exit('外部链接地址无效');
        }
        header('Cache-Control: no-store');
        header('Location: ' . $url, true, 302);
        exit;
    }

    $filepath = safeStoredFilePath($found_dir, (string)($item['name'] ?? ''), $upload_dir);
    if ($filepath === false) {
        http_response_code(404);
        exit('文件物理路径不存在');
    }
    sendFileDownload($filepath, (string)$item['name']);
}

/* Guestbook */
if ($action === 'add_msg') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    $content = trim(inputString($_POST['content'] ?? '', XIMI_MAX_TEXT_BYTES));
    $is_public = inputString($_POST['is_public'] ?? '1', 1) === '1';
    if ($content === '') jsonResp("error", "留言内容不能为空");

    $data['guestbook'][] = [
        "id" => 'msg_' . bin2hex(random_bytes(8)),
        "content" => $content,
        "is_public" => $is_public,
        "approved" => $is_admin ? true : false,
        "time" => date('Y-m-d H:i:s'),
        "ip" => substr((string)($_SERVER['REMOTE_ADDR'] ?? '未知'), 0, 64)
    ];
    $data['guestbook'] = array_slice($data['guestbook'], -1000);
    if (!saveJson($json_file, $data)) jsonResp('error', '留言保存失败', [], 500);
    jsonResp("success", $is_admin ? "留言已发布" : "留言已提交，等待审核后公开");
}

if ($action === 'approve_msg') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    if (!$is_admin) jsonResp("error", "无权限", [], 403);
    $msg_id = inputString($_POST['msg_id'] ?? '', 100);
    foreach ($data['guestbook'] as &$msg) {
        if ((string)($msg['id'] ?? '') === $msg_id) {
            $msg['approved'] = true;
            unset($msg);
            if (!saveJson($json_file, $data)) jsonResp('error', '留言状态保存失败', [], 500);
            jsonResp("success", "留言已审核通过");
        }
    }
    unset($msg);
    jsonResp('error', '留言不存在', [], 404);
}

if ($action === 'delete_msg') {
    if ($method !== 'POST') jsonResp('error', '请求方法不允许', [], 405);
    if (!$is_admin) jsonResp("error", "无权限", [], 403);
    $msg_id = inputString($_POST['msg_id'] ?? '', 100);
    foreach ($data['guestbook'] as $idx => $msg) {
        if ((string)($msg['id'] ?? '') === $msg_id) {
            array_splice($data['guestbook'], $idx, 1);
            if (!saveJson($json_file, $data)) jsonResp('error', '留言删除失败', [], 500);
            jsonResp("success", "留言已删除");
        }
    }
    jsonResp('error', '留言不存在', [], 404);
}

jsonResp('error', '无效的请求操作', [], 404);
?>
