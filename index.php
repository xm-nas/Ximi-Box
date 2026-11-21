<?php




$is_https = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off')
    || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
if ($is_https) ini_set('session.cookie_secure', '1');
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: SAMEORIGIN');

function escHtml($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function jsAttr($value) {
    $json = json_encode(
        $value,
        JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP |
        JSON_HEX_APOS | JSON_HEX_QUOT | JSON_INVALID_UTF8_SUBSTITUTE
    );
    if ($json === false) $json = 'null';
    return htmlspecialchars($json, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function isValidIndexDirKey($dir_key) {
    return is_string($dir_key)
        && strlen($dir_key) <= 90
        && preg_match('/\\A(?:dir_default|dir_[A-Za-z0-9_-]{1,80})\\z/D', $dir_key) === 1;
}

function isSafeIndexFilename($filename) {
    if (!is_string($filename) || $filename === '' || strlen($filename) > 240) return false;
    if ($filename === '.' || $filename === '..' || $filename[0] === '.') return false;
    if (preg_match('/[\\x00-\\x1F\\x7F\\/\\\\<>:"|?*]/u', $filename)) return false;
    if (preg_match('/[. ]\\z/u', $filename)) return false;
    return preg_match('//u', $filename) === 1;
}

$json_file = __DIR__ . '/data/metadata.json';
$netdata = file_exists($json_file) ? json_decode((string)file_get_contents($json_file), true) : [];
if (!is_array($netdata)) $netdata = [];
$directories = isset($netdata['directories']) && is_array($netdata['directories']) ? $netdata['directories'] : [];
$guestbook = isset($netdata['guestbook']) && is_array($netdata['guestbook']) ? $netdata['guestbook'] : [];
$is_admin = isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
$unlocked_dirs = isset($_SESSION['unlocked_dirs']) && is_array($_SESSION['unlocked_dirs']) ? $_SESSION['unlocked_dirs'] : [];
if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];


function formatSizeAuto($bytes) {
    $bytes = max(0, floatval($bytes));
    if ($bytes >= 1099511627776) {
        return round($bytes / 1099511627776, 2) . 'T';
    }
    if ($bytes >= 1073741824) {
        return round($bytes / 1073741824, 2) . 'G';
    }
    if ($bytes >= 1048576) {
        $mb = round($bytes / 1048576, 2);
        return (floor($mb) == $mb ? intval($mb) : $mb) . 'M';
    }
    if ($bytes >= 1024) {
        return round($bytes / 1024, 1) . 'K';
    }
    return intval($bytes) . 'B';
}

function formatMbShort($bytes) {
    $mb = round(max(0, floatval($bytes)) / 1048576, 2);
    return (floor($mb) == $mb ? intval($mb) : $mb) . 'M';
}

$upload_base_path = __DIR__ . '/uploads';
$dir_used_bytes_map = [];
$total_used_bytes = 0;

if (is_array($directories)) {
    foreach ($directories as $dk => $dv) {
        if (!isValidIndexDirKey((string)$dk)) continue;
        $sum_bytes = 0;
        $folder_path = $upload_base_path . '/' . $dk;
        if (is_dir($folder_path)) {
            $items = scandir($folder_path);
            if ($items) {
                foreach ($items as $it) {
                    if ($it === '.' || $it === '..' || $it === '@eaDir' || $it === '.DS_Store') continue;
                    $full = $folder_path . '/' . $it;
                    if (is_file($full)) {
                        $sum_bytes += filesize($full);
                    }
                }
            }
        }
        $dir_used_bytes_map[$dk] = $sum_bytes;
        $total_used_bytes += $sum_bytes;
    }
}

$used_total_display = formatMbShort($total_used_bytes);
$disk_total_bytes = @disk_total_space(__DIR__);
$disk_free_bytes = @disk_free_space(__DIR__);
$disk_total_display = ($disk_total_bytes !== false && $disk_total_bytes > 0)
    ? formatSizeAuto($disk_total_bytes)
    : (($netdata['settings']['space_total'] ?? 9999) . 'M');
$disk_free_display = ($disk_free_bytes !== false && $disk_free_bytes >= 0)
    ? formatSizeAuto($disk_free_bytes)
    : '未知';








$auto_popup_file = null;
$search_file_id = trim($_GET['file-id'] ?? '');
if (!empty($search_file_id)) {
    foreach ($directories as $dk => $dv) {
        if (!isValidIndexDirKey((string)$dk) || empty($dv['files']) || !is_array($dv['files'])) continue;
        foreach ($dv['files'] as $fv) {
            if (is_array($fv) && strcasecmp((string)($fv['pickup_code'] ?? ''), $search_file_id) === 0) {
                $auto_popup_file = $fv;
                break 2;
            }
        }
    }
}

$img_exts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'];
$dir_images_map = [];
foreach ($directories as $dk => $dv) {
    if (!isValidIndexDirKey((string)$dk)) continue;
    $list = [];
    if (!empty($dv['files']) && is_array($dv['files'])) {
        foreach ($dv['files'] as $fv) {
            if (!is_array($fv)) continue;
            if (($fv['type'] ?? 'file') === 'file' && isSafeIndexFilename((string)($fv['name'] ?? ''))) {
                $ext = strtolower(pathinfo($fv['name'], PATHINFO_EXTENSION));
                if (in_array($ext, $img_exts, true)) {
                    $list[] = [
                        'url' => 'backend.php?action=preview&dir=' . rawurlencode((string)$dk) . '&id=' . rawurlencode((string)($fv['file_id'] ?? '')),
                        'name' => (string)$fv['name']
                    ];
                }
            }
        }
    }
    $dir_images_map[$dk] = $list;
}
?>
<?php
$video_exts = ['mp4', 'webm', 'ogg', 'mov', 'm4v', 'mkv'];
$audio_exts = ['mp3', 'wav', 'ogg', 'm4a', 'aac', 'flac'];
?>
<!-- 
		发布地址：https://www.ximi.me/post-6049.html
		版本：v1.01
        作者：希米
        说明：一款轻量、零数据库的局域网私有云网盘系统，基于 PHP 与 JSON 文件存储，支持目录权限管控、分片大文件上传、快递取件码提取及在线多媒体预览。

		更新时间：2036-07-21
-->
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ximi Box - 私有云网盘</title>
    <meta name="csrf-token" content="<?php echo escHtml($csrf_token); ?>">
    <link rel="stylesheet" href="styles.css">
    <style>
        .perm-box { background: #f8f5fc; border: 1px solid #cbbbe0; padding: 10px; margin-top: 8px; }
        .perm-box h4 { margin: 0 0 6px 0; font-size: 13px; color: #8e2de2; }
        .perm-box label { margin-right: 12px; font-size: 13px; cursor: pointer; display: inline-flex; align-items: center; gap: 4px; }
        .modal-flat-box { background: #faf8fc; border: 1px solid #dfd5ee; padding: 10px; margin-bottom: 10px; }
        .modal-primary-btn { padding: 8px 16px; background: #8e2de2; color: #fff; border: 1px solid #731dc0; cursor: pointer; font-size: 13px; font-weight: bold; }
        .modal-primary-btn:hover { background: #7720c7; }
        .modal-secondary-btn { padding: 8px 16px; background: #f3eff8; color: #333; border: 1px solid #cbbbe0; cursor: pointer; font-size: 13px; }
        .modal-secondary-btn:hover { background: #e6ddf4; }
    </style>
</head>
<body>

<div class="header">
    <h2>
        Ximi Box - 私有云网盘
        <?php if($is_admin) echo '<span class="admin-badge">管理员模式</span>'; ?>
    </h2>
    <div style="font-size:13px; opacity:0.95;">
        <?php if($is_admin): ?>
            <span style="cursor:pointer; text-decoration:underline;" onclick="adminLogout()">退出管理模式</span>
        <?php else: ?>
            <span>访客模式</span>
        <?php endif; ?>
    </div>
</div>

<div class="left-sidebar">
    <div class="container">
        <div class="guestbook-header" style="background: #00897b; margin-bottom: 8px;">
            快递取件查询
        </div>
        <div class="login-container" style="padding: 0;">
            <form action="index.php" method="GET" style="display: flex; gap: 6px;">
                <input type="text" name="file-id" placeholder="输入取件码 (如: X6666)" required style="margin: 0; flex: 1;">
                <button type="submit" style="width: auto; padding: 0 16px; margin: 0; background: #00897b; border-color: #00695c;">提取</button>
            </form>
            <p class="note" style="margin-top: 6px;">输入取件码可直接跨目录提取下载文件，不受目录权限限制。</p>
        </div>
    </div>

    <div class="container">
        <div class="tab">
            <button class="tablinks" onclick="openTab(event, 'tab1')">留言</button>
            <button class="tablinks" onclick="openTab(event, 'tab2')">增加目录</button>
            <button class="tablinks" onclick="openTab(event, 'tab3')">上传/链接</button>
            <button class="tablinks" onclick="openTab(event, 'tab4')">管理区</button>
        </div>

        <div id="tab1" class="tabcontent">
            <div class="login-container">
                <div class="my-textarea">
                    <textarea id="msg_content" placeholder="输入留言内容（游客留言需审核后公开）..."></textarea>
                </div>
                <p style="margin: 4px 0; font-size: 13px;">
                    类型：
                    <label><input type="radio" name="msg_public" value="1" checked> 公开</label>
                    <label style="margin-left:10px;"><input type="radio" name="msg_public" value="0"> 私密(仅管理员)</label>
                </p>
                <button type="button" onclick="submitMsg()">提交留言</button>
            </div>
        </div>

        <div id="tab2" class="tabcontent">
            <div class="login-container">
                <?php if ($is_admin): ?>
                    <input type="text" id="new_dir_name" placeholder="目录标题 * (例如: Python_Link)">
                    <input type="text" id="new_dir_remark" placeholder="备注 (可不填，如: 链接收藏)">
                    
                    <div style="margin: 6px 0; font-size: 13px;">
                        <label>目录开启方式：</label>
                        <select id="new_dir_open_mode" onchange="document.getElementById('new_pwd_group').style.display = (this.value==='direct'?'none':'block')">
                            <option value="direct">直接打开，无需密码</option>
                            <option value="pwd" selected>需要输入密码才能打开</option>
                        </select>
                    </div>

                    <div id="new_pwd_group" style="margin-bottom:6px;">
                        <input type="password" id="new_dir_pwd" placeholder="开启密码 * (例如: zlym)">
                    </div>

                    <div class="perm-box">
                        <h4>访客直接打开时权限</h4>
                        <label><input type="checkbox" id="new_d_view" checked onchange="checkDirectView(this)"> 查看</label>
                        <label><input type="checkbox" id="new_d_download" onchange="autoCheckView('new_d', 'download')"> 下载</label>
                        <label><input type="checkbox" id="new_d_upload" onchange="autoCheckView('new_d', 'upload')"> 上传</label>
                    </div>

                    <div class="perm-box">
                        <h4>输入密码打开时权限</h4>
                        <label><input type="checkbox" id="new_p_download" checked> 下载</label>
                        <label><input type="checkbox" id="new_p_upload" checked> 上传</label>
                        <label><input type="checkbox" id="new_p_manage" checked onchange="handleManagePermChange(this)"> 管理</label>
                    </div>

                    <div class="perm-box">
                        <h4>上传容量与类型限制 (0或留空为不限)</h4>
                        <label style="display:block; margin:4px 0;">目录总容量上限 (MB)：</label>
                        <input type="text" id="new_max_total_mb" value="0" placeholder="0 表示不限">
                        <label style="display:block; margin:4px 0;">单文件大小上限 (MB)：</label>
                        <input type="text" id="new_max_file_mb" value="0" placeholder="0 表示不限">
                        <label style="display:block; margin:4px 0;">允许文件后缀 (逗号分隔)：</label>
                        <input type="text" id="new_allowed_exts" value="" placeholder="留空不限，如: jpg,png,zip,mp4">
                    </div>

                    <button type="button" onclick="addNewDir()" style="margin-top:10px;">确认新增目录</button>
                <?php else: ?>
                    <p class="note" style="color:#d32f2f; text-align:center; padding:15px 0;">请先在“管理区”登录管理员账号，才可新建带权限控制的目录。</p>
                <?php endif; ?>
            </div>
        </div>

        <div id="tab3" class="tabcontent">
            <div class="login-container">
                <select id="upload_dir_key">
                    <?php foreach($directories as $d_key => $d_val): if (!isValidIndexDirKey((string)$d_key)) continue; ?>
                        <option value="<?php echo escHtml($d_key); ?>"><?php echo escHtml($d_val['name'] ?? '未命名目录'); ?></option>
                    <?php endforeach; ?>
                </select>
                
                <p style="margin: 4px 0; font-size: 13px;">
                    模式：
                    <label><input type="radio" name="upload_type" value="file" checked onchange="toggleUploadMode()"> 本地文件</label>
                    <label style="margin-left:10px;"><input type="radio" name="upload_type" value="link" onchange="toggleUploadMode()"> 外部链接</label>
                </p>

                <div id="mode_file">
                    <input type="file" id="upload_file_input" multiple style="margin: 6px 0;" onchange="renderUploadQueue()">
                    <div style="display:flex; gap:6px;">
                        <button type="button" id="btnStartQueue" onclick="startQueueUpload()" style="flex:1;">开始队列上传</button>
                        <button type="button" id="btnClearQueue" onclick="clearUploadQueue()" style="width:auto; padding:0 12px; background:#f3eff8; color:#333; border-color:#cbbbe0;">清空</button>
                    </div>

                    <div id="upload_queue_box" class="upload-queue-box">
                        <div style="display:flex; justify-content:space-between; font-size:12px; color:#333;">
                            <span id="overallProgressText">总进度: 0%</span>
                            <span id="queueCountText">0/0</span>
                        </div>
                        <div class="progress-track">
                            <div id="overallProgressBar" class="progress-fill"></div>
                        </div>
                        <div id="uploadQueueList" class="queue-list"></div>
                    </div>
                </div>

                <div id="mode_link" style="display:none;">
                    <input type="text" id="link_title" placeholder="链接名称（如：局域网NAS入口）">
                    <input type="url" id="link_url" placeholder="完整地址（如：http://192.168.1.2）">
                    <button type="button" onclick="addLink()">添加外部链接</button>
                </div>
            </div>
        </div>

        <div id="tab4" class="tabcontent">
            <div class="login-container">
                <?php if (!$is_admin): ?>
                    <input type="password" id="admin_pwd_input" placeholder="请输入管理员密码" onkeyup="if(event.key==='Enter') adminLogin()">
                    <button type="button" onclick="adminLogin()">进入管理员模式</button>
                    <p class="note">首次部署请先从服务器本地 data/initial-admin-password.txt 获取随机初始密码；首次登录后该文件会自动删除。登录后请立即设置自己的强密码。</p>


<?php else: ?>
                    <?php $forbidden_exts_val = escHtml(is_scalar($netdata['settings']['forbidden_exts'] ?? null) ? ($netdata['settings']['forbidden_exts'] ?? 'php,phtml,php3,php4,php5,phar,exe,bat,cmd,sh,ps1,vbs,jsp,asp,aspx,cgi,pl') : ''); ?>
                    <p style="color:#00897b; font-weight:bold; margin:4px 0;">管理员权限已解锁</p>

                    <div class="perm-box" style="margin-bottom:10px;">
                        <h4>系统强制禁止文件类型 (高于目录密码权限)</h4>
                        <input type="text" id="sys_forbidden_exts" value="<?php echo $forbidden_exts_val; ?>" placeholder="逗号分隔，如: php,exe,sh,bat">
                        <button type="button" onclick="saveSecuritySettings()" style="background:#4a00e0; border-color:#3700b3; margin-top:6px;">保存禁止类型</button>
                        <p class="note">上传与重命名均会检查，防止先传再改后缀绕过。</p>
                    </div>

                    <input type="password" id="new_admin_pwd" placeholder="输入新管理密码（至少12位）">
                    <button type="button" onclick="changeAdminPwd()" style="background:#1976d2; border-color:#1565c0;">修改管理密码</button>
                    <button type="button" onclick="adminLogout()" style="background:#d32f2f; border-color:#b71c1c; margin-top:8px;">退出管理员模式</button>
             

                <?php endif; ?>
            </div>
        </div>
    </div>

<div class="guestbook">
        <div class="guestbook-header">
            公告与留言 <?php if($is_admin) echo '(管理员可审核/删除)'; ?>
        </div>
        <?php 
        $has_msg = false;
        foreach (array_reverse($guestbook) as $msg): 
            if (!$is_admin && (!$msg['approved'] || !$msg['is_public'])) continue;
            $has_msg = true;
        ?>
            <div class="msg-item">
                <div style="line-height:1.5;">
                    <b>匿名网友:</b> <?php echo nl2br(escHtml(htmlspecialchars_decode((string)($msg['content'] ?? ''), ENT_QUOTES))); ?>
                </div>
                <div style="color:#888; font-size:10px; margin-top:3px; line-height:1.3;">
                    <?php echo escHtml($msg['time'] ?? ''); ?>
                    <?php if(!$msg['is_public']) echo '<span style="color:#d32f2f; margin-left:4px;">[私密]</span>'; ?>
                    <?php if(!$msg['approved']) echo '<span style="color:#ef6c00; margin-left:4px;">[待审核]</span>'; ?>
                </div>
                <?php if($is_admin): ?>
                    <div style="margin-top:4px;">
                        <?php if(!$msg['approved']): ?>
                            <button type="button" class="action-btn" onclick="approveMsg(<?php echo jsAttr((string)($msg['id'] ?? '')); ?>)">通过审核</button>
                        <?php endif; ?>
                        <button type="button" class="action-btn" style="color:#d32f2f;" onclick="deleteMsg(<?php echo jsAttr((string)($msg['id'] ?? '')); ?>)">删除</button>
                    </div>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
        <?php if(!$has_msg) echo '<p class="note">暂无公开公告或留言。</p>'; ?>
    </div>
</div>

<div class="right-main">
    <div class="list_file">

<div class="list_dir_title"> 
    <div>目录列表</div>
    <div style="font-size:13px; font-weight:normal;">
        空间配额: <?php echo escHtml($used_total_display); ?>/<?php echo escHtml($disk_total_display); ?> (可用 <?php echo escHtml($disk_free_display); ?>) | 
        当前身份: <b><?php echo $is_admin ? '管理员' : '普通访客'; ?></b>
    </div>
    
</div>
        <?php 
        $i = 1;
        foreach($directories as $d_key => $dir):
            if (!isValidIndexDirKey((string)$d_key)) continue;
            $dir_files = isset($dir['files']) && is_array($dir['files']) ? $dir['files'] : [];
            $file_count = count($dir_files);
            $has_pwd = !empty(trim($dir['password'] ?? ''));
            $unlocked = isset($unlocked_dirs[$d_key]) && $unlocked_dirs[$d_key] === true;
            
            $direct_view = isset($dir['direct_perm']['view']) ? $dir['direct_perm']['view'] : true;
            $prohibit_visitor = !$direct_view;
            $is_locked = !$is_admin && (($has_pwd && !$unlocked) || ($prohibit_visitor && !$unlocked));

            $icon_img = "img/dir.png";
            if ($has_pwd || $prohibit_visitor) {
                $icon_img = "img/lock.png";
            }

$dir_used_display = formatMbShort($dir_used_bytes_map[$d_key] ?? 0);
$limits = $dir['limits'] ?? ["max_total_mb" => 0, "max_file_mb" => 0, "allowed_exts" => ""];
$limit_tags = [];
if (!empty($limits['max_total_mb'])) {
    $limit_tags[] = "总上限:" . $dir_used_display . "/" . $limits['max_total_mb'] . "M";
} else {
    $limit_tags[] = "已用:" . $dir_used_display;
}
if (!empty($limits['max_file_mb'])) {
    $limit_tags[] = "单文件:" . $limits['max_file_mb'] . "M";
}
if (!empty($limits['allowed_exts'])) {
    $limit_tags[] = "类型:" . $limits['allowed_exts'];
}
        ?>





            <div class="dir-row">
                <span class="toggleMenu" onclick="clickDirectory(<?php echo jsAttr('menu' . $i); ?>, <?php echo jsAttr((string)$d_key); ?>, <?php echo $has_pwd ? 'true' : 'false'; ?>, <?php echo $prohibit_visitor ? 'true' : 'false'; ?>, <?php echo $is_locked ? 'true' : 'false'; ?>)">
                    <img src="<?php echo escHtml($icon_img); ?>" style="width:16px; height:16px; vertical-align:middle; margin-right:6px;" onerror="this.src='img/dir.png'">
                    <b><?php echo escHtml($dir['name'] ?? '未命名目录'); ?></b>
                    <?php if(!empty($dir['remark'])) echo '<span style="color:#666; font-size:12px; margin-left:4px;">(' . escHtml($dir['remark']) . ')</span>'; ?>
                    <span style="color:#888; font-size:13px;">(<?php echo $file_count; ?>)</span>
                    <?php if($has_pwd) echo '<span style="color:#d32f2f; font-size:12px; margin-left:6px;">[加密]</span>'; ?>
                    <?php if($prohibit_visitor && !$has_pwd) echo '<span style="color:#d32f2f; font-size:12px; margin-left:6px;">[禁止游客]</span>'; ?>
                    <?php if(!empty($limit_tags)) echo '<span style="color:#5c6bc0; font-size:11px; margin-left:6px;">[' . escHtml(implode(' | ', $limit_tags)) . ']</span>'; ?>
                </span>
                
<?php 
$has_dir_manage_perm = $is_admin || ($unlocked && !empty($dir['pwd_perm']['manage']));
if($has_dir_manage_perm): 
?>
    <div>
        <?php $dir_for_js = $dir; unset($dir_for_js['password']); ?>
        <button type="button" class="action-btn" style="color:#1976d2;" onclick="openEditDirModal(<?php echo jsAttr($dir_for_js); ?>, <?php echo jsAttr((string)$d_key); ?>)">编辑</button>
        <?php if($is_admin): ?>
            <button type="button" class="action-btn" style="color:#d32f2f;" onclick="deleteDir(<?php echo jsAttr((string)$d_key); ?>)">删除</button>
        <?php endif; ?>
    </div>
<?php endif; ?>
            </div>

            <div class="menu" id="menu<?php echo $i; ?>">
                <?php if ($is_locked && !$is_admin): ?>
                    <div style="padding: 10px 0; color: #d32f2f; font-size: 13px; font-weight: bold;">
                        <?php if($has_pwd): ?>
                            此目录已加密，请点击目录名称输入密码解锁后查看。
                        <?php else: ?>
                            此目录禁止游客访问，请先在左侧管理区登录管理员账号。
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <p class="note" style="margin-bottom:8px;">
                        共 <?php echo $file_count; ?> 项内容 
                        <button type="button" class="action-btn" onclick="location.reload()">刷新列表</button>
                    </p>
                    
                    <?php if($file_count > 0): ?>
                        <?php foreach($dir_files as $file):
                            if (!is_array($file)) continue;
                            $file_name = (string)($file['name'] ?? '');
                            $is_link = ($file['type'] ?? 'file') === 'link';
                            if (!$is_link && !isSafeIndexFilename($file_name)) continue;
                            $ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
                            $file_id = (string)($file['file_id'] ?? '');
                            // $file_url = "backend.php?action=preview&dir=" . rawurlencode((string)$d_key) . "&id=" . rawurlencode($file_id);
$file_url = "backend.php?action=preview&dir=" . rawurlencode((string)$d_key) . "&id=" . rawurlencode($file_id);

$open_url = "backend.php?action=download&dir=" . rawurlencode((string)$d_key) . "&id=" . rawurlencode($file_id);

                            $pickup_code = (string)($file['pickup_code'] ?? '');
                            $has_manage_perm = $is_admin || ($unlocked && !empty($dir['pwd_perm']['manage']));
                        ?>
                            <div class="file-card">
                                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px;">
                                    <div>
                                        <b><?php echo escHtml($file_name); ?></b>
                                        <span style="color:#888; font-size:12px;">(<?php echo escHtml($file['size'] ?? ''); ?>)</span>

                                        <?php if($is_link): ?>
                                            <?php if($has_manage_perm): ?>
                                                <button type="button" class="share-inline-btn" onclick="editLink(<?php echo jsAttr((string)$d_key); ?>, <?php echo jsAttr($file_id); ?>, <?php echo jsAttr($file_name); ?>, <?php echo jsAttr((string)($file['url'] ?? '')); ?>)">编辑链接</button>
                                            <?php endif; ?>
                                        <?php elseif(!empty($pickup_code)): ?>
                                            <span style="color:#8e2de2; font-size:12px; margin-left:6px; background:#f3eff8; padding:2px 6px; font-weight:bold;">取件码: <?php echo escHtml($pickup_code); ?></span>
                                            <button type="button" class="share-inline-btn" onclick="copyShareLink(<?php echo jsAttr($pickup_code); ?>)">分享</button>
                                        <?php else: ?>
                                            <span style="color:#888; font-size:12px; margin-left:6px;">取件码: 无</span>
                                        <?php endif; ?>

                                    </div>
                                    <div style="font-size:12px; color:#777;">
                                        上传: <?php echo escHtml($file['upload_date'] ?? ''); ?> | 下载: <?php echo (int)($file['downloads'] ?? 0); ?>
                                    </div>
                                </div>
                                
                                <div style="margin-top: 6px; padding-top:5px; border-top:1px solid #eee; display:flex; flex-wrap:wrap; align-items:center;">
                                
<?php if($is_link): ?>

    <a href="<?php echo escHtml($open_url); ?>"
       target="_blank"
       rel="noopener noreferrer"
       class="action-btn">打开链接</a>

<?php else: ?>

    <?php if(in_array($ext, $img_exts, true)): ?>
        <button type="button" class="action-btn"
            onclick="previewImage(<?php echo jsAttr((string)$d_key); ?>, <?php echo jsAttr($file_url); ?>, <?php echo jsAttr($file_name); ?>)">预览图片</button>

    <?php elseif(in_array($ext, ['txt', 'ini', 'log', 'json', 'md', 'xml', 'csv'], true)): ?>
        <button type="button" class="action-btn"
            onclick="previewText(<?php echo jsAttr($file_url); ?>, <?php echo jsAttr($file_name); ?>)">预览文本</button>

    <?php elseif(in_array($ext, $video_exts, true)): ?>
        <button type="button" class="action-btn"
            onclick="previewVideo(<?php echo jsAttr($file_url); ?>, <?php echo jsAttr($file_name); ?>)">预览视频</button>

    <?php elseif(in_array($ext, $audio_exts, true)): ?>
        <button type="button" class="action-btn"
            onclick="previewAudio(<?php echo jsAttr($file_url); ?>, <?php echo jsAttr($file_name); ?>)">播放音乐</button>
    <?php endif; ?>

    <a href="<?php echo escHtml($open_url); ?>" class="action-btn">下载</a>

<?php endif; ?>


                                    <button type="button" class="action-btn" onclick="showDetails(<?php echo jsAttr($file); ?>)">详情/日志</button>

                                    <!-- </?php if($has_manage_perm): ?>
                                        <button type="button" class="action-btn" style="color:#8e2de2;" onclick="changePickupCode(</?php echo jsAttr((string)$d_key); ?>, </?php echo jsAttr($file_id); ?>, </?php echo jsAttr($pickup_code); ?>)">改取件码</button>
                                        <select onchange="moveFile(</?php echo jsAttr((string)$d_key); ?>, </?php echo jsAttr($file_id); ?>, this.value)" style="width:auto; padding:2px 6px; font-size:12px; margin:0 8px 0 0;">
                                            <option value="">迁移至...</option>
                                            </?php foreach($directories as $tk => $td): if(isValidIndexDirKey((string)$tk) && $tk != $d_key): ?>
                                                <option value="</?php echo escHtml($tk); ?>"></?php echo escHtml($td['name'] ?? '未命名目录'); ?></option>
                                            </?php endif; endforeach; ?>
                                        </select>
                                        <button type="button" class="action-btn" style="color:#ef6c00;" onclick="renameItem(</?php echo jsAttr((string)$d_key); ?>, </?php echo jsAttr($file_id); ?>, </?php echo jsAttr($file_name); ?>)">重命名</button>
                                        <button type="button" class="action-btn" style="color:#d32f2f;" onclick="deleteItem(</?php echo jsAttr((string)$d_key); ?>, </?php echo jsAttr($file_id); ?>)">删除</button>
                                    </?php endif; ?> -->


<?php if($has_manage_perm): ?>
    <?php if(!$is_link): ?>
        <button type="button" class="action-btn" style="color:#8e2de2;" onclick="changePickupCode(<?php echo jsAttr((string)$d_key); ?>, <?php echo jsAttr($file_id); ?>, <?php echo jsAttr($pickup_code); ?>)">改取件码</button>
    <?php endif; ?>
    <select onchange="moveFile(<?php echo jsAttr((string)$d_key); ?>, <?php echo jsAttr($file_id); ?>, this.value)" style="width:auto; padding:2px 6px; font-size:12px; margin:0 8px 0 0;">
        <option value="">迁移至...</option>
        <?php foreach($directories as $tk => $td): if(isValidIndexDirKey((string)$tk) && $tk != $d_key): ?>
            <option value="<?php echo escHtml($tk); ?>"><?php echo escHtml($td['name'] ?? '未命名目录'); ?></option>
        <?php endif; endforeach; ?>
    </select>
    <button type="button" class="action-btn" style="color:#ef6c00;" onclick="renameItem(<?php echo jsAttr((string)$d_key); ?>, <?php echo jsAttr($file_id); ?>, <?php echo jsAttr($file_name); ?>)">重命名</button>
    <button type="button" class="action-btn" style="color:#d32f2f;" onclick="deleteItem(<?php echo jsAttr((string)$d_key); ?>, <?php echo jsAttr($file_id); ?>)">删除</button>
<?php endif; ?>

                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="note" style="padding:8px 0;">该目录暂无内容</div>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
            <hr>
        <?php $i++; endforeach; ?>
    </div>

    <div class="intro-card">
        <div class="guestbook-header" style="background: #4a00e0; margin-bottom: 8px;">
            系统介绍说明
        </div>
        <div style="font-size: 13px; color: #555; line-height: 1.6;">
            <p style="margin: 4px 0;">一款轻量、零数据库的局域网私有云网盘系统，支持目录权限与密码管控。</p>
            <ul style="margin: 6px 0 0 0; padding-left: 18px; color: #666;">
                <li>支持访客直接查看/下载/上传权限以及密码解锁后权限配置。</li>
                <li>支持快递取件码自动生成与查重，凭取件码可直接提取文件。</li>
                <li>支持图片缩放拖拽预览、文本预览、文件迁移与日志记录。</li>
            </ul>
        </div>
    </div>
</div>

<div class="modal-overlay" id="modalOverlay" onclick="closeModal()"></div>
<div class="modal-box" id="modalBox">
    <div class="modal-header">
        <h3 id="modalTitle" style="margin:0; font-size:15px; color:#333;">标题</h3>
        <button type="button" onclick="closeModal()" style="background:none; border:none; cursor:pointer; font-size:20px; line-height:1; color:#666; padding:0 4px;">&times;</button>
    </div>
    <div id="modalBody" class="modal-body-content"></div>
</div>

<?php
// 将 PHP 配置转换为 JS 数组
$js_f_exts = array_values(array_filter(
    array_map('trim', explode(',', strtolower($netdata['settings']['forbidden_exts'] ?? '')))
));
?>

<script>
window.APP_CONFIG = {
    dirImagesMap: <?= json_encode(
        $dir_images_map ?? [],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES |
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
    ) ?>,

    systemForbiddenExts: <?= json_encode(
        $js_f_exts,
        JSON_UNESCAPED_UNICODE | JSON_HEX_TAG |
        JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
    ) ?>,

    autoPopupFile: <?= json_encode(
        $auto_popup_file ?? null,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES |
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
    ) ?>
};
</script>



<script type="text/javascript" src="./js.js" ></script>
</body>
</html>