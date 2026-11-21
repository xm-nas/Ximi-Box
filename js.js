// PHP 动态数据由 index.php 通过 window.APP_CONFIG 注入
const APP_CONFIG = window.APP_CONFIG || {};
const dirImagesMap = APP_CONFIG.dirImagesMap || {};
const systemForbiddenExts = Array.isArray(APP_CONFIG.systemForbiddenExts)
    ? APP_CONFIG.systemForbiddenExts
    : [];
const autoPopupFile = APP_CONFIG.autoPopupFile || null;

function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
}

function appendCsrfToken(formData) {
    if (!(formData instanceof FormData)) throw new TypeError('formData 必须是 FormData');
    const token = getCsrfToken();
    if (!token) throw new Error('安全令牌缺失，请刷新页面后重试');
    formData.set('csrf_token', token);
    return formData;
}

function escapeHtmlSimple(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function safeLocalUploadUrl(value) {
    try {
        const url = new URL(String(value || ''), window.location.href);
        if (url.origin !== window.location.origin) return '';
        if (!url.pathname.endsWith('/backend.php') || url.searchParams.get('action') !== 'preview') return '';
        if (!url.searchParams.get('dir') || !url.searchParams.get('id')) return '';
        if (url.username || url.password || /^(javascript|data|vbscript):/i.test(url.protocol)) return '';
        return url.href;
    } catch (error) {
        return '';
    }
}

const CHUNK_SIZE_BYTES = 3 * 1024 * 1024; // 每片 3MB

let uploadQueue = [];
let isUploadingQueue = false;
let currentOpenedDirKey = '';

let currentImgList = [];
let currentImgIndex = 0;
let imgScale = 1;
let imgRotate = 0;
let panX = 0;
let panY = 0;
let isDraggingImg = false;
let dragStartX = 0;
let dragStartY = 0;

document.addEventListener("DOMContentLoaded", function() {
    let firstTab = document.querySelector('.tablinks');
    if (firstTab) firstTab.click();

    if (autoPopupFile) showPickupResultModal(autoPopupFile);
});

function syncUploadDirSelect() {
    const selectEl = document.getElementById('upload_dir_key');
    if (!selectEl || !selectEl.options.length) return;

    let targetKey = currentOpenedDirKey;

    if (!targetKey) {
        const menus = document.querySelectorAll('.list_file .menu');
        for (let i = 0; i < menus.length; i++) {
            const m = menus[i];
            if (m.style.display === 'block') {
                const prevRow = m.previousElementSibling;
                if (prevRow) {
                    const toggleEl = prevRow.querySelector('.toggleMenu');
                    if (toggleEl) {
                        const onclickAttr = toggleEl.getAttribute('onclick') || '';
                        const match = onclickAttr.match(/clickDirectory\(\s*["'](?:menu[^"']*)["']\s*,\s*["']([^"']+)["']/);
                        if (match && match[1]) {
                            targetKey = match[1];
                            break;
                        }
                    }
                }
            }
        }
    }

    if (targetKey && Array.from(selectEl.options).some(opt => opt.value === targetKey)) {
        selectEl.value = targetKey;
    } else {
        selectEl.selectedIndex = 0;
    }
}

function openTab(evt, tabName) {
    let tabcontent = document.getElementsByClassName("tabcontent");
    for (let i = 0; i < tabcontent.length; i++) tabcontent[i].style.display = "none";
    let tablinks = document.getElementsByClassName("tablinks");
    for (let i = 0; i < tablinks.length; i++) tablinks[i].className = tablinks[i].className.replace(" active", "");
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.className += " active";

    if (tabName === 'tab3') {
        syncUploadDirSelect();
    }
}

function openModal(title, htmlContent, isDesktopPreview = false) {
    const box = document.getElementById('modalBox');
    const overlay = document.getElementById('modalOverlay');
    document.getElementById('modalTitle').innerText = title;
    document.getElementById('modalBody').innerHTML = htmlContent;

    box.classList.remove('desktop-preview-window', 'open');
    box.style.display = 'none';
    box.style.width = '';
    box.style.height = '';

    if (isDesktopPreview) {
        box.style.display = 'flex';
        box.classList.add('desktop-preview-window', 'open');
    } else {
        box.style.display = 'block';
    }
    overlay.style.display = 'block';
}

function closeModal() {
    const box = document.getElementById('modalBox');
    const body = document.getElementById('modalBody');
    if (body) {
        const mediaEls = body.querySelectorAll('video, audio');
        mediaEls.forEach(function(el) {
            el.pause();
            el.removeAttribute('src');
            el.load();
        });
    }
    box.classList.remove('desktop-preview-window', 'open');
    box.style.display = 'none';
    document.getElementById('modalOverlay').style.display = 'none';
    isDraggingImg = false;
}

function previewVideo(url, title) {
    const safeTitle = escapeHtmlSimple(title);
    const safeUrl = safeLocalUploadUrl(url);
    if (!safeUrl) return showInfoModal('预览失败', '文件地址无效或不属于本站上传目录');
    const html = `
        <div class="modal-flat-box" style="padding:8px; background:#111; border-color:#2b2b2b; text-align:center;">
            <video src="${escapeHtmlSimple(safeUrl)}" controls autoplay playsinline preload="metadata" style="width:100%; max-height:68vh; display:block; margin:0 auto; background:#000;"></video>
        </div>
        <p class="note" style="margin:6px 0 0 0;">当前播放：${safeTitle}（若部分编码格式无法解码，可点击下载到本地播放器播放）</p>
    `;
    openModal('视频预览 - ' + safeTitle, html, true);
}

function previewAudio(url, title) {
    const safeTitle = escapeHtmlSimple(title);
    const safeUrl = safeLocalUploadUrl(url);
    if (!safeUrl) return showInfoModal('预览失败', '文件地址无效或不属于本站上传目录');
    const html = `
        <div class="modal-flat-box" style="padding:16px;">
            <div style="font-weight:bold; color:#333; margin-bottom:12px; word-break:break-all;">${safeTitle}</div>
            <audio src="${escapeHtmlSimple(safeUrl)}" controls autoplay preload="metadata" style="width:100%; display:block;"></audio>
        </div>
        <p class="note" style="margin:6px 0 0 0;">关闭窗口将自动停止播放。</p>
    `;
    openModal('音乐播放 - ' + safeTitle, html, false);
}

function showInfoModal(title, message, onCloseCallback = null) {
    const safeMsg = escapeHtmlSimple(message).replace(/\n/g, "<br>");
    const html = `
        <div class="modal-flat-box" style="line-height:1.6; color:#333;">${safeMsg}</div>
        <div style="text-align:right; margin-top:12px;">
            <button type="button" id="modalInfoOkBtn" class="modal-primary-btn">确定</button>
        </div>
    `;
    openModal(title, html, false);
    document.getElementById('modalInfoOkBtn').onclick = function() {
        closeModal();
        if (typeof onCloseCallback === 'function') onCloseCallback();
    };
}

function showConfirmModal(title, message, onConfirmCallback, onCancelCallback = null) {
    const safeMsg = escapeHtmlSimple(message).replace(/\n/g, "<br>");
    const html = `
        <div class="modal-flat-box" style="line-height:1.6; color:#333;">${safeMsg}</div>
        <div style="text-align:right; margin-top:12px; display:flex; justify-content:flex-end; gap:8px;">
            <button type="button" id="modalCancelBtn" class="modal-secondary-btn">取消</button>
            <button type="button" id="modalConfirmBtn" class="modal-primary-btn">确认</button>
        </div>
    `;
    openModal(title, html, false);
    document.getElementById('modalCancelBtn').onclick = function() {
        closeModal();
        if (typeof onCancelCallback === 'function') onCancelCallback();
    };
    document.getElementById('modalConfirmBtn').onclick = function() {
        closeModal();
        if (typeof onConfirmCallback === 'function') onConfirmCallback();
    };
}

function showPromptModal(title, labelText, defaultValue, onSubmitCallback) {
    const safeLabel = escapeHtmlSimple(labelText);
    const html = `
        <div class="modal-flat-box">
            <label style="display:block; margin-bottom:6px; font-weight:bold; color:#333;">${safeLabel}</label>
            <input type="text" id="modalPromptInput" style="margin:0;">
        </div>
        <div style="text-align:right; margin-top:12px; display:flex; justify-content:flex-end; gap:8px;">
            <button type="button" id="modalPromptCancelBtn" class="modal-secondary-btn">取消</button>
            <button type="button" id="modalPromptSubmitBtn" class="modal-primary-btn">提交</button>
        </div>
    `;
    openModal(title, html, false);
    const inputEl = document.getElementById('modalPromptInput');
    inputEl.value = defaultValue || '';
    inputEl.focus();
    inputEl.select();

    const submitAction = function() {
        const val = inputEl.value;
        closeModal();
        if (typeof onSubmitCallback === 'function') onSubmitCallback(val);
    };

    inputEl.onkeydown = function(e) {
        if (e.key === 'Enter') submitAction();
    };
    document.getElementById('modalPromptCancelBtn').onclick = closeModal;
    document.getElementById('modalPromptSubmitBtn').onclick = submitAction;
}

function handleManagePermChange(checkbox) {
    if (!checkbox || checkbox.checked) return;
    checkbox.checked = true;
    showConfirmModal(
        '权限变更提醒',
        '此功能不可逆，取消管理权限后将失去该密码下的目录管理与权限设置能力，确认取消吗？',
        function() {
            checkbox.checked = false;
        },
        function() {
            checkbox.checked = true;
        }
    );
}

function postBackend(action, formData, reloadOnSuccess = true) {
    try {
        appendCsrfToken(formData);
    } catch (error) {
        showInfoModal('安全验证失败', error.message || '请刷新页面后重试');
        return;
    }
    fetch('backend.php?action=' + encodeURIComponent(action), { method: 'POST', body: formData, credentials: 'same-origin' })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                showInfoModal('操作成功', data.message, function() {
                    if (reloadOnSuccess) location.reload();
                });
            } else {
                showInfoModal('操作失败', data.message, null);
            }
        })
        .catch(() => showInfoModal('网络异常', '网络请求异常，请检查服务器设置', null));
}

function getFileExtensionLower(filename) {
    const clean = String(filename || '').trim();
    const dotIdx = clean.lastIndexOf('.');
    if (dotIdx <= 0 || dotIdx === clean.length - 1) return '';
    return clean.slice(dotIdx + 1).toLowerCase();
}

function isSystemForbiddenName(filename) {
    const ext = getFileExtensionLower(filename);
    return ext !== '' && systemForbiddenExts.includes(ext);
}

function saveSecuritySettings() {
    const raw = document.getElementById('sys_forbidden_exts').value.trim();
    const fd = new FormData();
    fd.append('forbidden_exts', raw);
    postBackend('save_security_settings', fd, true);
}

function formatBytesShort(bytes) {
    if (bytes > 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
    return (bytes / 1024).toFixed(1) + ' KB';
}

function renderUploadQueue() {
    if (isUploadingQueue) return;
    const input = document.getElementById('upload_file_input');
    const box = document.getElementById('upload_queue_box');
    const listEl = document.getElementById('uploadQueueList');
    uploadQueue = [];

    if (!input || !input.files || input.files.length === 0) {
        box.style.display = 'none';
        listEl.innerHTML = '';
        return;
    }

    for (let i = 0; i < input.files.length; i++) {
        uploadQueue.push({
            file: input.files[i],
            percent: 0,
            statusText: '等待中',
            state: 'pending'
        });
    }

    box.style.display = 'block';
    listEl.innerHTML = '';

    uploadQueue.forEach((item, idx) => {
        const row = document.createElement('div');
        row.className = 'queue-item';
        row.innerHTML = `
            <div class="queue-item-top">
                <span class="queue-item-name" title="${escapeHtmlSimple(item.file.name)}">${escapeHtmlSimple(item.file.name)} (${formatBytesShort(item.file.size)})</span>
                <span class="queue-item-status" id="qStatus_${idx}">等待中</span>
            </div>
            <div class="progress-track" style="height:8px; margin:3px 0 0 0;">
                <div class="progress-fill" id="qBar_${idx}" style="width:0%;"></div>
            </div>
        `;
        listEl.appendChild(row);
    });

    updateOverallQueueProgress();
}

function updateOverallQueueProgress() {
    const totalCount = uploadQueue.length;
    if (totalCount === 0) {
        document.getElementById('overallProgressText').innerText = '总进度: 0%';
        document.getElementById('queueCountText').innerText = '0/0';
        document.getElementById('overallProgressBar').style.width = '0%';
        return;
    }

    let sumPct = 0;
    let finishedCount = 0;
    for (let i = 0; i < totalCount; i++) {
        sumPct += uploadQueue[i].percent;
        if (uploadQueue[i].state === 'done' || uploadQueue[i].state === 'error') {
            finishedCount++;
        }
    }

    const avgPct = Math.round(sumPct / totalCount);
    document.getElementById('overallProgressText').innerText = '总进度: ' + avgPct + '%';
    document.getElementById('queueCountText').innerText = finishedCount + '/' + totalCount;
    document.getElementById('overallProgressBar').style.width = avgPct + '%';
}

function clearUploadQueue() {
    if (isUploadingQueue) return showInfoModal('提示', '正在上传中，请等待当前队列完成');
    document.getElementById('upload_file_input').value = '';
    uploadQueue = [];
    document.getElementById('upload_queue_box').style.display = 'none';
    document.getElementById('uploadQueueList').innerHTML = '';
}

function generateUploadId() {
    if (!window.crypto || typeof window.crypto.getRandomValues !== 'function') {
        throw new Error('当前浏览器不支持安全随机数，无法安全上传');
    }
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function uploadSingleChunk(dirKey, uploadId, file, chunkIndex, totalChunks, chunkBlob, onChunkProgress) {
    return new Promise((resolve, reject) => {
        const fd = new FormData();
        fd.append('dir_key', dirKey);
        fd.append('upload_id', uploadId);
        fd.append('filename', file.name);
        fd.append('chunk_index', String(chunkIndex));
        fd.append('total_chunks', String(totalChunks));
        fd.append('total_size', String(file.size));
        appendCsrfToken(fd);
        fd.append('chunk', chunkBlob, 'chunk.part');

        const xhr = new XMLHttpRequest();
        xhr.open('POST', 'backend.php?action=upload_chunk', true);

        xhr.upload.onprogress = function(e) {
            if (e.lengthComputable && typeof onChunkProgress === 'function') {
                onChunkProgress(Math.min(1, e.loaded / e.total));
            }
        };

        xhr.onload = function() {
            let resp = null;
            try {
                resp = JSON.parse(xhr.responseText);
            } catch (err) {
                resp = null;
            }
            if (xhr.status === 200 && resp && resp.status === 'success') {
                resolve(resp);
            } else {
                reject(new Error((resp && resp.message) ? resp.message : ('分片 ' + (chunkIndex + 1) + ' 上传失败')));
            }
        };

        xhr.onerror = function() {
            reject(new Error('分片 ' + (chunkIndex + 1) + ' 网络错误'));
        };

        xhr.send(fd);
    });
}

function mergeUploadedChunks(dirKey, uploadId, file, totalChunks) {
    return new Promise((resolve, reject) => {
        const fd = new FormData();
        fd.append('dir_key', dirKey);
        fd.append('upload_id', uploadId);
        fd.append('filename', file.name);
        fd.append('total_chunks', String(totalChunks));
        fd.append('total_size', String(file.size));
        appendCsrfToken(fd);

        fetch('backend.php?action=merge_chunks', { method: 'POST', body: fd, credentials: 'same-origin' })
            .then(res => res.json())
            .then(data => {
                if (data && data.status === 'success') {
                    resolve(data);
                } else {
                    reject(new Error((data && data.message) ? data.message : '分片合并失败'));
                }
            })
            .catch(() => reject(new Error('分片合并网络异常')));
    });
}

function startQueueUpload() {
    if (isUploadingQueue) return;
    if (!uploadQueue.length) {
        renderUploadQueue();
    }
    if (!uploadQueue.length) {
        return showInfoModal('提示', '请先选择要上传的文件');
    }

    const dirKey = document.getElementById('upload_dir_key').value;
    isUploadingQueue = true;
    document.getElementById('btnStartQueue').disabled = true;
    document.getElementById('btnClearQueue').disabled = true;
    document.getElementById('upload_file_input').disabled = true;
    const overallBar = document.getElementById('overallProgressBar');
    overallBar.classList.remove('done', 'error');

    let okCount = 0;
    let failCount = 0;
    let failMessages = [];

    async function processQueue() {
        for (let index = 0; index < uploadQueue.length; index++) {
            const entry = uploadQueue[index];
            const statusEl = document.getElementById('qStatus_' + index);
            const barEl = document.getElementById('qBar_' + index);

            if (isSystemForbiddenName(entry.file.name)) {
                const blockedExt = getFileExtensionLower(entry.file.name);
                const errMsg = '系统强制禁止上传 .' + blockedExt + ' 类型文件';
                entry.state = 'error';
                entry.percent = 100;
                barEl.style.width = '100%';
                barEl.classList.add('error');
                statusEl.innerText = errMsg;
                statusEl.style.color = '#d32f2f';
                failCount++;
                failMessages.push(entry.file.name + ': ' + errMsg);
                updateOverallQueueProgress();
                await new Promise(r => setTimeout(r, 20));
                continue;
            }

            entry.state = 'uploading';
            entry.percent = 0;
            statusEl.innerText = '0%';
            statusEl.style.color = '#8e2de2';
            updateOverallQueueProgress();

            const file = entry.file;
            const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE_BYTES));
            const uploadId = generateUploadId();

            try {
                for (let c = 0; c < totalChunks; c++) {
                    const start = c * CHUNK_SIZE_BYTES;
                    const end = Math.min(file.size, start + CHUNK_SIZE_BYTES);
                    const blob = file.slice(start, end);

                    await uploadSingleChunk(dirKey, uploadId, file, c, totalChunks, blob, function(subRatio) {
                        const fileRatio = (c + subRatio) / totalChunks;
                        const pct = Math.min(98, Math.round(fileRatio * 98));
                        entry.percent = pct;
                        statusEl.innerText = pct + '% (' + (c + 1) + '/' + totalChunks + ')';
                        barEl.style.width = pct + '%';
                        updateOverallQueueProgress();
                    });
                }

                statusEl.innerText = '合并中...';
                const mergeResp = await mergeUploadedChunks(dirKey, uploadId, file, totalChunks);

                entry.state = 'done';
                entry.percent = 100;
                barEl.style.width = '100%';
                barEl.classList.add('done');
                statusEl.innerText = mergeResp.pickup_code ? ('完成 (' + mergeResp.pickup_code + ')') : '已完成';
                statusEl.style.color = '#00897b';
                okCount++;
            } catch (err) {
                const errMsg = err && err.message ? err.message : '上传失败';
                entry.state = 'error';
                entry.percent = 100;
                barEl.style.width = '100%';
                barEl.classList.add('error');
                statusEl.innerText = errMsg;
                statusEl.style.color = '#d32f2f';
                failCount++;
                failMessages.push(file.name + ': ' + errMsg);
            }

            updateOverallQueueProgress();
            await new Promise(r => setTimeout(r, 30));
        }

        isUploadingQueue = false;
        document.getElementById('btnStartQueue').disabled = false;
        document.getElementById('btnClearQueue').disabled = false;
        document.getElementById('upload_file_input').disabled = false;
        overallBar.classList.add(failCount > 0 ? 'error' : 'done');

        let summary = '队列上传结束：成功 ' + okCount + ' 个，失败 ' + failCount + ' 个。';
        if (failMessages.length > 0) {
            summary += '\n' + failMessages.join('\n');
        }
        showConfirmModal('批量上传结果', summary + '\n是否立即刷新目录列表查看？', function() {
            location.reload();
        });
    }

    processQueue();
}

function getShareUrl(code) {
    const pathname = window.location.pathname || '/';
    const basePath = pathname.endsWith('/') ? pathname : pathname.replace(/[^/]*$/, '');
    return window.location.origin + basePath + 'index.php?file-id=' + encodeURIComponent(code);
}

function copyShareLink(code) {
    const shareUrl = getShareUrl(code);
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(shareUrl).then(() => {
            showInfoModal('分享链接已复制', '已复制当前文件的分享链接：\n' + shareUrl);
        }).catch(() => {
            fallbackCopyText(shareUrl);
        });
    } else {
        fallbackCopyText(shareUrl);
    }
}

function fallbackCopyText(text) {
    const tempInput = document.createElement('input');
    tempInput.value = text;
    document.body.appendChild(tempInput);
    tempInput.select();
    document.execCommand('copy');
    document.body.removeChild(tempInput);
    showInfoModal('分享链接已复制', '已复制当前文件的分享链接：\n' + text);
}

function changePickupCode(dirKey, fileId, oldCode) {
    showPromptModal('修改取件码', '请输入新的取件码（格式：1个大写字母+4位数字，如 X6666）：', oldCode, function(newCode) {
        if (!newCode || newCode.trim() === '' || newCode.trim().toUpperCase() === oldCode) return;
        let fd = new FormData();
        fd.append('dir_key', dirKey);
        fd.append('file_id', fileId);
        fd.append('pickup_code', newCode.trim().toUpperCase());
        postBackend('update_pickup_code', fd, true);
    });
}

function showPickupResultModal(file) {
    if (!file || typeof file !== 'object') return;
    const pickupCode = String(file.pickup_code || '');
    const dlUrl = "backend.php?action=pickup_download&code=" + encodeURIComponent(pickupCode);
    const shareUrl = getShareUrl(pickupCode);
    const safeName = escapeHtmlSimple(file.name);
    const html = `
        <div class="modal-flat-box">
            <p style="margin:6px 0;"><b>文件名称：</b>${safeName}</p>
            <p style="margin:6px 0;"><b>文件大小：</b>${escapeHtmlSimple(file.size)}</p>
            <p style="margin:6px 0;"><b>取件码：</b><span style="color:#8e2de2; font-weight:bold;">${escapeHtmlSimple(pickupCode)}</span></p>
            <p style="margin:6px 0;"><b>分享链接：</b>${escapeHtmlSimple(shareUrl)}</p>
            <p style="margin:6px 0;"><b>上传时间：</b>${escapeHtmlSimple(file.upload_date)}</p>
            <p style="margin:6px 0;"><b>下载次数：</b>${escapeHtmlSimple(file.downloads)} 次</p>
        </div>
        <div style="text-align:right; margin-top:12px; display:flex; justify-content:flex-end; gap:8px;">
            <button type="button" id="pickupCopyShareBtn" class="modal-secondary-btn">复制分享链接</button>
            <a href="${escapeHtmlSimple(dlUrl)}" class="modal-primary-btn" style="text-decoration:none; display:inline-block;">下载文件</a>
        </div>
    `;
    openModal('取件码详情 - ' + String(file.name || ''), html, false);
    const copyBtn = document.getElementById('pickupCopyShareBtn');
    if (copyBtn) copyBtn.addEventListener('click', function() {
        copyShareLink(pickupCode);
    });
}

function checkDirectView(checkbox) {
    if (!checkbox.checked) {
        let d_dl = document.getElementById('new_d_download');
        let d_up = document.getElementById('new_d_upload');
        if(d_dl) d_dl.checked = false;
        if(d_up) d_up.checked = false;
        let ed_dl = document.getElementById('edit_d_download');
        let ed_up = document.getElementById('edit_d_upload');
        if(ed_dl) ed_dl.checked = false;
        if(ed_up) ed_up.checked = false;
    }
}

function autoCheckView(prefix, type) {
    let subBox = document.getElementById(prefix + '_' + type);
    if (subBox && subBox.checked) {
        let viewBox = document.getElementById(prefix + '_view');
        if (viewBox) viewBox.checked = true;
    }
}

function clickDirectory(menuId, dirKey, hasPwd, prohibitVisitor, isLocked) {
    if (isLocked) {
        if (hasPwd) {
            showPromptModal('目录密码验证', '此目录已加密，请输入访问密码：', '', function(pwd) {
                if (pwd === null) return;
                let fd = new FormData();
                fd.append('dir_key', dirKey);
                fd.append('password', pwd);
                postBackend('unlock_dir', fd, true);
            });
        } else {
            showInfoModal('访问受限', '此目录禁止游客访问，请先在左侧管理区登录管理员账号后再打开。');
        }
        return;
    }

    const targetMenu = document.getElementById(menuId);
    if (!targetMenu) return;

    const willOpen = targetMenu.style.display !== 'block';

    const allMenus = document.querySelectorAll('.list_file .menu');
    allMenus.forEach(function(m) {
        m.style.display = 'none';
    });

    if (willOpen) {
        targetMenu.style.display = 'block';
        currentOpenedDirKey = dirKey || '';
    } else {
        targetMenu.style.display = 'none';
        currentOpenedDirKey = '';
    }
}

function addNewDir() {
    let name = document.getElementById('new_dir_name').value.trim();
    let remark = document.getElementById('new_dir_remark').value.trim();
    let openMode = document.getElementById('new_dir_open_mode').value;
    let pwd = document.getElementById('new_dir_pwd').value.trim();

    if (!name) return showInfoModal('提示', '请输入目录标题');
    if (openMode !== 'direct' && !pwd) return showInfoModal('提示', '密码访问模式下密码不能为空');

    let fd = new FormData();
    fd.append('name', name);
    fd.append('remark', remark);
    fd.append('open_mode', openMode);
    fd.append('password', pwd);

    fd.append('d_view', document.getElementById('new_d_view').checked ? '1' : '');
    fd.append('d_download', document.getElementById('new_d_download').checked ? '1' : '');
    fd.append('d_upload', document.getElementById('new_d_upload').checked ? '1' : '');

    fd.append('p_download', document.getElementById('new_p_download').checked ? '1' : '');
    fd.append('p_upload', document.getElementById('new_p_upload').checked ? '1' : '');
    fd.append('p_manage', document.getElementById('new_p_manage').checked ? '1' : '');

    fd.append('max_total_mb', document.getElementById('new_max_total_mb').value.trim());
    fd.append('max_file_mb', document.getElementById('new_max_file_mb').value.trim());
    fd.append('allowed_exts', document.getElementById('new_allowed_exts').value.trim());

    postBackend('add_dir', fd, true);
}

function openEditDirModal(dir, dirKey) {
    dir = dir && typeof dir === 'object' ? dir : {};
    const limits = dir.limits && typeof dir.limits === 'object' ? dir.limits : {};
    const directPerm = dir.direct_perm && typeof dir.direct_perm === 'object' ? dir.direct_perm : {};
    const pwdPerm = dir.pwd_perm && typeof dir.pwd_perm === 'object' ? dir.pwd_perm : {};
    const maxTotal = escapeHtmlSimple(limits.max_total_mb || 0);
    const maxFile = escapeHtmlSimple(limits.max_file_mb || 0);
    const allowedExts = escapeHtmlSimple(limits.allowed_exts || '');
    const dirName = escapeHtmlSimple(dir.name || '');
    const dirRemark = escapeHtmlSimple(dir.remark || '');
    const isDirect = dir.open_mode === 'direct';

    let html = `
        <div class="modal-flat-box">
            <label><b>目录标题 *</b></label>
            <input type="text" id="edit_dir_name" value="${dirName}">

            <label style="margin-top:6px; display:block;"><b>备注 (可不填)</b></label>
            <input type="text" id="edit_dir_remark" value="${dirRemark}">

            <label style="margin-top:6px; display:block;"><b>目录开启方式</b></label>
            <select id="edit_dir_open_mode">
                <option value="direct" ${isDirect ? 'selected' : ''}>直接打开，无需密码</option>
                <option value="pwd" ${!isDirect ? 'selected' : ''}>输入密码打开</option>
            </select>

            <div id="edit_pwd_group" style="margin-top:6px; display:${isDirect ? 'none' : 'block'};">
                <label><b>开启密码 *</b></label>
                <input type="password" id="edit_dir_pwd" value="" placeholder="已设置密码；留空表示不修改">
                <label style="display:block; margin-top:6px;"><input type="checkbox" id="edit_clear_pwd"> 取消密码保护并清空原密码</label>
            </div>

            <div class="perm-box">
                <h4>访客直接打开时权限</h4>
                <label><input type="checkbox" id="edit_d_view" ${!Object.prototype.hasOwnProperty.call(directPerm, 'view') || directPerm.view ? 'checked' : ''} onchange="checkDirectView(this)"> 查看</label>
                <label><input type="checkbox" id="edit_d_download" ${directPerm.download ? 'checked' : ''} onchange="autoCheckView('edit_d', 'download')"> 下载</label>
                <label><input type="checkbox" id="edit_d_upload" ${directPerm.upload ? 'checked' : ''} onchange="autoCheckView('edit_d', 'upload')"> 上传</label>
            </div>

            <div class="perm-box">
                <h4>输入密码打开时权限</h4>
                <label><input type="checkbox" id="edit_p_download" ${pwdPerm.download ? 'checked' : ''}> 下载</label>
                <label><input type="checkbox" id="edit_p_upload" ${pwdPerm.upload ? 'checked' : ''}> 上传</label>
                <label><input type="checkbox" id="edit_p_manage" ${pwdPerm.manage ? 'checked' : ''} onchange="handleManagePermChange(this)"> 管理</label>
            </div>

            <div class="perm-box">
                <h4>上传容量与类型限制 (0或留空为不限)</h4>
                <label style="display:block; margin:4px 0;">目录总容量上限 (MB)：</label>
                <input type="text" id="edit_max_total_mb" value="${maxTotal}">
                <label style="display:block; margin:4px 0;">单文件大小上限 (MB)：</label>
                <input type="text" id="edit_max_file_mb" value="${maxFile}">
                <label style="display:block; margin:4px 0;">允许文件后缀 (逗号分隔)：</label>
                <input type="text" id="edit_allowed_exts" value="${allowedExts}" placeholder="留空不限，如: jpg,png,zip,mp4">
            </div>
        </div>
        <div style="text-align:right;">
            <button type="button" id="submitEditDirBtn" class="modal-primary-btn">保存修改</button>
        </div>
    `;
    openModal('编辑目录权限与属性', html, false);

    const modeSelect = document.getElementById('edit_dir_open_mode');
    const pwdGroup = document.getElementById('edit_pwd_group');
    if (modeSelect && pwdGroup) {
        modeSelect.addEventListener('change', function() {
            pwdGroup.style.display = this.value === 'direct' ? 'none' : 'block';
        });
    }
    const submitBtn = document.getElementById('submitEditDirBtn');
    if (submitBtn) submitBtn.addEventListener('click', function() {
        submitEditDir(dirKey);
    });
}

function submitEditDir(dirKey) {
    let name = document.getElementById('edit_dir_name').value.trim();
    let remark = document.getElementById('edit_dir_remark').value.trim();
    let openMode = document.getElementById('edit_dir_open_mode').value;
    let pwd = document.getElementById('edit_dir_pwd').value.trim();

    if (!name) return showInfoModal('提示', '目录标题不能为空');

    let fd = new FormData();
    fd.append('dir_key', dirKey);
    fd.append('name', name);
    fd.append('remark', remark);
    fd.append('open_mode', openMode);
    fd.append('password', pwd);
    fd.append('clear_password', document.getElementById('edit_clear_pwd').checked ? '1' : '');

    fd.append('d_view', document.getElementById('edit_d_view').checked ? '1' : '');
    fd.append('d_download', document.getElementById('edit_d_download').checked ? '1' : '');
    fd.append('d_upload', document.getElementById('edit_d_upload').checked ? '1' : '');

    fd.append('p_download', document.getElementById('edit_p_download').checked ? '1' : '');
    fd.append('p_upload', document.getElementById('edit_p_upload').checked ? '1' : '');
    fd.append('p_manage', document.getElementById('edit_p_manage').checked ? '1' : '');

    fd.append('max_total_mb', document.getElementById('edit_max_total_mb').value.trim());
    fd.append('max_file_mb', document.getElementById('edit_max_file_mb').value.trim());
    fd.append('allowed_exts', document.getElementById('edit_allowed_exts').value.trim());

    closeModal();
    postBackend('edit_dir', fd, true);
}

function deleteDir(dirKey) {
    showConfirmModal('删除目录确认', '确定要删除整个目录及其内部所有文件吗？此操作不可恢复。', function() {
        let fd = new FormData();
        fd.append('dir_key', dirKey);
        postBackend('delete_dir', fd, true);
    });
}

function toggleUploadMode() {
    let type = document.querySelector('input[name="upload_type"]:checked').value;
    document.getElementById('mode_file').style.display = (type === 'file') ? 'block' : 'none';
    document.getElementById('mode_link').style.display = (type === 'link') ? 'block' : 'none';
}

function addLink() {
    let dirKey = document.getElementById('upload_dir_key').value;
    let title = document.getElementById('link_title').value.trim();
    let url = document.getElementById('link_url').value.trim();
    if (!title || !url) return showInfoModal('提示', '请填写链接名称和地址');
    let fd = new FormData();
    fd.append('dir_key', dirKey);
    fd.append('link_title', title);
    fd.append('link_url', url);
    postBackend('add_link', fd, true);
}

function editLink(dirKey, fileId, oldTitle, oldUrl) {
    const safeTitle = escapeHtmlSimple(oldTitle || '');
    const safeUrl = escapeHtmlSimple(oldUrl || '');
    const html = `
        <div class="modal-flat-box">
            <label style="display:block; margin-bottom:6px; font-weight:bold; color:#333;">链接名称 *</label>
            <input type="text" id="editLinkTitleInput" value="${safeTitle}" style="margin:0 0 10px 0;">

            <label style="display:block; margin-bottom:6px; font-weight:bold; color:#333;">链接地址 *</label>
            <input type="url" id="editLinkUrlInput" value="${safeUrl}" style="margin:0;">
        </div>
        <div style="text-align:right; margin-top:12px; display:flex; justify-content:flex-end; gap:8px;">
            <button type="button" id="editLinkCancelBtn" class="modal-secondary-btn">取消</button>
            <button type="button" id="editLinkSubmitBtn" class="modal-primary-btn">保存修改</button>
        </div>
    `;
    openModal('编辑外部链接', html, false);

    const titleEl = document.getElementById('editLinkTitleInput');
    const urlEl = document.getElementById('editLinkUrlInput');
    if (titleEl) {
        titleEl.focus();
        titleEl.select();
    }

    const submitAction = function() {
        const newTitle = titleEl ? titleEl.value.trim() : '';
        let newUrl = urlEl ? urlEl.value.trim() : '';
        if (!newTitle || !newUrl) {
            return showInfoModal('提示', '链接名称和地址不能为空');
        }
        if (!/^https?:\/\//i.test(newUrl)) {
            newUrl = 'https://' + newUrl;
        }
        closeModal();
        const fd = new FormData();
        fd.append('dir_key', dirKey);
        fd.append('file_id', fileId);
        fd.append('link_title', newTitle);
        fd.append('link_url', newUrl);
        postBackend('edit_link', fd, true);
    };

    if (titleEl) {
        titleEl.onkeydown = function(e) {
            if (e.key === 'Enter') submitAction();
        };
    }
    if (urlEl) {
        urlEl.onkeydown = function(e) {
            if (e.key === 'Enter') submitAction();
        };
    }
    const cancelBtn = document.getElementById('editLinkCancelBtn');
    const submitBtn = document.getElementById('editLinkSubmitBtn');
    if (cancelBtn) cancelBtn.onclick = closeModal;
    if (submitBtn) submitBtn.onclick = submitAction;
}

function renameItem(dirKey, fileId, oldName) {
    showPromptModal('重命名项目', '请输入新的名称（请保留文件后缀名）：', oldName, function(newName) {
        if (!newName || newName.trim() === '' || newName.trim() === oldName) return;
        const trimmed = newName.trim();
        if (isSystemForbiddenName(trimmed)) {
            const blockedExt = getFileExtensionLower(trimmed);
            return showInfoModal('操作拦截', '系统强制禁止使用 .' + blockedExt + ' 后缀，无法重命名。');
        }
        let fd = new FormData();
        fd.append('dir_key', dirKey);
        fd.append('file_id', fileId);
        fd.append('new_name', trimmed);
        postBackend('rename_item', fd, true);
    });
}

function deleteItem(dirKey, fileId) {
    showConfirmModal('删除确认', '确定要删除该项目吗？', function() {
        let fd = new FormData();
        fd.append('dir_key', dirKey);
        fd.append('file_id', fileId);
        postBackend('delete_item', fd, true);
    });
}

function moveFile(fromDir, fileId, toDir) {
    if (!toDir) return;
    let fd = new FormData();
    fd.append('from_dir', fromDir);
    fd.append('to_dir', toDir);
    fd.append('file_id', fileId);
    postBackend('move_file', fd, true);
}

function adminLogin() {
    let pwd = document.getElementById('admin_pwd_input').value;
    let fd = new FormData();
    fd.append('password', pwd);
    postBackend('login', fd, true);
}

function adminLogout() {
    postBackend('logout', new FormData(), true);
}

function changeAdminPwd() {
    let pwd = document.getElementById('new_admin_pwd').value;
    let fd = new FormData();
    fd.append('new_pwd', pwd);
    postBackend('change_admin_pwd', fd, true);
}

function submitMsg() {
    let content = document.getElementById('msg_content').value.trim();
    let isPublic = document.querySelector('input[name="msg_public"]:checked').value;
    if (!content) return showInfoModal('提示', '请输入留言内容');
    let fd = new FormData();
    fd.append('content', content);
    fd.append('is_public', isPublic);
    postBackend('add_msg', fd, true);
}

function approveMsg(id) {
    let fd = new FormData();
    fd.append('msg_id', id);
    postBackend('approve_msg', fd, true);
}

function deleteMsg(id) {
    showConfirmModal('删除留言确认', '确定要删除此条留言吗？', function() {
        let fd = new FormData();
        fd.append('msg_id', id);
        postBackend('delete_msg', fd, true);
    });
}

function previewImage(dirKey, url, title) {
    const safeUrl = safeLocalUploadUrl(url);
    if (!safeUrl) return showInfoModal('预览失败', '图片地址无效或不属于本站上传目录');
    const candidateList = Array.isArray(dirImagesMap[dirKey]) ? dirImagesMap[dirKey] : [];
    currentImgList = candidateList.length ? candidateList : [{ url: safeUrl, name: String(title || '') }];
    currentImgIndex = currentImgList.findIndex(item => safeLocalUploadUrl(item.url) === safeUrl);
    if (currentImgIndex < 0) currentImgIndex = 0;

    let html = `
        <div class="preview-toolbar">
            <button type="button" onclick="prevImage()">上一张</button>
            <button type="button" onclick="nextImage()">下一张</button>
            <button type="button" onclick="transformImg(0.25, 0)">放大 (+)</button>
            <button type="button" onclick="transformImg(-0.25, 0)">缩小 (-)</button>
            <button type="button" onclick="transformImg(0, -90)">左旋 90°</button>
            <button type="button" onclick="transformImg(0, 90)">右旋 90°</button>
            <button type="button" onclick="resetImg()">还原</button>
        </div>
        <div class="img-stage" id="imgStage" onwheel="handleImgWheel(event)" onmousedown="startImgDrag(event)" onmousemove="moveImgDrag(event)" onmouseup="endImgDrag()" onmouseleave="endImgDrag()">
            <img id="previewTargetImg" src="" alt="">
        </div>
        <p class="note" style="text-align:center;">提示：拖动窗口右下角可调整大小；放大后按住鼠标左键可拖动图片查看细节。</p>
    `;
    openModal('图片预览', html, true);
    loadImageAtIndex(currentImgIndex);
}

function loadImageAtIndex(idx) {
    if (!currentImgList.length) return;
    currentImgIndex = (idx + currentImgList.length) % currentImgList.length;
    const item = currentImgList[currentImgIndex];
    const safeUrl = safeLocalUploadUrl(item.url);
    if (!safeUrl) return showInfoModal('预览失败', '图片地址无效或不属于本站上传目录');
    imgScale = 1;
    imgRotate = 0;
    panX = 0;
    panY = 0;
    document.getElementById('modalTitle').innerText = `图片预览 (${currentImgIndex + 1}/${currentImgList.length}) - ${item.name}`;
    const img = document.getElementById('previewTargetImg');
    if (img) {
        img.src = safeUrl;
        img.alt = String(item.name || '');
        updateImgTransform();
    }
}

function prevImage() {
    loadImageAtIndex(currentImgIndex - 1);
}

function nextImage() {
    loadImageAtIndex(currentImgIndex + 1);
}

function updateImgTransform() {
    const img = document.getElementById('previewTargetImg');
    const stage = document.getElementById('imgStage');
    if (img) {
        img.style.transform = `translate(${panX}px, ${panY}px) scale(${imgScale}) rotate(${imgRotate}deg)`;
    }
    if (stage) {
        stage.style.cursor = imgScale > 1 ? (isDraggingImg ? 'grabbing' : 'grab') : 'default';
    }
}

function transformImg(scaleDelta, rotateDelta) {
    imgScale = Math.max(0.25, Math.min(6, Number((imgScale + scaleDelta).toFixed(2))));
    if (imgScale <= 1) {
        panX = 0;
        panY = 0;
    }
    imgRotate = (imgRotate + rotateDelta) % 360;
    updateImgTransform();
}

function resetImg() {
    imgScale = 1;
    imgRotate = 0;
    panX = 0;
    panY = 0;
    updateImgTransform();
}

function handleImgWheel(e) {
    e.preventDefault();
    transformImg(e.deltaY < 0 ? 0.2 : -0.2, 0);
}

function startImgDrag(e) {
    if (e.button !== 0 || imgScale <= 1) return;
    isDraggingImg = true;
    dragStartX = e.clientX - panX;
    dragStartY = e.clientY - panY;
    updateImgTransform();
}

function moveImgDrag(e) {
    if (!isDraggingImg) return;
    panX = e.clientX - dragStartX;
    panY = e.clientY - dragStartY;
    updateImgTransform();
}

function endImgDrag() {
    if (!isDraggingImg) return;
    isDraggingImg = false;
    updateImgTransform();
}

function previewText(url, title) {
    const safeUrl = safeLocalUploadUrl(url);
    if (!safeUrl) return showInfoModal('预览失败', '文本地址无效或不属于本站上传目录');
    fetch(safeUrl, { credentials: 'same-origin' })
        .then(response => {
            if (!response.ok) throw new Error('HTTP ' + response.status);
            return response.text();
        })
        .then(txt => {
            const escaped = escapeHtmlSimple(txt);
            openModal('文本预览 - ' + String(title || ''), `<pre style="white-space:pre-wrap; background:#faf8fc; padding:12px; border:1px solid #dfd5ee; line-height:1.5; margin:0;">${escaped}</pre>`, false);
        })
        .catch(() => showInfoModal('预览失败', '文件读取失败，请检查文件是否存在'));
}

function showDetails(file) {
    file = file && typeof file === 'object' ? file : {};
    const modifications = Array.isArray(file.modifications) ? file.modifications : [];
    const downloadLogs = Array.isArray(file.download_logs) ? file.download_logs : [];
    const modHtml = modifications.map(m =>
        `<li>${escapeHtmlSimple(m && m.time)} - ${escapeHtmlSimple(m && m.action)}</li>`
    ).join('');
    const dlHtml = downloadLogs.slice(-10).reverse().map(d =>
        `<li>${escapeHtmlSimple(d && d.time)} (来源IP: ${escapeHtmlSimple(d && d.ip)})</li>`
    ).join('');

    const html = `
        <div class="modal-flat-box">
            <p style="margin:4px 0;"><b>文件名称：</b>${escapeHtmlSimple(file.name)}</p>
            <p style="margin:4px 0;"><b>大小/类型：</b>${escapeHtmlSimple(file.size)}</p>
            <p style="margin:4px 0;"><b>取件码：</b><span style="color:#8e2de2; font-weight:bold;">${escapeHtmlSimple(file.pickup_code || '无')}</span></p>
            <p style="margin:4px 0;"><b>上传时间：</b>${escapeHtmlSimple(file.upload_date)}</p>
            <p style="margin:4px 0;"><b>下载/访问：</b>${escapeHtmlSimple(file.downloads)} 次</p>
        </div>
        <p style="margin-bottom:4px;"><b>修改与迁移轨迹：</b></p>
        <ul style="margin-top:0; padding-left:20px; color:#555;">${modHtml || '<li>无记录</li>'}</ul>
        <p style="margin-bottom:4px;"><b>最近下载记录 (最新10条)：</b></p>
        <ul style="margin-top:0; padding-left:20px; color:#555;">${dlHtml || '<li>暂无下载记录</li>'}</ul>
    `;
    openModal('文件详细信息与日志', html, false);
}
