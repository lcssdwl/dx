(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  let me = null;
  let devices = [];
  let currentId = null;
  let mailEnabled = false;
  let toastTimer = null;
  let encKey = null; // 由 dx_session + client_key 派生的 AES-GCM CryptoKey

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[c]);
  }

  function toast(msg, isError = false) {
    const el = $('toast');
    el.textContent = msg;
    el.className = 'toast show' + (isError ? ' error' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.className = 'toast'; }, 2600);
  }

  function b64url(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function unb64url(str) {
    const s = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // 与后端 envelopeKey 一致：SHA256("dx-api-v1:" + sessionID + ":" + clientKey)
  async function deriveKey(sessionID, clientKey) {
    const raw = new TextEncoder().encode('dx-api-v1:' + sessionID + ':' + clientKey);
    const digest = await crypto.subtle.digest('SHA-256', raw);
    return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  async function seal(plainBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, plainBytes);
    return b64url(iv) + '.' + b64url(new Uint8Array(cipher));
  }

  async function open(enc) {
    const [ivStr, ctStr] = enc.split('.');
    if (!ivStr || !ctStr) throw new Error('密文格式异常');
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64url(ivStr) }, encKey, unb64url(ctStr)
    );
    return new Uint8Array(plain);
  }

  // 后台 API 全部走整包信封：请求体 {"payload":密文}，响应用同样格式解密。
  async function api(path, method = 'GET', body) {
    const opts = { method, credentials: 'same-origin', headers: {} };
    if (body !== undefined) {
      const enc = await seal(new TextEncoder().encode(JSON.stringify(body)));
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify({ payload: enc });
    }
    let res;
    try {
      res = await fetch(path, opts);
    } catch {
      throw new Error('无法连接服务器');
    }
    let payload;
    try {
      payload = await res.json();
    } catch {
      throw new Error('服务器响应格式异常');
    }
    // 认证失败（UNAUTHORIZED）在加密层之前返回，是明文；其余为密文信封。
    if (payload && typeof payload.payload === 'string') {
      try {
        payload = JSON.parse(new TextDecoder().decode(await open(payload.payload)));
      } catch {
        throw new Error('响应解密失败，请刷新页面重试');
      }
    }
    if (!res.ok) {
      if (payload.code === 'UNAUTHORIZED') showAuth();
      const err = new Error(payload.message || '请求失败');
      err.code = payload.code;
      throw err;
    }
    return payload.data;
  }

  // 认证类接口（public config / logout）也加密：SHA256("dx-auth-v1:" + 后端注入的 client_key)。
  async function authKey() {
    const raw = new TextEncoder().encode('dx-auth-v1:' + (window.__DX_CK__ || ''));
    const digest = await crypto.subtle.digest('SHA-256', raw);
    return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  async function authFetch(path, method = 'GET', body) {
    const key = await authKey();
    const opts = { method, credentials: 'same-origin', headers: {} };
    if (body !== undefined) {
      const enc = await sealWith(key, new TextEncoder().encode(JSON.stringify(body)));
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify({ payload: enc });
    }
    try {
      const res = await fetch(path, opts);
      if (!res.ok) return null;
      const payload = await res.json();
      if (payload && typeof payload.payload === 'string') {
        const plain = await openWith(key, payload.payload);
        return JSON.parse(new TextDecoder().decode(plain)).data;
      }
      return payload.data;
    } catch {
      return null;
    }
  }

  async function sealWith(key, plainBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainBytes);
    return b64url(iv) + '.' + b64url(new Uint8Array(cipher));
  }

  async function openWith(key, enc) {
    const [ivStr, ctStr] = enc.split('.');
    if (!ivStr || !ctStr) throw new Error('密文格式异常');
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64url(ivStr) }, key, unb64url(ctStr)
    );
    return new Uint8Array(plain);
  }

  function showAuth() {
    sessionStorage.removeItem('dx_session');
    me = null;
    currentId = null;
    document.body.classList.remove('show-chat');
    $('appView').classList.add('hidden');
    location.href = 'login.html';
  }

  function showApp() {
    const r = $('authRedirect');
    if (r) r.classList.add('hidden');
    $('appView').classList.remove('hidden');
  }

  function fmtTime(t, full = false) {
    if (!t) return '';
    const d = new Date(t);
    if (isNaN(d)) return '';
    const hm = d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false });
    if (full) {
      return d.toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' }) + ' ' + hm;
    }
    const today = new Date();
    const sameDay = d.toDateString() === today.toDateString();
    return sameDay ? hm : d.toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' });
  }

  // ---------- 设备列表 ----------

  async function loadDevices(silent = false) {
    try {
      const data = await api('api/devices');
      devices = data.items || [];
      $('userName').textContent = me ? me.username : '-';
      $('userAvatar').textContent = me ? me.username.slice(0, 1).toUpperCase() : '我';
      $('deviceCount').textContent = devices.length + ' 台设备';
      renderDevices();
      if (currentId && !devices.some((d) => d.id === currentId)) {
        currentId = null;
        document.body.classList.remove('show-chat');
        renderMessages([]);
      }
    } catch (e) {
      if (!silent) toast(e.message, true);
    }
  }

  function renderDevices() {
    const q = $('searchInput').value.trim().toLowerCase();
    const list = devices.filter((d) => !q || d.id.toLowerCase().includes(q) || (d.name || '').toLowerCase().includes(q));
    const el = $('deviceList');
    if (list.length === 0) {
      el.innerHTML = '<div class="list-empty">暂无设备<br>点击「新建设备」开始接收短信</div>';
      return;
    }
    el.innerHTML = list.map((d) => {
      const preview = d.preview ? esc(d.preview) : (d.count ? d.count + ' 条短信' : '暂无短信');
      return `<div class="device-item ${d.id === currentId ? 'active' : ''}" data-id="${esc(d.id)}">
        <div class="dev-icon">▣</div>
        <div class="dev-body">
          <div class="dev-top"><strong><span class="${d.online ? 'online-dot' : 'offline-dot'}"></span>${esc(d.name || d.id)}</strong><time class="${d.online ? 'online' : ''}">${d.online ? '在线 · ' : ''}${fmtTime(d.last_seen)}</time></div>
          <div class="dev-preview">${preview}</div>
          <div class="dev-id">${esc(d.id)}</div>
        </div>
        <button class="icon-btn danger device-del" data-id="${esc(d.id)}" title="删除设备" aria-label="删除设备">✕</button>
      </div>`;
    }).join('');
    el.querySelectorAll('.device-item').forEach((item) => {
      item.addEventListener('click', () => selectDevice(item.dataset.id));
    });
    el.querySelectorAll('.device-del').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        deleteDevice(btn.dataset.id);
      });
    });
  }

  function selectDevice(id) {
    currentId = id;
    const d = devices.find((x) => x.id === id);
    $('chatName').textContent = d ? (d.name || d.id) : id;
    $('chatId').textContent = '设备 ID：' + id;
    renderDevices();
    document.body.classList.add('show-chat');
    $('messages').innerHTML = ''; // 切换设备时清空上一台设备的展开状态
    $('messages').scrollTop = 0;
    loadMessages();
  }

  // ---------- 短信 ----------

  async function loadMessages(silent = false) {
    if (!currentId) return;
    try {
      const data = await api(`api/devices/${encodeURIComponent(currentId)}/messages?page=1&size=100`);
      const box = $('messages');
      const scroll = box.scrollTop;
      // 刷新前记录已展开的条目，避免重建 DOM 后自动收起。
      const expanded = new Set(
        Array.from(box.querySelectorAll('.sms-row.expanded')).map((row) => row.dataset.id)
      );
      renderMessages(data.items || [], scroll, expanded);
    } catch (e) {
      if (!silent) toast(e.message, true);
    }
  }

  function renderMessages(items, scroll = 0, expanded = new Set()) {
    const el = $('messages');
    if (!items.length) {
      el.innerHTML = '<div class="empty-chat"><div class="empty-icon">📋</div><p>还没有短信</p><span>设备上报后，短信会以列表形式显示在这里</span></div>';
      return;
    }
    el.innerHTML = items.map((m) => {
      const from = m.sender || '未知号码';
      const simTag = m.sim ? `<span class="sms-tag sim">${esc(m.sim)}${m.carrier ? ' · ' + esc(m.carrier) : ''}</span>` : '';
      const subTag = m.sub_id !== undefined && m.sub_id !== '' ? `<span class="sms-tag">SubId ${esc(m.sub_id)}</span>` : '';
      const shownTime = m.sms_time || fmtTime(m.created_at, true);
      const meta = [];
      if (m.sim_number) meta.push('SIM号 ' + esc(m.sim_number));
      if (m.sub_id !== undefined && m.sub_id !== '') meta.push('SubId ' + esc(m.sub_id));
      if (m.sms_time) meta.push('接收 ' + fmtTime(m.created_at, true));
      const raw = m.raw || m.body || m.text || '';
      return `<div class="sms-row ${expanded.has(m.id) ? 'expanded' : ''}" data-id="${esc(m.id)}">
        <div class="sms-avatar">${esc(from.slice(-4))}</div>
        <div class="sms-main">
          <div class="sms-line1">
            <strong class="sms-from">${esc(from)}</strong>
            ${simTag}${subTag}
            <time class="sms-time">${esc(shownTime)}</time>
          </div>
          <div class="sms-body">${esc(m.body || m.text || '')}</div>
          ${meta.length ? `<div class="sms-meta">${meta.join(' · ')}</div>` : ''}
          <div class="sms-raw">${esc(raw)}</div>
        </div>
      </div>`;
    }).join('');
    el.querySelectorAll('.sms-row').forEach((row) => {
      row.addEventListener('click', () => row.classList.toggle('expanded'));
    });
    el.scrollTop = scroll;
  }

  // ---------- 弹窗 ----------

  function openModal(html, wide = false) {
    $('modalRoot').innerHTML = `<div class="modal-mask"><div class="modal ${wide ? 'wide' : ''}">${html}</div></div>`;
    const mask = $('modalRoot').querySelector('.modal-mask');
    mask.addEventListener('click', (e) => { if (e.target === mask) closeModal(); });
  }

  function closeModal() { $('modalRoot').innerHTML = ''; }

  function newDeviceModal() {
    openModal(`<h2>新建设备</h2>
      <p class="desc">设备 ID 全局唯一，创建后可配合你的 Token 上报短信。ID 仅支持字母、数字、下划线、点和连字符。</p>
      <label>设备 ID<input id="mDevId" maxlength="64" placeholder="例如 phone-01" autocomplete="off"></label>
      <label>设备名称（可选）<input id="mDevName" maxlength="64" placeholder="例如 备用安卓机"></label>
      <div class="modal-actions"><button class="btn ghost" id="mCancel">取消</button><button class="btn primary" id="mOk">创建</button></div>`);
    $('mCancel').onclick = closeModal;
    $('mDevId').focus();
    $('mOk').onclick = async () => {
      const id = $('mDevId').value.trim();
      const name = $('mDevName').value.trim();
      if (!id) return toast('请填写设备 ID', true);
      try {
        await api('api/devices', 'POST', { id, name });
        closeModal();
        toast('设备创建成功');
        await loadDevices();
        selectDevice(id);
      } catch (e) { toast(e.message, true); }
    };
  }

  function tokenModal(token) {
    openModal(`<h2>你的 API Token</h2>
      <p class="desc">用于设备端短信上报与数据加密。Token 等同于账号密钥，请勿泄露或提交到公开仓库。</p>
      <div class="token-box"><span id="mToken">${esc(token)}</span><button class="btn small" id="mCopy">复制</button></div>
      <div class="modal-actions"><button class="btn primary" id="mClose">完成</button></div>`);
    $('mClose').onclick = closeModal;
    $('mCopy').onclick = async () => {
      try {
        await navigator.clipboard.writeText(token);
        toast('已复制到剪贴板');
      } catch { toast('复制失败，请手动选择', true); }
    };
  }

  async function showToken() {
    try {
      const data = await api('api/token');
      tokenModal(data.token);
    } catch (e) { toast(e.message, true); }
  }

  function apiDocModal() {
    const origin = location.origin + location.pathname.replace(/\/$/, '');
    const sample = `curl -X POST ${origin}/api/sms/receive \\\n  -H "Content-Type: application/json" \\\n  -d '{\n    "token": "你的TOKEN",\n    "id": "phone-01",\n    "text": "您的验证码是 123456",\n    "from": "+8613800000000"\n  }'`;
    const heartbeatSample = `curl -X POST ${origin}/api/device/heartbeat \\\n  -H "Content-Type: application/json" \\\n  -d '{"token":"你的TOKEN","id":"phone-01"}'`;
    const getSample = `curl -G ${origin}/api/sms/receive \\\n  --data-urlencode "token=你的TOKEN" \\\n  --data-urlencode "id=phone-01" \\\n  --data-urlencode "text=您的验证码是 123456"`;
    const hbGetSample = `${origin}/api/device/heartbeat?token=你的TOKEN&id=phone-01`;
    openModal(`<h2>设备接口</h2>
      <p class="desc"><b>1. 短信上报</b> — token 为用户密钥，id 为设备 ID，text 为短信明文。明文用 token 派生密钥加密后落盘。</p>
      <pre>${esc(sample)}</pre>
      <p class="desc" style="margin-top:8px">也支持 GET（参数需 URL 编码）：</p>
      <pre>${esc(getSample)}</pre>
      <p class="desc" style="margin-top:16px"><b>2. 心跳</b> — 只需 token + id，建议设备每 10 秒请求一次；20 秒内有请求即显示在线。上报短信也自动视为活跃。</p>
      <pre>${esc(heartbeatSample)}</pre>
      <p class="desc" style="margin-top:8px">GET：<code>${esc(hbGetSample)}</code></p>
      <p class="desc" style="margin-top:14px">成功返回 <code>{"code":"OK"}</code>；token 无效返回 <code>INVALID_TOKEN</code>；设备不存在返回 <code>DEVICE_NOT_FOUND</code>；频率过高返回 <code>RATE_LIMITED</code>。</p>
      <div class="modal-actions"><button class="btn primary" id="mClose">关闭</button></div>`, true);
    $('mClose').onclick = closeModal;
  }

  async function clearMessages() {
    if (!currentId) return;
    if (!confirm('确定清空该设备的全部短信？此操作不可恢复。')) return;
    try {
      await api(`api/devices/${encodeURIComponent(currentId)}/messages`, 'DELETE');
      toast('短信已清空');
      await Promise.all([loadMessages(), loadDevices()]);
    } catch (e) { toast(e.message, true); }
  }

  async function deleteDevice(id) {
    if (!id) return;
    if (!confirm('确定删除该设备及其全部短信？此操作不可恢复。')) return;
    try {
      await api(`api/devices/${encodeURIComponent(id)}`, 'DELETE');
      if (id === currentId) {
        currentId = null;
        document.body.classList.remove('show-chat');
      }
      toast('设备已删除');
      await loadDevices();
    } catch (e) { toast(e.message, true); }
  }

  // ---------- 公开配置 ----------

  async function loadPublicConfig() {
    const data = await authFetch('api/public/config');
    mailEnabled = !!(data && data.mail_enabled);
  }

  function settingsModal() {
    const emailVal = me.email || '';
    const emailSection = mailEnabled ? `<div class="modal-section"><h3>${emailVal ? '更换' : '绑定'}邮箱</h3>
        <label>邮箱地址<input id="sEmail" type="email" value="${esc(emailVal)}" placeholder="you@example.com"></label>
        <button class="btn small ghost" id="sSendCode">发送验证码</button>
        <label style="margin-top:10px">邮箱验证码<input id="sEmailCode" maxlength="6" placeholder="6 位数字"></label>
        <button class="btn small" id="sEmailOk">保存邮箱</button>
      </div>` : '';
    openModal(`<h2>账号设置</h2>
      <p class="desc">当前账号：<b>${esc(me.username)}</b>${mailEnabled ? ' · ' + (emailVal ? esc(emailVal) : '未绑定邮箱') : ''}</p>
      <div class="modal-section"><h3>修改密码</h3>
        <label>原密码<input id="sOldPwd" type="password"></label>
        <label>新密码<input id="sNewPwd" type="password" placeholder="至少 6 位"></label>
        <label>确认新密码<input id="sNewPwd2" type="password" placeholder="再次输入新密码"></label>
        <button class="btn small" id="sPwdOk">保存密码</button>
      </div>
      ${emailSection}
      <div class="modal-actions"><button class="btn primary" id="mClose">完成</button></div>`);
    $('mClose').onclick = closeModal;
    $('sPwdOk').onclick = async () => {
      const oldPwd = $('sOldPwd').value;
      const newPwd = $('sNewPwd').value;
      const confirmPwd = $('sNewPwd2').value;
      if (!oldPwd || !newPwd) {
        toast('请填写原密码和新密码', true);
        return;
      }
      if (newPwd !== confirmPwd) {
        toast('两次输入的新密码不一致', true);
        return;
      }
      try {
        await api('api/account/password', 'POST', { old_password: oldPwd, new_password: newPwd });
        $('sOldPwd').value = '';
        $('sNewPwd').value = '';
        $('sNewPwd2').value = '';
        toast('密码已修改，其他设备已下线');
      } catch (e) { toast(e.message, true); }
    };
    if (mailEnabled) {
      $('sSendCode').onclick = async () => {
        try {
          await api('api/account/email/code', 'POST', { email: $('sEmail').value.trim() });
          toast('验证码已发送');
        } catch (e) { toast(e.message, true); }
      };
      $('sEmailOk').onclick = async () => {
        try {
          const data = await api('api/account/email', 'POST', { email: $('sEmail').value.trim(), code: $('sEmailCode').value.trim() });
          me.email = data.email;
          toast('邮箱已绑定，可用于找回密码');
        } catch (e) { toast(e.message, true); }
      };
    }
  }

  // ---------- 绑定与启动 ----------

  function bind() {
    $('btnNewDevice').onclick = newDeviceModal;
    $('btnToken').onclick = showToken;
    $('btnSettings').onclick = settingsModal;
    $('btnApiDoc').onclick = apiDocModal;
    $('btnRefresh').onclick = () => { loadMessages(); loadDevices(); toast('已刷新'); };
    $('btnClear').onclick = clearMessages;
    $('btnCloseChat').onclick = () => document.body.classList.remove('show-chat');
    $('btnBack').onclick = () => document.body.classList.remove('show-chat');
    $('searchInput').addEventListener('input', renderDevices);
    $('btnLogout').onclick = async () => {
      await authFetch('api/auth/logout', 'POST');
      sessionStorage.clear();
      showAuth();
    };
  }

  async function start() {
    const sid = sessionStorage.getItem('dx_session');
    const ck = window.__DX_CK__;
    if (!sid || !ck) { showAuth(); return; }
    try {
      encKey = await deriveKey(sid, ck);
    } catch {
      showAuth();
      return;
    }
    bind();
    await loadPublicConfig();
    try {
      const data = await api('api/auth/me');
      me = { id: data.id, username: data.username, email: data.email || '' };
      showApp();
      await loadDevices();
      const newToken = sessionStorage.getItem('dx_new_token');
      if (newToken) {
        sessionStorage.removeItem('dx_new_token');
        tokenModal(newToken);
      }
    } catch {
      showAuth();
      return;
    }
    // 3 秒刷新：设备在线判定为 20 秒内有心跳，需及时反映状态变化。
    setInterval(() => {
      if (!me) return;
      loadDevices(true);
      if (currentId) loadMessages(true);
    }, 3000);
  }

  start();
})();
