(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  let captchaId = '';
  let mailEnabled = false;
  let toastTimer = null;

  // client_key 由后端在返回本 JS 时动态注入（每次不同），并通过 HttpOnly Cookie 记住。
  // 前端只读这个变量用于加密；不生成、不存储，密钥本身不出现在前端存储里。
  function clientKey() {
    return window.__DX_CK__ || '';
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

  // 认证阶段密钥：SHA256("dx-auth-v1:" + client_key)，与后端 authEnvelopeKey 一致。
  async function authKey(ck) {
    const raw = new TextEncoder().encode('dx-auth-v1:' + ck);
    const digest = await crypto.subtle.digest('SHA-256', raw);
    return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  async function seal(key, plainBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainBytes);
    return b64url(iv) + '.' + b64url(new Uint8Array(cipher));
  }

  async function open(key, enc) {
    const [ivStr, ctStr] = enc.split('.');
    if (!ivStr || !ctStr) throw new Error('密文格式异常');
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64url(ivStr) }, key, unb64url(ctStr)
    );
    return new Uint8Array(plain);
  }

  // 认证接口整包加密：账号/密码/验证码均不出现在明文报文里。
  // client_key 由后端注入并以 HttpOnly Cookie 记住，前端不回传该 key，只用它加密。
  async function api(path, method = 'GET', body) {
    const key = await authKey(clientKey());
    const opts = { method, credentials: 'same-origin', headers: {} };
    if (body !== undefined) {
      const enc = await seal(key, new TextEncoder().encode(JSON.stringify(body)));
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
    if (payload && typeof payload.payload === 'string') {
      try {
        payload = JSON.parse(new TextDecoder().decode(await open(key, payload.payload)));
      } catch {
        throw new Error('响应解密失败，请刷新页面重试');
      }
    }
    if (!res.ok) {
      const err = new Error(payload.message || '请求失败');
      err.code = payload.code;
      throw err;
    }
    return payload.data;
  }

  function enterApp(data, token) {
    sessionStorage.setItem('dx_session', data.dx_session || '');
    sessionStorage.setItem('dx_username', data.username || '');
    sessionStorage.setItem('dx_email', data.email || '');
    if (token) sessionStorage.setItem('dx_new_token', token);
    location.href = 'index.html';
  }

  function switchTab(tab) {
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === tab));
    $('loginForm').classList.toggle('hidden', tab !== 'login');
    $('registerForm').classList.toggle('hidden', tab !== 'register');
  }

  async function submitAuth(form, path) {
    const fd = new FormData(form);
    const payload = {
      username: fd.get('username'),
      password: fd.get('password')
    };
    if (path === 'api/auth/register') {
      payload.auth_code = fd.get('auth_code') || '';
    }
    if (path === 'api/auth/login' && !$('captchaRow').classList.contains('hidden')) {
      payload.captcha_id = captchaId;
      payload.captcha_text = fd.get('captcha_text') || '';
    }
    try {
      const data = await api(path, 'POST', payload);
      enterApp(data, data.token);
    } catch (e) {
      if (e.code === 'NEED_CAPTCHA') {
        $('captchaRow').classList.remove('hidden');
        await loadCaptcha();
        toast('请输入图形验证码', true);
      } else {
        toast(e.message, true);
      }
    }
  }

  async function loadPublicConfig() {
    try {
      const data = await api('api/public/config');
      mailEnabled = !!data.mail_enabled;
    } catch {
      mailEnabled = false;
    }
    if (!mailEnabled) $('btnForgot').classList.add('hidden');
  }

  async function loadCaptcha() {
    try {
      const data = await api('api/auth/captcha');
      captchaId = data.id;
      $('captchaImg').src = data.image;
      const input = $('loginForm').elements['captcha_text'];
      if (input) input.value = '';
    } catch (e) { toast(e.message, true); }
  }

  function openModal(html) {
    $('modalRoot').innerHTML = `<div class="modal-mask"><div class="modal">${html}</div></div>`;
    const mask = $('modalRoot').querySelector('.modal-mask');
    mask.addEventListener('click', (e) => { if (e.target === mask) closeModal(); });
  }

  function closeModal() { $('modalRoot').innerHTML = ''; }

  function forgotModal() {
    openModal(`<h2>找回密码</h2>
      <div id="forgotStep1">
        <p class="desc">输入已绑定的邮箱，系统会发送 6 位验证码（5 分钟有效）。未绑定邮箱将提示不存在。</p>
        <label>邮箱地址<input id="fEmail" type="email" placeholder="you@example.com" autocomplete="email"></label>
        <div class="modal-actions"><button class="btn ghost" id="mCancel">取消</button><button class="btn primary" id="mSend">发送验证码</button></div>
      </div>
      <div id="forgotStep2" class="hidden">
        <div class="step-note">验证码已发送至 <b id="fEmailShow"></b>，请注意查收（含垃圾邮件）。</div>
        <label style="margin-top:14px">验证码<input id="fCode" maxlength="6" inputmode="numeric" placeholder="6 位数字"></label>
        <label>新密码<input id="fPwd" type="password" placeholder="至少 6 位"></label>
        <div class="modal-actions"><button class="btn ghost" id="mBack">上一步</button><button class="btn primary" id="mReset">重置密码</button></div>
      </div>`);
    $('mCancel').onclick = closeModal;
    $('mBack').onclick = () => {
      $('forgotStep2').classList.add('hidden');
      $('forgotStep1').classList.remove('hidden');
    };
    $('mSend').onclick = async () => {
      const email = $('fEmail').value.trim();
      if (!email) return toast('请输入邮箱', true);
      try {
        await api('api/auth/forgot-password', 'POST', { email });
        $('fEmailShow').textContent = email;
        $('forgotStep1').classList.add('hidden');
        $('forgotStep2').classList.remove('hidden');
        toast('验证码已发送');
      } catch (e) { toast(e.message, true); }
    };
    $('mReset').onclick = async () => {
      try {
        await api('api/auth/reset-password', 'POST', {
          email: $('fEmail').value.trim(),
          code: $('fCode').value.trim(),
          new_password: $('fPwd').value
        });
        closeModal();
        toast('密码已重置，请用新密码登录');
      } catch (e) { toast(e.message, true); }
    };
  }

  function bind() {
    document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => switchTab(t.dataset.tab)));
    $('loginForm').addEventListener('submit', (e) => { e.preventDefault(); submitAuth(e.target, 'api/auth/login'); });
    $('registerForm').addEventListener('submit', (e) => { e.preventDefault(); submitAuth(e.target, 'api/auth/register'); });
    $('btnForgot').onclick = forgotModal;
    $('btnRefreshCaptcha').onclick = loadCaptcha;
    $('captchaImg').onclick = loadCaptcha;
  }

  async function start() {
    bind();
    await loadPublicConfig();
  }

  start();
})();
