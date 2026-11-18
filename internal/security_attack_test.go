package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const (
	attackUsername = "admin"
	attackPassword = "admin1"
)

// secRegister 用测试账号 admin/admin1 注册（授权码由内置默认密钥派生）。
func secRegister(t *testing.T, c *http.Client, base string) map[string]any {
	t.Helper()
	return call(t, c, base, "POST", "/api/auth/register", map[string]any{
		"username": attackUsername, "password": attackPassword,
		"auth_code": authCode(attackUsername, attackPassword),
	}, 200)
}

// secNoJar 返回不带 CookieJar 的客户端，便于手工伪造 Cookie。
func secNoJar() *http.Client { return &http.Client{} }

// secRaw 发起原始请求，返回状态码、响应体与响应头。
func secRaw(t *testing.T, c *http.Client, base, method, path string, body []byte, headers map[string]string, cookies ...*http.Cookie) (int, string, http.Header) {
	t.Helper()
	if strings.HasPrefix(path, "/api/") {
		path = "/sdwl" + path
	}
	req, err := http.NewRequest(method, base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), res.Header
}

// secCaptchaText 取验证码 id 与服务端明文文本（同包测试可读取）。
func secCaptchaText(t *testing.T, s *Server, c *http.Client, base string) (string, string) {
	t.Helper()
	r := call(t, c, base, "GET", "/api/auth/captcha", nil, 200)
	id, _ := dataOf(t, r)["id"].(string)
	s.stateMu.Lock()
	text := s.captchas[id].Text
	s.stateMu.Unlock()
	return id, text
}

func secServerWithCfg(t *testing.T, cfg Config) (string, func()) {
	t.Helper()
	store, err := NewStore(cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	web := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}}
	srv := httptest.NewServer(newServer(cfg, store, web).handler())
	return srv.URL, srv.Close
}

func secBaseCfg(t *testing.T) Config {
	t.Helper()
	return Config{
		DataDir: t.TempDir(), SessionTTL: time.Hour,
		APIRateLimit: 1000, AuthRateLimit: 1000, MaxBodyBytes: 1 << 20,
		LoginMaxFail: 5, LoginLockMin: 15,
		MailEnabled: true, MailDebug: true,
		RegisterAuthSecret: DefaultRegisterAuthSecret,
	}
}

// ---------- A. 认证与会话 ----------

func TestAttackUnauthorizedAccess(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	endpoints := []struct{ m, p string }{
		{"GET", "/api/auth/me"}, {"GET", "/api/token"}, {"GET", "/api/devices"},
		{"POST", "/api/devices"}, {"DELETE", "/api/devices/x"},
		{"GET", "/api/devices/x/messages"}, {"DELETE", "/api/devices/x/messages"},
		{"POST", "/api/account/password"}, {"POST", "/api/account/email/code"},
		{"POST", "/api/account/email"},
	}
	for _, e := range endpoints {
		code, body, _ := secRaw(t, c, base, e.m, e.p, []byte(`{}`), nil)
		if code != 401 {
			t.Errorf("%s %s 未授权应返回 401，实际 %d: %s", e.m, e.p, code, body)
		}
	}
}

func TestAttackForgedSession(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := secNoJar()
	forged := []string{"admin", "root", strings.Repeat("a", 43), "..", "%%%", "a:b", ""}
	for _, sid := range forged {
		code, _, _ := secRaw(t, c, base, "GET", "/api/auth/me", nil, nil,
			&http.Cookie{Name: sessionCookie, Value: sid})
		if code != 401 {
			t.Errorf("伪造 session %q 应返回 401，实际 %d", sid, code)
		}
	}
}

func TestAttackBruteForceLock(t *testing.T) {
	base, _, s, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	secRegister(t, c, base)

	code, _, _ := secRaw(t, c, base, "POST", "/api/auth/login",
		[]byte(`{"username":"admin","password":"bad1"}`), nil)
	if code != 401 {
		t.Fatalf("首次错误密码应返回 401，实际 %d", code)
	}
	for i := 2; i <= 5; i++ {
		cid, ctext := secCaptchaText(t, s, c, base)
		body, _ := json.Marshal(map[string]any{
			"username": attackUsername, "password": fmt.Sprintf("bad%d", i),
			"captcha_id": cid, "captcha_text": ctext,
		})
		code, resp, _ := secRaw(t, c, base, "POST", "/api/auth/login", body, nil)
		if code != 401 {
			t.Fatalf("第 %d 次错误密码应返回 401，实际 %d: %s", i, code, resp)
		}
	}
	code, resp, _ := secRaw(t, c, base, "POST", "/api/auth/login",
		[]byte(`{"username":"admin","password":"admin1"}`), nil)
	if code != 423 {
		t.Errorf("暴力破解触发锁定应返回 423，实际 %d: %s", code, resp)
	}
}

func TestAttackCaptchaReplay(t *testing.T) {
	base, _, s, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	secRegister(t, c, base)
	// 制造一次失败，进入"需要验证码"状态
	secRaw(t, c, base, "POST", "/api/auth/login", []byte(`{"username":"admin","password":"bad"}`), nil)
	cid, ctext := secCaptchaText(t, s, c, base)
	body, _ := json.Marshal(map[string]any{
		"username": attackUsername, "password": "bad",
		"captcha_id": cid, "captcha_text": ctext,
	})
	code, _, _ := secRaw(t, c, base, "POST", "/api/auth/login", body, nil)
	if code != 401 {
		t.Fatalf("带验证码的错误密码应返回 401，实际 %d", code)
	}
	// 同一验证码重用应被拒绝（返回 NEED_CAPTCHA）
	code, resp, _ := secRaw(t, c, base, "POST", "/api/auth/login", body, nil)
	if code != 400 || !strings.Contains(resp, "NEED_CAPTCHA") {
		t.Errorf("验证码重用应被拒绝，实际 %d: %s", code, resp)
	}
}

func TestAttackSessionFixation(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := secNoJar()
	const injected = "attacker-fixed-session-id"
	body, _ := json.Marshal(map[string]any{
		"username": attackUsername, "password": attackPassword,
		"auth_code": authCode(attackUsername, attackPassword),
	})
	code, resp, hdr := secRaw(t, c, base, "POST", "/api/auth/register", body, nil,
		&http.Cookie{Name: sessionCookie, Value: injected})
	if code != 200 {
		t.Fatalf("注册应成功，实际 %d: %s", code, resp)
	}
	for _, sc := range hdr.Values("Set-Cookie") {
		if strings.HasPrefix(sc, sessionCookie+"=") && strings.Contains(sc, injected) {
			t.Errorf("登录后沿用了攻击者注入的 session id（会话固定）: %s", sc)
		}
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(resp), &out)
	sid, _ := dataOf(t, out)["dx_session"].(string)
	if sid == injected || sid == "" {
		t.Errorf("登录应生成全新 session id，实际 %q", sid)
	}
}

func TestAttackPasswordChangeInvalidatesSessions(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c1, c2 := testClient(t), testClient(t)
	secRegister(t, c1, base)
	call(t, c2, base, "POST", "/api/auth/login", map[string]any{
		"username": attackUsername, "password": attackPassword,
	}, 200)
	call(t, c1, base, "GET", "/api/auth/me", nil, 200)
	call(t, c1, base, "POST", "/api/account/password", map[string]any{
		"old_password": attackPassword, "new_password": "newpass123",
	}, 200)
	// 旧 session 应失效（c1 被重新签发新 session，c2 应失效）
	call(t, c2, base, "GET", "/api/auth/me", nil, 401)
	call(t, c1, base, "GET", "/api/auth/me", nil, 200)
	call(t, secNoJar(), base, "POST", "/api/auth/login", map[string]any{
		"username": attackUsername, "password": attackPassword,
	}, 401)
}

// ---------- B. 越权 ----------

func TestAttackIDOR(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c1, c2 := testClient(t), testClient(t)
	r1 := secRegister(t, c1, base)
	token1, _ := dataOf(t, r1)["token"].(string)
	registerOK(t, c2, base, "bob", "secret123")

	call(t, c1, base, "POST", "/api/devices", map[string]any{"id": "victim-dev", "name": "victim"}, 200)
	call(t, c1, base, "POST", "/api/sms/receive", map[string]any{
		"token": token1, "id": "victim-dev", "text": "secret sms",
	}, 200)

	call(t, c2, base, "GET", "/api/devices/victim-dev/messages", nil, 404)
	call(t, c2, base, "DELETE", "/api/devices/victim-dev", nil, 404)
	call(t, c2, base, "DELETE", "/api/devices/victim-dev/messages", nil, 404)
	// 用他人 token 上报到他人设备：token 与设备均属 c1，接口是设备端鉴权，成功属预期
	call(t, c2, base, "POST", "/api/sms/receive", map[string]any{
		"token": token1, "id": "victim-dev", "text": "from c2",
	}, 200)
	// bob 用自己的 token 上报到 victim 设备应失败
	r2 := call(t, c2, base, "GET", "/api/token", nil, 200)
	token2, _ := dataOf(t, r2)["token"].(string)
	call(t, c2, base, "POST", "/api/sms/receive", map[string]any{
		"token": token2, "id": "victim-dev", "text": "x",
	}, 404)
}

// ---------- C. 注入与路径穿越 ----------

func TestAttackPathTraversal(t *testing.T) {
	base, dataDir, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	secRegister(t, c, base)
	badIDs := []string{"../evil", "..", "a/b", "/abs", "a\\b", "....", "a..b", "a b", "a\x00b"}
	for _, id := range badIDs {
		body, _ := json.Marshal(map[string]any{"id": id, "name": "x"})
		code, _, _ := secRaw(t, c, base, "POST", "/api/devices", body, nil)
		if code != 400 {
			t.Errorf("恶意设备 ID %q 应被拒绝，实际 %d", id, code)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "/") || strings.Contains(e.Name(), "..") || strings.Contains(e.Name(), "\\") {
			t.Errorf("发现危险消息文件名: %q", e.Name())
		}
	}
}

func TestAttackXSSInjection(t *testing.T) {
	base, dataDir, _, closeFn := testServer(t)
	defer closeFn()
	c := secClientForXSS(t)
	secRegister(t, c, base)
	xss := `<script>alert(1)</script><img src=x onerror=alert(1)>`
	call(t, c, base, "POST", "/api/devices", map[string]any{"id": "xss-dev", "name": xss}, 200)

	// API 响应中不得出现原始 <script>（JSON 编码器会转义 HTML）
	code, body, _ := secRaw(t, c, base, "GET", "/api/devices", nil, nil)
	if code != 200 || strings.Contains(body, "<script>") {
		t.Errorf("设备列表响应含未转义 XSS: %d %s", code, body)
	}
	// 落盘文件不得含明文字段
	meta, _ := os.ReadFile(filepath.Join(dataDir, "meta.json"))
	if bytes.Contains(meta, []byte("<script>")) || bytes.Contains(meta, []byte(attackUsername)) {
		t.Error("meta.json 中出现明文 XSS 或明文用户名")
	}
}

func secClientForXSS(t *testing.T) *http.Client { return testClient(t) }

func TestAttackSQLCommandInjection(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	// 用户名正则应拒绝注入串
	for _, u := range []string{"' OR 1=1--", "admin';DROP", "a b", "<script>"} {
		body, _ := json.Marshal(map[string]any{
			"username": u, "password": "secret123", "auth_code": authCode(u, "secret123"),
		})
		code, _, _ := secRaw(t, c, base, "POST", "/api/auth/register", body, nil)
		if code != 400 {
			t.Errorf("注入用户名 %q 应被拒绝，实际 %d", u, code)
		}
	}
	secRegister(t, c, base)
	// 设备 ID 命令注入串应被拒绝
	for _, id := range []string{"dev;ls", "$(id)", "dev|sh", "dev`whoami`"} {
		body, _ := json.Marshal(map[string]any{"id": id, "name": "x"})
		code, _, _ := secRaw(t, c, base, "POST", "/api/devices", body, nil)
		if code != 400 {
			t.Errorf("注入设备 ID %q 应被拒绝，实际 %d", id, code)
		}
	}
}

// ---------- D. 加密与信封 ----------

func TestAttackPlaintextWithCK(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := secNoJar()
	code, resp, _ := secRaw(t, c, base, "POST", "/api/auth/login",
		[]byte(`{"username":"admin","password":"admin1"}`), nil,
		&http.Cookie{Name: clientKeyCookie, Value: "attack-ck"})
	if code != 400 || !strings.Contains(resp, "BAD_REQUEST") {
		t.Errorf("带 dx_ck 的明文请求应被拒绝，实际 %d: %s", code, resp)
	}
}

func TestAttackCiphertextTamper(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	ck := "tamper-ck"
	key := authEnvelopeKey(ck)
	body, _ := json.Marshal(map[string]any{
		"username": "tamperuser", "password": "secret123",
		"auth_code": authCode("tamperuser", "secret123"),
	})
	enc, _ := sealEnvelope(key, body)
	parts := strings.Split(enc, ".")
	ct := []byte(parts[1])
	if ct[len(ct)-1] == 'A' {
		ct[len(ct)-1] = 'B'
	} else {
		ct[len(ct)-1] = 'A'
	}
	tampered := parts[0] + "." + string(ct)
	envBytes, _ := json.Marshal(envelope{Payload: tampered})
	code, resp, _ := secRaw(t, secNoJar(), base, "POST", "/api/auth/register", envBytes, nil,
		&http.Cookie{Name: clientKeyCookie, Value: ck})
	if code != 400 || !strings.Contains(resp, "DECRYPT_FAILED") {
		t.Errorf("篡改密文应解密失败，实际 %d: %s", code, resp)
	}
}

func TestAttackWrongKey(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	body, _ := json.Marshal(map[string]any{"username": attackUsername, "password": attackPassword})
	enc, _ := sealEnvelope(authEnvelopeKey("wrong-key"), body)
	envBytes, _ := json.Marshal(envelope{Payload: enc})
	code, resp, _ := secRaw(t, secNoJar(), base, "POST", "/api/auth/login", envBytes, nil,
		&http.Cookie{Name: clientKeyCookie, Value: "right-key"})
	if code != 400 || !strings.Contains(resp, "DECRYPT_FAILED") {
		t.Errorf("错误密钥加密应解密失败，实际 %d: %s", code, resp)
	}
}

// ---------- E. CSRF 与入口 ----------

func TestAttackCSRF(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	secRegister(t, c, base)
	body, _ := json.Marshal(map[string]any{"id": "csrf-dev", "name": "x"})
	for _, origin := range []string{"https://evil.com", "http://evil.com", "null", "http://sdwl.attacker.com"} {
		code, resp, _ := secRaw(t, c, base, "POST", "/api/devices", body, map[string]string{"Origin": origin})
		if code != 403 {
			t.Errorf("跨站 Origin %q 应被拒绝，实际 %d: %s", origin, code, resp)
		}
	}
}

func TestAttackHiddenEntry(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := secNoJar()
	// 直接拼接 base+path，绕过 secRaw 的 /sdwl 前缀补全，验证裸路径被隐藏。
	for _, p := range []string{"/", "/api/auth/me", "/index.html", "/login.js", "/app.js", "/config.ini"} {
		res, err := c.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 404 {
			t.Errorf("非 /sdwl 路径 %q 应返回 404，实际 %d", p, res.StatusCode)
		}
	}
}

func TestAttackSecurityHeaders(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	_, _, hdr := secRaw(t, secNoJar(), base, "GET", "/api/public/config", nil, nil)
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := hdr.Get(k); got != want {
			t.Errorf("响应头 %s = %q，期望 %q", k, got, want)
		}
	}
	if csp := hdr.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP 异常: %q", csp)
	}
}

// ---------- F. 限流与资源 ----------

func TestAttackRateLimitSMS(t *testing.T) {
	cfg := secBaseCfg(t)
	cfg.APIRateLimit = 2
	base, closeFn := secServerWithCfg(t, cfg)
	defer closeFn()
	c := testClient(t)
	r := secRegister(t, c, base)
	token, _ := dataOf(t, r)["token"].(string)
	call(t, c, base, "POST", "/api/devices", map[string]any{"id": "rl-dev", "name": "x"}, 200)
	for i := 1; i <= 2; i++ {
		call(t, c, base, "POST", "/api/sms/receive", map[string]any{
			"token": token, "id": "rl-dev", "text": "x",
		}, 200)
	}
	call(t, c, base, "POST", "/api/sms/receive", map[string]any{
		"token": token, "id": "rl-dev", "text": "x",
	}, 429)
}

func TestAttackOversizedBody(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := secNoJar()
	big := map[string]any{
		"username": attackUsername, "password": attackPassword,
		"auth_code": authCode(attackUsername, attackPassword),
		"padding":   strings.Repeat("A", 2<<20),
	}
	body, _ := json.Marshal(big)
	code, _, _ := secRaw(t, c, base, "POST", "/api/auth/register", body, nil)
	if code != 400 {
		t.Errorf("超大请求体应被拒绝，实际 %d", code)
	}
}

func TestAttackPlaintextAtRest(t *testing.T) {
	base, dataDir, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	secRegister(t, c, base)
	call(t, c, base, "POST", "/api/devices", map[string]any{"id": "atrest-dev", "name": "secret-device-name"}, 200)
	meta, _ := os.ReadFile(filepath.Join(dataDir, "meta.json"))
	for _, s := range []string{attackUsername, attackPassword, "secret-device-name"} {
		if bytes.Contains(meta, []byte(s)) {
			t.Errorf("meta.json 中出现明文: %q", s)
		}
	}
}
