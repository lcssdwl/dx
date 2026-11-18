package app

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func testServer(t *testing.T) (string, string, *Server, func()) {
	t.Helper()
	cfg := Config{
		DataDir:            t.TempDir(),
		SessionTTL:         time.Hour,
		APIRateLimit:       1000,
		AuthRateLimit:      1000,
		MaxBodyBytes:       1 << 20,
		LoginMaxFail:       5,
		LoginLockMin:       15,
		MailEnabled:        true,
		MailDebug:          true,
		RegisterAuthSecret: DefaultRegisterAuthSecret,
	}
	store, err := NewStore(cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	web := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}}
	s := newServer(cfg, store, fs.FS(web))
	srv := httptest.NewServer(s.handler())
	return srv.URL, cfg.DataDir, s, srv.Close
}

func testClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func call(t *testing.T, c *http.Client, base, method, path string, body any, want int, headers ...map[string]string) map[string]any {
	t.Helper()
	if strings.HasPrefix(path, "/api/") {
		path = "/sdwl" + path
	}
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, base+path, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, h := range headers {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("%s %s 解析响应失败: %v", method, path, err)
	}
	if res.StatusCode != want {
		t.Fatalf("%s %s 期望状态码 %d，实际 %d：%v", method, path, want, res.StatusCode, out)
	}
	return out
}

func dataOf(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	d, ok := resp["data"].(map[string]any)
	if !ok {
		t.Fatalf("data 字段类型异常: %#v", resp["data"])
	}
	return d
}

func authCode(username, password string) string {
	sum := md5.Sum([]byte(username + password + DefaultRegisterAuthSecret))
	return hex.EncodeToString(sum[:])
}

func registerOK(t *testing.T, c *http.Client, base, username, password string) map[string]any {
	t.Helper()
	return call(t, c, base, "POST", "/api/auth/register", map[string]any{
		"username": username, "password": password, "auth_code": authCode(username, password),
	}, 200)
}

func TestEncryptDecrypt(t *testing.T) {
	token, _ := randomID()
	nonce, ct, err := encryptText(token, "您好，验证码 888888")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decryptText(token, nonce, ct)
	if err != nil || plain != "您好，验证码 888888" {
		t.Fatalf("解密结果异常: %q, %v", plain, err)
	}
	other, _ := randomID()
	if _, err := decryptText(other, nonce, ct); err == nil {
		t.Fatal("错误 token 本应无法解密")
	}
}

func TestFullFlow(t *testing.T) {
	base, dataDir, _, closeFn := testServer(t)
	defer closeFn()
	c1 := testClient(t)
	c2 := testClient(t)

	// 注册：自动生成 token
	r1 := registerOK(t, c1, base, "alice", "secret123")
	token1, _ := dataOf(t, r1)["token"].(string)
	if len(token1) < 32 {
		t.Fatalf("token 异常: %q", token1)
	}
	r2 := registerOK(t, c2, base, "bob", "secret123")
	token2, _ := dataOf(t, r2)["token"].(string)

	// 设备 ID 全局唯一
	call(t, c1, base, "POST", "/api/devices", map[string]any{"id": "dev-1", "name": "主手机"}, 200)
	call(t, c2, base, "POST", "/api/devices", map[string]any{"id": "dev-1", "name": "抢占"}, 409)
	call(t, c2, base, "POST", "/api/devices", map[string]any{"id": "dev-2", "name": "备用机"}, 200)

	// 正常上报
	call(t, c1, base, "POST", "/api/sms/receive", map[string]any{
		"token": token1, "id": "dev-1", "text": "验证码 123456", "from": "+8613800000000",
	}, 200)

	// 设备不存在 / 越权 / token 无效
	call(t, c1, base, "POST", "/api/sms/receive", map[string]any{"token": token1, "id": "no-such-device", "text": "x"}, 404)
	call(t, c1, base, "POST", "/api/sms/receive", map[string]any{"token": token1, "id": "dev-2", "text": "x"}, 404)
	call(t, c1, base, "POST", "/api/sms/receive", map[string]any{"token": "wrong-token", "id": "dev-1", "text": "x"}, 401)

	// 查看短信：明文正确
	list := call(t, c1, base, "GET", "/api/devices/dev-1/messages?page=1&size=20", nil, 200)
	items, _ := list["data"].(map[string]any)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("短信数量异常: %#v", list)
	}
	item := items[0].(map[string]any)
	if item["text"] != "验证码 123456" || item["sender"] != "+8613800000000" {
		t.Fatalf("短信明文异常: %#v", item)
	}

	// 越权查看他人设备
	call(t, c2, base, "GET", "/api/devices/dev-1/messages", nil, 404)

	// 校验明文没有落盘
	raw, err := os.ReadFile(filepath.Join(dataDir, "messages", fieldIndex("dev-1")+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "验证码 123456") {
		t.Fatal("磁盘中出现了短信明文")
	}

	// 重新登录并查看 token
	call(t, c1, base, "POST", "/api/auth/logout", nil, 200)
	call(t, c1, base, "POST", "/api/auth/login", map[string]any{"username": "alice", "password": "secret123"}, 200)
	tk := call(t, c1, base, "GET", "/api/token", nil, 200)
	if dataOf(t, tk)["token"] != token1 {
		t.Fatal("登录后 token 不一致")
	}

	// 删除设备后，该设备不再能接收短信
	call(t, c1, base, "DELETE", "/api/devices/dev-1", nil, 200)
	call(t, c1, base, "POST", "/api/sms/receive", map[string]any{"token": token1, "id": "dev-1", "text": "x"}, 404)
	_ = token2
}

func TestAccountSecurityFlow(t *testing.T) {
	base, _, s, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)

	r := registerOK(t, c, base, "carol", "secret123")
	userID := dataOf(t, r)["id"].(string)

	// 不允许修改用户名
	call(t, c, base, "POST", "/api/account/username", map[string]any{"new_username": "carolx"}, 404)

	call(t, c, base, "POST", "/api/auth/logout", nil, 200)
	call(t, c, base, "POST", "/api/auth/login", map[string]any{"username": "carol", "password": "secret123"}, 200)

	// 修改密码
	call(t, c, base, "POST", "/api/account/password", map[string]any{"old_password": "secret123", "new_password": "newsecret456"}, 200)
	call(t, c, base, "POST", "/api/auth/logout", nil, 200)
	call(t, c, base, "POST", "/api/auth/login", map[string]any{"username": "carol", "password": "wrong"}, 401)
	need := call(t, c, base, "POST", "/api/auth/login", map[string]any{"username": "carol", "password": "newsecret456"}, 400)
	if need["code"] != "NEED_CAPTCHA" {
		t.Fatalf("失败后应要求图形验证码: %#v", need)
	}
	cap := call(t, c, base, "GET", "/api/auth/captcha", nil, 200)
	cid := dataOf(t, cap)["id"].(string)
	if img, _ := dataOf(t, cap)["image"].(string); !strings.HasPrefix(img, "data:image/png;base64,") {
		t.Fatalf("验证码图片格式异常: %q", img)
	}
	s.stateMu.Lock()
	ct := s.captchas[cid].Text
	s.stateMu.Unlock()
	call(t, c, base, "POST", "/api/auth/login", map[string]any{
		"username": "carol", "password": "newsecret456", "captcha_id": cid, "captcha_text": ct,
	}, 200)

	// 绑定邮箱
	email := "carol@example.com"
	call(t, c, base, "POST", "/api/account/email/code", map[string]any{"email": email}, 200)
	bindKey := "bind:" + userID + ":" + email
	s.stateMu.Lock()
	bindCode := s.mailCodes[bindKey].Code
	s.stateMu.Unlock()
	call(t, c, base, "POST", "/api/account/email", map[string]any{"email": email, "code": bindCode}, 200)

	// 找回密码
	call(t, c, base, "POST", "/api/auth/logout", nil, 200)
	call(t, c, base, "POST", "/api/auth/forgot-password", map[string]any{"email": email}, 200)
	s.stateMu.Lock()
	resetCode := s.mailCodes["reset:"+email].Code
	s.stateMu.Unlock()
	call(t, c, base, "POST", "/api/auth/reset-password", map[string]any{
		"email": email, "code": resetCode, "new_password": "resetpass789",
	}, 200)
	call(t, c, base, "POST", "/api/auth/login", map[string]any{"username": "carol", "password": "resetpass789"}, 200)

	// 连续失败锁定 IP（而非账号）
	c2 := testClient(t)
	registerOK(t, c2, base, "dave", "secret123")
	call(t, c2, base, "POST", "/api/auth/logout", nil, 200)
	call(t, c2, base, "POST", "/api/auth/login", map[string]any{"username": "dave", "password": "wrong"}, 401)
	for i := 0; i < 4; i++ {
		cap := call(t, c2, base, "GET", "/api/auth/captcha", nil, 200)
		cid := dataOf(t, cap)["id"].(string)
		s.stateMu.Lock()
		ct := s.captchas[cid].Text
		s.stateMu.Unlock()
		call(t, c2, base, "POST", "/api/auth/login", map[string]any{
			"username": "dave", "password": "wrong", "captcha_id": cid, "captcha_text": ct,
		}, 401)
	}
	cap = call(t, c2, base, "GET", "/api/auth/captcha", nil, 200)
	cid = dataOf(t, cap)["id"].(string)
	s.stateMu.Lock()
	ct = s.captchas[cid].Text
	s.stateMu.Unlock()
	locked := call(t, c2, base, "POST", "/api/auth/login", map[string]any{
		"username": "dave", "password": "secret123", "captcha_id": cid, "captcha_text": ct,
	}, http.StatusLocked)
	if locked["code"] != "IP_LOCKED" {
		t.Fatalf("应返回 IP 锁定: %#v", locked)
	}
}

func TestLoginLockByIPNotAccount(t *testing.T) {
	cfg := Config{
		DataDir:            t.TempDir(),
		SessionTTL:         time.Hour,
		APIRateLimit:       1000,
		AuthRateLimit:      1000,
		MaxBodyBytes:       1 << 20,
		LoginMaxFail:       5,
		LoginLockMin:       15,
		TrustedProxy:       true,
		RegisterAuthSecret: DefaultRegisterAuthSecret,
	}
	store, err := NewStore(cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(cfg, store, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}})
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	base := srv.URL

	c := testClient(t)
	registerOK(t, c, base, "grace", "secret123")

	h1 := map[string]string{"X-Forwarded-For": "10.0.0.1"}
	// 从 IP1 连续失败 5 次
	call(t, c, base, "POST", "/api/auth/logout", nil, 200, h1)
	for i := 0; i < 5; i++ {
		cap := call(t, c, base, "GET", "/api/auth/captcha", nil, 200, h1)
		cid := dataOf(t, cap)["id"].(string)
		s.stateMu.Lock()
		ct := s.captchas[cid].Text
		s.stateMu.Unlock()
		call(t, c, base, "POST", "/api/auth/login", map[string]any{
			"username": "grace", "password": "wrong", "captcha_id": cid, "captcha_text": ct,
		}, 401, h1)
	}
	// IP1 被锁定
	cap := call(t, c, base, "GET", "/api/auth/captcha", nil, 200, h1)
	cid := dataOf(t, cap)["id"].(string)
	s.stateMu.Lock()
	ct := s.captchas[cid].Text
	s.stateMu.Unlock()
	locked := call(t, c, base, "POST", "/api/auth/login", map[string]any{
		"username": "grace", "password": "secret123", "captcha_id": cid, "captcha_text": ct,
	}, http.StatusLocked, h1)
	if locked["code"] != "IP_LOCKED" {
		t.Fatalf("IP1 应被锁定: %#v", locked)
	}

	// 换 IP2，同一账号仍可正常登录（证明锁的是 IP 不是账号）
	h2 := map[string]string{"X-Forwarded-For": "10.0.0.2"}
	call(t, c, base, "POST", "/api/auth/login", map[string]any{
		"username": "grace", "password": "secret123",
	}, 200, h2)
}

func TestHeartbeat(t *testing.T) {
	base, _, s, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)

	r := registerOK(t, c, base, "eve", "secret123")
	token := dataOf(t, r)["token"].(string)
	call(t, c, base, "POST", "/api/devices", map[string]any{"id": "hb-1", "name": "心跳设备"}, 200)

	call(t, c, base, "POST", "/api/device/heartbeat", map[string]any{"token": token, "id": "hb-1"}, 200)
	list := call(t, c, base, "GET", "/api/devices", nil, 200)
	d := dataOf(t, list)["items"].([]any)[0].(map[string]any)
	if d["online"] != true {
		t.Fatalf("心跳后应在线: %#v", d)
	}

	// 把心跳改为 30 秒前，应判定离线
	s.stateMu.Lock()
	s.heartbeats["hb-1"] = time.Now().Add(-30 * time.Second)
	s.stateMu.Unlock()
	list = call(t, c, base, "GET", "/api/devices", nil, 200)
	d = dataOf(t, list)["items"].([]any)[0].(map[string]any)
	if d["online"] != false {
		t.Fatalf("30 秒无心跳应离线: %#v", d)
	}

	call(t, c, base, "POST", "/api/device/heartbeat", map[string]any{"token": "bad", "id": "hb-1"}, 401)
	call(t, c, base, "POST", "/api/device/heartbeat", map[string]any{"token": token, "id": "nope"}, 404)
}

func TestGETApis(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)

	r := registerOK(t, c, base, "frank", "secret123")
	token := dataOf(t, r)["token"].(string)
	call(t, c, base, "POST", "/api/devices", map[string]any{"id": "get-1", "name": "GET设备"}, 200)

	q := url.Values{}
	q.Set("token", token)
	q.Set("id", "get-1")
	q.Set("text", "验证码 654321")
	q.Set("from", "+8613900000000")
	call(t, c, base, "GET", "/api/sms/receive?"+q.Encode(), nil, 200)

	list := call(t, c, base, "GET", "/api/devices/get-1/messages", nil, 200)
	items := dataOf(t, list)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["text"] != "验证码 654321" {
		t.Fatalf("GET 上报短信异常: %#v", list)
	}

	gq := url.Values{}
	gq.Set("token", token)
	gq.Set("id", "get-1")
	call(t, c, base, "GET", "/api/device/heartbeat?"+gq.Encode(), nil, 200)
	dlist := call(t, c, base, "GET", "/api/devices", nil, 200)
	d := dataOf(t, dlist)["items"].([]any)[0].(map[string]any)
	if d["online"] != true {
		t.Fatalf("GET 心跳后应在线: %#v", d)
	}

	call(t, c, base, "GET", "/api/sms/receive?token="+token, nil, 400)
	call(t, c, base, "GET", "/api/device/heartbeat?token="+token, nil, 400)
}

func TestMailDisabled(t *testing.T) {
	cfg := Config{
		DataDir: t.TempDir(), SessionTTL: time.Hour,
		APIRateLimit: 1000, AuthRateLimit: 1000, MaxBodyBytes: 1 << 20,
		LoginMaxFail: 5, LoginLockMin: 15, MailEnabled: false,
		RegisterAuthSecret: DefaultRegisterAuthSecret,
	}
	store, err := NewStore(cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	web := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}}
	s := newServer(cfg, store, fs.FS(web))
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	c := testClient(t)

	pub := call(t, c, srv.URL, "GET", "/api/public/config", nil, 200)
	if dataOf(t, pub)["mail_enabled"] != false {
		t.Fatalf("邮件功能应为未启用: %#v", pub)
	}
	call(t, c, srv.URL, "POST", "/api/auth/forgot-password", map[string]any{"email": "a@b.com"}, 403)
	call(t, c, srv.URL, "POST", "/api/auth/reset-password", map[string]any{
		"email": "a@b.com", "code": "123456", "new_password": "abcdef123",
	}, 403)

	registerOK(t, c, srv.URL, "grace", "secret123")
	forgot := call(t, c, srv.URL, "POST", "/api/auth/forgot-password", map[string]any{"email": "a@b.com"}, 403)
	if forgot["code"] != "MAIL_NOT_CONFIGURED" {
		t.Fatalf("应返回 MAIL_NOT_CONFIGURED: %#v", forgot)
	}
	call(t, c, srv.URL, "POST", "/api/account/email/code", map[string]any{"email": "a@b.com"}, 403)
	call(t, c, srv.URL, "POST", "/api/account/email", map[string]any{"email": "a@b.com", "code": "123456"}, 403)
}

func TestINIConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	content := "[smtp]\nhost = smtp.example.com\nport = 465\nuser = me@example.com\npass = p@ss#word\nfrom = me@example.com\ntls = implicit\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, enabled, err := loadSMTPConfig(path)
	if err != nil || !enabled {
		t.Fatalf("应解析并启用邮件功能: %#v %v", cfg, err)
	}
	if cfg.Host != "smtp.example.com" || cfg.Port != "465" || cfg.Pass != "p@ss#word" || cfg.TLS != "implicit" {
		t.Fatalf("INI 解析结果异常: %#v", cfg)
	}

	if _, enabled, err := loadSMTPConfig(filepath.Join(dir, "none.ini")); err != nil || enabled {
		t.Fatalf("文件不存在应禁用邮件功能: %v", err)
	}
	emptyPath := filepath.Join(dir, "empty.ini")
	if err := os.WriteFile(emptyPath, []byte("[other]\nx=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, enabled, err := loadSMTPConfig(emptyPath); err != nil || enabled {
		t.Fatalf("无 smtp 节应禁用邮件功能: %v", err)
	}
}

func TestSMSParse(t *testing.T) {
	text := "19999999999\n【测试通道】恭喜您，该发送通道测试成功，请继续添加转发规则！\nSIM1_测试运营商_18888888888\nSubId：0\n2026-11-17 02:24:18"
	p := parseSMS(text)
	if p.Sender != "19999999999" || p.Body != "【测试通道】恭喜您，该发送通道测试成功，请继续添加转发规则！" {
		t.Fatalf("发件人或正文解析异常: %#v", p)
	}
	if p.SIM != "SIM1" || p.Carrier != "测试运营商" || p.SIMNumber != "18888888888" || p.SubID != "0" || p.SMSTime != "2026-11-17 02:24:18" {
		t.Fatalf("SIM/SubId/时间解析异常: %#v", p)
	}
	if p.Raw != text {
		t.Fatal("原始文本未保留")
	}

	plain := "普通短信内容"
	q := parseSMS(plain)
	if q.Body != plain || q.Sender != "" {
		t.Fatalf("非标准格式应回退为纯文本: %#v", q)
	}
	if old := decodeSMSPayload(plain); old.Body != plain {
		t.Fatalf("旧版纯文本数据兼容失败: %#v", old)
	}
}

func TestStructuredSMSFlow(t *testing.T) {
	base, dataDir, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	r := registerOK(t, c, base, "heidi", "secret123")
	token := dataOf(t, r)["token"].(string)
	call(t, c, base, "POST", "/api/devices", map[string]any{"id": "sms-1", "name": "测试设备"}, 200)

	text := "19999999999\n【测试通道】恭喜您，该发送通道测试成功，请继续添加转发规则！\nSIM1_测试运营商_18888888888\nSubId：0\n2026-11-17 02:24:18"
	call(t, c, base, "POST", "/api/sms/receive", map[string]any{"token": token, "id": "sms-1", "text": text}, 200)

	list := call(t, c, base, "GET", "/api/devices/sms-1/messages", nil, 200)
	items := dataOf(t, list)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("短信数量异常: %#v", list)
	}
	m := items[0].(map[string]any)
	want := map[string]string{
		"sender":     "19999999999",
		"body":       "【测试通道】恭喜您，该发送通道测试成功，请继续添加转发规则！",
		"sim":        "SIM1",
		"carrier":    "测试运营商",
		"sim_number": "18888888888",
		"sub_id":     "0",
		"sms_time":   "2026-11-17 02:24:18",
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("字段 %s 期望 %q，实际 %#v", k, v, m[k])
		}
	}

	raw, err := os.ReadFile(filepath.Join(dataDir, "messages", fieldIndex("sms-1")+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "恭喜您") || strings.Contains(string(raw), "19999999999") {
		t.Fatal("磁盘中出现短信明文")
	}
}

func TestRegisterAuthCode(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)

	bad := call(t, c, base, "POST", "/api/auth/register", map[string]any{
		"username": "ivan", "password": "secret123", "auth_code": "00000000000000000000000000000000",
	}, 403)
	if bad["code"] != "INVALID_AUTH_CODE" {
		t.Fatalf("应返回 INVALID_AUTH_CODE: %#v", bad)
	}

	// 授权码大小写不敏感
	r := call(t, c, base, "POST", "/api/auth/register", map[string]any{
		"username": "ivan", "password": "secret123",
		"auth_code": strings.ToUpper(authCode("ivan", "secret123")),
	}, 200)
	if dataOf(t, r)["token"] == "" {
		t.Fatal("正确授权码应注册成功")
	}

	call(t, c, base, "POST", "/api/auth/register", map[string]any{
		"username": "ivan", "password": "secret123", "auth_code": authCode("ivan", "secret123"),
	}, 409)
}

func TestAuthSecretConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(path, []byte("[auth]\nsecret = custom-key-123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DX_CONFIG", path)
	if cfg := LoadConfig(); cfg.RegisterAuthSecret != DefaultRegisterAuthSecret+"custom-key-123" {
		t.Fatalf("应从 config.ini 拼接密钥: %q", cfg.RegisterAuthSecret)
	}

	if err := os.WriteFile(path, []byte("[smtp]\nhost = smtp.example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if cfg := LoadConfig(); cfg.RegisterAuthSecret != DefaultRegisterAuthSecret {
		t.Fatalf("无 [auth] 节应使用默认密钥: %q", cfg.RegisterAuthSecret)
	}
}

func TestAppKeyAppendFromConfig(t *testing.T) {
	original := appKey
	defer func() { appKey = original }()

	// 无 [security] 节：appKey = sha256(基值)
	setAppKey("")
	base := sha256.Sum256([]byte("sdwl88"))
	if !bytes.Equal(appKey, base[:]) {
		t.Fatal("未配置时 appKey 应为 sha256(内置基值)")
	}

	// config.ini 配置 appKey：应拼接在基值之后，而非替换
	path := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(path, []byte("[security]\nappKey = extra-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DX_CONFIG", path)
	LoadConfig()
	appended := sha256.Sum256([]byte("sdwl88extra-secret"))
	if !bytes.Equal(appKey, appended[:]) {
		t.Fatal("配置 appKey 后应为 sha256(基值 + 追加串)")
	}

	// 追加串留空：回到仅基值
	if err := os.WriteFile(path, []byte("[security]\nappKey =\n"), 0600); err != nil {
		t.Fatal(err)
	}
	LoadConfig()
	if !bytes.Equal(appKey, base[:]) {
		t.Fatal("追加串留空时应回到 sha256(内置基值)")
	}
}

func TestCustomAuthSecretRegister(t *testing.T) {
	base, _, s, closeFn := testServer(t)
	defer closeFn()
	s.cfg.RegisterAuthSecret = "custom-secret"
	c := testClient(t)

	// 默认密钥算出的授权码应被拒绝
	call(t, c, base, "POST", "/api/auth/register", map[string]any{
		"username": "judy", "password": "secret123", "auth_code": authCode("judy", "secret123"),
	}, 403)

	// 配置密钥算出的授权码应通过
	sum := md5.Sum([]byte("judy" + "secret123" + "custom-secret"))
	code := hex.EncodeToString(sum[:])
	call(t, c, base, "POST", "/api/auth/register", map[string]any{
		"username": "judy", "password": "secret123", "auth_code": code,
	}, 200)
}

func TestTokenNotStoredPlain(t *testing.T) {
	base, dataDir, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	r := registerOK(t, c, base, "ken", "secret123")
	token := dataOf(t, r)["token"].(string)

	raw, err := os.ReadFile(filepath.Join(dataDir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) {
		t.Fatal("meta.json 中出现明文 token")
	}
	if !strings.Contains(string(raw), "token_hash") || !strings.Contains(string(raw), "token_enc") {
		t.Fatalf("meta.json 缺少 token 哈希或密文字段: %s", raw)
	}

	got := call(t, c, base, "GET", "/api/token", nil, 200)
	if dataOf(t, got)["token"] != token {
		t.Fatal("查看 Token 接口未能还原 token")
	}
}

func TestLegacyTokenMigration(t *testing.T) {
	dir := t.TempDir()
	oldToken := "HZaytRcVTahcZ7cDvCaHpA3Sxg1rRIKGbXcDyBSxzoE"
	oldMeta, err := json.Marshal(map[string]any{
		"users": []any{map[string]any{
			"id": "u1", "username": "admin", "password_hash": "x", "salt": "y",
			"token": oldToken, "email": "", "created_at": "2026-11-16T18:05:37Z",
		}},
		"devices": []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), oldMeta, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "messages"), 0700); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	u := store.GetUserByToken(oldToken)
	if u == nil {
		t.Fatal("迁移后旧 token 应仍能鉴权")
	}
	plain, err := store.DecryptToken(u)
	if err != nil || plain != oldToken {
		t.Fatalf("迁移后 token 还原失败: %q %v", plain, err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), oldToken) {
		t.Fatal("迁移后 meta.json 仍含明文 token")
	}
	if !strings.Contains(string(raw), "token_hash") || !strings.Contains(string(raw), "token_enc") {
		t.Fatalf("迁移后缺少哈希/密文字段: %s", raw)
	}
	if strings.Contains(string(raw), "password_hash") || strings.Contains(string(raw), "\"salt\"") {
		t.Fatalf("迁移后仍含明文凭证字段: %s", raw)
	}
	if !strings.Contains(string(raw), "cred_enc") {
		t.Fatalf("迁移后缺少加密凭证字段: %s", raw)
	}
	if strings.Contains(string(raw), `"username"`) || strings.Contains(string(raw), `"username":"admin"`) {
		t.Fatalf("迁移后仍含明文字段名或用户名: %s", raw)
	}
	if !strings.Contains(string(raw), "username_enc") || !strings.Contains(string(raw), "username_hash") {
		t.Fatalf("迁移后缺少用户名密文/索引字段: %s", raw)
	}
}

func TestIdentityFieldsEncryptedAtRest(t *testing.T) {
	base, dataDir, s, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)

	r := registerOK(t, c, base, "rachel", "secret123")
	userID := dataOf(t, r)["id"].(string)
	call(t, c, base, "POST", "/api/account/email/code", map[string]any{"email": "rachel@example.com"}, 200)
	s.stateMu.Lock()
	bindCode := s.mailCodes["bind:"+userID+":rachel@example.com"].Code
	s.stateMu.Unlock()
	call(t, c, base, "POST", "/api/account/email", map[string]any{"email": "rachel@example.com", "code": bindCode}, 200)
	call(t, c, base, "POST", "/api/devices", map[string]any{"id": "secret-dev-01", "name": "我的备用机"}, 200)
	token, _ := dataOf(t, call(t, c, base, "GET", "/api/token", nil, 200))["token"].(string)
	call(t, c, base, "POST", "/api/sms/receive", map[string]any{
		"token": token, "id": "secret-dev-01", "text": "测试短信明文检查", "from": "+8613900001234",
	}, 200)

	raw, err := os.ReadFile(filepath.Join(dataDir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	metaText := string(raw)
	for _, plain := range []string{"rachel", "rachel@example.com", "secret-dev-01", "我的备用机"} {
		if strings.Contains(metaText, plain) {
			t.Fatalf("meta.json 出现明文 %q: %s", plain, metaText)
		}
	}
	for _, field := range []string{"username_enc", "username_hash", "email_enc", "email_hash", "id_enc", "id_hash", "name_enc"} {
		if !strings.Contains(metaText, field) {
			t.Fatalf("meta.json 缺少字段 %s: %s", field, metaText)
		}
	}

	// 消息文件名也不得出现明文设备 ID
	entries, err := os.ReadDir(filepath.Join(dataDir, "messages"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "secret-dev-01") {
			t.Fatalf("消息文件名泄露设备 ID: %s", e.Name())
		}
		content, err := os.ReadFile(filepath.Join(dataDir, "messages", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), "secret-dev-01") {
			t.Fatalf("消息文件内容泄露设备 ID: %s", e.Name())
		}
		if strings.Contains(string(content), "+8613900001234") {
			t.Fatalf("消息文件内容泄露发送方号码: %s", e.Name())
		}
		if !strings.Contains(string(content), "sender_enc") {
			t.Fatalf("消息文件缺少 sender_enc: %s", e.Name())
		}
	}

	// 解密后发送方号码仍正确返回给后台
	list := call(t, c, base, "GET", "/api/devices/secret-dev-01/messages", nil, 200)
	item := dataOf(t, list)["items"].([]any)[0].(map[string]any)
	if item["sender"] != "+8613900001234" {
		t.Fatalf("发送方号码解密异常: %#v", item)
	}

	// 查找功能仍正常
	call(t, c, base, "GET", "/api/devices", nil, 200)
	call(t, c, base, "POST", "/api/auth/logout", nil, 200)
	call(t, c, base, "POST", "/api/auth/forgot-password", map[string]any{"email": "rachel@example.com"}, 200)
}

func TestPasswordHashNotStoredPlain(t *testing.T) {
	base, dataDir, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	registerOK(t, c, base, "liam", "secret123")
	pwHash := "HpYNIFUKRer4EubzYzqrmLOCn/GCQu+idBGJC7yKG4I="

	raw, err := os.ReadFile(filepath.Join(dataDir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(s, "password_hash") || strings.Contains(s, "\"salt\"") || strings.Contains(s, pwHash) {
		t.Fatalf("meta.json 出现明文凭证字段: %s", s)
	}
	if !strings.Contains(s, "cred_enc") {
		t.Fatalf("meta.json 缺少 cred_enc: %s", s)
	}

	// 修改密码后仍不得出现明文凭证
	call(t, c, base, "POST", "/api/account/password", map[string]any{
		"old_password": "secret123", "new_password": "newsecret456",
	}, 200)
	raw, _ = os.ReadFile(filepath.Join(dataDir, "meta.json"))
	if strings.Contains(string(raw), "password_hash") || strings.Contains(string(raw), "\"salt\"") {
		t.Fatalf("改密后 meta.json 出现明文凭证: %s", raw)
	}
	call(t, c, base, "POST", "/api/auth/logout", nil, 200)
	call(t, c, base, "POST", "/api/auth/login", map[string]any{"username": "liam", "password": "newsecret456"}, 200)
}

func TestTamperedCredentialCannotLogin(t *testing.T) {
	base, dataDir, s, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	registerOK(t, c, base, "noah", "secret123")

	metaPath := filepath.Join(dataDir, "meta.json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Users []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			CredEnc  string `json:"cred_enc"`
		} `json:"users"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.Users) != 1 || meta.Users[0].CredEnc == "" {
		t.Fatalf("读取 cred_enc 失败: %s", raw)
	}

	// 场景一：直接篡改 cred_enc 的一个字符，重新加载后应无法登录。
	tampered := append([]byte(nil), raw...)
	idx := bytes.Index(tampered, []byte(meta.Users[0].CredEnc))
	if idx < 0 {
		t.Fatal("未在 meta.json 中找到 cred_enc")
	}
	enc := []byte(meta.Users[0].CredEnc)
	if enc[len(enc)/2] == 'A' {
		enc[len(enc)/2] = 'B'
	} else {
		enc[len(enc)/2] = 'A'
	}
	copy(tampered[idx:], enc)
	if err := os.WriteFile(metaPath, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	store2, err := NewStore(dataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if store2.Authenticate("noah", "secret123") != nil {
		t.Fatal("凭证被篡改后仍能登录")
	}

	// 场景二：把另一个用户的整段 cred_enc 复制过来，因身份绑定仍应失败。
	registerOK(t, c, base, "olivia", "secret123")
	raw, _ = os.ReadFile(metaPath)
	var meta2 struct {
		Users []struct {
			ID          string `json:"id"`
			UsernameEnc string `json:"username_enc"`
			CredEnc     string `json:"cred_enc"`
		} `json:"users"`
	}
	if err := json.Unmarshal(raw, &meta2); err != nil {
		t.Fatal(err)
	}
	var noahEnc, oliviaEnc string
	for _, u := range meta2.Users {
		name, err := decryptField("username", u.ID, u.UsernameEnc)
		if err != nil {
			t.Fatal(err)
		}
		if name == "noah" {
			noahEnc = u.CredEnc
		}
		if name == "olivia" {
			oliviaEnc = u.CredEnc
		}
	}
	if noahEnc == "" || oliviaEnc == "" {
		t.Fatalf("读取两个用户凭证失败: %s", raw)
	}
	swapped := bytes.Replace(raw, []byte(noahEnc), []byte(oliviaEnc), 1)
	if err := os.WriteFile(metaPath, swapped, 0600); err != nil {
		t.Fatal(err)
	}
	s.store, _ = NewStore(dataDir, nil)
	if s.store.Authenticate("noah", "secret123") != nil {
		t.Fatal("跨用户复制凭证后仍能登录")
	}
}

func TestEntryPath(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()

	c := testClient(t)
	// 隐藏入口：非 /sdwl 路径一律 404，包含根路径与旧 /api 路径。
	for _, p := range []string{"/", "/api/public/config", "/api/sms/receive", "/index.html", "/app.js"} {
		res, err := c.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 404 {
			t.Fatalf("%s 应返回 404，实际 %d", p, res.StatusCode)
		}
	}

	// /sdwl 跳转到 /sdwl/（Get 自动跟随，最终取到前端首页）
	res, err := c.Get(base + "/sdwl")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || res.Request.URL.Path != "/sdwl/" {
		t.Fatalf("/sdwl 应规范化为 /sdwl/：%d %s", res.StatusCode, res.Request.URL.Path)
	}

	// 带前缀的页面资源与 API 可用，且鉴权中间件仍生效
	registerOK(t, c, base, "peter", "secret123")
	call(t, c, base, "POST", "/sdwl/api/devices", map[string]any{"id": "entry-1", "name": "入口设备"}, 200)
	call(t, c, base, "GET", "/sdwl/api/public/config", nil, 200)
	noAuth := testClient(t)
	call(t, noAuth, base, "GET", "/sdwl/api/devices", nil, 401)
}

func TestForgotPasswordUserNotFound(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)

	// 未绑定邮箱也返回成功，避免通过响应差异枚举注册邮箱。
	res := call(t, c, base, "POST", "/api/auth/forgot-password", map[string]any{
		"email": "nobody@example.com",
	}, 200)
	if res["code"] != "OK" || dataOf(t, res)["sent"] != true {
		t.Fatalf("未绑定邮箱应返回统一的成功响应: %#v", res)
	}
}

func TestLegacyConfigKeyTokenMigration(t *testing.T) {
	dir := t.TempDir()
	oldToken := "legacy-token-abcdefghijklmnopqrstuvwxyz123456"
	legacyKey := bytes.Repeat([]byte("z"), 32)

	// 模拟旧版 meta.json：token_enc 由旧 config.ini 主密钥加密，无 cred_enc。
	oldEnc, err := aesGCMSeal(legacyKey, []byte(oldToken), nil)
	if err != nil {
		t.Fatal(err)
	}
	hash, salt, err := hashPassword("secret123")
	if err != nil {
		t.Fatal(err)
	}
	oldMeta, err := json.Marshal(map[string]any{
		"users": []any{map[string]any{
			"id": "u1", "username": "admin",
			"password_hash": hash, "salt": salt,
			"token_hash": tokenHash(oldToken), "token_enc": oldEnc,
			"created_at": "2026-11-16T18:05:37Z",
		}},
		"devices": []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), oldMeta, 0600); err != nil {
		t.Fatal(err)
	}

	// 无遗留密钥时解不开旧密文
	storeBad, err := NewStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	u := storeBad.GetUserByToken(oldToken)
	if u == nil {
		t.Fatal("token_hash 仍应可用于鉴权查找")
	}
	if _, err := storeBad.DecryptToken(u); err == nil {
		t.Fatal("无遗留密钥时不应解开旧密文")
	}

	// 提供遗留密钥后，启动即迁移为内置密钥密文
	store, err := NewStore(dir, legacyKey)
	if err != nil {
		t.Fatal(err)
	}
	u = store.GetUserByToken(oldToken)
	if u == nil {
		t.Fatal("迁移后 token 应仍可鉴权")
	}
	plain, err := store.DecryptToken(u)
	if err != nil || plain != oldToken {
		t.Fatalf("迁移后 token 还原失败: %q %v", plain, err)
	}
	// 迁移后内置密钥可直接解开，且不再依赖遗留密钥
	if _, err := decryptToken(u.TokenEnc); err != nil {
		t.Fatalf("token_enc 未迁移为内置密钥密文: %v", err)
	}
	if store.Authenticate("admin", "secret123") == nil {
		t.Fatal("迁移后应能正常登录")
	}

	raw, _ := os.ReadFile(filepath.Join(dir, "meta.json"))
	if strings.Contains(string(raw), oldToken) {
		t.Fatal("迁移后 meta.json 出现明文 token")
	}
}

func TestLegacySenderMigration(t *testing.T) {
	dir := t.TempDir()
	devID := "old-dev"
	msgDir := filepath.Join(dir, "messages")
	if err := os.MkdirAll(msgDir, 0700); err != nil {
		t.Fatal(err)
	}
	// 旧格式 meta.json（明文设备 ID/名称）与旧格式消息文件（明文 sender、明文文件名）。
	oldMeta, _ := json.Marshal(map[string]any{
		"users": []any{map[string]any{
			"id": "u1", "username": "admin", "password_hash": "x", "salt": "y",
			"token": "legacy-token-value-0123456789", "email": "", "created_at": "2026-11-16T18:05:37Z",
		}},
		"devices": []any{map[string]any{
			"id": devID, "user_id": "u1", "name": "旧设备", "created_at": "2026-11-16T18:05:37Z",
		}},
	})
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), oldMeta, 0600); err != nil {
		t.Fatal(err)
	}
	oldLine, _ := json.Marshal(map[string]any{
		"id": "m1", "device_id": devID, "sender": "+8613800009999",
		"nonce": "n", "ciphertext": "c", "created_at": "2026-11-16T18:05:37Z",
	})
	if err := os.WriteFile(filepath.Join(msgDir, devID+".jsonl"), append(oldLine, '\n'), 0600); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	msgs, _ := store.ListMessages(devID, 1, 10)
	if len(msgs) != 1 || msgs[0].Sender != "+8613800009999" {
		t.Fatalf("迁移后 sender 应保留: %#v", msgs)
	}

	// 旧明文文件应已迁移为哈希文件名，且内容无明文 sender
	if _, err := os.Stat(filepath.Join(msgDir, devID+".jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("旧明文消息文件应被重命名: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(msgDir, fieldIndex(devID)+".jsonl"))
	if strings.Contains(string(raw), "+8613800009999") || strings.Contains(string(raw), devID) {
		t.Fatalf("迁移后消息文件仍含明文: %s", raw)
	}
	if !strings.Contains(string(raw), "sender_enc") {
		t.Fatalf("迁移后消息文件缺少 sender_enc: %s", raw)
	}
}

func TestBuiltinMasterKeyNoConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.ini")
	t.Setenv("DX_CONFIG", path)
	_ = LoadConfig()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadConfig 不应创建配置文件: %v", err)
	}

	enc, err := encryptToken("builtin-token-check")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decryptToken(enc)
	if err != nil || plain != "builtin-token-check" {
		t.Fatalf("内置密钥加解密失败: %q %v", plain, err)
	}
}

// encCall 用 dx_session + dx_ck 派生的密钥发送整包密文请求，并解密响应。
func encCall(t *testing.T, c *http.Client, base, method, path string, body any, sid, ck string, want int) map[string]any {
	t.Helper()
	if strings.HasPrefix(path, "/api/") {
		path = "/sdwl" + path
	}
	key := envelopeKey(sid, ck)
	var raw []byte
	if body != nil {
		b, _ := json.Marshal(body)
		enc, err := sealEnvelope(key, b)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = json.Marshal(envelope{Payload: enc})
	}
	req, err := http.NewRequest(method, base+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: clientKeyCookie, Value: ck})
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	respRaw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(respRaw, &env); err != nil || env.Payload == "" {
		t.Fatalf("响应不是密文信封: %s (%v)", respRaw, err)
	}
	plain, err := openEnvelope(key, env.Payload)
	if err != nil {
		t.Fatalf("响应解密失败: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(plain, &out); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != want {
		t.Fatalf("%s %s 期望 %d 实际 %d: %v", method, path, want, res.StatusCode, out)
	}
	return out
}

func TestAPIEnvelopeEncryption(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	ck := "browser-random-key-abc"

	// 注册后响应返回 dx_session。
	r := call(t, c, base, "POST", "/api/auth/register", map[string]any{
		"username": "encryptuser", "password": "secret123",
		"auth_code": authCode("encryptuser", "secret123"),
	}, 200)
	sid, _ := dataOf(t, r)["dx_session"].(string)
	if sid == "" {
		t.Fatal("注册响应应返回 dx_session")
	}

	// 已绑定 key 的会话：GET /api/auth/me 响应为密文，解密后拿到用户名。
	me := encCall(t, c, base, "GET", "/api/auth/me", nil, sid, ck, 200)
	if dataOf(t, me)["username"] != "encryptuser" {
		t.Fatalf("解密后的 me 数据异常: %#v", me)
	}

	// 写接口：创建设备请求体也走密文。
	dev := encCall(t, c, base, "POST", "/api/devices", map[string]any{
		"id": "enc-dev-1", "name": "加密设备",
	}, sid, ck, 200)
	if dataOf(t, dev)["id_hash"] == "" || dataOf(t, dev)["user_id"] == "" {
		t.Fatalf("解密后的设备数据异常: %#v", dev)
	}

	// 带 dx_ck cookie 但发明文 body：应被拒绝。
	badReq, _ := http.NewRequest("POST", base+"/sdwl/api/devices",
		strings.NewReader(`{"id":"plain-dev"}`))
	badReq.Header.Set("Content-Type", "application/json")
	badReq.AddCookie(&http.Cookie{Name: clientKeyCookie, Value: ck})
	badRes, err := c.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	badBody, _ := io.ReadAll(badRes.Body)
	badRes.Body.Close()
	if badRes.StatusCode != http.StatusBadRequest || !strings.Contains(string(badBody), "BAD_REQUEST") {
		t.Fatalf("明文请求应被拒绝，实际 %d: %s", badRes.StatusCode, badBody)
	}

	// 取 Token（密文）用于明文短信上报。
	tokData := dataOf(t, encCall(t, c, base, "GET", "/api/token", nil, sid, ck, 200))
	token, _ := tokData["token"].(string)

	// 短信上报接口保持明文，不受加密中间件影响。
	cDev := testClient(t)
	call(t, cDev, base, "POST", "/api/sms/receive", map[string]any{
		"token": token, "id": "enc-dev-1", "text": "明文短信上行",
	}, 200)
}

// authEncCall 用 dx_ck 派生的认证密钥发送整包密文请求并解密响应。
func authEncCall(t *testing.T, c *http.Client, base, method, path string, body any, ck string, want int) map[string]any {
	t.Helper()
	if strings.HasPrefix(path, "/api/") {
		path = "/sdwl" + path
	}
	key := authEnvelopeKey(ck)
	var raw []byte
	if body != nil {
		b, _ := json.Marshal(body)
		enc, err := sealEnvelope(key, b)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = json.Marshal(envelope{Payload: enc})
	}
	req, err := http.NewRequest(method, base+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: clientKeyCookie, Value: ck})
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	respRaw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(respRaw, &env); err != nil || env.Payload == "" {
		t.Fatalf("响应不是密文信封: %s (%v)", respRaw, err)
	}
	plain, err := openEnvelope(key, env.Payload)
	if err != nil {
		t.Fatalf("响应解密失败: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(plain, &out); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != want {
		t.Fatalf("%s %s 期望 %d 实际 %d: %v", method, path, want, res.StatusCode, out)
	}
	return out
}

func TestAuthAPIEncrypted(t *testing.T) {
	base, _, _, closeFn := testServer(t)
	defer closeFn()
	c := testClient(t)
	ck := "login-page-random-key"

	// 注册：账号、密码、授权码均在密文里，响应也是密文。
	r := authEncCall(t, c, base, "POST", "/api/auth/register", map[string]any{
		"username": "secureuser", "password": "secret123",
		"auth_code": authCode("secureuser", "secret123"),
	}, ck, 200)
	if dataOf(t, r)["dx_session"] == "" {
		t.Fatal("注册响应应含 dx_session")
	}

	// 验证码：密文往返。
	cap := authEncCall(t, c, base, "GET", "/api/auth/captcha", nil, ck, 200)
	if dataOf(t, cap)["image"] == "" {
		t.Fatal("验证码响应异常")
	}

	// 带 dx_ck cookie 但发明文 body：应被拒绝。
	req, _ := http.NewRequest("POST", base+"/sdwl/api/auth/login",
		strings.NewReader(`{"username":"secureuser","password":"secret123"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: clientKeyCookie, Value: ck})
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("认证接口明文请求应被拒绝，实际 %d", res.StatusCode)
	}

	// 不带 dx_ck cookie 的明文请求保持兼容（脚本/curl）。
	call(t, testClient(t), base, "POST", "/api/auth/login", map[string]any{
		"username": "secureuser", "password": "secret123",
	}, 200)
}

func TestInjectedJSKey(t *testing.T) {
	cfg := Config{
		DataDir: t.TempDir(), SessionTTL: time.Hour,
		APIRateLimit: 1000, AuthRateLimit: 1000, MaxBodyBytes: 1 << 20,
		LoginMaxFail: 5, LoginLockMin: 15, RegisterAuthSecret: DefaultRegisterAuthSecret,
	}
	store, err := NewStore(cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	web := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("ok")},
		"login.js":   &fstest.MapFile{Data: []byte("console.log('login');")},
	}
	srv := httptest.NewServer(newServer(cfg, store, fs.FS(web)).handler())
	defer srv.Close()
	base := srv.URL

	// 两次请求 login.js 应拿到不同的注入 key 与 cookie。
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		res, err := http.Get(base + "/sdwl/login.js")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("login.js 状态 %d", res.StatusCode)
		}
		if got := res.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
			t.Fatalf("动态 JS 必须禁止缓存: %q", got)
		}
		var inj string
		for _, c := range res.Cookies() {
			if c.Name == clientKeyCookie {
				inj = c.Value
			}
		}
		if inj == "" || !strings.Contains(string(body), "window.__DX_CK__=\""+inj+"\"") {
			t.Fatalf("JS 注入的 key 与 cookie 不一致: body=%s cookie=%s", body, inj)
		}
		if seen[inj] {
			t.Fatalf("两次请求注入了相同的 key: %s", inj)
		}
		seen[inj] = true
	}
}

// TestBrowserLoginFlow 模拟真实浏览器：登录页拿 key→登录→后台页拿新 key→调 me。
func TestBrowserLoginFlow(t *testing.T) {
	cfg := Config{
		DataDir: t.TempDir(), SessionTTL: time.Hour,
		APIRateLimit: 1000, AuthRateLimit: 1000, MaxBodyBytes: 1 << 20,
		LoginMaxFail: 5, LoginLockMin: 15, RegisterAuthSecret: DefaultRegisterAuthSecret,
	}
	store, err := NewStore(cfg.DataDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	web := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("ok")},
		"login.js":   &fstest.MapFile{Data: []byte("// login")},
		"app.js":     &fstest.MapFile{Data: []byte("// app")},
	}
	srv := httptest.NewServer(newServer(cfg, store, fs.FS(web)).handler())
	defer srv.Close()
	base := srv.URL
	c := testClient(t) // 带 cookiejar，模拟浏览器自动保存/携带 cookie

	// 1) 访问 login.js：注入 keyA，cookie=keyA。
	keyA := fetchInjectedKey(t, c, base+"/sdwl/login.js")

	// 2) 用 keyA 加密注册（请求自动带 cookie=keyA）。
	regKey := authEnvelopeKey(keyA)
	regBody, _ := json.Marshal(map[string]any{
		"username": "flowuser", "password": "secret123",
		"auth_code": authCode("flowuser", "secret123"),
	})
	regEnc, _ := sealEnvelope(regKey, regBody)
	regRaw, _ := json.Marshal(envelope{Payload: regEnc})
	regRes, err := c.Post(base+"/sdwl/api/auth/register", "application/json", bytes.NewReader(regRaw))
	if err != nil {
		t.Fatal(err)
	}
	regRespRaw, _ := io.ReadAll(regRes.Body)
	regRes.Body.Close()
	var regEnv envelope
	if err := json.Unmarshal(regRespRaw, &regEnv); err != nil {
		t.Fatalf("注册响应非信封: %s", regRespRaw)
	}
	regPlain, err := openEnvelope(regKey, regEnv.Payload)
	if err != nil {
		t.Fatalf("注册响应解密失败（keyA 与 cookie 不匹配?）: %v", err)
	}
	var regOut map[string]any
	_ = json.Unmarshal(regPlain, &regOut)
	sid, _ := dataOf(t, regOut)["dx_session"].(string)
	if sid == "" {
		t.Fatalf("注册未返回 dx_session: %s", regPlain)
	}

	// 3) 跳后台，访问 app.js：注入 keyB 覆盖 cookie。
	keyB := fetchInjectedKey(t, c, base+"/sdwl/app.js")
	if keyB == keyA {
		t.Fatal("app.js 应注入新 key")
	}

	// 4) 用 keyB + dx_session 加密调 me（请求自动带 cookie: dx_session + dx_ck=keyB）。
	meKey := envelopeKey(sid, keyB)
	meReq, _ := http.NewRequest("GET", base+"/sdwl/api/auth/me", nil)
	meRes, err := c.Do(meReq)
	if err != nil {
		t.Fatal(err)
	}
	meRaw, _ := io.ReadAll(meRes.Body)
	meRes.Body.Close()
	var meEnv envelope
	if err := json.Unmarshal(meRaw, &meEnv); err != nil || meEnv.Payload == "" {
		t.Fatalf("me 响应非信封（可能未触发加密，cookie 丢失?）: %s (%v)", meRaw, err)
	}
	mePlain, err := openEnvelope(meKey, meEnv.Payload)
	if err != nil {
		t.Fatalf("me 响应解密失败（keyB+dx_session 与后端不一致?）: %v", err)
	}
	var meOut map[string]any
	_ = json.Unmarshal(mePlain, &meOut)
	if dataOf(t, meOut)["username"] != "flowuser" {
		t.Fatalf("me 数据异常: %s", mePlain)
	}
}

func fetchInjectedKey(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	res, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	for _, ck := range res.Cookies() {
		if ck.Name == clientKeyCookie {
			if !strings.Contains(string(body), "window.__DX_CK__=\""+ck.Value+"\"") {
				t.Fatalf("注入值与 cookie 不一致: %s", body)
			}
			return ck.Value
		}
	}
	t.Fatal("JS 响应未设置 dx_ck cookie")
	return ""
}
