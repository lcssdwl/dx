package app

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const sessionCookie = "dx_session"

type ctxKey int

const ctxUserKey ctxKey = 1

var (
	usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,32}$`)
	emailPattern    = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

func (s *Server) writeJSON(w http.ResponseWriter, status int, code, msg string, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiResp{Code: code, Message: msg, Data: data})
}

func (s *Server) ok(w http.ResponseWriter, data any) {
	s.writeJSON(w, http.StatusOK, "OK", "success", data)
}

func (s *Server) fail(w http.ResponseWriter, status int, code, msg string) {
	s.writeJSON(w, status, code, msg, nil)
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "请求体必须是合法 JSON: "+err.Error())
		return false
	}
	return true
}

// ---------- 会话辅助 ----------

func (s *Server) setSession(w http.ResponseWriter, userID string) string {
	id, err := randomID()
	if err != nil {
		return ""
	}
	now := time.Now()
	s.sessMu.Lock()
	for k, v := range s.sessions {
		if now.After(v.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = session{UserID: userID, ExpiresAt: now.Add(s.cfg.SessionTTL)}
	s.sessMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  now.Add(s.cfg.SessionTTL),
	})
	return id
}

func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessMu.Lock()
		delete(s.sessions, c.Value)
		s.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (s *Server) currentUser(r *http.Request) *User {
	u, _ := r.Context().Value(ctxUserKey).(*User)
	return u
}

func (s *Server) ownedDevice(r *http.Request, id string) (*Device, *User, bool) {
	u := s.currentUser(r)
	if u == nil {
		return nil, nil, false
	}
	d := s.store.GetDevice(id)
	if d == nil || d.UserID != u.ID {
		return nil, u, false
	}
	return d, u, true
}

func (s *Server) invalidateUserSessions(userID string) {
	s.sessMu.Lock()
	for k, v := range s.sessions {
		if v.UserID == userID {
			delete(s.sessions, k)
		}
	}
	s.sessMu.Unlock()
}

// verifyCaptchaLocked 在持有 stateMu 时校验并消费一次性验证码。
func (s *Server) verifyCaptchaLocked(id, text string) bool {
	e, ok := s.captchas[id]
	if !ok {
		return false
	}
	delete(s.captchas, id)
	if time.Now().After(e.ExpiresAt) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.ToUpper(strings.TrimSpace(text))), []byte(e.Text)) == 1
}

// mailGuard 在 config.ini 未配置发信邮箱时拒绝邮件相关接口。
func (s *Server) mailGuard(w http.ResponseWriter) bool {
	if !s.cfg.MailEnabled {
		s.fail(w, http.StatusForbidden, "MAIL_NOT_CONFIGURED", "邮件服务未配置，找回密码与邮箱绑定功能不可用")
		return false
	}
	return true
}

func validEmail(email string) bool {
	return len(email) <= 254 && emailPattern.MatchString(email)
}

func randomSixDigits() (string, error) {
	v, err := secureRandInt(1000000)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", v), nil
}

func (s *Server) markHeartbeat(deviceID string) {
	s.stateMu.Lock()
	s.heartbeats[deviceID] = time.Now()
	s.stateMu.Unlock()
}

func (s *Server) heartbeatTime(deviceID string) (time.Time, bool) {
	s.stateMu.Lock()
	t, ok := s.heartbeats[deviceID]
	s.stateMu.Unlock()
	return t, ok
}

// issueMailCode 生成邮箱验证码并发送；发送失败时撤回记录以便重试。
func (s *Server) issueMailCode(key, email, purpose, username string) error {
	now := time.Now()
	s.stateMu.Lock()
	mc := s.mailCodes[key]
	if mc != nil && now.Sub(mc.LastSent) < 60*time.Second {
		s.stateMu.Unlock()
		return errors.New("验证码发送过于频繁，请 60 秒后重试")
	}
	code, err := randomSixDigits()
	if err != nil {
		s.stateMu.Unlock()
		return err
	}
	s.mailCodes[key] = &mailCode{Code: code, ExpiresAt: now.Add(5 * time.Minute), LastSent: now}
	s.stateMu.Unlock()

	if err := sendMail(s.cfg, email, "验证码 - 云讯短信中心", mailVerificationBody(code, purpose, username)); err != nil {
		s.stateMu.Lock()
		delete(s.mailCodes, key)
		s.stateMu.Unlock()
		return err
	}
	return nil
}

// checkMailCode 校验并消费邮箱验证码，最多允许 5 次错误尝试。
func (s *Server) checkMailCode(key, code string) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	mc := s.mailCodes[key]
	if mc == nil || time.Now().After(mc.ExpiresAt) || mc.Attempts >= 5 {
		delete(s.mailCodes, key)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(code)), []byte(mc.Code)) != 1 {
		mc.Attempts++
		return false
	}
	delete(s.mailCodes, key)
	return true
}

// ---------- 公开接口：短信接收 ----------

// receiveSMS 是设备端上报短信的接口。
// 参数：token（用户唯一）、id（设备 ID）、text（明文短信）、from（可选发送方）。
// 明文仅存在于内存中，落盘前使用 token 派生的密钥做 AES-256-GCM 加密。
func (s *Server) receiveSMS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token  string `json:"token"`
		ID     string `json:"id"`
		Text   string `json:"text"`
		Sender string `json:"from"`
	}
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		req.Token = q.Get("token")
		req.ID = q.Get("id")
		req.Text = q.Get("text")
		req.Sender = q.Get("from")
	} else if !s.decodeJSON(w, r, &req) {
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	req.ID = strings.TrimSpace(req.ID)

	if req.Token == "" || req.ID == "" || req.Text == "" {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "token、id、text 为必填参数")
		return
	}
	if len(req.Text) > 8192 || len(req.Sender) > 64 {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "text 最长 8192 字节，from 最长 64 字节")
		return
	}
	if !s.apiLimiter.allow(req.Token) {
		s.fail(w, http.StatusTooManyRequests, "RATE_LIMITED", "请求过于频繁，请稍后再试")
		return
	}

	user := s.store.GetUserByToken(req.Token)
	if user == nil {
		s.fail(w, http.StatusUnauthorized, "INVALID_TOKEN", "token 无效")
		return
	}
	dev := s.store.GetDevice(req.ID)
	if dev == nil || dev.UserID != user.ID {
		// 无论设备不存在还是属于其他用户，均统一返回“设备不存在”，避免信息泄露。
		s.fail(w, http.StatusNotFound, "DEVICE_NOT_FOUND", "设备不存在")
		return
	}

	plain, err := encodeSMSPayload(req.Text)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "短信格式化失败")
		return
	}
	nonce, ciphertext, err := encryptText(req.Token, string(plain))
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "短信加密失败")
		return
	}
	m := Message{
		ID:         randomMustID(),
		DeviceID:   req.ID,
		Sender:     req.Sender,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.store.AddMessage(m); err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			s.fail(w, http.StatusNotFound, "DEVICE_NOT_FOUND", "设备不存在")
			return
		}
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "短信保存失败")
		return
	}
	// 上报短信也视为设备活跃，与独立心跳接口等效。
	s.markHeartbeat(req.ID)
	s.ok(w, map[string]any{"id": m.ID, "received_at": m.CreatedAt})
}

func randomMustID() string {
	id, err := randomID()
	if err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return id
}

// ---------- 后台认证接口 ----------

// validRegisterAuthCode 校验注册授权码：md5(用户名 + 密码 + 配置密钥)。
func validRegisterAuthCode(username, password, code, secret string) bool {
	sum := md5.Sum([]byte(username + password + secret))
	want := hex.EncodeToString(sum[:])
	got := strings.ToLower(strings.TrimSpace(code))
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		AuthCode string `json:"auth_code"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !usernamePattern.MatchString(req.Username) {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "用户名需为 3-32 位字母、数字或下划线")
		return
	}
	if len(req.Password) < 6 || len(req.Password) > 128 {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "密码长度需在 6-128 字节之间")
		return
	}
	if !validRegisterAuthCode(req.Username, req.Password, req.AuthCode, s.cfg.RegisterAuthSecret) {
		s.fail(w, http.StatusForbidden, "INVALID_AUTH_CODE", "授权码错误，注册被拒绝")
		return
	}
	u, err := s.store.CreateUser(req.Username, req.Password)
	if errors.Is(err, ErrUsernameExists) {
		s.fail(w, http.StatusConflict, "USERNAME_EXISTS", "用户名已存在")
		return
	}
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "注册失败")
		return
	}
	sid := s.setSession(w, u.ID)
	s.ok(w, map[string]any{"id": u.ID, "username": u.Username, "token": u.TokenPlain, "dx_session": sid})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		CaptchaID   string `json:"captcha_id"`
		CaptchaText string `json:"captcha_text"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" || req.Password == "" {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "请输入用户名和密码")
		return
	}
	now := time.Now()
	ip := s.clientIP(r)

	s.stateMu.Lock()
	fail := s.loginFails[ip]
	if fail != nil && fail.LockedUntil.After(now) {
		minutes := int(time.Until(fail.LockedUntil).Minutes()) + 1
		s.stateMu.Unlock()
		s.fail(w, http.StatusLocked, "IP_LOCKED", fmt.Sprintf("当前 IP 登录失败次数过多，已临时锁定，请 %d 分钟后再试", minutes))
		return
	}
	// 失败过后必须带图形验证码；验证码一次性且校验时不计入密码失败次数。
	if fail != nil && fail.Count > 0 && !s.verifyCaptchaLocked(req.CaptchaID, req.CaptchaText) {
		s.stateMu.Unlock()
		s.fail(w, http.StatusBadRequest, "NEED_CAPTCHA", "请输入图形验证码")
		return
	}
	s.stateMu.Unlock()

	u := s.store.Authenticate(username, req.Password)
	if u == nil {
		s.stateMu.Lock()
		// 重新取最新计数对象，避免并发失败请求互相覆盖导致锁定失效。
		fail = s.loginFails[ip]
		if fail == nil {
			fail = &loginFail{}
			s.loginFails[ip] = fail
		}
		fail.Count++
		if fail.Count >= s.cfg.LoginMaxFail {
			fail.LockedUntil = now.Add(time.Duration(s.cfg.LoginLockMin) * time.Minute)
		}
		s.stateMu.Unlock()
		s.fail(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "用户名或密码错误")
		return
	}
	s.stateMu.Lock()
	delete(s.loginFails, ip)
	s.stateMu.Unlock()
	sid := s.setSession(w, u.ID)
	s.ok(w, map[string]any{"id": u.ID, "username": u.Username, "dx_session": sid})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w, r)
	s.ok(w, nil)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	s.ok(w, map[string]any{"id": u.ID, "username": u.Username, "email": s.store.UserEmail(u.ID), "created_at": u.CreatedAt})
}

func (s *Server) getToken(w http.ResponseWriter, r *http.Request) {
	token, err := s.store.DecryptToken(s.currentUser(r))
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "读取 Token 失败")
		return
	}
	s.ok(w, map[string]any{"token": token})
}

// ---------- 设备管理 ----------

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	token, err := s.store.DecryptToken(u)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "读取密钥失败")
		return
	}
	items := s.store.ListDevices(u.ID)
	for i := range items {
		if hb, ok := s.heartbeatTime(items[i].ID); ok {
			if hb.After(items[i].LastSeen) {
				items[i].LastSeen = hb
			}
			items[i].Online = time.Since(hb) <= 20*time.Second
		}
		if m, ok := s.store.LastMessage(items[i].ID); ok {
			if text, err := decryptText(token, m.Nonce, m.Ciphertext); err == nil {
				items[i].Preview = decodeSMSPayload(text).Body
			}
		}
	}
	s.ok(w, map[string]any{"items": items})
}

func (s *Server) createDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Name = strings.TrimSpace(req.Name)
	if !validateDeviceID(req.ID) {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "设备 ID 只能包含字母、数字、下划线、点和连字符，且以字母或数字开头，长度 1-64")
		return
	}
	if len(req.Name) > 64 {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "设备名称最长 64 字节")
		return
	}
	d, err := s.store.CreateDevice(s.currentUser(r).ID, req.ID, req.Name)
	if errors.Is(err, ErrDeviceExists) {
		s.fail(w, http.StatusConflict, "DEVICE_EXISTS", "设备 ID 已存在")
		return
	}
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "创建设备失败")
		return
	}
	s.ok(w, d)
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, _, ok := s.ownedDevice(r, id); !ok {
		s.fail(w, http.StatusNotFound, "DEVICE_NOT_FOUND", "设备不存在")
		return
	}
	if err := s.store.DeleteDevice(s.currentUser(r).ID, id); err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "删除设备失败")
		return
	}
	s.ok(w, nil)
}

// ---------- 短信查看 ----------

func (s *Server) listMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, u, ok := s.ownedDevice(r, id)
	if !ok {
		s.fail(w, http.StatusNotFound, "DEVICE_NOT_FOUND", "设备不存在")
		return
	}
	token, err := s.store.DecryptToken(u)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "读取密钥失败")
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("size"))
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 20
	}
	msgs, total := s.store.ListMessages(id, page, size)
	items := make([]MessageView, 0, len(msgs))
	for _, m := range msgs {
		text, err := decryptText(token, m.Nonce, m.Ciphertext)
		if err != nil {
			continue // 跳过无法解密（被篡改或密钥不一致）的记录
		}
		p := decodeSMSPayload(text)
		sender := p.Sender
		if sender == "" {
			sender = m.Sender // 兼容旧数据中明文保存的发件人字段
		}
		items = append(items, MessageView{
			ID:        m.ID,
			Sender:    sender,
			Text:      p.Body,
			Raw:       p.Raw,
			Body:      p.Body,
			SIM:       p.SIM,
			Carrier:   p.Carrier,
			SIMNumber: p.SIMNumber,
			SubID:     p.SubID,
			SMSTime:   p.SMSTime,
			CreatedAt: m.CreatedAt,
		})
	}
	s.ok(w, map[string]any{"items": items, "total": total, "page": page, "size": size})
}

func (s *Server) clearMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, _, ok := s.ownedDevice(r, id); !ok {
		s.fail(w, http.StatusNotFound, "DEVICE_NOT_FOUND", "设备不存在")
		return
	}
	if err := s.store.ClearMessages(id); err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "清空短信失败")
		return
	}
	s.ok(w, nil)
}

// ---------- 图形验证码 ----------

func (s *Server) captcha(w http.ResponseWriter, r *http.Request) {
	text, err := randomCaptchaText(6)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "生成验证码失败")
		return
	}
	image, err := generateCaptchaImage(text)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "生成验证码图片失败")
		return
	}
	id := randomMustID()
	now := time.Now()
	s.stateMu.Lock()
	for k, v := range s.captchas {
		if now.After(v.ExpiresAt) {
			delete(s.captchas, k)
		}
	}
	s.captchas[id] = captchaEntry{Text: text, ExpiresAt: now.Add(5 * time.Minute)}
	s.stateMu.Unlock()
	s.ok(w, map[string]any{"id": id, "image": image})
}

// ---------- 邮箱验证码 / 找回密码 ----------

func (s *Server) forgotPassword(w http.ResponseWriter, r *http.Request) {
	if !s.mailGuard(w) {
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !validEmail(email) {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "邮箱格式不正确")
		return
	}
	u := s.store.FindUserByEmail(email)
	if u == nil {
		// 与已注册邮箱返回相同响应，避免通过响应差异枚举注册邮箱。
		s.ok(w, map[string]any{"sent": true})
		return
	}
	if err := s.issueMailCode("reset:"+email, email, "找回密码", u.Username); err != nil {
		log.Printf("发送找回密码邮件失败: %v", err)
		s.fail(w, http.StatusInternalServerError, "MAIL_FAILED", "验证码邮件发送失败，请稍后重试")
		return
	}
	s.ok(w, map[string]any{"sent": true})
}

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.mailGuard(w) {
		return
	}
	var req struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		NewPassword string `json:"new_password"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !validEmail(email) || len(req.NewPassword) < 6 || len(req.NewPassword) > 128 {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "邮箱格式不正确或新密码长度需在 6-128 字节之间")
		return
	}
	if !s.checkMailCode("reset:"+email, req.Code) {
		s.fail(w, http.StatusBadRequest, "INVALID_CODE", "验证码错误或已过期")
		return
	}
	u := s.store.FindUserByEmail(email)
	if u == nil {
		s.fail(w, http.StatusBadRequest, "INVALID_CODE", "验证码错误或已过期")
		return
	}
	hash, salt, err := hashPassword(req.NewPassword)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "密码处理失败")
		return
	}
	if err := s.store.UpdatePassword(u.ID, hash, salt); err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "密码重置失败")
		return
	}
	s.invalidateUserSessions(u.ID)
	s.ok(w, nil)
}

// ---------- 账号设置 ----------

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	u := s.currentUser(r)
	if s.store.Authenticate(u.Username, req.OldPassword) == nil {
		s.fail(w, http.StatusBadRequest, "INVALID_PASSWORD", "原密码错误")
		return
	}
	if len(req.NewPassword) < 6 || len(req.NewPassword) > 128 {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "新密码长度需在 6-128 字节之间")
		return
	}
	hash, salt, err := hashPassword(req.NewPassword)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "密码处理失败")
		return
	}
	if err := s.store.UpdatePassword(u.ID, hash, salt); err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "修改密码失败")
		return
	}
	s.invalidateUserSessions(u.ID)
	s.setSession(w, u.ID) // 仅保留当前会话
	s.ok(w, nil)
}

func (s *Server) sendEmailCode(w http.ResponseWriter, r *http.Request) {
	if !s.mailGuard(w) {
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !validEmail(email) {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "邮箱格式不正确")
		return
	}
	u := s.currentUser(r)
	if other := s.store.FindUserByEmail(email); other != nil && other.ID != u.ID {
		s.fail(w, http.StatusConflict, "EMAIL_IN_USE", "该邮箱已被其他账号绑定")
		return
	}
	if err := s.issueMailCode("bind:"+u.ID+":"+email, email, "绑定邮箱", u.Username); err != nil {
		if strings.Contains(err.Error(), "频繁") {
			s.fail(w, http.StatusTooManyRequests, "RATE_LIMITED", err.Error())
		} else {
			s.fail(w, http.StatusInternalServerError, "MAIL_FAILED", "验证码邮件发送失败，请稍后重试")
		}
		return
	}
	s.ok(w, nil)
}

func (s *Server) changeEmail(w http.ResponseWriter, r *http.Request) {
	if !s.mailGuard(w) {
		return
	}
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if !s.decodeJSON(w, r, &req) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !validEmail(email) {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "邮箱格式不正确")
		return
	}
	u := s.currentUser(r)
	if !s.checkMailCode("bind:"+u.ID+":"+email, req.Code) {
		s.fail(w, http.StatusBadRequest, "INVALID_CODE", "验证码错误或已过期")
		return
	}
	if err := s.store.UpdateEmail(u.ID, email); err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "绑定邮箱失败")
		return
	}
	s.ok(w, map[string]any{"email": email})
}

// ---------- 设备心跳 ----------

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
		ID    string `json:"id"`
	}
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		req.Token = q.Get("token")
		req.ID = q.Get("id")
	} else if !s.decodeJSON(w, r, &req) {
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	req.ID = strings.TrimSpace(req.ID)
	if req.Token == "" || req.ID == "" {
		s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "token、id 为必填参数")
		return
	}
	user := s.store.GetUserByToken(req.Token)
	if user == nil {
		s.fail(w, http.StatusUnauthorized, "INVALID_TOKEN", "token 无效")
		return
	}
	dev := s.store.GetDevice(req.ID)
	if dev == nil || dev.UserID != user.ID {
		s.fail(w, http.StatusNotFound, "DEVICE_NOT_FOUND", "设备不存在")
		return
	}
	s.markHeartbeat(req.ID)
	s.ok(w, map[string]any{"online": true, "server_time": time.Now().UTC()})
}

// ---------- 公开配置 ----------

func (s *Server) publicConfig(w http.ResponseWriter, r *http.Request) {
	s.ok(w, map[string]any{"mail_enabled": s.cfg.MailEnabled})
}
