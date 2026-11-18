package app

import (
	"context"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// entryPrefix 是写死的统一入口：页面、静态资源与 API 全部挂在 /sdwl 下。
const entryPrefix = "/sdwl"

// Server 聚合配置、存储、会话与限流状态。
type Server struct {
	cfg         Config
	store       *Store
	webFS       fs.FS
	sessions    map[string]session
	sessMu      sync.Mutex
	apiLimiter  *limiter // 按 token 限制短信上报
	ipLimiter   *limiter // 按 IP 限制所有 API
	authLimiter *limiter // 按 IP 限制认证接口

	stateMu    sync.Mutex
	captchas   map[string]captchaEntry
	mailCodes  map[string]*mailCode
	loginFails map[string]*loginFail
	heartbeats map[string]time.Time
}

// NewHandler 构建完整 HTTP 处理器（路由 + 中间件）。
func NewHandler(cfg Config, store *Store, webFS fs.FS) http.Handler {
	return newServer(cfg, store, webFS).handler()
}

func newServer(cfg Config, store *Store, webFS fs.FS) *Server {
	return &Server{
		cfg:         cfg,
		store:       store,
		webFS:       webFS,
		sessions:    make(map[string]session),
		apiLimiter:  newLimiter(cfg.APIRateLimit, time.Minute),
		ipLimiter:   newLimiter(600, time.Minute),
		authLimiter: newLimiter(cfg.AuthRateLimit, time.Minute),
		captchas:    make(map[string]captchaEntry),
		mailCodes:   make(map[string]*mailCode),
		loginFails:  make(map[string]*loginFail),
		heartbeats:  make(map[string]time.Time),
	}
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()

	// 设备接口：短信上报与心跳保持明文（设备端接口，不参与浏览器加密）。
	mux.HandleFunc("GET /api/sms/receive", s.receiveSMS)
	mux.HandleFunc("POST /api/sms/receive", s.receiveSMS)
	mux.HandleFunc("GET /api/device/heartbeat", s.heartbeat)
	mux.HandleFunc("POST /api/device/heartbeat", s.heartbeat)

	// 认证接口：整包加密（请求带 dx_ck Cookie 时启用，不带则明文兼容脚本/设备端）。
	authWrap := func(h http.HandlerFunc) http.HandlerFunc {
		return s.authEncryption(h).ServeHTTP
	}
	mux.HandleFunc("GET /api/auth/captcha", authWrap(s.captcha))
	mux.HandleFunc("GET /api/public/config", authWrap(s.publicConfig))
	mux.HandleFunc("POST /api/auth/register", authWrap(s.register))
	mux.HandleFunc("POST /api/auth/login", authWrap(s.login))
	mux.HandleFunc("POST /api/auth/logout", authWrap(s.logout))
	mux.HandleFunc("POST /api/auth/forgot-password", authWrap(s.forgotPassword))
	mux.HandleFunc("POST /api/auth/reset-password", authWrap(s.resetPassword))

	// 需要登录的后台接口
	protected := http.NewServeMux()
	protected.HandleFunc("GET /api/auth/me", s.me)
	protected.HandleFunc("GET /api/token", s.getToken)
	protected.HandleFunc("POST /api/account/password", s.changePassword)
	protected.HandleFunc("POST /api/account/email/code", s.sendEmailCode)
	protected.HandleFunc("POST /api/account/email", s.changeEmail)
	protected.HandleFunc("GET /api/devices", s.listDevices)
	protected.HandleFunc("POST /api/devices", s.createDevice)
	protected.HandleFunc("DELETE /api/devices/{id}", s.deleteDevice)
	protected.HandleFunc("GET /api/devices/{id}/messages", s.listMessages)
	protected.HandleFunc("DELETE /api/devices/{id}/messages", s.clearMessages)
	protected.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, http.StatusNotFound, "NOT_FOUND", "接口不存在")
	})
	mux.Handle("/api/", s.authMiddleware(s.apiEncryption(protected)))

	// 动态 JS：每次请求生成随机 client_key 注入脚本，并写入 HttpOnly Cookie 供后端解密。
	mux.HandleFunc("GET /login.js", func(w http.ResponseWriter, r *http.Request) {
		s.serveInjectedJS(w, "login.js")
	})
	mux.HandleFunc("GET /app.js", func(w http.ResponseWriter, r *http.Request) {
		s.serveInjectedJS(w, "app.js")
	})

	// 其余静态前端
	mux.Handle("/", http.FileServer(http.FS(s.webFS)))

	var h http.Handler = mux
	h = s.ipRateLimit(h)
	h = s.authRateLimit(h)
	h = s.csrfGuard(h)
	h = s.maxBytes(h)
	h = s.securityHeaders(h)
	h = s.recoverPanic(h)

	// 隐藏入口：仅 /sdwl 及其子路径可访问，其余一律 404。
	// 命中后去掉 /sdwl 前缀再交给内部处理器，限流/CSRF 等中间件仍按 /api/... 匹配。
	return notFoundHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == entryPrefix {
			http.Redirect(w, r, entryPrefix+"/", http.StatusMovedPermanently)
			return
		}
		if !strings.HasPrefix(r.URL.Path, entryPrefix+"/") {
			notFound(w)
			return
		}
		r2 := r.Clone(r.Context())
		u := *r.URL
		u.Path = strings.TrimPrefix(r.URL.Path, entryPrefix)
		u.RawPath = ""
		r2.URL = &u
		h.ServeHTTP(w, r2)
	}))
}

// serveInjectedJS 读取原始 JS，在开头注入本次请求专属的随机 client_key，
// 同时把同一 key 写入 HttpOnly Cookie 供后端解密。每次请求 key 都不同，且禁止缓存。
func (s *Server) serveInjectedJS(w http.ResponseWriter, name string) {
	raw, err := fs.ReadFile(s.webFS, name)
	if err != nil {
		notFound(w)
		return
	}
	key, err := randomID()
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "INTERNAL", "生成会话密钥失败")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     clientKeyCookie,
		Value:    key,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	_, _ = w.Write([]byte("window.__DX_CK__=" + strconv.Quote(key) + ";\n"))
	_, _ = w.Write(raw)
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(apiResp{Code: "NOT_FOUND", Message: "接口不存在"})
}

// notFoundHandler 让 404 响应也套上统一安全响应头。
func notFoundHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustedProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v %s", err, r.URL.Path)
				s.fail(w, http.StatusInternalServerError, "INTERNAL", "服务器内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) maxBytes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// csrfGuard 阻止跨站写入：浏览器携带 Cookie 的写请求必须同源。
// 无 Origin 头的客户端（curl、App、服务端程序）不受影响，仍受 SameSite Cookie 保护。
func (s *Server) csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut ||
			r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			if origin := r.Header.Get("Origin"); origin != "" {
				if !sameOrigin(origin, r.Host) {
					s.fail(w, http.StatusForbidden, "CSRF_REJECTED", "跨站请求被拒绝")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(origin, host string) bool {
	rest, ok := strings.CutPrefix(origin, "http://")
	if !ok {
		rest, ok = strings.CutPrefix(origin, "https://")
		if !ok {
			return false
		}
	}
	return strings.EqualFold(strings.Split(rest, "/")[0], host)
}

func (s *Server) ipRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && !s.ipLimiter.allow(s.clientIP(r)) {
			s.fail(w, http.StatusTooManyRequests, "RATE_LIMITED", "请求过于频繁，请稍后再试")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login", "/api/auth/register", "/api/auth/forgot-password",
			"/api/auth/reset-password", "/api/auth/captcha", "/api/account/email/code":
			if !s.authLimiter.allow(s.clientIP(r)) {
				s.fail(w, http.StatusTooManyRequests, "RATE_LIMITED", "尝试过于频繁，请稍后再试")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			s.fail(w, http.StatusUnauthorized, "UNAUTHORIZED", "请先登录")
			return
		}
		s.sessMu.Lock()
		sess, ok := s.sessions[c.Value]
		if ok && time.Now().After(sess.ExpiresAt) {
			delete(s.sessions, c.Value)
			ok = false
		}
		s.sessMu.Unlock()
		if !ok {
			s.fail(w, http.StatusUnauthorized, "UNAUTHORIZED", "登录已过期，请重新登录")
			return
		}
		u := s.store.GetUserByID(sess.UserID)
		if u == nil {
			s.fail(w, http.StatusUnauthorized, "UNAUTHORIZED", "用户不存在")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserKey, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
