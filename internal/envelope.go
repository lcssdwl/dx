package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const clientKeyCookie = "dx_ck"

// envelope 是后台 API 的整包密文信封：请求与响应都是 {"payload":"<base64>"}，
// 解开后才是原本的 JSON。报文外看不到任何业务字段。
type envelope struct {
	Payload string `json:"payload"`
}

// envelopeKey 由登录返回的 dx_session id 与后端注入的 client_key 共同派生，
// 保证每个浏览器、每次请求的密钥都不同。两端算法必须一致：
// AES-256 key = SHA256("dx-api-v1:" + sessionID + ":" + clientKey)
func envelopeKey(sessionID, clientKey string) []byte {
	sum := sha256.Sum256([]byte("dx-api-v1:" + sessionID + ":" + clientKey))
	return sum[:]
}

// sealEnvelope 加密明文并返回 base64url(nonce)+"."+base64url(ciphertext) 形状的字符串。
func sealEnvelope(key, plain []byte) (string, error) {
	return aesGCMSeal(key, plain, nil)
}

// openEnvelope 解密 sealEnvelope 生成的字符串。
func openEnvelope(key []byte, enc string) ([]byte, error) {
	return aesGCMOpen(key, enc, nil)
}

// bufferedResponse 先把 handler 的响应写入内存，便于整包加密后一次性输出。
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header), status: http.StatusOK}
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(code int) { b.status = code }

func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }

// authEnvelopeKey 用于认证阶段（尚未登录、没有 dx_session）：
// AES-256 key = SHA256("dx-auth-v1:" + clientKey)。clientKey 由后端返回 JS 时注入，
// 并写入 HttpOnly Cookie dx_ck；与 dx_session 无关，因此登录/注册/验证码均可加密。
func authEnvelopeKey(clientKey string) []byte {
	sum := sha256.Sum256([]byte("dx-auth-v1:" + clientKey))
	return sum[:]
}

// encryptedWith 用给定密钥对请求/响应做整包加解密的通用中间件。
func (s *Server) encryptedWith(keyOf func(r *http.Request) ([]byte, bool)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, ok := keyOf(r)
			if !ok {
				next.ServeHTTP(w, r) // 未启用加密（旧客户端/测试）时透明放行
				return
			}

			// 请求：解开 {"payload": "..."} 还原为原业务 JSON。
			if r.Body != nil {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "读取请求体失败")
					return
				}
				_ = r.Body.Close()
				if len(bytes.TrimSpace(raw)) > 0 {
					var env envelope
					if err := json.Unmarshal(raw, &env); err != nil || strings.TrimSpace(env.Payload) == "" {
						s.fail(w, http.StatusBadRequest, "BAD_REQUEST", "请求体必须是加密信封")
						return
					}
					plain, err := openEnvelope(key, env.Payload)
					if err != nil {
						s.fail(w, http.StatusBadRequest, "DECRYPT_FAILED", "请求解密失败，请刷新页面后重试")
						return
					}
					r.Body = io.NopCloser(bytes.NewReader(plain))
					r.ContentLength = int64(len(plain))
				} else {
					r.Body = http.NoBody
					r.ContentLength = 0
				}
			}

			// 响应：把原本的 apiResp JSON 整包加密成 {"payload": "..."}。
			buf := newBufferedResponse()
			next.ServeHTTP(buf, r)
			sealed, err := sealEnvelope(key, buf.body.Bytes())
			if err != nil {
				s.fail(w, http.StatusInternalServerError, "INTERNAL", "响应加密失败")
				return
			}
			// 复制 handler 设置的响应头（尤其登录/注册的 Set-Cookie: dx_session），
			// 否则浏览器拿不到会话 cookie，登录后跳后台会变成未登录。
			for k, vals := range buf.header {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			if w.Header().Get("Content-Type") == "" {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
			}
			w.WriteHeader(buf.status)
			_ = json.NewEncoder(w).Encode(envelope{Payload: sealed})
		})
	}
}

// apiEncryption 对已登录会话的后台 API 做整包加解密。
// key 取自 cookie 中的 dx_session 与本次 JS 注入的 dx_ck；两者缺一（脚本/curl）则明文兼容。
func (s *Server) apiEncryption(next http.Handler) http.Handler {
	return s.encryptedWith(func(r *http.Request) ([]byte, bool) {
		sid, err1 := r.Cookie(sessionCookie)
		ck, err2 := r.Cookie(clientKeyCookie)
		if err1 != nil || err2 != nil || sid.Value == "" || ck.Value == "" {
			return nil, false
		}
		s.sessMu.Lock()
		_, ok := s.sessions[sid.Value]
		s.sessMu.Unlock()
		if !ok {
			return nil, false
		}
		return envelopeKey(sid.Value, ck.Value), true
	})(next)
}

// authEncryption 对认证接口（登录/注册/验证码/找回密码/public config）做整包加解密。
// key 取自本次 JS 注入写入的 dx_ck cookie；无该 cookie（脚本/curl）则明文兼容。
func (s *Server) authEncryption(next http.Handler) http.Handler {
	return s.encryptedWith(func(r *http.Request) ([]byte, bool) {
		ck, err := r.Cookie(clientKeyCookie)
		if err != nil || strings.TrimSpace(ck.Value) == "" {
			return nil, false
		}
		return authEnvelopeKey(ck.Value), true
	})(next)
}
