package app

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultRegisterAuthSecret 是注册授权码密钥的基值；config.ini [auth] secret 若配置会拼接在后。
const DefaultRegisterAuthSecret = "sdwl88"

// Config 保存服务运行配置。通用项通过环境变量设置，邮箱与注册密钥从 config.ini 读取。
type Config struct {
	Addr            string        // 监听地址
	DataDir         string        // 数据目录
	SessionTTL      time.Duration // 后台会话有效期
	APIRateLimit    int           // 短信接收接口每个 token 每分钟允许次数
	AuthRateLimit   int           // 认证接口每个 IP 每分钟允许次数
	MaxBodyBytes    int64         // 请求体最大字节数
	SecureCookie    bool          // Cookie 是否带 Secure 标志（HTTPS 场景开启）
	TrustedProxy    bool          // 是否信任 X-Forwarded-For（仅在反代后开启）
	ShutdownTimeout time.Duration // 优雅退出等待时间

	TLSEnabled  bool   // 是否启用内置 HTTPS（默认开启，前端 crypto.subtle 需要安全上下文）
	TLSCertFile string // 自定义证书路径，留空则自动生成自签证书
	TLSKeyFile  string // 自定义私钥路径

	SMTPHost     string // 来自 config.ini [smtp]
	SMTPPort     string
	SMTPUser     string
	SMTPPass     string
	SMTPFrom     string
	SMTPTLS      string
	MailEnabled  bool // config.ini 未正确配置时为 false，找回密码与邮箱绑定功能禁用
	MailDebug    bool // 仅调试：验证码打印到日志而不实际发信（需 MailEnabled 为 true）
	LoginMaxFail int  // 同一 IP 连续登录失败多少次后锁定该 IP
	LoginLockMin int  // IP 锁定时长（分钟）

	RegisterAuthSecret string // 注册授权码密钥，来自 config.ini [auth] secret
	LegacyMasterKey    []byte // 旧版 config.ini [security] key，仅用于一次性迁移，读到后不写回
}

// LoadConfig 加载配置。DX_CONFIG 可指定 ini 路径，默认当前目录 config.ini。
func LoadConfig() Config {
	c := Config{
		Addr:               env("DX_ADDR", ":8080"),
		DataDir:            env("DX_DATA_DIR", "./data"),
		SessionTTL:         time.Duration(envInt("DX_SESSION_TTL_MIN", 720)) * time.Minute,
		APIRateLimit:       envInt("DX_API_RATE_LIMIT", 120),
		AuthRateLimit:      envInt("DX_AUTH_RATE_LIMIT", 20),
		MaxBodyBytes:       envInt64("DX_MAX_BODY_BYTES", 1<<20), // 1 MiB
		SecureCookie:       envBool("DX_SECURE_COOKIE", true),
		TrustedProxy:       envBool("DX_TRUSTED_PROXY", false),
		ShutdownTimeout:    5 * time.Second,
		MailDebug:          envBool("DX_MAIL_DEBUG", false),
		LoginMaxFail:       envInt("DX_LOGIN_MAX_FAIL", 5),
		LoginLockMin:       envInt("DX_LOGIN_LOCK_MIN", 15),
		RegisterAuthSecret: DefaultRegisterAuthSecret,
		TLSEnabled:         envBool("DX_TLS_ENABLED", true),
		TLSCertFile:        env("DX_TLS_CERT", ""),
		TLSKeyFile:         env("DX_TLS_KEY", ""),
	}
	// 关闭内置 HTTPS 时（例如反代已终止 TLS），SecureCookie 默认关闭，
	// 除非显式通过 DX_SECURE_COOKIE 指定。
	if !c.TLSEnabled && os.Getenv("DX_SECURE_COOKIE") == "" {
		c.SecureCookie = false
	}

	path := env("DX_CONFIG", "config.ini")
	// 主密钥基值编译在二进制里，默认仅用基值；config.ini [security] appKey 若有值则拼接在基值后，
	// 派生出实际数据主密钥。必须在存储层加载（解密）之前设置。
	setAppKey("")
	// 旧版遗留的 [security] key 仅用于一次性数据迁移，绝不写回。
	c.LegacyMasterKey = loadLegacyMasterKey(path)
	if data, err := loadINI(path); err == nil {
		// 数据主密钥追加串：拼接到内置基值后，为空则只用基值。
		if sec := data["security"]; sec != nil {
			setAppKey(strings.TrimSpace(sec["appKey"]))
		}
		// 注册授权码密钥：config.ini [auth] secret 若有值则拼接在基值后，而非替换。
		if sec := data["auth"]; sec != nil {
			if v := strings.TrimSpace(sec["secret"]); v != "" {
				c.RegisterAuthSecret = DefaultRegisterAuthSecret + v
			}
		}
		// HTTPS：环境变量优先，ini 作为补充。
		if sec := data["tls"]; sec != nil {
			if v := strings.TrimSpace(sec["enabled"]); v != "" && os.Getenv("DX_TLS_ENABLED") == "" {
				c.TLSEnabled = strings.EqualFold(v, "true") || v == "1"
			}
			if v := strings.TrimSpace(sec["cert"]); v != "" && c.TLSCertFile == "" {
				c.TLSCertFile = v
			}
			if v := strings.TrimSpace(sec["key"]); v != "" && c.TLSKeyFile == "" {
				c.TLSKeyFile = v
			}
		}
	}
	// ini 指定关闭 HTTPS 且未显式设置 SecureCookie 时，SecureCookie 随之关闭。
	if !c.TLSEnabled && os.Getenv("DX_SECURE_COOKIE") == "" {
		c.SecureCookie = false
	}
	smtp, enabled, err := loadSMTPConfig(path)
	if err != nil {
		log.Printf("读取配置文件 %s 失败: %v（邮件功能已禁用）", path, err)
	}
	c.SMTPHost, c.SMTPPort = smtp.Host, smtp.Port
	c.SMTPUser, c.SMTPPass = smtp.User, smtp.Pass
	c.SMTPFrom, c.SMTPTLS = smtp.From, smtp.TLS
	c.MailEnabled = enabled
	return c
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
