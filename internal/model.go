package app

import "time"

// User 表示一个注册用户。Token 既用于短信接收接口鉴权，也作为短信加密密钥的根。
// 登录凭证与 Token 均只以内置密钥加密后的密文落盘，明文不写文件。
type User struct {
	ID string `json:"id"`

	Username       string `json:"-"`                  // 运行时明文，不落盘
	UsernameEnc    string `json:"username_enc"`       // 内置密钥加密的用户名
	UsernameHash   string `json:"username_hash"`      // 用户名索引（HMAC，精确匹配）
	LegacyUsername string `json:"username,omitempty"` // 旧数据兼容，迁移后清空

	PasswordHash string `json:"password_hash,omitempty"` // 旧数据兼容，迁移后清空且不再读取
	Salt         string `json:"salt,omitempty"`          // 旧数据兼容，迁移后清空且不再读取
	CredEnc      string `json:"cred_enc"`                // 内置密钥加密的 password_hash + salt（绑定 ID/用户名）
	TokenHash    string `json:"token_hash"`              // SHA256(token)，用于鉴权查找
	TokenEnc     string `json:"token_enc"`               // 内置密钥加密的 token，用于解密短信
	TokenPlain   string `json:"-"`                       // 仅注册/初始化时临时返回，不落盘
	Token        string `json:"token,omitempty"`         // 旧数据兼容，迁移后清空

	Email       string `json:"-"`                    // 运行时明文，不落盘
	EmailEnc    string `json:"email_enc,omitempty"`  // 内置密钥加密的邮箱
	EmailHash   string `json:"email_hash,omitempty"` // 邮箱索引（HMAC，小写归一）
	LegacyEmail string `json:"email,omitempty"`      // 旧数据兼容，迁移后清空

	CreatedAt time.Time `json:"created_at"`
}

// Device 表示用户创建的设备。ID 全局唯一。
type Device struct {
	ID       string `json:"-"`            // 运行时明文，不落盘
	IDEnc    string `json:"id_enc"`       // 内置密钥加密的设备 ID
	IDHash   string `json:"id_hash"`      // 设备 ID 索引（HMAC），同时用于消息文件名
	LegacyID string `json:"id,omitempty"` // 旧数据兼容，迁移后清空
	UserID   string `json:"user_id"`

	Name       string `json:"-"`              // 运行时明文，不落盘
	NameEnc    string `json:"name_enc"`       // 内置密钥加密的设备名称
	LegacyName string `json:"name,omitempty"` // 旧数据兼容，迁移后清空

	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// Message 为落盘的加密短信。明文永不写入磁盘。
type Message struct {
	ID       string `json:"id"`
	DeviceID string `json:"-"` // 运行时明文，不落盘
	Sender   string `json:"-"` // 运行时明文（from 发送方号码），不落盘

	SenderEnc    string `json:"sender_enc,omitempty"` // 内置密钥加密的发送方号码（绑定设备 ID）
	LegacySender string `json:"sender,omitempty"`     // 旧数据兼容，迁移后清空

	Nonce      string    `json:"nonce"`      // base64
	Ciphertext string    `json:"ciphertext"` // base64(AES-256-GCM)
	CreatedAt  time.Time `json:"created_at"`
}

// MessageView 为解密后返回给后台的短信视图。
type MessageView struct {
	ID        string    `json:"id"`
	Sender    string    `json:"sender,omitempty"` // 发件人号码
	Text      string    `json:"text"`             // 正文（兼容旧字段）
	Raw       string    `json:"raw"`              // 原始上报文本
	Body      string    `json:"body"`             // 正文
	SIM       string    `json:"sim,omitempty"`    // SIM 槽位
	Carrier   string    `json:"carrier,omitempty"`
	SIMNumber string    `json:"sim_number,omitempty"`
	SubID     string    `json:"sub_id,omitempty"`
	SMSTime   string    `json:"sms_time,omitempty"` // 短信原始时间
	CreatedAt time.Time `json:"created_at"`         // 服务端接收时间
}

// apiResp 为统一的 JSON 响应结构。
type apiResp struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// session 为后台登录会话。
type session struct {
	UserID    string
	ExpiresAt time.Time
}

// captchaEntry 为一次性图形验证码。
type captchaEntry struct {
	Text      string
	ExpiresAt time.Time
}

// mailCode 为邮箱验证码（找回密码 / 绑定邮箱共用）。
type mailCode struct {
	Code      string
	ExpiresAt time.Time
	LastSent  time.Time
	Attempts  int
}

// loginFail 记录某客户端 IP 的连续登录失败状态。
type loginFail struct {
	Count       int
	LockedUntil time.Time
}
