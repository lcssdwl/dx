package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	keyDerivePrefix = "dx-sms-key-v1:"
	pbkdf2Iter      = 210000
)

// appKeyBase 是编译进二进制的主密钥基值；config.ini [security] appKey 若有值会拼接在后。
const appKeyBase = "sdwl88"

// appKey 是数据主密钥：sha256(appKeyBase + iniAppKey)，无 ini 配置时即 sha256(appKeyBase)。
// 用于加密 Token、登录凭证、用户名/邮箱/设备字段与短信发送方号码，并生成 HMAC 索引。
var appKey = deriveAppKey("")

func deriveAppKey(iniAppKey string) []byte {
	sum := sha256.Sum256([]byte(appKeyBase + iniAppKey))
	return sum[:]
}

// setAppKey 用 config.ini [security] appKey 重设主密钥，须在创建 Store 之前调用。
func setAppKey(iniAppKey string) {
	appKey = deriveAppKey(iniAppKey)
}

// aesGCMSeal 用 AES-256-GCM 加密，aad 为附加认证数据（不加密但参与认证）。
// 返回格式为 base64url(nonce) + "." + base64url(ciphertext)。
func aesGCMSeal(key, plaintext, aad []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	return base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// aesGCMOpen 解密 aesGCMSeal 生成的密文，aad 必须与加密时一致。
func aesGCMOpen(key []byte, enc string, aad []byte) ([]byte, error) {
	parts := strings.Split(enc, ".")
	if len(parts) != 2 {
		return nil, errors.New("密文格式非法")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	sealed, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("nonce 长度非法")
	}
	return gcm.Open(nil, nonce, sealed, aad)
}

// randomBytes 生成密码学安全的随机字节。
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// randomID 生成 URL 安全的随机 ID（32 字节 -> 43 字符）。
func randomID() (string, error) {
	b, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// keyFromToken 从高熵 token 派生 32 字节 AES 密钥。
// token 本身即 256 位随机值，使用 SHA-256 派生足以保证安全且极快；
// PBKDF2 仅用于用户密码这类低熵输入。
func keyFromToken(token string) []byte {
	sum := sha256.Sum256([]byte(keyDerivePrefix + token))
	return sum[:]
}

// encryptText 用 token 派生的密钥加密明文短信，返回 base64 的 nonce 与密文。
func encryptText(token, plaintext string) (nonceB64, cipherB64 string, err error) {
	block, err := aes.NewCipher(keyFromToken(token))
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return "", "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(sealed), nil
}

// decryptText 用 token 解密短信；token 错误或数据被篡改都会报错。
func decryptText(token, nonceB64, cipherB64 string) (string, error) {
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", fmt.Errorf("nonce 编码非法: %w", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return "", fmt.Errorf("密文编码非法: %w", err)
	}
	block, err := aes.NewCipher(keyFromToken(token))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(nonce) != gcm.NonceSize() {
		return "", errors.New("nonce 长度非法")
	}
	plain, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", errors.New("解密失败：token 不匹配或数据被篡改")
	}
	return string(plain), nil
}

// hashPassword 生成 PBKDF2-SHA256 密码哈希。
func hashPassword(password string) (hashB64, saltB64 string, err error) {
	salt, err := randomBytes(16)
	if err != nil {
		return "", "", err
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(dk), base64.StdEncoding.EncodeToString(salt), nil
}

// verifyPassword 常量时间校验密码。
func verifyPassword(password, hashB64, saltB64 string) bool {
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iter, 32)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// tokenHash 计算 token 的 SHA-256（URL-safe base64），用于鉴权查找，不落盘明文。
func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// encryptToken 用内置密钥加密 token，密文格式为 base64url(nonce) + "." + base64url(sealed)。
func encryptToken(token string) (string, error) {
	return aesGCMSeal(appKey, []byte(token), nil)
}

// decryptToken 用内置密钥还原 token，供短信解密使用。
func decryptToken(enc string) (string, error) {
	return decryptTokenWithKey(appKey, enc)
}

// decryptTokenWithKey 用指定密钥还原 token，仅用于升级时迁移旧密钥加密的数据。
func decryptTokenWithKey(key []byte, enc string) (string, error) {
	plain, err := aesGCMOpen(key, enc, nil)
	if err != nil {
		return "", errors.New("token 解密失败：密钥不匹配或数据被篡改")
	}
	return string(plain), nil
}

// credentialPlain 是落盘前被加密的登录凭证，攻击者拿到 meta.json 也看不到 scrypt/PBKDF2 哈希与盐。
type credentialPlain struct {
	PasswordHash string `json:"p"`
	Salt         string `json:"s"`
}

// credentialAAD 把凭证绑定到具体用户：即使把 A 的 cred_enc 整段复制到 B，
// 因 userID/username 不同，GCM 认证失败，无法用来伪造 B 的登录。
func credentialAAD(userID, username string) []byte {
	return []byte("dx-cred:v1\x00" + userID + "\x00" + username)
}

// encryptCredential 用内置密钥加密 password_hash + salt。
func encryptCredential(userID, username, passwordHash, salt string) (string, error) {
	raw, err := json.Marshal(credentialPlain{PasswordHash: passwordHash, Salt: salt})
	if err != nil {
		return "", err
	}
	return aesGCMSeal(appKey, raw, credentialAAD(userID, username))
}

// decryptCredential 还原并认证登录凭证；密文或身份任一被改动都会失败。
func decryptCredential(userID, username, enc string) (passwordHash, salt string, err error) {
	raw, err := aesGCMOpen(appKey, enc, credentialAAD(userID, username))
	if err != nil {
		return "", "", errors.New("登录凭证校验失败：数据被篡改")
	}
	var c credentialPlain
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", "", err
	}
	return c.PasswordHash, c.Salt, nil
}

// fieldAAD 把字段密文绑定到所属实体，防止跨用户/跨设备复制密文。
func fieldAAD(kind, ownerID string) []byte {
	return []byte("dx-field:v1\x00" + kind + "\x00" + ownerID)
}

// encryptField 用内置密钥加密一个字符串字段（用户名/邮箱/设备 ID/名称）。
func encryptField(kind, ownerID, plain string) (string, error) {
	return aesGCMSeal(appKey, []byte(plain), fieldAAD(kind, ownerID))
}

// decryptField 还原字段明文；密文或归属被改动都会失败。
func decryptField(kind, ownerID, enc string) (string, error) {
	raw, err := aesGCMOpen(appKey, enc, fieldAAD(kind, ownerID))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// fieldIndex 生成不可逆索引，用于在不解密的情况下按字段查找（用户名/邮箱/设备 ID）。
// 用 HMAC 而非裸 SHA-256，避免低熵值被彩虹表命中。
func fieldIndex(normalized string) string {
	mac := hmac.New(sha256.New, appKey)
	_, _ = mac.Write([]byte(normalized))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
