package app

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strings"
)

// iniData 为简单的 section -> key -> value 映射。
type iniData map[string]map[string]string

// loadINI 解析简易 INI：支持 [section]、key=value / key:value、# 与 ; 整行注释。
// 值中的 # 和 : 不做截断，便于密码包含特殊字符。
func loadINI(path string) (iniData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data := make(iniData)
	section := "default"
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "" {
				section = "default"
			}
			if data[section] == nil {
				data[section] = make(map[string]string)
			}
			continue
		}
		idx := strings.IndexAny(line, "=:")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		if key == "" {
			continue
		}
		if data[section] == nil {
			data[section] = make(map[string]string)
		}
		data[section][key] = strings.TrimSpace(line[idx+1:])
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

type smtpConfig struct {
	Host string
	Port string
	User string
	Pass string
	From string
	TLS  string
}

// loadSMTPConfig 从 config.ini 的 [smtp] 节读取发信配置。
// 文件不存在、[smtp] 节缺失或 host/from 为空时，enabled 为 false。
func loadSMTPConfig(path string) (cfg smtpConfig, enabled bool, err error) {
	data, err := loadINI(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return smtpConfig{}, false, nil
		}
		return smtpConfig{}, false, err
	}
	sec := data["smtp"]
	if sec == nil {
		return smtpConfig{}, false, nil
	}
	cfg = smtpConfig{
		Host: strings.TrimSpace(sec["host"]),
		Port: strings.TrimSpace(sec["port"]),
		User: strings.TrimSpace(sec["user"]),
		Pass: strings.TrimSpace(sec["pass"]),
		From: strings.TrimSpace(sec["from"]),
		TLS:  strings.TrimSpace(sec["tls"]),
	}
	if cfg.Port == "" {
		cfg.Port = "587"
	}
	if cfg.TLS == "" {
		cfg.TLS = "starttls"
	}
	return cfg, cfg.Host != "" && cfg.From != "", nil
}

// loadLegacyMasterKey 仅用于一次性迁移：读取旧版写入 config.ini [security] key 的主密钥。
// 读不到返回 nil；新版绝不写回该字段。
func loadLegacyMasterKey(path string) []byte {
	data, err := loadINI(path)
	if err != nil {
		return nil
	}
	sec := data["security"]
	if sec == nil {
		return nil
	}
	v := strings.TrimSpace(sec["key"])
	if v == "" {
		return nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(v); err == nil && len(b) == 32 {
		return b
	}
	sum := sha256.Sum256([]byte(v))
	return sum[:]
}
