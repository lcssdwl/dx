package app

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// smsPayload 为设备上报短信的结构化内容。整个 payload 会被加密后落盘，
// 其中任一字段都不会以明文形式写入磁盘。
type smsPayload struct {
	V         int    `json:"v"`          // 格式版本，1 表示结构化 payload
	Raw       string `json:"raw"`        // 设备上报的原始文本
	Sender    string `json:"sender"`     // 发件人号码
	Body      string `json:"body"`       // 短信正文
	SIM       string `json:"sim"`        // SIM 槽位，如 SIM1
	Carrier   string `json:"carrier"`    // 运营商
	SIMNumber string `json:"sim_number"` // SIM 卡号码
	SubID     string `json:"sub_id"`     // SubId
	SMSTime   string `json:"sms_time"`   // 短信原始时间字符串
}

var (
	phonePattern = regexp.MustCompile(`^\+?[0-9][0-9\-\s]{4,19}$`)
	subIDPattern = regexp.MustCompile(`(?i)^sub\s*id\s*[:：]\s*(.*)$`)
)

func looksLikeDateTime(s string) bool {
	if s == "" {
		return false
	}
	for _, layout := range []string{
		"2006-01-02 15:04:05", "2006/01/02 15:04:05",
		"2006-01-02T15:04:05", "01-02 15:04:05", "15:04:05",
	} {
		if _, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return true
		}
	}
	return false
}

func parseSIMLine(line string) (sim, carrier, number string, ok bool) {
	if !strings.HasPrefix(strings.ToUpper(line), "SIM") {
		return "", "", "", false
	}
	parts := strings.Split(line, "_")
	sim = strings.TrimSpace(parts[0])
	if len(parts) >= 2 {
		carrier = strings.TrimSpace(parts[1])
	}
	if len(parts) >= 3 {
		number = strings.TrimSpace(parts[2])
	}
	return sim, carrier, number, true
}

// parseSMS 解析设备上报的固定多行格式：
//
//	发件人号码
//	短信正文
//	SIM1_运营商_SIM号码
//	SubId：0
//	2026-11-17 02:24:18
//
// 无法可靠识别时退回为纯文本（正文即原文）。
func parseSMS(text string) smsPayload {
	p := smsPayload{V: 1, Raw: text, Body: text}
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) < 3 {
		return p
	}

	recognized := 0
	// 时间（末行）
	if t := strings.TrimSpace(lines[len(lines)-1]); looksLikeDateTime(t) {
		p.SMSTime = t
		lines = lines[:len(lines)-1]
		recognized++
	}
	// SubId
	if len(lines) > 0 {
		if m := subIDPattern.FindStringSubmatch(strings.TrimSpace(lines[len(lines)-1])); m != nil {
			p.SubID = strings.TrimSpace(m[1])
			lines = lines[:len(lines)-1]
			recognized++
		}
	}
	// SIM 信息
	if len(lines) > 0 {
		if sim, carrier, number, ok := parseSIMLine(strings.TrimSpace(lines[len(lines)-1])); ok {
			p.SIM, p.Carrier, p.SIMNumber = sim, carrier, number
			lines = lines[:len(lines)-1]
			recognized++
		}
	}
	// 发件人号码（首行）
	if len(lines) > 0 {
		if from := strings.TrimSpace(lines[0]); phonePattern.MatchString(from) {
			p.Sender = from
			lines = lines[1:]
		}
	}

	body := strings.TrimSpace(strings.Join(lines, "\n"))
	if recognized < 2 || p.Sender == "" || body == "" {
		return smsPayload{V: 1, Raw: text, Body: text}
	}
	p.Body = body
	return p
}

// encodeSMSPayload 将短信文本解析为结构化 payload 并序列化为待加密的明文。
func encodeSMSPayload(text string) ([]byte, error) {
	return json.Marshal(parseSMS(text))
}

// decodeSMSPayload 解密后还原结构；同时兼容旧版直接加密纯文本的数据。
func decodeSMSPayload(plain string) smsPayload {
	var p smsPayload
	if err := json.Unmarshal([]byte(plain), &p); err == nil && p.V == 1 {
		if p.Raw == "" {
			p.Raw = plain
		}
		if p.Body == "" {
			p.Body = p.Raw
		}
		return p
	}
	return parseSMS(plain)
}
