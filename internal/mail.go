package app

import (
	"crypto/tls"
	"fmt"
	"log"
	"mime"
	"net"
	"net/smtp"
	"strings"
)

// sendMail 发送纯文本邮件，支持 STARTTLS / 隐式 TLS / 无加密，以及调试模式。
func sendMail(cfg Config, to, subject, body string) error {
	if !cfg.MailEnabled {
		return fmt.Errorf("邮件服务未配置：请在 config.ini 的 [smtp] 中填写 host 与 from")
	}
	if cfg.MailDebug {
		log.Printf("[MAIL-DEBUG] To=%s Subject=%s Body=%s", to, subject, body)
		return nil
	}
	port := cfg.SMTPPort
	if port == "" {
		port = "587"
	}
	addr := net.JoinHostPort(cfg.SMTPHost, port)
	tlsCfg := &tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	var err error
	if strings.EqualFold(cfg.SMTPTLS, "implicit") {
		conn, err = tls.Dial("tcp", addr, tlsCfg)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("连接邮件服务器失败: %w", err)
	}

	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()

	if !strings.EqualFold(cfg.SMTPTLS, "none") {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("STARTTLS 失败: %w", err)
			}
		} else if strings.EqualFold(cfg.SMTPTLS, "starttls") {
			return fmt.Errorf("邮件服务器不支持 STARTTLS")
		}
	}
	if cfg.SMTPUser != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)); err != nil {
			return fmt.Errorf("邮件服务器认证失败: %w", err)
		}
	}
	if err := client.Mail(cfg.SMTPFrom); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		cfg.SMTPFrom, to, mime.QEncoding.Encode("utf-8", subject), body)
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func mailVerificationBody(code, purpose, username string) string {
	return fmt.Sprintf("%s，您好：\n\n您的%s验证码是：%s\n\n验证码 5 分钟内有效，请勿泄露给他人。\n若非本人操作，请忽略此邮件。", username, purpose, code)
}
