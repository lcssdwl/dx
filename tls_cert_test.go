package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureTLSCertSelfSigned(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, err := ensureTLSCert(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !fileExists(certFile) || !fileExists(keyFile) {
		t.Fatal("自签证书未生成")
	}
	certPEM, _ := os.ReadFile(certFile)
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("证书 PEM 解析失败")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	san := map[string]bool{}
	for _, n := range cert.DNSNames {
		san[n] = true
	}
	for _, ip := range cert.IPAddresses {
		san[ip.String()] = true
	}
	for _, want := range []string{"localhost", "127.0.0.1", "::1"} {
		if !san[want] {
			t.Errorf("证书 SAN 缺少 %s: %v", want, san)
		}
	}
	// 重启复用：第二次调用返回相同路径且证书内容不变
	certFile2, keyFile2, err := ensureTLSCert(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if certFile2 != certFile || keyFile2 != keyFile {
		t.Fatal("重启后证书路径不一致")
	}
	again, _ := os.ReadFile(certFile)
	if string(again) != string(certPEM) {
		t.Fatal("重启后自签证书被重新生成（应复用）")
	}
}

func TestEnsureTLSCertCustom(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "custom.crt")
	keyFile := filepath.Join(dir, "custom.key")
	if err := os.WriteFile(certFile, []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	gotCert, gotKey, err := ensureTLSCert(dir, certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if gotCert != certFile || gotKey != keyFile {
		t.Fatalf("未使用自定义证书: %s %s", gotCert, gotKey)
	}
	// 只给证书不给私钥应报错
	if _, _, err := ensureTLSCert(dir, certFile, ""); err == nil {
		t.Error("仅指定证书应报错")
	}
}

func TestLocalIPsNoLoopback(t *testing.T) {
	for _, ip := range localIPs() {
		if ip.IsLoopback() {
			t.Errorf("localIPs 不应包含回环地址: %s", ip)
		}
		if ip.To4() == nil {
			t.Errorf("localIPs 应只含 IPv4: %s", ip)
		}
	}
}
