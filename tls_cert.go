package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ensureTLSCert 返回证书与私钥路径。优先使用显式配置；否则在 dataDir 下
// 复用已有自签证书，不存在则生成。自签证书 SAN 含 localhost、回环地址与
// 全部本机网卡 IP，使局域网 IP 访问也被浏览器视为安全上下文（crypto.subtle 可用）。
func ensureTLSCert(dataDir, certFile, keyFile string) (string, string, error) {
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return "", "", errors.New("同时指定 DX_TLS_CERT 与 DX_TLS_KEY 才能使用自定义证书")
		}
		if _, err := os.Stat(certFile); err != nil {
			return "", "", fmt.Errorf("读取证书 %s 失败: %w", certFile, err)
		}
		if _, err := os.Stat(keyFile); err != nil {
			return "", "", fmt.Errorf("读取私钥 %s 失败: %w", keyFile, err)
		}
		return certFile, keyFile, nil
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return "", "", fmt.Errorf("创建数据目录失败: %w", err)
	}
	certFile = filepath.Join(dataDir, "tls_cert.pem")
	keyFile = filepath.Join(dataDir, "tls_key.pem")
	if fileExists(certFile) && fileExists(keyFile) {
		return certFile, keyFile, nil
	}
	if err := generateSelfSigned(certFile, keyFile); err != nil {
		return "", "", err
	}
	return certFile, keyFile, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func generateSelfSigned(certFile, keyFile string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("生成 TLS 私钥失败: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("生成证书序列号失败: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "dx-sms-center", Organization: []string{"DX SMS Center"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	for _, ip := range localIPs() {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("签发自签证书失败: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("导出私钥失败: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("写入证书失败: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("写入私钥失败: %w", err)
	}
	return nil
}

// localIPs 枚举本机所有非回环 IPv4 地址，用于证书 SAN。
func localIPs() []net.IP {
	var out []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				out = append(out, ip.To4())
			}
		}
	}
	return out
}
