package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPToHTTPSHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "http://192.168.1.10:8080/sdwl/index.html?a=1&b=2", nil)
	w := httptest.NewRecorder()
	httpToHTTPSHandler().ServeHTTP(w, req)
	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("期望 301，实际 %d", w.Code)
	}
	want := "https://192.168.1.10:8080/sdwl/index.html?a=1&b=2"
	if loc := w.Header().Get("Location"); loc != want {
		t.Fatalf("跳转地址 %q，期望 %q", loc, want)
	}
}

func TestProtoListenerSplitAndRedirect(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, err := ensureTLSCert(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proto := newProtoListener(ln)
	defer proto.close()

	httpsSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "SECURE:"+r.URL.Path)
	})}
	redirect := &http.Server{Handler: httpToHTTPSHandler()}
	go httpsSrv.ServeTLS(proto.tlsListener(), certFile, keyFile)
	go redirect.Serve(proto.plainListener())
	defer httpsSrv.Close()
	defer redirect.Close()

	addr := ln.Addr().String()

	// 明文 HTTP 请求应收到 301 到 https。
	plainConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(plainConn, fmt.Sprintf("GET /sdwl/login.js HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr))
	resp, err := http.ReadResponse(bufio.NewReader(plainConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	plainConn.Close()
	if resp.StatusCode != http.StatusMovedPermanently || !strings.Contains(resp.Header.Get("Location"), "https://"+addr+"/sdwl/login.js") {
		t.Fatalf("HTTP 未跳转到 HTTPS: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}

	// TLS 请求应被分流到 HTTPS 服务并拿到正常响应。
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	res, err := client.Get("https://" + addr + "/sdwl/login.js")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(b) != "SECURE:/sdwl/login.js" {
		t.Fatalf("HTTPS 响应异常: %d %q", res.StatusCode, b)
	}
}

func TestProtoListenerCloseStopsAccept(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proto := newProtoListener(ln)
	addr := ln.Addr().String()
	proto.close()
	time.Sleep(50 * time.Millisecond)
	if _, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		t.Error("监听器关闭后仍可连接")
	}
}
