package main

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"dx/internal"
)

//go:embed web
var webFS embed.FS

func main() {
	cfg := app.LoadConfig()

	store, err := app.NewStore(cfg.DataDir, cfg.LegacyMasterKey)
	if err != nil {
		log.Fatalf("初始化存储失败: %v", err)
	}
	web, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("加载前端资源失败: %v", err)
	}

	initAdmin(store)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           app.NewHandler(cfg, store, web),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	var redirectSrv atomic.Pointer[http.Server]
	go func() {
		if cfg.TLSEnabled {
			certFile, keyFile, err := ensureTLSCert(cfg.DataDir, cfg.TLSCertFile, cfg.TLSKeyFile)
			if err != nil {
				log.Fatalf("准备 TLS 证书失败: %v", err)
			}
			ln, err := net.Listen("tcp", cfg.Addr)
			if err != nil {
				log.Fatalf("监听 %s 失败: %v", cfg.Addr, err)
			}
			proto := newProtoListener(ln)

			// HTTP 请求自动 301 跳转到 HTTPS，同端口共存。
			redirect := &http.Server{
				Handler:           httpToHTTPSHandler(),
				ReadHeaderTimeout: 5 * time.Second,
			}
			redirectSrv.Store(redirect)
			go func() {
				if err := redirect.Serve(proto.plainListener()); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
					log.Printf("HTTP 重定向服务退出: %v", err)
				}
			}()

			note := ""
			if cfg.TLSCertFile == "" {
				note = "（自签证书，浏览器首次访问需信任）"
			}
			log.Printf("短信服务已启动: https://%s%s (数据目录: %s, 证书: %s)", cfg.Addr, note, cfg.DataDir, certFile)
			log.Printf("HTTP 访问同端口将自动 301 跳转到 HTTPS")
			if err := srv.ServeTLS(proto.tlsListener(), certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				log.Fatalf("服务异常退出: %v", err)
			}
			return
		}
		log.Printf("短信服务已启动: http://%s (数据目录: %s, 内置 HTTPS 已关闭)", cfg.Addr, cfg.DataDir)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("服务异常退出: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if redirect := redirectSrv.Load(); redirect != nil {
		if err := redirect.Shutdown(ctx); err != nil {
			log.Printf("重定向服务退出失败: %v", err)
		}
	}
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("优雅退出失败: %v", err)
	}
	log.Println("服务已停止")
}

// initAdmin 根据环境变量创建初始管理员（可选）。
// DX_INIT_ADMIN_USER / DX_INIT_ADMIN_PASS 必填其一则必须同时提供；DX_INIT_ADMIN_TOKEN 可选。
func initAdmin(store *app.Store) {
	username := strings.TrimSpace(os.Getenv("DX_INIT_ADMIN_USER"))
	password := os.Getenv("DX_INIT_ADMIN_PASS")
	if username == "" && password == "" {
		return
	}
	if username == "" || password == "" {
		log.Println("跳过初始管理员：需同时设置 DX_INIT_ADMIN_USER 与 DX_INIT_ADMIN_PASS")
		return
	}
	u, err := store.CreateUserWithToken(username, password, strings.TrimSpace(os.Getenv("DX_INIT_ADMIN_TOKEN")))
	if errors.Is(err, app.ErrUsernameExists) {
		return
	}
	if err != nil {
		log.Printf("创建初始管理员失败: %v", err)
		return
	}
	log.Printf("初始管理员已创建: %s，其 API Token 为: %s（请妥善保存）", u.Username, u.TokenPlain)
}
