package main

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	go func() {
		log.Printf("短信服务已启动: http://%s (数据目录: %s)", cfg.Addr, cfg.DataDir)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("服务异常退出: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
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
