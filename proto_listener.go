package main

import (
	"bufio"
	"net"
	"net/http"
	"sync"
	"time"
)

// bufferedConn 保存预读的字节，避免第一个字节被吃掉。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// protoListener 在同一 TCP 端口上按首字节分流：
// TLS ClientHello 首字节为 0x16 -> tls 通道（HTTPS）；其余 -> plain 通道（HTTP 301 跳转）。
type protoListener struct {
	raw   net.Listener
	tls   chan net.Conn
	plain chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newProtoListener(raw net.Listener) *protoListener {
	p := &protoListener{
		raw:   raw,
		tls:   make(chan net.Conn, 64),
		plain: make(chan net.Conn, 64),
		done:  make(chan struct{}),
	}
	go p.acceptLoop()
	return p
}

func (p *protoListener) acceptLoop() {
	for {
		c, err := p.raw.Accept()
		if err != nil {
			p.close()
			return
		}
		go p.route(c)
	}
}

func (p *protoListener) route(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		_ = c.Close()
		return
	}
	bc := &bufferedConn{Conn: c, r: br}
	target := p.plain
	if b[0] == 0x16 {
		target = p.tls
	}
	select {
	case target <- bc:
	case <-p.done:
		_ = c.Close()
	}
}

func (p *protoListener) close() {
	p.once.Do(func() {
		close(p.done)
		close(p.tls)
		close(p.plain)
		_ = p.raw.Close()
	})
}

// subListener 把某一路连接通道包装成 net.Listener 供 http.Server 使用。
type subListener struct {
	ch   <-chan net.Conn
	done <-chan struct{}
	addr net.Addr
	once sync.Once
}

func (l *subListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *subListener) Close() error   { return nil }
func (l *subListener) Addr() net.Addr { return l.addr }

func (p *protoListener) tlsListener() net.Listener {
	return &subListener{ch: p.tls, done: p.done, addr: p.raw.Addr()}
}
func (p *protoListener) plainListener() net.Listener {
	return &subListener{ch: p.plain, done: p.done, addr: p.raw.Addr()}
}

// httpToHTTPSHandler 把 HTTP 请求 301 到同主机同路径的 HTTPS。
func httpToHTTPSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if host == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}
