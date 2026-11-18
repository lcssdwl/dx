package app

import (
	"sync"
	"time"
)

type window struct {
	start time.Time
	count int
}

// limiter 为固定窗口限流器，key 通常为 token 或客户端 IP。
type limiter struct {
	mu     sync.Mutex
	limit  int
	period time.Duration
	hits   map[string]*window
	ops    uint64
}

func newLimiter(limit int, period time.Duration) *limiter {
	return &limiter{limit: limit, period: period, hits: make(map[string]*window)}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	// 每 256 次调用惰性清理一次过期窗口：无需常驻 goroutine，
	// 既避免测试/多实例场景的 goroutine 泄漏，也防止 hit map 无限增长。
	l.ops++
	if l.ops%256 == 0 {
		for k, w := range l.hits {
			if now.Sub(w.start) >= l.period {
				delete(l.hits, k)
			}
		}
	}
	w := l.hits[key]
	if w == nil || now.Sub(w.start) >= l.period {
		l.hits[key] = &window{start: now, count: 1}
		return true
	}
	if w.count >= l.limit {
		return false
	}
	w.count++
	return true
}
