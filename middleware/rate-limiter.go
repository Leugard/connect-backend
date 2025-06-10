package middleware

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	limiters  = make(map[string]*rate.Limiter)
	mu        sync.Mutex
	rateLimit = rate.Every(12 * time.Second)
	burst     = 5
)

func GetIP(rAddr string) string {
	ip, _, err := net.SplitHostPort(rAddr)
	if err != nil {
		return rAddr
	}

	return ip
}

func getLimiter(ip string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	limiter, exists := limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rateLimit, burst)
		limiters[ip] = limiter
	}

	return limiter
}

func AllowRequest(ip string) bool {
	return getLimiter(ip).Allow()
}
