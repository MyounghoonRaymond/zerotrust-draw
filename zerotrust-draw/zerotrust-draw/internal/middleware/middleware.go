package middleware

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	applog "zerotrust-draw/internal/log"
	"zerotrust-draw/internal/security"
	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/response"
)

// ─────────────────────────────────────────────
//  요청 바디 크기 제한
// ─────────────────────────────────────────────

const (
	// MaxBodyBytes는 모든 JSON 요청 바디 상한입니다 (16KB).
	MaxBodyBytes int64 = 16 * 1024
)

// LimitBody는 요청 바디를 MaxBodyBytes로 제한하는 미들웨어입니다.
func LimitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// ─────────────────────────────────────────────
//  보안 헤더 (OWASP A05:2021 — Security Misconfiguration)
// ─────────────────────────────────────────────

// SecurityHeaders는 모든 응답에 OWASP 권장 보안 헤더를 추가합니다.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy", "default-src 'none'")
		// 응답 헤더로 서버/프레임워크 정보 누출 차단
		h.Set("Server", "")
		h.Set("X-Powered-By", "")
		next.ServeHTTP(w, r)
	})
}

// ─────────────────────────────────────────────
//  Content-Type 검증
// ─────────────────────────────────────────────

// RequireJSON은 POST/PUT/PATCH 요청에 Content-Type: application/json 강제.
func RequireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				reqID := r.Header.Get("X-Request-Id")
				response.Error(w, &appErrors.AppError{
					Code:    "ERR_BID_004",
					Message: "요청을 처리할 수 없습니다.",
				}, reqID)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ─────────────────────────────────────────────
//  입력 검증 헬퍼
// ─────────────────────────────────────────────

// ValidateCommitRequest는 입찰 Commit 요청을 검증합니다.
func ValidateCommitRequest(hash string) error {
	if !security.ValidateHash(hash) {
		return appErrors.ErrInvalidHashFmt
	}
	if security.ContainsDangerousChars(hash) {
		return appErrors.ErrInvalidHashFmt
	}
	return nil
}

// ValidateRevealRequest는 입찰 Reveal 요청을 검증합니다.
func ValidateRevealRequest(price int, salt string) error {
	if price < 0 || price > 1_000_000_000 {
		return appErrors.ErrInvalidPrice
	}
	if len(salt) < 32 || len(salt) > 128 {
		return appErrors.ErrInvalidHashFmt
	}
	if security.ContainsDangerousChars(salt) {
		return appErrors.ErrInvalidHashFmt
	}
	return nil
}

// ─────────────────────────────────────────────
//  Rate Limiter
// ─────────────────────────────────────────────

type requestRecord struct {
	count     int
	windowEnd time.Time
}

// RateLimiter는 사용자별 요청 횟수를 제한합니다 (1분 윈도우 등).
type RateLimiter struct {
	mu          sync.Mutex
	records     map[string]*requestRecord
	maxRequests int
	window      time.Duration
}

// NewRateLimiter는 RateLimiter를 생성합니다.
func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		records:     make(map[string]*requestRecord),
		maxRequests: maxRequests,
		window:      window,
	}
	go rl.cleanupLoop(window * 10)
	return rl
}

// cleanupLoop는 만료된 records 항목을 주기적으로 정리합니다.
func (rl *RateLimiter) cleanupLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		rl.mu.Lock()
		now := time.Now()
		for key, rec := range rl.records {
			if now.After(rec.windowEnd) {
				delete(rl.records, key)
			}
		}
		rl.mu.Unlock()
	}
}

// CheckRateLimit는 key의 요청 횟수를 확인하고 초과 시 에러를 반환합니다.
func (rl *RateLimiter) CheckRateLimit(key string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rec, exists := rl.records[key]
	if !exists || now.After(rec.windowEnd) {
		rl.records[key] = &requestRecord{count: 1, windowEnd: now.Add(rl.window)}
		return nil
	}
	rec.count++
	if rec.count > rl.maxRequests {
		applog.Warn("RATE_LIMIT_HIT", "", key, "", "요청 횟수 초과", "ERR_RATE_001")
		return appErrors.ErrRateLimit
	}
	return nil
}

// ─────────────────────────────────────────────
//  실제 클라이언트 IP 추출 (XFF 스푸핑 방어)
// ─────────────────────────────────────────────

// trustedProxies는 X-Forwarded-For / X-Real-IP 헤더를 신뢰할 프록시 목록입니다.
// TRUSTED_PROXY 환경변수 미설정 시(=빈 set) XFF 헤더는 무시되고 r.RemoteAddr만 사용됩니다.
//
// 보안:
//   - 빈 set일 때 XFF 무시 → 공격자가 헤더로 IP 위조 후 rate limit 우회 차단
//   - 신뢰 프록시 뒤일 때만 XFF의 첫 번째 항목(=원 클라이언트) 사용
var trustedProxies = func() map[string]struct{} {
	set := make(map[string]struct{})
	val := os.Getenv("TRUSTED_PROXY")
	if val == "" {
		return set
	}
	for _, ip := range strings.Split(val, ",") {
		set[strings.TrimSpace(ip)] = struct{}{}
	}
	return set
}()

// realIP는 실제 클라이언트 IP를 안전하게 추출합니다.
//
//	1. r.RemoteAddr 의 호스트만 추출 (IPv4/IPv6 모두 net.SplitHostPort 로 처리)
//	2. TRUSTED_PROXY 미설정 시 → RemoteAddr 만 사용
//	3. RemoteAddr 가 신뢰 프록시일 때만 X-Forwarded-For / X-Real-IP 사용
func realIP(r *http.Request) string {
	remoteHost := r.RemoteAddr
	if h, _, err := net.SplitHostPort(remoteHost); err == nil {
		remoteHost = h
	}

	if len(trustedProxies) == 0 {
		return remoteHost
	}
	if _, trusted := trustedProxies[remoteHost]; !trusted {
		return remoteHost
	}

	// 신뢰 프록시 뒤 → XFF 의 첫 번째(=원 클라이언트) 사용
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
		if first != "" {
			return first
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	return remoteHost
}

// Limit는 인증된 사용자 기반 Rate Limit 미들웨어 (Auth 미들웨어 뒤에 연결).
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-Id")
		claims, ok := ClaimsFromContext(r.Context())
		key := "ip:" + realIP(r)
		if ok {
			key = "user:" + claims.UserID
		}
		if err := rl.CheckRateLimit(key); err != nil {
			response.Error(w, appErrors.ErrRateLimit, reqID)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LimitByIP는 IP 주소 기반 Rate Limit 미들웨어 (공개 엔드포인트용).
func (rl *RateLimiter) LimitByIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-Id")
		key := "ip:" + realIP(r)
		if err := rl.CheckRateLimit(key); err != nil {
			applog.Warn("RATE_LIMIT_HIT", "", "", reqID, "공개 엔드포인트 IP 제한 초과", "ERR_RATE_001")
			response.Error(w, appErrors.ErrRateLimit, reqID)
			return
		}
		next.ServeHTTP(w, r)
	})
}
