// Package middleware는 HTTP 미들웨어를 제공합니다.
package middleware

import (
	"context"
	"net/http"

	applog "zerotrust-draw/internal/log"
	"zerotrust-draw/pkg/auth"
	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/response"
	"zerotrust-draw/pkg/session"
)

// contextKey는 context에 값을 저장할 때 쓰는 타입입니다.
type contextKey string

const (
	// ClaimsKey는 context에서 UserClaims를 꺼낼 때 사용하는 키입니다.
	ClaimsKey contextKey = "claims"
)

// Auth는 세션 쿠키를 검증하는 미들웨어입니다.
// 변경: Authorization Bearer 헤더 → HttpOnly 세션 쿠키 방식으로 전환
// 검증 성공 시 UserClaims를 context에 저장하고 next를 호출합니다.
// 검증 실패 시 에러 원인을 구분하지 않고 ERR_AUTH_001(401)만 반환합니다.
func Auth(authenticator auth.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := r.Header.Get("X-Request-Id")

			// 세션 쿠키 추출
			sessionID, err := extractSessionCookie(r)
			if err != nil {
				// 세션 없음 — 원인을 클라이언트에 노출하지 않음
				applog.Warn("SESSION_INVALID", "", "", reqID, "세션 쿠키 없음", "ERR_AUTH_001")
				response.Error(w, appErrors.ErrAuthInvalid, reqID)
				return
			}

			// 세션 검증 — 없음/만료/변조 모두 동일한 에러 반환
			claims, err := authenticator.ValidateSession(sessionID)
			if err != nil {
				applog.Warn("SESSION_INVALID", "", "", reqID, "세션 검증 실패", "ERR_AUTH_001")
				response.Error(w, appErrors.ErrAuthInvalid, reqID)
				return
			}

			// claims를 context에 저장 후 다음 핸들러로 전달
			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext는 context에서 UserClaims를 꺼냅니다.
// Auth 미들웨어를 거친 요청에서만 유효합니다.
func ClaimsFromContext(ctx context.Context) (*auth.UserClaims, bool) {
	claims, ok := ctx.Value(ClaimsKey).(*auth.UserClaims)
	return claims, ok
}

// extractSessionCookie는 HttpOnly 세션 쿠키에서 세션 ID를 추출합니다.
// 쿠키가 없거나 값이 비어있으면 에러를 반환합니다.
func extractSessionCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(session.CookieName)
	if err != nil || cookie.Value == "" {
		return "", appErrors.ErrAuthInvalid
	}
	return cookie.Value, nil
}
