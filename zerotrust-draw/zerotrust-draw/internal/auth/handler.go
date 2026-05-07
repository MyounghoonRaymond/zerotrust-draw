// Package auth HTTP 핸들러
// POST /api/auth/signup  — 회원가입
// POST /api/auth/login   — 로그인 → HttpOnly 세션 쿠키 발급
// POST /api/auth/logout  — 로그아웃 → 세션 쿠키 삭제
package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"zerotrust-draw/internal/middleware"
	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/response"
	"zerotrust-draw/pkg/session"
)

// isSecureCookie는 TLS 환경일 때 true를 반환하여 Secure 쿠키 플래그를 켭니다.
func isSecureCookie() bool {
	return os.Getenv("TLS_CERT_FILE") != ""
}

// sessionCookieAttrs는 발급/삭제 시 동일하게 적용해야 하는 쿠키 속성을 반환합니다.
// 삭제 시 속성이 다르면 브라우저가 쿠키를 지우지 않을 수 있습니다.
func sessionCookieAttrs(value string, expires time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     session.CookieName,
		Value:    value,
		Expires:  expires,
		MaxAge:   maxAge,
		HttpOnly: true,                    // OWASP A03 — XSS로 JS 접근 불가
		Secure:   isSecureCookie(),        // OWASP A02 — HTTPS 환경에서만
		SameSite: http.SameSiteStrictMode, // OWASP A01/A05 — CSRF 방지
		Path:     "/",
	}
}

// Handler는 인증 관련 HTTP 핸들러를 담습니다.
type Handler struct {
	svc *Service
}

// NewHandler는 Handler를 생성합니다.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// ─────────────────────────────────────────────
//  POST /api/auth/signup
// ─────────────────────────────────────────────

type signupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Signup handles POST /api/auth/signup
func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")

	var req signupRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // 잉여 필드 거부 — 정책 우회 / 파라미터 오염 방어
	if err := dec.Decode(&req); err != nil {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "요청을 처리할 수 없습니다."}, reqID)
		return
	}

	result, err := h.svc.Signup(req.Username, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserAlreadyExists):
			// 사용자 존재 여부를 노출하지 않기 위해 일반 오류로 응답
			response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "요청을 처리할 수 없습니다."}, reqID)
		case errors.Is(err, ErrInvalidUsername),
			errors.Is(err, ErrWeakPassword),
			errors.Is(err, ErrPasswordTooLong):
			// 정책 세부 노출 차단 — 단일 메시지로 통일
			response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "요청을 처리할 수 없습니다."}, reqID)
		default:
			response.Error(w, appErrors.ErrSystemError, reqID)
		}
		return
	}

	response.JSON(w, http.StatusCreated, map[string]string{
		"userId":   result.UserID,
		"username": result.Username,
		"role":     string(result.Role),
	}, reqID)
}

// ─────────────────────────────────────────────
//  POST /api/auth/login
// ─────────────────────────────────────────────

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Login handles POST /api/auth/login
// 성공 시 HttpOnly 세션 쿠키 발급. 응답 바디에 세션 ID 포함하지 않음.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")

	var req loginRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		response.Error(w, &appErrors.AppError{Code: "ERR_BID_004", Message: "요청을 처리할 수 없습니다."}, reqID)
		return
	}

	result, err := h.svc.Login(req.Username, req.Password)
	if err != nil {
		// 실패 원인 구분 없이 단일 응답 (사용자 존재 여부 / 잠금 여부 모두 숨김)
		response.Error(w, appErrors.ErrAuthInvalid, reqID)
		return
	}

	// HttpOnly 세션 쿠키 발급
	cookie := sessionCookieAttrs(result.SessionID, result.ExpiresAt, 0)
	http.SetCookie(w, cookie)

	response.JSON(w, http.StatusOK, map[string]interface{}{
		"userId":    result.UserID,
		"username":  result.Username,
		"role":      string(result.Role),
		"expiresAt": result.ExpiresAt.Format(time.RFC3339),
	}, reqID)
}

// ─────────────────────────────────────────────
//  POST /api/auth/logout
// ─────────────────────────────────────────────

// Logout handles POST /api/auth/logout
// 세션 쿠키를 즉시 만료시키고 DB에서 세션을 삭제합니다.
// 보안: 삭제 쿠키의 Secure/SameSite/Path 가 발급 시와 동일해야 브라우저가 정상 삭제합니다.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")

	cookie, err := r.Cookie(session.CookieName)
	if err == nil {
		_ = h.svc.Logout(cookie.Value)
	}

	expired := sessionCookieAttrs("", time.Unix(0, 0), -1)
	http.SetCookie(w, expired)

	response.JSON(w, http.StatusOK, map[string]string{"message": "ok"}, reqID)
}

// ─────────────────────────────────────────────
//  GET /api/auth/me
// ─────────────────────────────────────────────

// Me handles GET /api/auth/me — 인증된 사용자 정보 반환.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")

	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		response.Error(w, appErrors.ErrAuthInvalid, reqID)
		return
	}
	response.JSON(w, http.StatusOK, map[string]string{
		"userId":   claims.UserID,
		"username": claims.Username,
		"role":     claims.Role,
	}, reqID)
}
