package auth

import (
	"zerotrust-draw/internal/db"
	pkgauth "zerotrust-draw/pkg/auth"
)

// SessionAuthenticator는 pkg/auth.Authenticator 인터페이스를 구현합니다.
// DB sessions 테이블을 기반으로 세션을 검증합니다.
//
// C·D팀 인터페이스 계약:
//   - ValidateSession(sessionID) → (*UserClaims, error)
//   - 실패 시 항상 ErrSessionInvalid 반환 (원인 구분 없음)
type SessionAuthenticator struct {
	store *db.SessionStore
}

// NewSessionAuthenticator는 SessionAuthenticator를 생성합니다.
func NewSessionAuthenticator(store *db.SessionStore) *SessionAuthenticator {
	return &SessionAuthenticator{store: store}
}

// ValidateSession은 세션 ID를 검증하고 UserClaims를 반환합니다.
// 세션 없음·만료·변조 모두 ErrSessionInvalid를 반환합니다.
func (a *SessionAuthenticator) ValidateSession(sessionID string) (*pkgauth.UserClaims, error) {
	s, err := a.store.Get(sessionID)
	if err != nil {
		// 원인을 구분하지 않고 단일 에러 반환
		return nil, pkgauth.ErrSessionInvalid
	}

	// last_seen_at 갱신 (에러 무시: 조회 실패여도 인증은 성공)
	_ = a.store.UpdateLastSeen(sessionID)

	return s.Claims, nil
}

// 컴파일 타임에 인터페이스 구현 여부 확인
var _ pkgauth.Authenticator = (*SessionAuthenticator)(nil)
