// Package auth는 인증 계약(인터페이스)을 정의합니다.
//
// ★ 이 파일은 C팀이 작성합니다. A·B팀은 이 인터페이스를 구현하기만 하면 됩니다.
// ★ 필드명·타입은 Day 1 합의 내용 기준입니다. 변경 시 PR + 전 팀원 동의 필수.
//
// [JWT → 세션 전환]
//   - JWT는 서버가 즉시 무효화할 수 없어 탈취 대응이 어렵습니다.
//   - 세션은 DB(sessions 테이블)에서 직접 삭제·만료 처리가 가능합니다.
//
// [RoleGuest 추가 — A·B팀 변경사항 반영]
//   - GUEST는 경매 조회(GET)만 허용합니다.
//   - HasRole에서 GUEST는 명시적 요청에만 통과합니다.
package auth

import (
	"zerotrust-draw/pkg/models"
	"time"
)

// Session은 DB에서 조회한 세션 정보입니다. (session_store 내부용)
type Session struct {
	Claims    *UserClaims
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

// Authenticator는 A·B팀이 반드시 이 형태로 구현해야 하는 인증 인터페이스입니다.
// 세션 ID를 받아 유효한 사용자 정보를 반환합니다.
//
// 구현 시 주의사항:
//   - 세션 ID는 crypto/rand로 생성한 16바이트 이상의 무작위 값이어야 합니다.
//   - 세션은 DB(sessions 테이블)에 저장하고 만료·로그아웃 시 즉시 삭제합니다.
//   - 에러 종류(세션 없음 / 만료 / 변조)를 클라이언트에 구분해서 알려주지 않습니다.
//     → 항상 ErrSessionInvalid 하나만 반환합니다.
type Authenticator interface {
	// ValidateSession은 세션 ID를 검증하고 사용자 정보를 반환합니다.
	// 세션이 없거나 만료되었거나 변조된 경우 모두 동일하게 ErrSessionInvalid를 반환합니다.
	ValidateSession(sessionID string) (*UserClaims, error)
}

// UserClaims는 ValidateSession이 반환하는 사용자 정보입니다.
type UserClaims struct {
	UserID   string // DB users.id (UUID v4)
	Username string // DB users.username
	Role     string // models.Role 상수값: "BIDDER" | "AUCTIONEER" | "ADMIN" | "GUEST"
}

// HasRole은 UserClaims의 Role이 주어진 role과 일치하는지 확인합니다.
//
// 규칙:
//   - GUEST 체크를 최우선으로 처리합니다. ADMIN이라도 GUEST 전용 경로를 통과하지 못합니다.
//   - ADMIN은 GUEST를 제외한 모든 역할 요구를 충족합니다.
//   - GUEST 사용자는 HasRole(RoleBidder), HasRole(RoleAuctioneer)에서 자동으로 false가 되어
//     C팀 서비스 레이어에서 별도 GUEST 차단 로직 없이 자동 차단됩니다.
func (c *UserClaims) HasRole(role models.Role) bool {
	userRole := models.Role(c.Role)

	// GUEST 전용 경로: 정확히 GUEST인 경우에만 허용 (ADMIN도 통과 불가)
	if role == models.RoleGuest {
		return userRole == models.RoleGuest
	}

	// ADMIN은 GUEST를 제외한 모든 역할 요구를 충족
	if userRole == models.RoleAdmin {
		return true
	}

	return userRole == role
}

// 인증 관련 공통 에러
// ※ 세션 없음 / 만료 / 변조를 구분하지 않고 ErrSessionInvalid 하나로 통일합니다.
//
//	공격자가 세션 존재 여부나 만료 시각을 유추할 수 없도록 합니다.
var (
	ErrSessionInvalid = sessionError("인증이 필요합니다.")
	ErrUnauthorized   = sessionError("요청을 처리할 수 없습니다.")
)

type sessionError string

func (e sessionError) Error() string { return string(e) }
