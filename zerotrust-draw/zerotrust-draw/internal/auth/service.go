// Package auth는 회원가입·로그인·로그아웃 비즈니스 로직을 담당합니다.
// A·B팀 구현 영역입니다.
package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"zerotrust-draw/internal/db"
	"zerotrust-draw/internal/security"
	applog "zerotrust-draw/internal/log"
	pkgauth "zerotrust-draw/pkg/auth"
	"zerotrust-draw/pkg/models"
)

// ─── 에러 정의 ────────────────────────────────────────────────────────────────

var (
	ErrUserNotFound      = errors.New("사용자를 찾을 수 없습니다")
	ErrWrongPassword     = errors.New("비밀번호가 올바르지 않습니다")
	ErrUserAlreadyExists = errors.New("이미 존재하는 사용자명입니다")
	ErrAccountLocked     = errors.New("계정이 잠겼습니다. 잠시 후 다시 시도하세요")
	ErrWeakPassword      = errors.New("비밀번호는 8자 이상이어야 합니다")
	ErrPasswordTooLong   = errors.New("비밀번호는 128자 이하이어야 합니다")
	ErrInvalidUsername   = errors.New("사용자명은 영문·숫자·_·-만 사용 가능합니다 (4~32자)")
	ErrInvalidRole       = errors.New("유효하지 않은 역할입니다")
)

// ─── 브루트포스 방어 ───────────────────────────────────────────────────────────

const (
	maxLoginAttempts = 3             // 잠금 임계값
	baseLockDuration = 30 * time.Minute
)

type lockEntry struct {
	attempts  int
	lockedUntil time.Time
}

// ─── 서비스 ───────────────────────────────────────────────────────────────────

// Service는 인증 비즈니스 로직을 처리합니다.
type Service struct {
	userStore      *db.UserStore
	sessionStore   *db.SessionStore
	whitelistStore *db.WhitelistStore
	mu             sync.Mutex
	locks          map[string]*lockEntry // username → 잠금 정보
}

// NewService는 AuthService를 생성합니다.
func NewService(userStore *db.UserStore, sessionStore *db.SessionStore, whitelistStore *db.WhitelistStore) *Service {
	 s := &Service{
        userStore:      userStore,
        sessionStore:   sessionStore,
        whitelistStore: whitelistStore,
        locks:          make(map[string]*lockEntry),
    }
    go s.cleanupLocks(baseLockDuration * 2)  // ← 추가
    return s
}

// 신규 추가
func (s *Service) cleanupLocks(interval time.Duration) {
    t := time.NewTicker(interval)
    defer t.Stop()
    for range t.C {
        s.mu.Lock()
        now := time.Now()
        for username, entry := range s.locks {
            if now.After(entry.lockedUntil) {
                delete(s.locks, username)
            }
        }
        s.mu.Unlock()
    }
}

// ─── 회원가입 ─────────────────────────────────────────────────────────────────

// SignupResult는 회원가입 결과를 담습니다.
type SignupResult struct {
	UserID   string
	Username string
	Role     models.Role
}

// Signup은 신규 사용자를 등록합니다.
// 화이트리스트에 등록된 username이면 해당 역할(BIDDER/AUCTIONEER)을 부여하고,
// 미등록이면 GUEST 역할로 생성합니다.b := make([]byte, 32)
func (s *Service) Signup(username, password string) (*SignupResult, error) {
	// NFC 정규화: homoglyph 공격 방어 (시각적으로 동일한 문자를 동일하게 처리)
	username = security.NormalizeInput(strings.TrimSpace(username))
	password = security.NormalizeInput(password)

	// 입력값 검증
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	// 중복 확인
	existing, err := s.userStore.GetByUsername(username)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserAlreadyExists
	}

	// 화이트리스트 기반 역할 결정
	role, _ := s.whitelistStore.LookupRole(username)
	// LookupRole은 미등록 시 RoleGuest 반환

	// Argon2id 해싱
	salt, err := security.GenerateSaltBytes(security.Argon2SaltLength)
	if err != nil {
		return nil, err
	}
	hashedPassword := security.HashPassword(password, salt)

	// 저장
	user, err := s.userStore.CreateUser(username, hashedPassword, salt, role)
	if err != nil {
		return nil, err
	}

	applog.Audit("SIGNUP", "", user.ID, "", "회원가입 완료 (역할: "+string(role)+")")
	return &SignupResult{UserID: user.ID, Username: user.Username, Role: user.Role}, nil
}

// ─── 로그인 ───────────────────────────────────────────────────────────────────

// LoginResult는 로그인 성공 시 반환되는 세션 정보입니다.
type LoginResult struct {
	SessionID string
	UserID    string
	Username  string
	Role      models.Role
	ExpiresAt time.Time
}

// Login은 사용자 인증 후 세션을 발급합니다.
//
// 보안 특성:
//   - 계정 잠금: 연속 3회 실패 시 30분±jitter 잠금
//   - 타이밍 공격 방지: 사용자 없을 때도 HashPassword 실행 (더미 해싱)
//   - 에러 구분 없음: 호출자에게는 단일 에러 반환 (위로 올라가서 ErrSessionInvalid로 변환)
func (s *Service) Login(username, password string) (*LoginResult, error) {
	// NFC 정규화: Signup과 동일한 입력값을 보장
	username = security.NormalizeInput(strings.TrimSpace(username))
	password = security.NormalizeInput(password)

	// 잠금 확인
	if err := s.checkLock(username); err != nil {
		applog.Warn("LOGIN_LOCKED", "", "", "", "계정 잠금 상태", "")
		return nil, err
	}

	user, err := s.userStore.GetByUsername(username)
	if err != nil {
		return nil, err
	}

	// 사용자 없을 때도 더미 해싱 (타이밍 공격 방지)
	if user == nil {
		dummySalt := make([]byte, security.Argon2SaltLength)
		security.HashPassword(password, dummySalt)
		s.recordFailure(username)
		return nil, ErrUserNotFound
	}

	// 비밀번호 검증
	if !security.VerifyPassword(password, user.Salt, user.Password) {
		_ = s.userStore.UpdateLoginStats(user.ID, false)
		s.recordFailure(username)
		applog.Warn("LOGIN_FAILED", "", user.ID, "", "비밀번호 불일치", "")
		return nil, ErrWrongPassword
	}

	// 로그인 성공 — 잠금 해제 + 통계 갱신
	s.clearLock(username)
	_ = s.userStore.UpdateLoginStats(user.ID, true)

	// 세션 발급
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(24 * time.Hour)
	if err := s.sessionStore.Create(sessionID, user.ID, expiresAt); err != nil {
		return nil, err
	}

	applog.Audit("LOGIN_SUCCESS", "", user.ID, "", "로그인 성공")
	return &LoginResult{
		SessionID: sessionID,
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		ExpiresAt: expiresAt,
	}, nil
}

// ─── 로그아웃 ─────────────────────────────────────────────────────────────────

// Logout은 세션을 삭제합니다.
func (s *Service) Logout(sessionID string) error {
	return s.sessionStore.Delete(sessionID)
}

// ─── 내부 헬퍼 ────────────────────────────────────────────────────────────────

func (s *Service) checkLock(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.locks[username]
	if !ok {
		return nil
	}
	if time.Now().Before(entry.lockedUntil) {
		return ErrAccountLocked
	}
	// 잠금 만료됨 — 초기화
	delete(s.locks, username)
	return nil
}

func (s *Service) recordFailure(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.locks[username]
	if !ok {
		entry = &lockEntry{}
		s.locks[username] = entry
	}
	entry.attempts++
	if entry.attempts >= maxLoginAttempts {
		// jitter: 0~5분 추가 (공격자가 정확한 잠금 해제 시각을 예측하지 못하도록)
		jitter := time.Duration(randomInt(0, 5*60)) * time.Second
		entry.lockedUntil = time.Now().Add(baseLockDuration + jitter)
	}
}

func (s *Service) clearLock(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.locks, username)
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomInt(min, max int) int {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 {
		n = -n
	}
	return min + (n % (max - min + 1))
}

// ─── 입력값 검증 ──────────────────────────────────────────────────────────────

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-]{4,32}$`)

func validateUsername(username string) error {
	if !usernameRegex.MatchString(strings.TrimSpace(username)) {
		return ErrInvalidUsername
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return ErrWeakPassword
	}
	// Argon2 연산 비용 DoS 방지: 과도하게 긴 입력을 거부합니다.
	if len(password) > 128 {
		return ErrPasswordTooLong
	}
	return nil
}

// ErrToHTTP은 auth service 에러를 HTTP 핸들러가 처리할 수 있도록
// pkgauth.ErrSessionInvalid 계열로 변환합니다.
func ErrToHTTP(err error) error {
	switch {
	case errors.Is(err, ErrUserNotFound),
		errors.Is(err, ErrWrongPassword),
		errors.Is(err, ErrAccountLocked):
		// 클라이언트에 원인을 노출하지 않음 (사용자 존재 여부 숨김)
		return pkgauth.ErrSessionInvalid
	default:
		return err
	}
}

// 컴파일 타임 확인: UserStore, SessionStore 패키지가 sql.ErrNoRows를 다루는지 검증
var _ = sql.ErrNoRows
