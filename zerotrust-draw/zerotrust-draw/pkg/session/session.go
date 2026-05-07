// Package session은 서버 사이드 세션을 관리합니다.
//
// 세션 흐름:
//  1. 로그인 시 Create() 호출 → 세션 ID(쿠키) 발급
//  2. 요청마다 Get() 로 세션 조회 → UserClaims 반환
//  3. 로그아웃 시 Delete() 호출 → 세션 파기
package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"zerotrust-draw/pkg/auth"
)

// 세션 관련 공통 에러
var (
	ErrSessionNotFound = errors.New("세션이 존재하지 않습니다")
	ErrSessionExpired  = errors.New("세션이 만료되었습니다")
)

// CookieName은 세션 ID를 담는 HTTP 쿠키 이름입니다.
// 일반적인 "session_id" 대신 앱 고유 이름으로 핑거프린팅을 방지합니다.
const CookieName = "__ba_sid"

// DefaultTTL은 세션 기본 유효 기간(24시간)입니다.
const DefaultTTL = 24 * time.Hour

// Store는 세션 저장소 인터페이스입니다.
// 인메모리 구현체(MemoryStore)를 기본 제공하며, Redis 등으로 교체 가능합니다.
type Store interface {
	// Create는 새 세션을 생성하고 세션 ID를 반환합니다.
	Create(claims *auth.UserClaims, ttl time.Duration) (sessionID string, err error)
	// Get은 세션 ID로 UserClaims를 조회합니다. 만료된 세션은 ErrSessionExpired를 반환합니다.
	Get(sessionID string) (*auth.UserClaims, error)
	// Delete는 세션을 삭제합니다(로그아웃).
	Delete(sessionID string) error
}

// entry는 내부적으로 세션 데이터와 만료 시각을 함께 저장합니다.
type entry struct {
	claims    *auth.UserClaims
	expiresAt time.Time
}

// MemoryStore는 sync.Map 기반 인메모리 세션 저장소입니다.
//
// ⚠️  단일 프로세스 전용 — 다중 인스턴스 환경에서는 Redis 기반 구현체로 교체하세요.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]*entry
}

// NewMemoryStore는 MemoryStore를 초기화하고 백그라운드 만료 정리 고루틴을 시작합니다.
func NewMemoryStore() *MemoryStore {
	s := &MemoryStore{
		entries: make(map[string]*entry),
	}
	go s.cleanupLoop()
	return s
}

// Create는 새 세션을 생성하고 세션 ID(128-bit hex)를 반환합니다.
func (s *MemoryStore) Create(claims *auth.UserClaims, ttl time.Duration) (string, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[sessionID] = &entry{
		claims:    claims,
		expiresAt: time.Now().Add(ttl),
	}
	return sessionID, nil
}

// Get은 세션 ID로 UserClaims를 반환합니다.
func (s *MemoryStore) Get(sessionID string) (*auth.UserClaims, error) {
	s.mu.RLock()
	e, ok := s.entries[sessionID]
	s.mu.RUnlock()

	if !ok {
		return nil, ErrSessionNotFound
	}
	if time.Now().After(e.expiresAt) {
		s.mu.Lock()
		delete(s.entries, sessionID)
		s.mu.Unlock()
		return nil, ErrSessionExpired
	}
	return e.claims, nil
}

// Delete는 세션을 삭제합니다.
func (s *MemoryStore) Delete(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, sessionID)
	return nil
}

// cleanupLoop는 60초마다 만료된 세션을 정리합니다.
func (s *MemoryStore) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for id, e := range s.entries {
			if now.After(e.expiresAt) {
				delete(s.entries, id)
			}
		}
		s.mu.Unlock()
	}
}

// generateSessionID는 암호학적으로 안전한 128-bit 세션 ID를 생성합니다.
func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
