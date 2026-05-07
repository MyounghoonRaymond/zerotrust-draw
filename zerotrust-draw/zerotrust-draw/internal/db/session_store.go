package db

import (
	"database/sql"
	"errors"
	"time"

	"zerotrust-draw/pkg/auth"
)

// SessionStore는 SQLite sessions 테이블을 관리합니다.
type SessionStore struct {
	db *sql.DB
}

// NewSessionStore는 SessionStore를 생성합니다.
func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

// Create는 새 세션을 INSERT합니다.
func (s *SessionStore) Create(sessionID, userID string, expiresAt time.Time) error {
	const q = `
		INSERT INTO sessions (session_id, user_id, expires_at, last_seen_at, created_at)
		VALUES (?, ?, ?, ?, ?)`
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(q,
		sessionID,
		userID,
		expiresAt.UTC().Format(time.RFC3339),
		now,
		now,
	)
	return err
}

// Get은 세션 ID로 Session을 조회합니다.
// 세션 없음·만료 모두 ErrSessionNotFound를 반환합니다 (클라이언트에 원인 숨김).
func (s *SessionStore) Get(sessionID string) (*auth.Session, error) {
	const q = `
		SELECT s.user_id, s.expires_at, s.last_seen_at, s.created_at,
		       u.username, u.role
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.session_id = ?`

	var userID, expiresAtStr, lastSeenStr, createdAtStr, username, role string
	err := s.db.QueryRow(q, sessionID).Scan(
		&userID, &expiresAtStr, &lastSeenStr, &createdAtStr,
		&username, &role,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, auth.ErrSessionInvalid
		}
		return nil, auth.ErrSessionInvalid
	}

	expiresAt, _ := time.Parse(time.RFC3339, expiresAtStr)
	if time.Now().After(expiresAt) {
		// 만료된 세션은 즉시 삭제
		_ = s.Delete(sessionID)
		return nil, auth.ErrSessionInvalid
	}

	lastSeen, _ := time.Parse(time.RFC3339, lastSeenStr)
	createdAt, _ := time.Parse(time.RFC3339, createdAtStr)

	return &auth.Session{
		Claims: &auth.UserClaims{
			UserID:   userID,
			Username: username,
			Role:     role,
		},
		CreatedAt: createdAt,
		LastSeen:  lastSeen,
		ExpiresAt: expiresAt,
	}, nil
}

// UpdateLastSeen은 세션의 마지막 활동 시각을 갱신합니다.
func (s *SessionStore) UpdateLastSeen(sessionID string) error {
	const q = `UPDATE sessions SET last_seen_at = ? WHERE session_id = ?`
	_, err := s.db.Exec(q, time.Now().UTC().Format(time.RFC3339), sessionID)
	return err
}

// Delete는 세션을 삭제합니다 (로그아웃 / 만료).
func (s *SessionStore) Delete(sessionID string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE session_id = ?`, sessionID)
	return err
}

// DeleteExpired는 만료된 세션을 일괄 삭제합니다 (주기적 정리용).
func (s *SessionStore) DeleteExpired() error {
	_, err := s.db.Exec(
		`DELETE FROM sessions WHERE expires_at < ?`,
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}
