package db

import (
	"database/sql"
	"errors"
	"time"

	"zerotrust-draw/pkg/models"

	"github.com/google/uuid"
)

// UserStore는 SQLite users 테이블을 관리합니다.
type UserStore struct {
	db *sql.DB
}

// NewUserStore는 UserStore를 생성합니다.
func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{db: db}
}

// GetByUsername은 사용자명으로 사용자를 조회합니다.
// 존재하지 않으면 (nil, nil)을 반환합니다.
func (s *UserStore) GetByUsername(username string) (*models.User, error) {
	const q = `
		SELECT id, username, password, salt, role, created_at, last_login_at, last_failed_at
		FROM users
		WHERE username = ?`

	var u models.User
	var createdAt string
	var lastLoginAt, lastFailedAt sql.NullString

	err := s.db.QueryRow(q, username).Scan(
		&u.ID, &u.Username, &u.Password, &u.Salt, &u.Role,
		&createdAt, &lastLoginAt, &lastFailedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if lastLoginAt.Valid {
		t, _ := time.Parse(time.RFC3339, lastLoginAt.String)
		u.LastLoginAt = &t
	}
	if lastFailedAt.Valid {
		t, _ := time.Parse(time.RFC3339, lastFailedAt.String)
		u.LastFailedAt = &t
	}
	return &u, nil
}

// CreateUser는 새 사용자를 INSERT합니다.
// hashedPassword는 반드시 Argon2id 해시값이어야 합니다.
func (s *UserStore) CreateUser(username, hashedPassword string, salt []byte, role models.Role) (*models.User, error) {
	id := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	const q = `
		INSERT INTO users (id, username, password, salt, role, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(q, id, username, hashedPassword, salt, string(role), now)
	if err != nil {
		return nil, err
	}

	return &models.User{
		ID:        id,
		Username:  username,
		Password:  hashedPassword,
		Salt:      salt,
		Role:      role,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// UpdateLoginStats는 로그인 성공/실패 시각을 갱신합니다.
func (s *UserStore) UpdateLoginStats(userID string, success bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	var q string
	if success {
		q = `UPDATE users SET last_login_at = ? WHERE id = ?`
	} else {
		q = `UPDATE users SET last_failed_at = ? WHERE id = ?`
	}
	_, err := s.db.Exec(q, now, userID)
	return err
}
