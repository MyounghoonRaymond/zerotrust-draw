package db

import (
	"database/sql"
	"errors"

	"zerotrust-draw/pkg/models"
)

// WhitelistStore는 SQLite whitelist 테이블을 관리합니다.
// Signup 시 username으로 조회해 역할(BIDDER/AUCTIONEER)을 결정합니다.
// 화이트리스트에 없는 사용자는 GUEST로 등록됩니다.
type WhitelistStore struct {
	db *sql.DB
}

// NewWhitelistStore는 WhitelistStore를 생성합니다.
func NewWhitelistStore(db *sql.DB) *WhitelistStore {
	return &WhitelistStore{db: db}
}

// LookupRole은 username이 화이트리스트에 등록되어 있으면 해당 역할을 반환합니다.
// 미등록이면 (RoleGuest, false)를 반환합니다.
func (s *WhitelistStore) LookupRole(username string) (models.Role, bool) {
	var role string
	err := s.db.QueryRow(
		`SELECT role FROM whitelist WHERE username = ?`, username,
	).Scan(&role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.RoleGuest, false
		}
		return models.RoleGuest, false
	}
	return models.Role(role), true
}

// Add는 화이트리스트에 username과 역할을 등록합니다.
// 이미 등록된 경우 역할을 덮어씁니다.
func (s *WhitelistStore) Add(username string, role models.Role) error {
	_, err := s.db.Exec(
		`INSERT INTO whitelist (username, role) VALUES (?, ?)
		 ON CONFLICT(username) DO UPDATE SET role = excluded.role`,
		username, string(role),
	)
	return err
}

// Remove는 화이트리스트에서 username을 삭제합니다.
func (s *WhitelistStore) Remove(username string) error {
	_, err := s.db.Exec(`DELETE FROM whitelist WHERE username = ?`, username)
	return err
}
