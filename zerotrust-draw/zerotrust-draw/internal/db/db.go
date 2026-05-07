package db

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

// InitDB는 SQLite DB를 초기화하고 schema.sql 마이그레이션을 실행합니다.
func InitDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	// 외래 키 제약 활성화
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, err
	}

	// WAL 모드: 동시 읽기 성능 향상
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return nil, err
	}

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("마이그레이션 실패: %w", err)
	}

	return db, nil
}

// runMigrations는 schema.sql 을 읽어 테이블을 생성합니다.
// CREATE TABLE IF NOT EXISTS 이므로 멱등(idempotent)합니다.
func runMigrations(db *sql.DB) error {
	schemaPath := os.Getenv("SCHEMA_PATH")
	if schemaPath == "" {
		schemaPath = "db/schema.sql"
	}

	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("schema.sql 읽기 실패 (%s): %w", schemaPath, err)
	}

	if _, err := db.Exec(string(schema)); err != nil {
		return fmt.Errorf("schema 실행 실패: %w", err)
	}
	return nil
}
