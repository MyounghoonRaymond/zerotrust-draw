// Package auction - Repository는 auctions/bids 테이블의 모든 SQL을 담당합니다.
// Service는 Repository를 통해서만 DB에 접근합니다.
// 모든 쿼리는 Prepared Statement(?)를 사용합니다.
package auction

import (
	"database/sql"
	"errors"
	"time"

	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/models"
)

// Repository는 경매 DB 접근을 담당합니다.
type Repository struct {
	db *sql.DB
}

// NewRepository는 Repository를 생성합니다.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// ─────────────────────────────────────────────
//  auctions 테이블
// ─────────────────────────────────────────────

// InsertAuction은 새 경매를 INSERT합니다.
func (r *Repository) InsertAuction(id, itemName, createdBy string, startAt, endAt time.Time) error {
	const q = `
		INSERT INTO auctions (id, item_name, created_by, status, start_at, end_at, created_at)
		VALUES (?, ?, ?, 'OPEN', ?, ?, ?)`

	_, err := r.db.Exec(q,
		id, itemName, createdBy,
		startAt.UTC().Format(time.RFC3339),
		endAt.UTC().Format(time.RFC3339),
		time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// FindAuctionByID는 경매 1건을 조회합니다.
// 존재하지 않으면 ERR_BID_001을 반환합니다.
func (r *Repository) FindAuctionByID(auctionID string) (*models.Auction, error) {
	const q = `
		SELECT id, item_name, created_by, status, start_at, end_at, reveal_deadline, created_at
		FROM auctions
		WHERE id = ?`

	row := r.db.QueryRow(q, auctionID)
	auction, err := scanAuction(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &appErrors.AppError{Code: "ERR_BID_001", Message: "존재하지 않는 경매입니다."}
	}
	if err != nil {
		return nil, err
	}
	return auction, nil
}

// SetRevealDeadline은 경매 마감 시 reveal_deadline을 설정합니다.
func (r *Repository) SetRevealDeadline(tx *sql.Tx, auctionID string, deadline time.Time) error {
	const q = `UPDATE auctions SET reveal_deadline = ? WHERE id = ?`
	deadlineStr := deadline.UTC().Format(time.RFC3339)
	if tx != nil {
		_, err := tx.Exec(q, deadlineStr, auctionID)
		return err
	}
	_, err := r.db.Exec(q, deadlineStr, auctionID)
	return err
}

// FindRevealDeadline은 경매의 reveal_deadline을 조회합니다.
func (r *Repository) FindRevealDeadline(auctionID string) (*time.Time, error) {
	var raw sql.NullString
	err := r.db.QueryRow(`SELECT reveal_deadline FROM auctions WHERE id = ?`, auctionID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &appErrors.AppError{Code: "ERR_BID_001", Message: "존재하지 않는 경매입니다."}
	}
	if err != nil {
		return nil, err
	}
	if !raw.Valid {
		return nil, nil
	}
	t, _ := time.Parse(time.RFC3339, raw.String)
	return &t, nil
}

// UpdateAuctionStatus는 경매 상태를 변경합니다.
// tx가 nil이면 직접 실행, 아니면 트랜잭션 안에서 실행합니다.
func (r *Repository) UpdateAuctionStatus(tx *sql.Tx, auctionID, status string) error {
	const q = `UPDATE auctions SET status = ? WHERE id = ?`
	if tx != nil {
		_, err := tx.Exec(q, status, auctionID)
		return err
	}
	_, err := r.db.Exec(q, status, auctionID)
	return err
}

// FindAuctionStatusForUpdate는 트랜잭션 내에서 현재 상태를 조회합니다.
func (r *Repository) FindAuctionStatusForUpdate(tx *sql.Tx, auctionID string) (string, error) {
	var status string
	err := tx.QueryRow(`SELECT status FROM auctions WHERE id = ?`, auctionID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", &appErrors.AppError{Code: "ERR_BID_001", Message: "존재하지 않는 경매입니다."}
	}
	return status, err
}

// ─────────────────────────────────────────────
//  bids 테이블
// ─────────────────────────────────────────────

// ListAuctions는 경매 목록을 페이지네이션하여 반환합니다.
// limit: 페이지당 항목 수 (최대 50), offset: 건너뛸 항목 수
func (r *Repository) ListAuctions(limit, offset int) ([]*models.Auction, int, error) {
	// 전체 건수 조회
	var total int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM auctions`).Scan(&total); err != nil {
		return nil, 0, err
	}

	const q = `
		SELECT id, item_name, created_by, status, start_at, end_at, reveal_deadline, created_at
		FROM auctions
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?`

	rows, err := r.db.Query(q, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var auctions []*models.Auction
	for rows.Next() {
		var a models.Auction
		var startAt, endAt, createdAt string
		var revealDeadline sql.NullString
		if err := rows.Scan(&a.ID, &a.ItemName, &a.CreatedBy, &a.Status,
			&startAt, &endAt, &revealDeadline, &createdAt); err != nil {
			return nil, 0, err
		}
		a.StartAt, _ = time.Parse(time.RFC3339, startAt)
		a.EndAt, _ = time.Parse(time.RFC3339, endAt)
		a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		if revealDeadline.Valid {
			t, _ := time.Parse(time.RFC3339, revealDeadline.String)
			a.RevealDeadline = &t
		}
		auctions = append(auctions, &a)
	}
	return auctions, total, rows.Err()
}

// FindBidsByAuctionID는 경매의 모든 입찰을 조회합니다.
// is_valid=1 우선, revealed_price 내림차순, committed_at 오름차순 정렬합니다.
func (r *Repository) FindBidsByAuctionID(auctionID string) ([]BidEntry, error) {
	const q = `
		SELECT id, user_id, is_valid, revealed_price
		FROM bids
		WHERE auction_id = ?
		ORDER BY is_valid DESC, revealed_price DESC, committed_at ASC`

	rows, err := r.db.Query(q, auctionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bids []BidEntry
	for rows.Next() {
		var e BidEntry
		if err := rows.Scan(&e.BidID, &e.UserID, &e.IsValid, &e.Price); err != nil {
			return nil, err
		}
		bids = append(bids, e)
	}
	return bids, rows.Err()
}

// FindUsernameByID는 users 테이블에서 username을 조회합니다.
func (r *Repository) FindUsernameByID(userID string) string {
	var username string
	_ = r.db.QueryRow(`SELECT username FROM users WHERE id = ?`, userID).Scan(&username)
	return username
}

// CloseExpiredAuctions는 end_at이 지났지만 아직 OPEN인 경매를 CLOSED로 전환합니다.
// reveal_deadline = 전환 시각 + 24h 도 함께 설정합니다.
// 반환값: 전환된 경매 수
func (r *Repository) CloseExpiredAuctions() (int, error) {
	now := time.Now().UTC()
	deadline := now.Add(24 * time.Hour)

	result, err := r.db.Exec(`
		UPDATE auctions
		SET status = 'CLOSED', reveal_deadline = ?
		WHERE status = 'OPEN' AND end_at < ?`,
		deadline.Format(time.RFC3339),
		now.Format(time.RFC3339),
	)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

// BeginTx는 트랜잭션을 시작합니다.
func (r *Repository) BeginTx() (*sql.Tx, error) {
	return r.db.Begin()
}
