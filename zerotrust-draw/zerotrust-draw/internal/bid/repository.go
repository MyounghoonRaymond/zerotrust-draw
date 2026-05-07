package bid

import (
	"database/sql"
	"errors"
	"time"

	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/models"
)

// Repository는 bids 테이블 SQL을 전담합니다.
type Repository struct {
	db *sql.DB
}

// NewRepository는 Repository를 생성합니다.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// FindAuctionStatus는 경매 상태를 조회합니다.
func (r *Repository) FindAuctionStatus(auctionID string) (string, error) {
	var status string
	err := r.db.QueryRow(`SELECT status FROM auctions WHERE id = ?`, auctionID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", &appErrors.AppError{Code: "ERR_BID_001", Message: "존재하지 않는 경매입니다."}
	}
	return status, err
}

// FindRevealDeadline은 경매의 reveal_deadline을 조회합니다.
// nil 반환 시 마감 시각이 설정되지 않은 상태입니다.
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

// InsertBid는 입찰 커밋을 INSERT합니다.
// UNIQUE(auction_id, user_id) 제약으로 중복 입찰을 DB 레벨에서 차단합니다.
func (r *Repository) InsertBid(tx *sql.Tx, id, auctionID, userID, commitHash string, committedAt time.Time) error {
	const q = `
		INSERT INTO bids (id, auction_id, user_id, commit_hash, committed_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	now := committedAt.UTC().Format(time.RFC3339)
	_, err := tx.Exec(q, id, auctionID, userID, commitHash, now, now)
	return err
}

// FindBidByUserAndAuction은 특정 사용자의 입찰을 조회합니다.
func (r *Repository) FindBidByUserAndAuction(auctionID, userID string) (*models.Bid, error) {
	const q = `
		SELECT id, auction_id, user_id, commit_hash, revealed_price, revealed_salt,
		       is_valid, committed_at, revealed_at, created_at
		FROM bids
		WHERE auction_id = ? AND user_id = ?`
	row := r.db.QueryRow(q, auctionID, userID)
	return scanBid(row)
}

// UpdateReveal은 Reveal 데이터(가격, salt)를 업데이트합니다.
func (r *Repository) UpdateReveal(auctionID, userID string, price int, salt string, revealedAt time.Time) error {
	const q = `
		UPDATE bids
		SET revealed_price = ?, revealed_salt = ?, revealed_at = ?
		WHERE auction_id = ? AND user_id = ?`
	_, err := r.db.Exec(q, price, salt, revealedAt.UTC().Format(time.RFC3339), auctionID, userID)
	return err
}

// FindRevealedBids는 Reveal된 입찰 전체를 조회합니다.
func (r *Repository) FindRevealedBids(auctionID string) ([]models.Bid, error) {
	const q = `
		SELECT id, auction_id, user_id, commit_hash, revealed_price, revealed_salt,
		       is_valid, committed_at, revealed_at, created_at
		FROM bids
		WHERE auction_id = ? AND revealed_price IS NOT NULL
		ORDER BY committed_at ASC`
	rows, err := r.db.Query(q, auctionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bids []models.Bid
	for rows.Next() {
		b, err := scanBidRow(rows)
		if err != nil {
			return nil, err
		}
		bids = append(bids, *b)
	}
	return bids, rows.Err()
}

// UpdateIsValid는 입찰의 is_valid 값을 업데이트합니다.
func (r *Repository) UpdateIsValid(bidID string, isValid int) error {
	_, err := r.db.Exec(`UPDATE bids SET is_valid = ? WHERE id = ?`, isValid, bidID)
	return err
}

// UpdateAuctionStatus는 경매 상태를 변경합니다.
func (r *Repository) UpdateAuctionStatus(auctionID, status string) error {
	_, err := r.db.Exec(`UPDATE auctions SET status = ? WHERE id = ?`, status, auctionID)
	return err
}

// BeginTx는 트랜잭션을 시작합니다.
func (r *Repository) BeginTx() (*sql.Tx, error) {
	return r.db.Begin()
}

// ─── scan 헬퍼 ───────────────────────────────

func scanBid(row *sql.Row) (*models.Bid, error) {
	var b models.Bid
	var committedAt, createdAt string
	var revealedAt *string
	err := row.Scan(
		&b.ID, &b.AuctionID, &b.UserID, &b.CommitHash,
		&b.RevealedPrice, &b.RevealedSalt, &b.IsValid,
		&committedAt, &revealedAt, &createdAt,
	)
	if err != nil {
		return nil, err
	}
	b.CommittedAt, _ = time.Parse(time.RFC3339, committedAt)
	b.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if revealedAt != nil {
		t, _ := time.Parse(time.RFC3339, *revealedAt)
		b.RevealedAt = &t
	}
	return &b, nil
}

func scanBidRow(rows *sql.Rows) (*models.Bid, error) {
	var b models.Bid
	var committedAt, createdAt string
	var revealedAt *string
	err := rows.Scan(
		&b.ID, &b.AuctionID, &b.UserID, &b.CommitHash,
		&b.RevealedPrice, &b.RevealedSalt, &b.IsValid,
		&committedAt, &revealedAt, &createdAt,
	)
	if err != nil {
		return nil, err
	}
	b.CommittedAt, _ = time.Parse(time.RFC3339, committedAt)
	b.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if revealedAt != nil {
		t, _ := time.Parse(time.RFC3339, *revealedAt)
		b.RevealedAt = &t
	}
	return &b, nil
}
