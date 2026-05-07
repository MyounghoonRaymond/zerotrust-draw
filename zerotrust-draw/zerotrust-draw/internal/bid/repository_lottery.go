// Package bid - Lottery 전용 Repository 메서드 (기존 Repository에 메서드만 추가).
// 기존 repository.go는 손대지 않습니다. SQLite ALTER로 추가된 nonce_value 컬럼만 참조합니다.
package bid

import (
	"database/sql"
	"errors"
	"time"

	appErrors "zerotrust-draw/pkg/errors"
)

// LotteryNonceReveal은 추첨용 nonce reveal 정보입니다(검증 시 사용).
type LotteryNonceReveal struct {
	BidID       string
	UserID      string
	CommitHash  string
	NonceValue  string // reveal된 평문 nonce (hex)
	Salt        string // reveal된 salt
	CommittedAt time.Time
	RevealedAt  *time.Time
}

// UpdateRevealNonce는 nonce_value, revealed_salt, revealed_at을 갱신합니다.
// 기존 UpdateReveal과 달리 가격(price) 대신 평문 nonce를 저장합니다.
func (r *Repository) UpdateRevealNonce(auctionID, userID, nonce, salt string, revealedAt time.Time) error {
	const q = `
		UPDATE bids
		   SET nonce_value = ?, revealed_salt = ?, revealed_at = ?
		 WHERE auction_id = ? AND user_id = ?`
	res, err := r.db.Exec(q, nonce, salt, revealedAt.UTC().Format(time.RFC3339), auctionID, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return &appErrors.AppError{Code: "ERR_BID_001", Message: "해당 라운드의 commit이 없습니다."}
	}
	return nil
}

// FindRevealedNonces는 추첨 라운드에서 reveal된 모든 nonce 기여분을 반환합니다.
// 검증 페이지/Draw 단계에서 결합 시드 계산에 사용됩니다.
func (r *Repository) FindRevealedNonces(auctionID string) ([]LotteryNonceReveal, error) {
	const q = `
		SELECT id, user_id, commit_hash, nonce_value, revealed_salt, committed_at, revealed_at
		  FROM bids
		 WHERE auction_id = ? AND nonce_value IS NOT NULL
		 ORDER BY user_id ASC`
	rows, err := r.db.Query(q, auctionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []LotteryNonceReveal
	for rows.Next() {
		var rec LotteryNonceReveal
		var nonce, salt sql.NullString
		var committedAt string
		var revealedAt sql.NullString
		if err := rows.Scan(&rec.BidID, &rec.UserID, &rec.CommitHash, &nonce, &salt, &committedAt, &revealedAt); err != nil {
			return nil, err
		}
		if nonce.Valid {
			rec.NonceValue = nonce.String
		}
		if salt.Valid {
			rec.Salt = salt.String
		}
		rec.CommittedAt, _ = time.Parse(time.RFC3339, committedAt)
		if revealedAt.Valid {
			t, _ := time.Parse(time.RFC3339, revealedAt.String)
			rec.RevealedAt = &t
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// FindCommitOnly는 commit 단계에서 등록된 모든 참가자(공개 검증용)를 반환합니다.
// nonce_value 유무와 관계없이 같은 라운드의 모든 commit을 가져옵니다.
func (r *Repository) FindCommitOnly(auctionID string) ([]LotteryNonceReveal, error) {
	const q = `
		SELECT id, user_id, commit_hash, nonce_value, revealed_salt, committed_at, revealed_at
		  FROM bids
		 WHERE auction_id = ?
		 ORDER BY user_id ASC`
	rows, err := r.db.Query(q, auctionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []LotteryNonceReveal
	for rows.Next() {
		var rec LotteryNonceReveal
		var nonce, salt sql.NullString
		var committedAt string
		var revealedAt sql.NullString
		if err := rows.Scan(&rec.BidID, &rec.UserID, &rec.CommitHash, &nonce, &salt, &committedAt, &revealedAt); err != nil {
			return nil, err
		}
		if nonce.Valid {
			rec.NonceValue = nonce.String
		}
		if salt.Valid {
			rec.Salt = salt.String
		}
		rec.CommittedAt, _ = time.Parse(time.RFC3339, committedAt)
		if revealedAt.Valid {
			t, _ := time.Parse(time.RFC3339, revealedAt.String)
			rec.RevealedAt = &t
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no commits found")
	}
	return out, nil
}
