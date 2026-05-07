// Package bid - 검증 가능한 공정 추첨용 nonce commit/reveal 서비스 메서드.
// 기존 *Service에 메서드만 추가합니다. 기존 service.go는 변경하지 않습니다.
//
// 호출 흐름:
//  1. CommitNonce(claims, auctionID, commitHash)   ← 다자간 베이컨 commit 단계
//  2. RevealNonce(claims, auctionID, nonce, salt)  ← 다자간 베이컨 reveal 단계
//  3. (서버 내부) auction.Service.DrawLottery 호출 → VRF로 결정적 추첨
package bid

import (
	"database/sql"
	"strings"
	"time"

	applog "zerotrust-draw/internal/log"
	"zerotrust-draw/internal/security"
	"zerotrust-draw/pkg/auth"
	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/models"

	"github.com/google/uuid"
)

// CommitNonceResult는 CommitNonce 성공 응답 데이터입니다.
type CommitNonceResult struct {
	BidID       string    `json:"bidId"`
	AuctionID   string    `json:"auctionId"`
	CommittedAt time.Time `json:"committedAt"`
}

// CommitNonce는 추첨 참가자의 nonce commit을 등록합니다.
//   - commitHash: SHA-256(userID:nonce:salt) 의 hex 문자열 (64자, 소문자)
//   - 라운드 status 가 OPEN일 때만 허용
//   - UNIQUE(auction_id, user_id) 제약으로 중복 commit DB 레벨 차단
func (s *Service) CommitNonce(claims *auth.UserClaims, auctionID, commitHash string) (*CommitNonceResult, error) {
	if !claims.HasRole(models.RoleBidder) {
		return nil, appErrors.ErrForbidden
	}
	if !validateNonceCommit(commitHash) {
		return nil, appErrors.ErrInvalidHashFmt
	}

	tx, err := s.repo.BeginTx()
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	defer tx.Rollback() //nolint:errcheck

	status, err := s.repo.FindAuctionStatus(auctionID)
	if err != nil {
		return nil, err
	}
	if status != "OPEN" {
		return nil, appErrors.ErrBidPeriodClosed
	}

	bidID := uuid.NewString()
	now := time.Now().UTC()
	if err := s.repo.InsertBid(tx, bidID, auctionID, claims.UserID, commitHash, now); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, appErrors.ErrDuplicateBid
		}
		applog.Error("LOTTERY_COMMIT_FAIL", auctionID, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}
	if err := tx.Commit(); err != nil {
		return nil, appErrors.ErrSystemError
	}

	applog.Audit("LOTTERY_COMMITTED", auctionID, claims.UserID, "", "추첨 nonce commit 완료")
	return &CommitNonceResult{BidID: bidID, AuctionID: auctionID, CommittedAt: now}, nil
}

// RevealNonceResult는 RevealNonce 성공 응답 데이터입니다.
type RevealNonceResult struct {
	BidID      string    `json:"bidId"`
	IsValid    bool      `json:"isValid"`
	RevealedAt time.Time `json:"revealedAt"`
}

// RevealNonce는 commit된 nonce를 공개하고 해시 일치를 검증합니다.
//   - 라운드 status가 CLOSED일 때만 허용 (OPEN 또는 VERIFIED는 거부)
//   - reveal_deadline이 설정되어 있고 그 시각을 넘었으면 거부
//   - 해시 검증 실패 시 ERR_VER_001 반환 + 감사 로그
func (s *Service) RevealNonce(claims *auth.UserClaims, auctionID, nonce, salt string) (*RevealNonceResult, error) {
	if !claims.HasRole(models.RoleBidder) {
		return nil, appErrors.ErrForbidden
	}
	if !validateNonceValue(nonce) || !validateNonceSalt(salt) {
		return nil, appErrors.ErrInvalidHashFmt
	}

	status, err := s.repo.FindAuctionStatus(auctionID)
	if err != nil {
		return nil, err
	}
	if status == "OPEN" {
		return nil, appErrors.ErrRevealTooEarly
	}
	if status == "VERIFIED" {
		applog.Warn("REVEAL_ALREADY_DRAWN", auctionID, claims.UserID, "", "이미 추첨 완료된 라운드", "ERR_BID_002")
		return nil, appErrors.ErrRevealTooEarly
	}

	deadline, err := s.repo.FindRevealDeadline(auctionID)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	if deadline != nil && time.Now().UTC().After(*deadline) {
		applog.Warn("REVEAL_DEADLINE_EXCEEDED", auctionID, claims.UserID, "", "Reveal 마감 초과", "ERR_BID_002")
		return nil, appErrors.ErrRevealTooEarly
	}

	bid, err := s.repo.FindBidByUserAndAuction(auctionID, claims.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, appErrors.ErrBidPeriodClosed
		}
		return nil, appErrors.ErrSystemError
	}

	if !security.VerifyBeaconCommit(claims.UserID, nonce, salt, bid.CommitHash) {
		applog.Warn("HASH_MISMATCH", auctionID, claims.UserID, "", "Reveal 해시 불일치", "ERR_VER_001")
		return nil, appErrors.ErrHashMismatch
	}

	now := time.Now().UTC()
	if err := s.repo.UpdateRevealNonce(auctionID, claims.UserID, nonce, salt, now); err != nil {
		applog.Error("LOTTERY_REVEAL_FAIL", auctionID, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}

	applog.Audit("HASH_VERIFIED", auctionID, claims.UserID, "", "nonce reveal 검증 성공")
	return &RevealNonceResult{BidID: bid.ID, IsValid: true, RevealedAt: now}, nil
}

// ─────────────────────────────────────────────
//  helper: 입력 검증
// ─────────────────────────────────────────────

// validateNonceCommit: SHA-256 hex 64자, 소문자 hex만 허용
func validateNonceCommit(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// validateNonceValue: 16~128자 hex (8~64바이트). 너무 짧으면 충돌·grinding 위험
func validateNonceValue(nonce string) bool {
	if len(nonce) < 16 || len(nonce) > 128 {
		return false
	}
	for _, c := range nonce {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// validateNonceSalt: 8~64자, 영숫자만 허용
func validateNonceSalt(salt string) bool {
	if len(salt) < 8 || len(salt) > 64 {
		return false
	}
	for _, c := range salt {
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}
