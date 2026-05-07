// Package bid는 본 프로젝트의 commit-reveal 핵심 로직을 담당합니다.
//
// 본 프로젝트는 "검증 가능한 공정 추첨(Verifiable Fair Lottery)" 으로 진화했습니다.
// 새 흐름은 service_lottery.go 의 CommitNonce / RevealNonce 를 사용하고,
// 본 파일의 CommitBid / RevealBid / VerifyBid 는 가격 기반 블라인드 경매의
// 레거시 흐름이며 회귀 테스트 호환을 위해 유지됩니다.
package bid

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	applog "zerotrust-draw/internal/log"
	"zerotrust-draw/pkg/auth"
	appErrors "zerotrust-draw/pkg/errors"
	"zerotrust-draw/pkg/models"

	"github.com/google/uuid"
)

// Service는 입찰/추첨 비즈니스 로직을 처리합니다.
// 인증은 미들웨어+세션이 전담하고, 본 서비스는 권한(role)만 검증합니다.
type Service struct {
	repo *Repository
}

// NewService는 Service를 생성합니다.
func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// ─────────────────────────────────────────────
//  [LEGACY] 1. 입찰 커밋  POST /api/auctions/:id/bids
// ─────────────────────────────────────────────

// CommitBid는 입찰(Commit) 요청을 처리합니다(레거시 가격 기반).
func (s *Service) CommitBid(claims *auth.UserClaims, auctionID, commitHash string) error {
	_, err := s.CommitBidWithResult(claims, auctionID, commitHash)
	return err
}

// CommitResult는 CommitBid 성공 응답 데이터입니다.
type CommitResult struct {
	BidID       string    `json:"bidId"`
	AuctionID   string    `json:"auctionId"`
	CommittedAt time.Time `json:"committedAt"`
}

// CommitBidWithResult는 CommitBid와 동일하지만 결과 데이터를 반환합니다.
func (s *Service) CommitBidWithResult(claims *auth.UserClaims, auctionID, commitHash string) (*CommitResult, error) {
	// GUEST 차단: BIDDER 이상 권한 필요
	if !claims.HasRole(models.RoleBidder) {
		return nil, appErrors.ErrForbidden
	}
	if !validateCommitHash(commitHash) {
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
		applog.Error("BID_COMMIT_FAIL", auctionID, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}

	if err := tx.Commit(); err != nil {
		return nil, appErrors.ErrSystemError
	}

	applog.Audit("BID_COMMITTED", auctionID, claims.UserID, "", "입찰 커밋 완료")
	return &CommitResult{BidID: bidID, AuctionID: auctionID, CommittedAt: now}, nil
}

// ─────────────────────────────────────────────
//  [LEGACY] 2. 입찰 공개  POST /api/auctions/:id/reveal
// ─────────────────────────────────────────────

// RevealResult는 RevealBid 성공 응답 데이터입니다.
type RevealResult struct {
	BidID      string    `json:"bidId"`
	IsValid    bool      `json:"isValid"`
	RevealedAt time.Time `json:"revealedAt"`
}

// RevealBid는 입찰 공개(Reveal) 요청을 처리합니다(레거시 가격 기반).
func (s *Service) RevealBid(claims *auth.UserClaims, auctionID string, price int, salt string) (*RevealResult, error) {
	if !claims.HasRole(models.RoleBidder) {
		return nil, appErrors.ErrForbidden
	}

	status, err := s.repo.FindAuctionStatus(auctionID)
	if err != nil {
		return nil, err
	}
	if status == "OPEN" {
		return nil, appErrors.ErrRevealTooEarly
	}
	if status == "VERIFIED" {
		applog.Warn("REVEAL_ALREADY_VERIFIED", auctionID, claims.UserID, "", "이미 검증 완료된 경매", "ERR_BID_002")
		return nil, appErrors.ErrRevealTooEarly
	}

	deadline, err := s.repo.FindRevealDeadline(auctionID)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}
	if deadline != nil && time.Now().UTC().After(*deadline) {
		applog.Warn("REVEAL_DEADLINE_EXCEEDED", auctionID, claims.UserID, "", "Reveal 마감 시각 초과", "ERR_BID_002")
		return nil, appErrors.ErrRevealTooEarly
	}

	bid, err := s.repo.FindBidByUserAndAuction(auctionID, claims.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, appErrors.ErrBidPeriodClosed
		}
		return nil, appErrors.ErrSystemError
	}

	expected := ComputeCommitHash(claims.UserID, price, salt)
	now := time.Now().UTC()
	isValid := expected == bid.CommitHash

	if !isValid {
		applog.Warn("HASH_MISMATCH", auctionID, claims.UserID, "", "Reveal 해시 불일치", "ERR_VER_001")
		return nil, appErrors.ErrHashMismatch
	}

	if err := s.repo.UpdateReveal(auctionID, claims.UserID, price, salt, now); err != nil {
		applog.Error("BID_REVEAL_FAIL", auctionID, claims.UserID, "", err.Error(), "ERR_SYS_001")
		return nil, appErrors.ErrSystemError
	}

	applog.Audit("HASH_VERIFIED", auctionID, claims.UserID, "", "해시 검증 성공")
	return &RevealResult{BidID: bid.ID, IsValid: true, RevealedAt: now}, nil
}

// ─────────────────────────────────────────────
//  [LEGACY] 3. 낙찰 검증
// ─────────────────────────────────────────────

// WinnerInfo는 낙찰자 정보입니다(레거시).
type WinnerInfo struct {
	BidID       string
	UserID      string
	Price       int
	CommittedAt time.Time
}

// VerifyBid는 Reveal된 모든 입찰을 검증하고 낙찰자를 선정합니다(레거시).
func (s *Service) VerifyBid(auctionID string) (*WinnerInfo, error) {
	status, err := s.repo.FindAuctionStatus(auctionID)
	if err != nil {
		return nil, err
	}
	if status != "CLOSED" {
		applog.Warn("VERIFY_INVALID_STATUS", auctionID, "", "", "CLOSED 아닌 경매 검증 시도", "ERR_BID_001")
		return nil, appErrors.ErrBidPeriodClosed
	}

	bids, err := s.repo.FindRevealedBids(auctionID)
	if err != nil {
		return nil, appErrors.ErrSystemError
	}

	var winner *WinnerInfo
	for _, b := range bids {
		if b.RevealedPrice == nil || b.RevealedSalt == nil {
			continue
		}
		expected := ComputeCommitHash(b.UserID, *b.RevealedPrice, *b.RevealedSalt)
		isValid := 0
		if expected == b.CommitHash {
			isValid = 1
			applog.Audit("HASH_VERIFIED", auctionID, b.UserID, "", "검증 통과")
		} else {
			applog.Warn("HASH_MISMATCH", auctionID, b.UserID, "", "검증 실패", "ERR_VER_001")
		}

		if err := s.repo.UpdateIsValid(b.ID, isValid); err != nil {
			applog.Error("VERIFY_UPDATE_FAIL", auctionID, b.UserID, "", err.Error(), "ERR_SYS_001")
			return nil, appErrors.ErrSystemError
		}

		if isValid == 1 {
			if winner == nil || *b.RevealedPrice > winner.Price {
				winner = &WinnerInfo{
					BidID:       b.ID,
					UserID:      b.UserID,
					Price:       *b.RevealedPrice,
					CommittedAt: b.CommittedAt,
				}
			}
		}
	}

	if err := s.repo.UpdateAuctionStatus(auctionID, "VERIFIED"); err != nil {
		return nil, appErrors.ErrSystemError
	}

	if winner != nil {
		applog.Audit("WINNER_SELECTED", auctionID, winner.UserID, "",
			fmt.Sprintf("낙찰자 선정 완료, 낙찰가: %d", winner.Price))
	} else {
		applog.Audit("NO_WINNER", auctionID, "", "", "유효한 입찰 없음")
	}

	return winner, nil
}

// ─────────────────────────────────────────────
//  공통: 해시 계산 (레거시)
// ─────────────────────────────────────────────

// ComputeCommitHash는 (레거시) 입찰 Commit 해시를 계산합니다.
// 포맷: SHA-256(userID + ":" + price + ":" + salt)
func ComputeCommitHash(userID string, price int, salt string) string {
	raw := userID + ":" + fmt.Sprintf("%d", price) + ":" + salt
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// VerifyHash는 외부에서 해시 검증만 할 때 사용합니다(레거시).
func VerifyHash(userID string, price int, salt, commitHash string) bool {
	return ComputeCommitHash(userID, price, salt) == commitHash
}

// validateCommitHash는 64자 소문자 hex 문자열 검증.
func validateCommitHash(hash string) bool {
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

// ─── 미사용 모델 참조 방지용 ───────────────────
var _ = models.Bid{}
