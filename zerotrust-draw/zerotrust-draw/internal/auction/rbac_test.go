package auction_test

// rbac_test.go — RBAC 강화 테스트
//
// 검증 항목:
//   1. BIDDER가 경매 생성 시도 → ERR_AUTH_002 (403 Forbidden)
//   2. GUEST가 경매 생성 시도  → ERR_AUTH_002 (403 Forbidden)
//   3. GUEST가 입찰(Commit) 시도 → ERR_AUTH_002 (403 Forbidden)
//   4. AUCTIONEER는 경매 생성 성공
//   5. ADMIN은 경매 생성 성공 (HasRole 규칙상 ADMIN은 모든 역할 충족)

import (
	"testing"
	"time"

	"zerotrust-draw/internal/auction"
	"zerotrust-draw/internal/bid"
	"zerotrust-draw/pkg/auth"
)

// ─────────────────────────────────────────────
//  경매 생성 RBAC 테스트
// ─────────────────────────────────────────────

func TestCreateAuction_RBAC(t *testing.T) {
	db := setupTestDB(t)
	repo := auction.NewRepository(db)
	svc := auction.NewService(repo)

	input := auction.CreateAuctionInput{
		ItemName: "테스트 상품",
		StartAt:  time.Now().Add(time.Minute),
		EndAt:    time.Now().Add(time.Hour),
	}

	cases := []struct {
		name        string
		claims      *auth.UserClaims
		wantErrCode string // 빈 문자열이면 성공 기대
	}{
		{
			name:        "BIDDER는 경매 생성 불가 → ERR_AUTH_002",
			claims:      auth.NewMockBidder("bidder-1", "buyer1").Claims,
			wantErrCode: "ERR_AUTH_002",
		},
		{
			name:        "GUEST는 경매 생성 불가 → ERR_AUTH_002",
			claims:      auth.NewMockGuest("guest-1", "visitor").Claims,
			wantErrCode: "ERR_AUTH_002",
		},
		{
			name:        "AUCTIONEER는 경매 생성 성공",
			claims:      auth.NewMockAuctioneer("auctioneer-1", "seller").Claims,
			wantErrCode: "",
		},
		{
			name:        "ADMIN은 경매 생성 성공",
			claims:      auth.NewMockAdmin("admin-1", "admin").Claims,
			wantErrCode: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateAuction(tc.claims, input)
			if tc.wantErrCode == "" {
				if err != nil {
					t.Fatalf("TC-RBAC-CREATE-01: 예상치 못한 오류 발생 (코드: %T)", err)
				}
				return
			}
			assertErrCode(t, err, tc.wantErrCode)
		})
	}
}

// ─────────────────────────────────────────────
//  경매 마감 RBAC 테스트
// ─────────────────────────────────────────────

func TestCloseAuction_RBAC(t *testing.T) {
	db := setupTestDB(t)
	repo := auction.NewRepository(db)
	svc := auction.NewService(repo)

	insertOpenAuction(t, db, "auction-rbac-close")

	cases := []struct {
		name        string
		claims      *auth.UserClaims
		wantErrCode string
	}{
		{
			name:        "BIDDER는 마감 불가 → ERR_AUTH_002",
			claims:      auth.NewMockBidder("bidder-1", "buyer1").Claims,
			wantErrCode: "ERR_AUTH_002",
		},
		{
			name:        "GUEST는 마감 불가 → ERR_AUTH_002",
			claims:      auth.NewMockGuest("guest-1", "visitor").Claims,
			wantErrCode: "ERR_AUTH_002",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.CloseAuction(tc.claims, "auction-rbac-close")
			assertErrCode(t, err, tc.wantErrCode)
		})
	}
}

// ─────────────────────────────────────────────
//  입찰(Commit) RBAC 테스트
// ─────────────────────────────────────────────

func TestCommitBid_GuestBlocked(t *testing.T) {
	db := setupTestDB(t)
	bidSvc := bid.NewService(bid.NewRepository(db))
	insertOpenAuction(t, db, "auction-guest-commit")

	// 유효한 64자 hex 해시 (더미)
	dummyHash := "a" + string(make([]rune, 63))
	for i := range dummyHash {
		_ = i // 실제 유효 hex: 아래에서 직접 지정
	}
	validHash := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	cases := []struct {
		name        string
		claims      *auth.UserClaims
		wantErrCode string
	}{
		{
			name:        "GUEST는 CommitBid 불가 → ERR_AUTH_002",
			claims:      auth.NewMockGuest("guest-1", "visitor").Claims,
			wantErrCode: "ERR_AUTH_002",
		},
		{
			name:        "BIDDER는 CommitBid 가능",
			claims:      auth.NewMockBidder("bidder-1", "buyer1").Claims,
			wantErrCode: "", // 성공
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := bidSvc.CommitBid(tc.claims, "auction-guest-commit", validHash)
			if tc.wantErrCode == "" {
				if err != nil {
					t.Fatalf("TC-RBAC-COMMIT-01: 예상치 못한 오류 발생 (코드: %T)", err)
				}
				return
			}
			assertErrCode(t, err, tc.wantErrCode)
		})
	}
}

// ─────────────────────────────────────────────
//  Reveal RBAC 테스트
// ─────────────────────────────────────────────

func TestRevealBid_GuestBlocked(t *testing.T) {
	db := setupTestDB(t)
	bidSvc := bid.NewService(bid.NewRepository(db))
	insertClosedAuction(t, db, "auction-guest-reveal")

	guestClaims := auth.NewMockGuest("guest-1", "visitor").Claims
	_, err := bidSvc.RevealBid(guestClaims, "auction-guest-reveal", 1000, "somesalt")
	if err == nil {
		t.Fatal("TC-RBAC-REVEAL-01: 권한 없는 접근이 허용됨")
	}
	assertErrCode(t, err, "ERR_AUTH_002")
}
